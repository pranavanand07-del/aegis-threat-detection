package com.threatdetection.correlation;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * Looks ACROSS events, which per-event scoring cannot do:
 *  - DISTRIBUTED_BRUTE_FORCE  many failures on one account from many addresses (each address alone looks quiet)
 *  - PASSWORD_SPRAYING        one address failing against many accounts
 *  - BRUTE_FORCE_SUCCESS      a successful logon right after a run of failures on that account
 *  - PORT_SCAN_SWEEP          a slow/wide scan whose individual events each score low
 *  - MULTI_STAGE_ATTACK       one address or host showing 3+ different ATT&CK tactics inside an hour
 * Thresholds: -Daegis.chain.dist.failures (20), .dist.ips (5), .spray.accounts (8), .scan.ports (100), .stages (3).
 * It only reads events; blocking is done by whoever registers the callback.
 */
public final class AttackChainEngine {
    public static final class Finding {
        public final String id, lane, type, entity;
        public String ip = "";
        public long first, last;
        public String severity = "HIGH";
        public final Set<String> tactics = new LinkedHashSet<>();
        public final Set<String> techniques = new LinkedHashSet<>();
        public final Set<String> ruleNames = new LinkedHashSet<>();
        public final List<String> evidence = new ArrayList<>();
        public String explanation = "", recommendation = "", response = "";

        Finding(String id, String lane, String type, String entity) {
            this.id = id; this.lane = lane; this.type = type; this.entity = entity;
        }
    }

    private record Obs(long ts, String tactic, String rule, String technique, String summary) {}
    private record Fail(long ts, String ip) {}

    private static final long SHORT_MS = 10 * 60 * 1000L, LONG_MS = 60 * 60 * 1000L;
    private static final int MAX_ENTITIES = 20_000, PER_ENTITY = 400;

    private final String lane;
    private final Consumer<Finding> onFinding;
    private final int distFailures = Integer.getInteger("aegis.chain.dist.failures", 20);
    private final int distIps = Integer.getInteger("aegis.chain.dist.ips", 5);
    private final int sprayAccounts = Integer.getInteger("aegis.chain.spray.accounts", 8);
    private final int scanPorts = Integer.getInteger("aegis.chain.scan.ports", 100);
    private final int stages = Integer.getInteger("aegis.chain.stages", 3);

    private final Map<String, Deque<Obs>> byEntity = new HashMap<>();
    private final Map<String, Deque<Fail>> failsByAccount = new HashMap<>();
    private final Map<String, Deque<Fail>> failsByIp = new HashMap<>();   // Fail.ip field holds the account here
    private final Map<String, Deque<Fail>> portsByIp = new HashMap<>();   // Fail.ip field holds the port here
    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final Set<String> alerted = new HashSet<>();
    private long seq;

    /** @param onFinding called (outside no lock guarantees) when a finding appears or first reaches CRITICAL; may be null */
    public AttackChainEngine(String lane, Consumer<Finding> onFinding) {
        this.lane = lane;
        this.onFinding = onFinding;
    }

    public void observe(AegisEvent e, AegisSignal s) {
        List<Finding> fire = new ArrayList<>();
        synchronized (this) {
            long ts = e.ts > 0 ? e.ts : System.currentTimeMillis();
            tactics(e, s, ts, fire);
            if (s.kind == AegisSignal.Kind.AUTH) auth(e, s, ts, fire);
            if (s.kind == AegisSignal.Kind.NETWORK && !"out".equals(s.direction) && s.port > 0 && !s.ip.isEmpty()) scan(e, s, ts, fire);
            evict(ts);
        }
        if (onFinding != null) for (Finding f : fire) {
            try { onFinding.accept(f); } catch (RuntimeException ex) { System.err.println("[AEGIS] chain callback failed: " + ex); }
        }
    }

    public synchronized List<Finding> findings() {
        List<Finding> out = new ArrayList<>(findings.values());
        out.sort((a, b) -> Long.compare(b.last, a.last));
        return out;
    }

    // ---------------------------------------------------------------- multi-stage chains

    private void tactics(AegisEvent e, AegisSignal s, long ts, List<Finding> fire) {
        List<Obs> mapped = new ArrayList<>();
        for (AegisEvent.Contribution c : e.rules) {
            if (c.score <= 0) continue;
            MitreMap.Tech t = MitreMap.lookup(c.rule);
            if (t != null) mapped.add(new Obs(ts, t.tactic(), c.rule, t.id() + " " + t.name(), e.summary));
        }
        if (mapped.isEmpty()) return;
        for (String key : EntityResolver.keys(s)) {
            if (key.startsWith("user:")) continue;   // accounts are handled by the auth trackers
            Deque<Obs> q = byEntity.computeIfAbsent(key, k -> new ArrayDeque<>());
            for (Obs o : mapped) { q.addLast(o); if (q.size() > PER_ENTITY) q.removeFirst(); }
            while (!q.isEmpty() && ts - q.peekFirst().ts > LONG_MS) q.removeFirst();
            Set<String> tac = new TreeSet<>((a, b) -> MitreMap.order(a) != MitreMap.order(b) ? Integer.compare(MitreMap.order(a), MitreMap.order(b)) : a.compareTo(b));
            for (Obs o : q) tac.add(o.tactic());
            if (tac.size() >= stages) {
                Finding f = upsert("MULTI_STAGE_ATTACK", key, ts, tac.size() >= stages + 1 ? "CRITICAL" : "HIGH", fire);
                f.ip = key.startsWith("ip:") ? key.substring(3) : f.ip;
                f.tactics.clear(); f.tactics.addAll(tac);
                f.techniques.clear(); f.ruleNames.clear(); f.evidence.clear();
                for (Obs o : q) {
                    f.techniques.add(o.technique());
                    f.ruleNames.add(o.rule());
                    if (f.evidence.size() < 12) f.evidence.add(o.rule() + ": " + clip(o.summary()));
                }
                f.explanation = key + " produced evidence in " + tac.size() + " ATT&CK tactics within an hour: " + String.join(" -> ", tac) + ".";
                f.recommendation = key.startsWith("ip:") ? "Investigate this address; block it if it is external and the activity is confirmed."
                        : "Treat this host as potentially compromised: isolate it and review the listed evidence.";
                maybeAlert(f, fire);
            }
        }
    }

    // ---------------------------------------------------------------- authentication patterns

    private void auth(AegisEvent e, AegisSignal s, long ts, List<Finding> fire) {
        String acct = s.user == null ? "" : s.user.toLowerCase();
        if (!EntityResolver.isAccount(acct)) return;
        if (s.authFailure) {
            Deque<Fail> q = failsByAccount.computeIfAbsent(acct, k -> new ArrayDeque<>());
            q.addLast(new Fail(ts, s.ip == null ? "" : s.ip));
            trim(q, ts);
            Set<String> ips = new HashSet<>();
            for (Fail f : q) if (!f.ip().isEmpty()) ips.add(f.ip());
            if (q.size() >= distFailures && ips.size() >= distIps) {
                Finding f = upsert("DISTRIBUTED_BRUTE_FORCE", "user:" + acct, ts, "HIGH", fire);
                f.tactics.add("Credential Access"); f.techniques.add("T1110 Brute Force"); f.ruleNames.add("BRUTE_FORCE");
                f.explanation = q.size() + " failed logons for '" + acct + "' from " + ips.size() + " different addresses in 10 minutes. "
                        + "Each address stays under the per-IP brute-force threshold, so no single-IP rule fires.";
                f.recommendation = "Force a password reset / require MFA for '" + acct + "'. Blocking single addresses will not stop this.";
                f.evidence.clear();
                f.evidence.add(q.size() + " failures, " + ips.size() + " distinct source addresses"
                        + (q.stream().anyMatch(x -> x.ip().isEmpty()) ? " (some events had no source address)" : ""));
                maybeAlert(f, fire);
            }
            if (!s.ip.isEmpty()) {
                Deque<Fail> sq = failsByIp.computeIfAbsent(s.ip, k -> new ArrayDeque<>());
                sq.addLast(new Fail(ts, acct));
                trim(sq, ts);
                Set<String> accts = new HashSet<>();
                for (Fail f : sq) accts.add(f.ip());
                if (accts.size() >= sprayAccounts) {
                    Finding f = upsert("PASSWORD_SPRAYING", "ip:" + s.ip, ts, "CRITICAL", fire);
                    f.ip = s.ip;
                    f.tactics.add("Credential Access"); f.techniques.add("T1110.003 Password Spraying"); f.ruleNames.add("BRUTE_FORCE");
                    f.explanation = s.ip + " failed to log on to " + accts.size() + " different accounts in 10 minutes.";
                    f.recommendation = "Block the address if external; check whether any of those accounts later logged on successfully.";
                    f.evidence.clear();
                    f.evidence.add(accts.size() + " accounts, " + sq.size() + " failures");
                    maybeAlert(f, fire);
                }
            }
        } else if (s.winEventId == 4624 || e.summary.startsWith("Successful")) {
            Deque<Fail> q = failsByAccount.get(acct);
            if (q != null) {
                trim(q, ts);
                if (q.size() >= 5) {
                    // A forgetful user (5 typos, then success from the same office address) must not read as a breach:
                    // CRITICAL needs a long run of failures AND a success from an external address.
                    boolean external = !s.ip.isEmpty() && !com.threatdetection.aegis.intel.IpClassifier.isInternal(s.ip);
                    Finding f = upsert("BRUTE_FORCE_SUCCESS", "user:" + acct, ts, q.size() >= 10 && external ? "CRITICAL" : "HIGH", fire);
                    f.ip = s.ip;
                    f.tactics.add("Credential Access"); f.tactics.add("Initial Access");
                    f.techniques.add("T1110 Brute Force"); f.techniques.add("T1078 Valid Accounts"); f.ruleNames.add("BRUTE_FORCE"); f.ruleNames.add("IMPOSSIBLE_LOGIN");
                    f.explanation = "Successful logon for '" + acct + "' after " + q.size() + " failures in the previous 10 minutes"
                            + (s.ip.isEmpty() ? "." : " (success from " + s.ip + ").");
                    f.recommendation = "Assume the account is compromised: reset credentials, end its sessions, review what it did after the logon.";
                    f.evidence.clear();
                    f.evidence.add(q.size() + " failures then success");
                    maybeAlert(f, fire);
                }
            }
        }
    }

    // ---------------------------------------------------------------- scans

    private void scan(AegisEvent e, AegisSignal s, long ts, List<Finding> fire) {
        Deque<Fail> q = portsByIp.computeIfAbsent(s.ip, k -> new ArrayDeque<>());
        q.addLast(new Fail(ts, Integer.toString(s.port)));
        while (q.size() > 5000) q.removeFirst();
        trim(q, ts);
        Set<String> ports = new HashSet<>();
        for (Fail f : q) ports.add(f.ip());
        if (ports.size() >= scanPorts) {
            Finding f = upsert("PORT_SCAN_SWEEP", "ip:" + s.ip, ts, ports.size() >= scanPorts * 5 ? "CRITICAL" : "HIGH", fire);
            f.ip = s.ip;
            f.tactics.add("Reconnaissance"); f.techniques.add("T1046 Network Service Discovery"); f.ruleNames.add("PORT_SCAN");
            f.explanation = s.ip + " touched " + ports.size() + " different ports in 10 minutes. Each event scores low on its own, so the per-event score never reaches the block line.";
            f.recommendation = "Block the address if external; check which ports answered.";
            f.evidence.clear();
            f.evidence.add(ports.size() + " distinct ports");
            maybeAlert(f, fire);
        }
    }

    // ---------------------------------------------------------------- plumbing

    private Finding upsert(String type, String entity, long ts, String severity, List<Finding> fire) {
        String key = type + "|" + entity;
        Finding f = findings.get(key);
        if (f == null) {
            f = new Finding(lane + "-" + (++seq), lane, type, entity);
            f.first = ts;
            f.severity = severity;
            findings.put(key, f);
            if (findings.size() > 2000) findings.remove(findings.keySet().iterator().next());
        } else if (severity.equals("CRITICAL")) {
            f.severity = severity;
        }
        f.last = ts;
        return f;
    }

    /** The callback fires once per finding, when it is first created or first reaches CRITICAL. */
    private void maybeAlert(Finding f, List<Finding> fire) {
        String mark = f.id + "|" + f.severity;
        if (alerted.add(mark)) fire.add(f);
        if (alerted.size() > 10_000) alerted.clear();
    }

    private static void trim(Deque<Fail> q, long now) {
        while (!q.isEmpty() && now - q.peekFirst().ts() > SHORT_MS) q.removeFirst();
    }

    private void evict(long now) {
        if (byEntity.size() > MAX_ENTITIES) byEntity.values().removeIf(q -> q.isEmpty() || now - q.peekLast().ts > LONG_MS);
        if (failsByAccount.size() > MAX_ENTITIES) failsByAccount.values().removeIf(q -> q.isEmpty() || now - q.peekLast().ts() > SHORT_MS);
        if (failsByIp.size() > MAX_ENTITIES) failsByIp.values().removeIf(q -> q.isEmpty() || now - q.peekLast().ts() > SHORT_MS);
        if (portsByIp.size() > MAX_ENTITIES) portsByIp.values().removeIf(q -> q.isEmpty() || now - q.peekLast().ts() > SHORT_MS);
    }

    private static String clip(String s) { return s == null ? "" : s.length() > 100 ? s.substring(0, 100) + "..." : s; }
}
