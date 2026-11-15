package com.threatdetection.response;

import com.threatdetection.decision.ConfidenceEngine;
import com.threatdetection.model.ThreatLevel;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Ties confidence + policy + the Windows Firewall adapter + the audit trail together. Only the LIVE lane gets one
 * of these; the sandbox (simulator / Attack Lab) never touches the operating-system firewall.
 */
public final class OsResponseCoordinator {
    public record Pending(long id, String ip, long ts, int score, double confidence, List<String> reasons, String source) {}

    private static final long DEFAULT_TTL_MS = 10 * 60 * 1000L;
    private static final int MAX_PENDING = 200;

    private final WindowsFirewallAdapter firewall;
    private final ResponsePolicyEngine policy;
    private final AuditLogger audit;
    private final AtomicLong ids = new AtomicLong();

    public OsResponseCoordinator(WindowsFirewallAdapter firewall, ResponsePolicyEngine policy, AuditLogger audit) {
        this.firewall = firewall;
        this.policy = policy;
        this.audit = audit;
    }

    public static OsResponseCoordinator fromSystemProperties(Allowlist allowlist) {
        Path dir = Path.of(System.getProperty("aegis.data.dir", "aegis-data"));
        AuditLogger audit = "false".equalsIgnoreCase(System.getProperty("aegis.persist"))
                ? AuditLogger.memoryOnly() : new AuditLogger(dir.resolve("response-audit.log"));
        return new OsResponseCoordinator(WindowsFirewallAdapter.fromSystemProperties(allowlist, audit),
                ResponsePolicyEngine.fromSystemProperties(allowlist), audit);
    }

    public AuditLogger audit() { return audit; }
    public WindowsFirewallAdapter firewall() { return firewall; }

    /** Structured answer: {@code status} is one of APPLIED, ALREADY_BLOCKED, DRY_RUN, AWAITING_APPROVAL, NO_ACTION, REFUSED, FAILED, DISABLED. */
    public record Handled(String note, String status) {}

    /**
     * Called when the core engine has classified an address CRITICAL.
     * @return a one-line note for the event's rule list (never null)
     */
    public String handle(String ip, int score, ThreatLevel level, List<String> rules, String source) {
        return handleDetailed(ip, score, level, rules, source).note();
    }

    public Handled handleDetailed(String ip, int score, ThreatLevel level, List<String> rules, String source) {
        boolean external = !com.threatdetection.aegis.intel.IpClassifier.isInternal(ip);
        ConfidenceEngine.Confidence conf = ConfidenceEngine.assess(rules, score, external);
        ResponsePolicyEngine.Decision d = policy.decide(ip, level, conf.value());
        String detail = d.reason() + " | " + String.join("; ", conf.reasons());
        switch (d.action()) {
            case BLOCK -> {
                WindowsFirewallAdapter.Outcome o = firewall.block(ip, DEFAULT_TTL_MS, source + ": " + d.reason(), "auto-response");
                String st = switch (o.status()) {
                    case APPLIED -> "APPLIED";
                    case ALREADY_BLOCKED -> "ALREADY_BLOCKED";
                    case DRY_RUN -> "DRY_RUN";
                    case REFUSED -> "REFUSED";
                    case DISABLED -> "DISABLED";
                    case ERROR -> "FAILED";
                };
                return new Handled("OS_FIREWALL: " + o.status() + " - " + o.message(), st);
            }
            case APPROVE -> {
                queue(ip, score, conf, source);
                audit.log("auto-response", "APPROVAL_REQUESTED", ip, "PENDING", detail);
                return new Handled("OS_FIREWALL: awaiting analyst approval (" + d.reason() + ")", "AWAITING_APPROVAL");
            }
            default -> {
                audit.log("auto-response", "RESPONSE_DECISION", ip, d.action().name(), detail);
                return new Handled("OS_FIREWALL: no firewall action (" + d.action() + ": " + d.reason() + ")", "NO_ACTION");
            }
        }
    }

    /** Lifecycle of an analyst-approval request. PENDING and FAILED requests are still open (FAILED can be retried). */
    public enum ApprovalState { PENDING, APPROVED, APPLIED, DRY_RUN, FAILED, REFUSED, REJECTED }

    /** Full record of a request, kept after it is decided so the analyst identity and outcome stay visible. */
    public record Decision(long id, String ip, ApprovalState state, long requestedAt, String decidedBy, long decidedAt, String outcome) {}

    private static final class Request {
        final Pending p;
        ApprovalState state = ApprovalState.PENDING;
        String decidedBy = "";
        long decidedAt;
        String outcome = "";
        Request(Pending p) { this.p = p; }
        boolean open() { return state == ApprovalState.PENDING || state == ApprovalState.FAILED; }
    }

    private static final int MAX_HISTORY = 500;
    private final List<Request> requests = new ArrayList<>();

    private synchronized void queue(String ip, int score, ConfidenceEngine.Confidence c, String source) {
        for (Request r : requests) if (r.open() && r.p.ip().equals(ip)) return;   // one open request per address
        long open = requests.stream().filter(Request::open).count();
        if (open >= MAX_PENDING) {
            for (Request r : requests) {
                if (r.open()) {   // evict the oldest open request, but never silently
                    r.state = ApprovalState.REFUSED;
                    r.decidedBy = "system";
                    r.decidedAt = System.currentTimeMillis();
                    r.outcome = "queue full, request evicted unanswered";
                    audit.log("system", "APPROVAL_EVICTED", r.p.ip(), "REFUSED", r.outcome);
                    break;
                }
            }
        }
        requests.add(new Request(new Pending(ids.incrementAndGet(), ip, System.currentTimeMillis(), score, c.value(), c.reasons(), source)));
        while (requests.size() > MAX_PENDING + MAX_HISTORY) {
            for (int i = 0; i < requests.size(); i++) if (!requests.get(i).open()) { requests.remove(i); break; }
            if (requests.stream().allMatch(Request::open)) break;
        }
    }

    /** Requests still waiting for a decision (including ones whose last attempt FAILED and can be retried). */
    public synchronized List<Pending> pending() {
        List<Pending> out = new ArrayList<>();
        for (Request r : requests) if (r.open()) out.add(r.p);
        return out;
    }

    /** Decided requests, newest last: who decided, when, and what happened. */
    public synchronized List<Decision> history() {
        List<Decision> out = new ArrayList<>();
        for (Request r : requests) if (r.decidedAt > 0)
            out.add(new Decision(r.p.id(), r.p.ip(), r.state, r.p.ts(), r.decidedBy, r.decidedAt, r.outcome));
        return out;
    }

    /**
     * Applies an approved block. The request is NOT removed before the outcome is known:
     *  PENDING/FAILED -> APPROVED (in progress) -> APPLIED | DRY_RUN | FAILED | REFUSED.
     * The method is synchronized, so concurrent approvals of one request are serialized and the second sees a final
     * state and does nothing: the firewall action can never run twice. A FAILED request can be approved again.
     */
    public synchronized WindowsFirewallAdapter.Outcome approve(long id, String analyst) {
        for (Request r : requests) {
            if (r.p.id() != id) continue;
            if (!r.open()) {
                String note = "request " + id + " is already " + r.state + (r.decidedBy.isEmpty() ? "" : " (by " + r.decidedBy + ")");
                audit.log(analyst, "APPROVAL_IGNORED", r.p.ip(), r.state.name(), note);
                WindowsFirewallAdapter.Status st = r.state == ApprovalState.APPLIED ? WindowsFirewallAdapter.Status.ALREADY_BLOCKED
                        : r.state == ApprovalState.DRY_RUN ? WindowsFirewallAdapter.Status.DRY_RUN : WindowsFirewallAdapter.Status.REFUSED;
                return new WindowsFirewallAdapter.Outcome(st, note);
            }
            r.state = ApprovalState.APPROVED;
            r.decidedBy = analyst;
            r.decidedAt = System.currentTimeMillis();
            audit.log(analyst, "APPROVAL_GRANTED", r.p.ip(), "APPROVED", "confidence " + String.format("%.2f", r.p.confidence()));
            WindowsFirewallAdapter.Outcome o;
            try {
                o = firewall.block(r.p.ip(), DEFAULT_TTL_MS, "approved by " + analyst, analyst);
            } catch (RuntimeException e) {
                o = new WindowsFirewallAdapter.Outcome(WindowsFirewallAdapter.Status.ERROR, "unexpected failure: " + e.getClass().getSimpleName());
            }
            r.outcome = o.status() + ": " + o.message();
            r.state = switch (o.status()) {
                case APPLIED, ALREADY_BLOCKED -> ApprovalState.APPLIED;
                case DRY_RUN -> ApprovalState.DRY_RUN;
                case REFUSED -> ApprovalState.REFUSED;
                case ERROR, DISABLED -> ApprovalState.FAILED;
            };
            audit.log(analyst, "APPROVAL_RESULT", r.p.ip(), r.state.name(), r.outcome);
            return o;
        }
        return new WindowsFirewallAdapter.Outcome(WindowsFirewallAdapter.Status.REFUSED, "no request " + id);
    }

    public synchronized boolean reject(long id, String analyst) {
        for (Request r : requests) {
            if (r.p.id() == id && r.open()) {
                r.state = ApprovalState.REJECTED;
                r.decidedBy = analyst;
                r.decidedAt = System.currentTimeMillis();
                r.outcome = "analyst declined to block";
                audit.log(analyst, "APPROVAL_REJECTED", r.p.ip(), "REJECTED", r.outcome);
                return true;
            }
        }
        return false;
    }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>(firewall.status());
        m.put("pendingApprovals", pending().size());
        String chain = audit.verify();
        m.put("auditChainIntact", chain == null);
        if (chain != null) m.put("auditProblem", chain);
        return m;
    }
}
