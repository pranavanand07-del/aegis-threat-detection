package com.threatdetection.platform;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Human-readable description of every detection rule: what triggers it, how many points it adds,
 * which attack-chain stage it belongs to and which MITRE ATT&CK technique it relates to.
 *
 * This is documentation-as-data. The thresholds and point values below mirror the detector classes
 * (com.threatdetection.detector.* and com.threatdetection.aegis.rules.*); the self-test in
 * {@link SelfTest} runs the real rule code against these claims.
 */
public final class RuleCatalog {
    private RuleCatalog() {}

    /** One stage of the simplified attack chain used by the campaign correlator. */
    public record Stage(String id, String name, String summary) {}

    /**
     * @param id        rule name exactly as the engine reports it
     * @param origin    "core" (original 11 detectors) or "aegis" (added rules)
     * @param family    Signature | Threshold | Behavioural | Network | Host | Intel
     * @param stage     attack-chain stage id, or null for context signals that only add weight
     * @param technique MITRE ATT&CK technique, or "" when there is no clean mapping
     * @param trigger   what has to happen for the rule to fire
     * @param min       fewest points it can add
     * @param max       most points it can add
     * @param caution   where it can be wrong
     */
    public record Rule(String id, String origin, String family, String stage, String technique,
                       String trigger, int min, int max, String caution) {}

    public static final List<Stage> STAGES = List.of(
            new Stage("recon", "Recon & discovery", "Mapping the target: open ports, hidden paths, accounts."),
            new Stage("access", "Initial access", "Getting in: password guessing, web exploits, exposed services."),
            new Stage("exec", "Execution", "Running attacker code on a machine."),
            new Stage("persist", "Persistence & credential theft", "Staying in and stealing keys: new accounts, scheduled tasks, password dumps."),
            new Stage("impact", "Impact & cover-up", "Doing damage or hiding it: floods, backup deletion, log clearing."));

    private static final String HEURISTIC = "Behavioural heuristic: legitimate admin tooling can trigger it, which is why it adds points instead of blocking by itself.";

    public static final List<Rule> RULES = List.of(
            // ---- core detectors ------------------------------------------------------------
            new Rule("BLACKLISTED_IP", "core", "Intel", null, "",
                    "Source IP is on the blacklist (3 demo addresses built in; threat-intel feeds add more).",
                    50, 50, "Shared or recycled addresses can be listed wrongly. Use feeds that expire old entries."),
            new Rule("BRUTE_FORCE", "core", "Threshold", "access", "T1110 Brute Force",
                    "5 or more failed logins from one IP inside 2 minutes. Points = 10 + min(40, (failures - 5) x 5).",
                    10, 50, "Someone who forgot a password five times looks identical, so this rule alone can never reach the block line."),
            new Rule("SQL_INJECTION", "core", "Signature", "access", "T1190 Exploit Public-Facing Application",
                    "Path or body contains a known SQL attack string (e.g. ' or 1=1, union select, drop table). Input is URL-decoded (up to 3 layers) and comment-stripped first, so %27 OR 1%3D1 and UNION/**/SELECT are seen as the server sees them.",
                    40, 40, "Signature matching only: a novel payload with no known keyword still slips through. A bare \"--\" no longer counts; it needs a quote or SQL keyword before it."),
            new Rule("XSS_ATTACK", "core", "Signature", "access", "T1059.007 JavaScript",
                    "Path or body contains script-injection markers (<script, onerror=, javascript:, document.cookie, alert( ...).",
                    25, 25, "Code samples posted on a developer forum can match."),
            new Rule("DDOS", "core", "Threshold", "impact", "T1498 Network Denial of Service",
                    "50 or more requests from one IP inside 10 seconds. Points = 30 + min(30, floor((n - 50) / 10) x 5).",
                    30, 60, "A busy NAT gateway makes many users look like one client."),
            new Rule("PORT_SCAN", "core", "Threshold", "recon", "T1046 Network Service Discovery",
                    "5 or more different ports touched by one IP inside 1 minute.",
                    25, 25, "Vulnerability scanners you run yourself will trigger it. Allow-list them."),
            new Rule("BOT_DETECTED", "core", "Signature", null, "T1595 Active Scanning",
                    "User-Agent is missing (+10) or names an automation tool such as sqlmap, nikto, nmap, curl (+15). Not applied to port or firewall events, which have no HTTP headers.",
                    10, 15, "Health checks and scripts that use curl are legitimate. It adds weight but cannot block alone. Logon events that arrive without a User-Agent (for example Windows logons) also receive the +10, a known limitation."),
            new Rule("IMPOSSIBLE_LOGIN", "core", "Behavioural", "access", "T1078 Valid Accounts",
                    "A successful login for an account reports a different country than that same account's previous login, within 10 minutes (from any IP).",
                    35, 35, "Needs a trustworthy country on the event (GeoIP or the source system). Corporate VPNs and mobile carriers that exit in another country cause false positives."),
            new Rule("MALWARE_DOWNLOAD", "core", "Signature", "exec", "T1105 Ingress Tool Transfer",
                    "Download request for a .exe, .bat, .dll, .vbs, .ps1 or .scr file.",
                    30, 30, "Legitimate installers are .exe too. Trusted internal hosts should be allowed."),
            new Rule("SUSPICIOUS_TIME", "core", "Behavioural", null, "T1078 Valid Accounts",
                    "Login activity between 02:00 and 03:59 server time.",
                    10, 10, "Night-shift staff trigger it. The weight is deliberately tiny."),
            new Rule("BEHAVIOR_ANOMALY", "core", "Behavioural", null, "",
                    "At least 20 requests in the last 60 s AND more than 5 times that IP's own running average, after a learning period of 3 observations. Abnormal minutes are never folded into the average.",
                    20, 20, "Needs history first, so a brand-new IP is never flagged by it. This is the anomaly-based detector; the rest are signature or threshold based."),

            // ---- AEGIS: web ---------------------------------------------------------------
            new Rule("PATH_TRAVERSAL", "aegis", "Signature", "access", "T1190 Exploit Public-Facing Application",
                    "Request contains ../ style sequences or sensitive files (/etc/passwd, win.ini ...). Checked raw, URL-decoded once and decoded twice (13 markers).",
                    40, 40, "Decoding twice catches %252e%252e%252f tricks, but a legitimate relative link containing ../ will match."),
            new Rule("LOG4SHELL_PROBE", "aegis", "Signature", "access", "T1190 Exploit Public-Facing Application (CVE-2021-44228)",
                    "Request contains a ${jndi: lookup string.",
                    50, 50, "Very specific. Obfuscated variants that avoid the literal text are not covered."),
            new Rule("COMMAND_INJECTION", "aegis", "Signature", "access", "T1059 Command and Scripting Interpreter",
                    "A shell separator (; | && ` $( ) is followed by a command such as cat, whoami, wget, bash or powershell.",
                    35, 35, "Free text that happens to contain \"; cat\" will match."),
            new Rule("SENSITIVE_PATH_PROBE", "aegis", "Signature", "recon", "T1595.003 Wordlist Scanning",
                    "Request for a path scanners love: /.env, /.git/, /.aws/, /phpmyadmin, /wp-config, /id_rsa ... (14 paths).",
                    15, 15, "Low weight on purpose: a single probe proves little, a series of them is the signal."),

            // ---- AEGIS: network -----------------------------------------------------------
            new Rule("EXPOSED_SERVICE_ACCESS", "aegis", "Network", "access", "T1133 External Remote Services",
                    "The firewall ALLOWED an outside address to reach a port that should never face the internet (23, 135, 139, 445, 2375, 3389, 5900).",
                    25, 25, "This is a configuration finding as much as an attack: it says the door was open."),
            new Rule("REPEATED_CONNECTIONS", "aegis", "Threshold", "recon", "T1046 Network Service Discovery",
                    "15 or more connection attempts from one IP to one port inside 60 seconds.",
                    20, 20, "Chatty but legitimate clients (polling scripts) can reach 15 per minute."),
            new Rule("SENSITIVE_PORT_PROBE", "aegis", "Network", "recon", "T1046 Network Service Discovery",
                    "A blocked attempt to reach a sensitive port (21, 23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017).",
                    10, 10, "Internet background noise hits these ports all day, hence the small weight."),

            // ---- AEGIS: Windows Security log ------------------------------------------------
            new Rule("ACCOUNT_LOCKOUT", "aegis", "Host", "access", "T1110 Brute Force",
                    "Windows Event 4740: an account was locked out.",
                    40, 40, "Users lock themselves out. Weighted as evidence, not proof."),
            new Rule("AUDIT_LOG_CLEARED", "aegis", "Host", "impact", "T1070.001 Clear Windows Event Logs",
                    "Windows Event 1102: the security log was cleared.",
                    60, 60, "Rare in normal operation, so it carries a high weight."),
            new Rule("ACCOUNT_CREATED", "aegis", "Host", "persist", "T1136 Create Account",
                    "Windows Event 4720: a new account was created.",
                    30, 30, "Normal during onboarding. Matters most when it follows other suspicious steps."),
            new Rule("GROUP_MEMBERSHIP_CHANGE", "aegis", "Host", "persist", "T1098 Account Manipulation",
                    "Windows Events 4728 / 4732 / 4756: a member was added to a group. 45 points if the group name contains \"admin\", otherwise 25.",
                    25, 45, "Routine IT changes look the same. Context from the campaign view is what separates them."),
            new Rule("RDP_FAILED_LOGON", "aegis", "Host", "access", "T1110 Brute Force",
                    "Windows Event 4625 with logon type 10 (Remote Desktop).",
                    10, 10, "A single mistyped password is normal."),
            new Rule("EXTERNAL_RDP_LOGON", "aegis", "Host", "access", "T1021.001 Remote Desktop Protocol",
                    "Windows Event 4624 with logon type 10 from a non-private IP address.",
                    25, 25, "Legitimate remote workers will match unless their IPs are allow-listed."),

            // ---- AEGIS: Sysmon process events ---------------------------------------------
            new Rule("CREDENTIAL_DUMPING", "aegis", "Host", "persist", "T1003 OS Credential Dumping",
                    "mimikatz, sekurlsa:: or lsadump:: appears in the program path or command line.",
                    70, 70, "Security teams run these tools in tests. Renamed binaries evade the text match."),
            new Rule("BACKUP_DESTRUCTION", "aegis", "Host", "impact", "T1490 Inhibit System Recovery",
                    "vssadmin delete shadows, wbadmin delete, or bcdedit turning recovery off. A classic ransomware step.",
                    60, 60, HEURISTIC),
            new Rule("OFFICE_SPAWNS_SHELL", "aegis", "Host", "exec", "T1204.002 Malicious File",
                    "Word, Excel, PowerPoint, Outlook or Access starts cmd, PowerShell, wscript, cscript or mshta.",
                    55, 55, "Some old macro-based business tools do this legitimately."),
            new Rule("REGISTRY_HIVE_DUMP", "aegis", "Host", "persist", "T1003.002 Security Account Manager",
                    "reg save of the SAM, SECURITY or SYSTEM hive.",
                    55, 55, HEURISTIC),
            new Rule("LOG_CLEARING", "aegis", "Host", "impact", "T1070.001 Clear Windows Event Logs",
                    "A wevtutil cl or Clear-EventLog command line.",
                    50, 50, HEURISTIC),
            new Rule("SUSPICIOUS_POWERSHELL", "aegis", "Host", "exec", "T1059.001 PowerShell",
                    "PowerShell with an encoded command, DownloadString, Invoke-Expression / iex, FromBase64String, or -nop with a hidden window.",
                    45, 45, HEURISTIC),
            new Rule("LOLBIN_ABUSE", "aegis", "Host", "exec", "T1218 System Binary Proxy Execution",
                    "certutil -urlcache / -decode, bitsadmin /transfer, mshta with http, regsvr32 scrobj, rundll32 javascript:.",
                    45, 45, HEURISTIC),
            new Rule("ACCOUNT_CREATION_CLI", "aegis", "Host", "persist", "T1136.001 Local Account",
                    "net user ... /add, or adding a user to the local administrators group from the command line.",
                    40, 40, HEURISTIC),
            new Rule("SUSPICIOUS_PERSISTENCE", "aegis", "Host", "persist", "T1053.005 Scheduled Task",
                    "schtasks /create pointing at a temp or AppData folder.",
                    30, 30, HEURISTIC),
            new Rule("EXEC_FROM_USER_PATH", "aegis", "Host", "exec", "T1204 User Execution",
                    "A process started from AppData\\Local\\Temp, Users\\Public or Downloads.",
                    20, 20, "Portable apps and installers run from Downloads all the time. Small weight."),
            new Rule("RECON_COMMAND", "aegis", "Host", "recon", "T1087 Account Discovery",
                    "whoami /priv, whoami /all, nltest /dclist or a listing of Domain Admins.",
                    15, 15, "Admins run these daily."),

            // ---- AEGIS: reputation ------------------------------------------------------------
            new Rule("THREAT_INTEL_MATCH", "aegis", "Intel", null, "",
                    "The IP appears in a loaded threat-intel feed (only added when the core blacklist did not already match).",
                    30, 30, "Only as good as the feed. With no feed loaded, reputation is reported as NO_DATA, never as clean."));

    private static final Map<String, Rule> BY_ID = new HashMap<>();
    private static final Map<String, Integer> STAGE_INDEX = new HashMap<>();

    static {
        for (Rule r : RULES) BY_ID.put(r.id(), r);
        for (int i = 0; i < STAGES.size(); i++) STAGE_INDEX.put(STAGES.get(i).id(), i);
    }

    public static Rule find(String id) {
        return BY_ID.get(id);
    }

    /** Stage id for a rule, or null when the rule is unknown or only a context signal. */
    public static String stageOf(String ruleId) {
        Rule r = BY_ID.get(ruleId);
        return r == null ? null : r.stage();
    }

    public static int stageIndex(String stageId) {
        Integer i = STAGE_INDEX.get(stageId);
        return i == null ? -1 : i;
    }

    public static String stageName(String stageId) {
        int i = stageIndex(stageId);
        return i < 0 ? "" : STAGES.get(i).name();
    }
}
