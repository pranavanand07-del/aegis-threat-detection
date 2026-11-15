package com.threatdetection.correlation;

import java.util.List;
import java.util.Map;

/** Rule name to MITRE ATT&CK tactic and technique. Hand-maintained; unmapped rules simply carry no tactic. */
public final class MitreMap {
    public record Tech(String tactic, String id, String name) {}

    /** Typical order of an intrusion; used to print a chain left to right. */
    public static final List<String> TACTIC_ORDER = List.of("Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Command and Control", "Impact");

    private static final Map<String, Tech> MAP = Map.ofEntries(
            Map.entry("PORT_SCAN", new Tech("Reconnaissance", "T1595.001", "Scanning IP Blocks")),
            Map.entry("REPEATED_CONNECTIONS", new Tech("Reconnaissance", "T1046", "Network Service Discovery")),
            Map.entry("SENSITIVE_PORT_PROBE", new Tech("Reconnaissance", "T1046", "Network Service Discovery")),
            Map.entry("SENSITIVE_PATH_PROBE", new Tech("Reconnaissance", "T1595.003", "Wordlist Scanning")),
            Map.entry("SQL_INJECTION", new Tech("Initial Access", "T1190", "Exploit Public-Facing Application")),
            Map.entry("XSS_ATTACK", new Tech("Initial Access", "T1190", "Exploit Public-Facing Application")),
            Map.entry("PATH_TRAVERSAL", new Tech("Initial Access", "T1190", "Exploit Public-Facing Application")),
            Map.entry("LOG4SHELL_PROBE", new Tech("Initial Access", "T1190", "Exploit Public-Facing Application")),
            Map.entry("COMMAND_INJECTION", new Tech("Initial Access", "T1190", "Exploit Public-Facing Application")),
            Map.entry("EXTERNAL_RDP_LOGON", new Tech("Initial Access", "T1133", "External Remote Services")),
            Map.entry("EXPOSED_SERVICE_ACCESS", new Tech("Initial Access", "T1133", "External Remote Services")),
            Map.entry("IMPOSSIBLE_LOGIN", new Tech("Initial Access", "T1078", "Valid Accounts")),
            Map.entry("BRUTE_FORCE", new Tech("Credential Access", "T1110", "Brute Force")),
            Map.entry("RDP_FAILED_LOGON", new Tech("Credential Access", "T1110", "Brute Force")),
            Map.entry("ACCOUNT_LOCKOUT", new Tech("Credential Access", "T1110", "Brute Force")),
            Map.entry("CREDENTIAL_DUMPING", new Tech("Credential Access", "T1003", "OS Credential Dumping")),
            Map.entry("REGISTRY_HIVE_DUMP", new Tech("Credential Access", "T1003.002", "Security Account Manager")),
            Map.entry("SUSPICIOUS_POWERSHELL", new Tech("Execution", "T1059.001", "PowerShell")),
            Map.entry("OFFICE_SPAWNS_SHELL", new Tech("Execution", "T1204.002", "Malicious File")),
            Map.entry("EXEC_FROM_USER_PATH", new Tech("Execution", "T1204", "User Execution")),
            Map.entry("ACCOUNT_CREATED", new Tech("Persistence", "T1136", "Create Account")),
            Map.entry("ACCOUNT_CREATION_CLI", new Tech("Persistence", "T1136.001", "Local Account")),
            Map.entry("SUSPICIOUS_PERSISTENCE", new Tech("Persistence", "T1053.005", "Scheduled Task")),
            Map.entry("GROUP_MEMBERSHIP_CHANGE", new Tech("Privilege Escalation", "T1098", "Account Manipulation")),
            Map.entry("LOLBIN_ABUSE", new Tech("Defense Evasion", "T1218", "System Binary Proxy Execution")),
            Map.entry("LOG_CLEARING", new Tech("Defense Evasion", "T1070.001", "Clear Windows Event Logs")),
            Map.entry("AUDIT_LOG_CLEARED", new Tech("Defense Evasion", "T1070.001", "Clear Windows Event Logs")),
            Map.entry("RECON_COMMAND", new Tech("Discovery", "T1033", "System Owner/User Discovery")),
            Map.entry("MALWARE_DOWNLOAD", new Tech("Command and Control", "T1105", "Ingress Tool Transfer")),
            Map.entry("BACKUP_DESTRUCTION", new Tech("Impact", "T1490", "Inhibit System Recovery")),
            Map.entry("DDOS", new Tech("Impact", "T1498", "Network Denial of Service")));

    private MitreMap() {}

    public static Tech lookup(String rule) { return MAP.get(rule); }

    public static int order(String tactic) {
        int i = TACTIC_ORDER.indexOf(tactic);
        return i < 0 ? 99 : i;
    }
}
