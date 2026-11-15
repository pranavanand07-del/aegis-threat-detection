package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.model.DetectionOutcome;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Heuristic checks on Sysmon process-creation events (Event ID 1). These are well-known
 * behavioural indicators, not proof of compromise: expect some false positives from admin tooling.
 */
public class SysmonProcessRule implements AegisRule {
    private static final Set<String> OFFICE = Set.of("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe");
    private static final Set<String> SHELLS = Set.of("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe");
    private static final Pattern ENC_PS = Pattern.compile("\\s-(e|ec|enc|encodedcommand)\\s+[a-z0-9+/=]{20,}");

    @Override
    public DetectionOutcome evaluate(AegisSignal s) {
        if (s.kind != AegisSignal.Kind.PROCESS) return null;
        String image = s.path.toLowerCase();
        String cmd = s.command.toLowerCase();
        String exe = base(image);
        String parent = base(s.parent.toLowerCase());
        String all = image + " " + cmd;

        if (all.contains("mimikatz") || all.contains("sekurlsa::") || all.contains("lsadump::")) {
            return hit("CREDENTIAL_DUMPING", 70, "Credential-dumping tool or command: " + shorten(s.command));
        }
        if (cmd.contains("vssadmin") && cmd.contains("delete") && cmd.contains("shadows")
                || cmd.contains("wbadmin") && cmd.contains("delete")
                || cmd.contains("bcdedit") && cmd.contains("recoveryenabled") && cmd.contains("no")) {
            return hit("BACKUP_DESTRUCTION", 60, "Backup/shadow-copy deletion (ransomware precursor): " + shorten(s.command));
        }
        if (OFFICE.contains(parent) && SHELLS.contains(exe)) {
            return hit("OFFICE_SPAWNS_SHELL", 55, parent + " started " + exe + " (macro/exploit behaviour)");
        }
        if (cmd.contains("reg") && cmd.contains("save") && (cmd.contains("hklm\\sam") || cmd.contains("hklm\\security") || cmd.contains("hklm\\system"))) {
            return hit("REGISTRY_HIVE_DUMP", 55, "Registry hive export: " + shorten(s.command));
        }
        if (cmd.contains("wevtutil") && (cmd.contains(" cl ") || cmd.contains("clear-log")) || cmd.contains("clear-eventlog")) {
            return hit("LOG_CLEARING", 50, "Event log clearing command: " + shorten(s.command));
        }
        if (exe.startsWith("powershell") || exe.equals("pwsh.exe")) {
            if (ENC_PS.matcher(" " + cmd).find() || cmd.contains("downloadstring") || cmd.contains("invoke-expression")
                    || cmd.contains(" iex ") || cmd.contains("frombase64string") || cmd.contains("-nop") && cmd.contains("-w hidden")) {
                return hit("SUSPICIOUS_POWERSHELL", 45, "Encoded/download-and-execute PowerShell: " + shorten(s.command));
            }
        }
        if (cmd.contains("certutil") && (cmd.contains("-urlcache") || cmd.contains("-decode"))
                || cmd.contains("bitsadmin") && cmd.contains("/transfer")
                || exe.equals("mshta.exe") && cmd.contains("http")
                || cmd.contains("regsvr32") && (cmd.contains("/i:http") || cmd.contains("scrobj"))
                || cmd.contains("rundll32") && cmd.contains("javascript:")) {
            return hit("LOLBIN_ABUSE", 45, "Living-off-the-land binary used to fetch/run code: " + shorten(s.command));
        }
        if (cmd.contains("net user") && cmd.contains("/add") || cmd.contains("net localgroup administrators") && cmd.contains("/add")) {
            return hit("ACCOUNT_CREATION_CLI", 40, "Account created via command line: " + shorten(s.command));
        }
        if (cmd.contains("schtasks") && cmd.contains("/create") && (cmd.contains("\\temp\\") || cmd.contains("appdata"))) {
            return hit("SUSPICIOUS_PERSISTENCE", 30, "Scheduled task pointing at a user-writable path: " + shorten(s.command));
        }
        if (image.contains("\\appdata\\local\\temp\\") || image.contains("\\users\\public\\") || image.contains("\\downloads\\")) {
            return hit("EXEC_FROM_USER_PATH", 20, "Process launched from a user-writable folder: " + shorten(s.path));
        }
        if (cmd.contains("whoami /priv") || cmd.contains("whoami /all") || cmd.contains("nltest /dclist")
                || cmd.contains("net group \"domain admins\"")) {
            return hit("RECON_COMMAND", 15, "Host/domain reconnaissance command: " + shorten(s.command));
        }
        return null;
    }

    private static DetectionOutcome hit(String name, int score, String detail) {
        return new DetectionOutcome(name, score, detail);
    }

    private static String base(String path) {
        int i = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'));
        return i >= 0 ? path.substring(i + 1) : path;
    }

    private static String shorten(String s) {
        return s.length() > 140 ? s.substring(0, 140) + "..." : s;
    }
}
