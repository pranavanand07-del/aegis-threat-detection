package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.AegisSignal;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Supported formats: Windows Firewall (pfirewall.log, W3C-style) and Linux netfilter/UFW lines
 * (those containing SRC= DST= DPT=). Other vendors' formats are not parsed.
 */
public final class FirewallLogParser {
    private static final Pattern WIN_DATE = Pattern.compile("^(\\d{4})-(\\d{2})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2}) .*");
    private static final Pattern SRC = Pattern.compile("SRC=(\\S+)");
    private static final Pattern DPT = Pattern.compile("DPT=(\\d+)");
    private static final Pattern IN_IF = Pattern.compile("\\bIN=(\\S*)");

    private FirewallLogParser() {}

    public static AegisSignal parse(String line) {
        if (line.isEmpty() || line.startsWith("#")) return null;
        if (WIN_DATE.matcher(line).matches()) return parseWindows(line);
        if (line.contains("SRC=") && line.contains("DPT=")) return parseNetfilter(line);
        return null;
    }

    // date time action protocol src-ip dst-ip src-port dst-port size tcpflags ... info path
    private static AegisSignal parseWindows(String line) {
        String[] t = line.trim().split("\\s+");
        if (t.length < 8) return null;
        String action = t[2];
        if (!action.equals("ALLOW") && !action.equals("DROP")) return null;
        AegisSignal s = new AegisSignal(AegisSignal.Kind.NETWORK);
        s.channel = "firewall-log";
        s.action = action;
        boolean send = t[t.length - 1].equals("SEND");
        s.direction = send ? "out" : "in";
        s.ip = send ? t[5] : t[4];
        try {
            s.port = Integer.parseInt(t[7]);
        } catch (NumberFormatException e) {
            return null;
        }
        try {
            Matcher m = WIN_DATE.matcher(line);
            if (m.matches()) {
                s.ts = LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
                        Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)), Integer.parseInt(m.group(6)))
                        .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
            }
        } catch (RuntimeException e) {
            s.ts = 0;
        }
        return s;
    }

    private static AegisSignal parseNetfilter(String line) {
        Matcher src = SRC.matcher(line), dpt = DPT.matcher(line);
        if (!src.find() || !dpt.find()) return null;
        AegisSignal s = new AegisSignal(AegisSignal.Kind.NETWORK);
        s.channel = "firewall-log";
        s.ip = src.group(1);
        s.port = Integer.parseInt(dpt.group(1));
        Matcher in = IN_IF.matcher(line);
        s.direction = in.find() && !in.group(1).isEmpty() ? "in" : "out";
        String up = line.toUpperCase();
        s.action = up.contains("ALLOW") || up.contains("ACCEPT") ? "ALLOW" : "DROP";
        return s;      // syslog lines carry no year, so the arrival time is used
    }
}
