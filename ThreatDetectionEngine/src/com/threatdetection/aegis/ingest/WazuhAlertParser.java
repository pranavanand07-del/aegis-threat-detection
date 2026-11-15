package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.MiniJson;
import com.threatdetection.aegis.intel.IpClassifier;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Reads one line of Wazuh's alerts.json (one JSON object per line, default
 * /var/ossec/logs/alerts/alerts.json on the manager). Alerts are real telemetry from a configured
 * local file, so they count as OBSERVED. Wazuh's own rule level and MITRE ids are kept.
 */
public final class WazuhAlertParser {
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    private WazuhAlertParser() {}

    public static AegisSignal parse(String line) {
        if (line == null || line.length() < 2 || line.length() > 200_000 || line.charAt(0) != '{') return null;
        Map<String, Object> root;
        try {
            Object o = MiniJson.parse(line);
            if (!(o instanceof Map)) return null;
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
            root = m;
        } catch (RuntimeException e) {
            return null;
        }
        Map<String, Object> rule = MiniJson.obj(root, "rule");
        if (rule.isEmpty()) return null;
        Map<String, Object> data = MiniJson.obj(root, "data");
        AegisSignal s = new AegisSignal(AegisSignal.Kind.EXTERNAL);
        s.channel = "wazuh-alerts";
        s.extId = MiniJson.text(rule, "id");
        s.extLevel = MiniJson.integer(rule, "level", 0);
        s.extDesc = MiniJson.text(rule, "description");
        List<?> ids = MiniJson.list(MiniJson.obj(rule, "mitre"), "id");
        s.extMitre = ids.isEmpty() ? "" : String.valueOf(ids.get(0));
        s.host = MiniJson.text(MiniJson.obj(root, "agent"), "name");
        String ip = MiniJson.text(data, "srcip");
        s.ip = IpClassifier.isValid(ip) ? ip : "";
        String user = MiniJson.text(data, "dstuser");
        if (user.isEmpty()) user = MiniJson.text(data, "srcuser");
        if (!user.isEmpty()) s.user = user;
        s.path = s.extDesc;
        try {
            s.ts = OffsetDateTime.parse(MiniJson.text(root, "timestamp"), TS).toInstant().toEpochMilli();
        } catch (RuntimeException e) {
            s.ts = 0;
        }
        return s;
    }
}
