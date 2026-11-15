package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.intel.IpClassifier;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Windows event XML (as printed by `wevtutil qe ... /f:xml`) to AEGIS signals.
 *   Security: 4625 failed logon, 4624 logon, 4740 lockout, 4720 account created,
 *             4728/4732/4756 group member added, 1102 audit log cleared
 *   Sysmon:   1 process creation, 3 network connection
 */
public final class WindowsEventMapper {
    private WindowsEventMapper() {}

    public static final class Parsed {
        public final AegisSignal signal;
        public final String recordId;

        Parsed(AegisSignal signal, String recordId) {
            this.signal = signal;
            this.recordId = recordId;
        }
    }

    /** Parses one or many concatenated {@code <Event>} elements. */
    public static List<Parsed> parse(String xmlChunk) throws Exception {
        List<Parsed> out = new ArrayList<>();
        String body = xmlChunk.replaceAll("<\\?xml[^>]*\\?>", "").trim();
        if (body.isEmpty()) return out;
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);   // no XXE
        f.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        DocumentBuilder b = f.newDocumentBuilder();
        b.setErrorHandler(null);   // no parser chatter on stderr; failures still throw SAXParseException
        Document doc = b.parse(new InputSource(new StringReader("<Events>" + body + "</Events>")));
        NodeList events = doc.getElementsByTagName("Event");
        for (int i = 0; i < events.getLength(); i++) {
            Parsed p = map((Element) events.item(i));
            if (p != null) out.add(p);
        }
        return out;
    }

    private static Parsed map(Element ev) {
        int id = intOf(text(ev, "EventID"), -1);
        String record = text(ev, "EventRecordID");
        String computer = text(ev, "Computer");
        Map<String, String> d = new HashMap<>();
        NodeList data = ev.getElementsByTagName("Data");
        for (int i = 0; i < data.getLength(); i++) {
            Element e = (Element) data.item(i);
            String name = e.getAttribute("Name");
            if (!name.isEmpty()) d.put(name, e.getTextContent().trim());
        }
        String channel = text(ev, "Channel");
        boolean sysmon = channel.toLowerCase().contains("sysmon");

        long ts = 0;
        NodeList tc = ev.getElementsByTagName("TimeCreated");
        if (tc.getLength() > 0) {
            try { ts = Instant.parse(((Element) tc.item(0)).getAttribute("SystemTime")).toEpochMilli(); }
            catch (RuntimeException ignored) { /* use arrival time */ }
        }

        AegisSignal s;
        if (sysmon) {
            if (id == 1) {
                s = new AegisSignal(AegisSignal.Kind.PROCESS);
                s.path = d.getOrDefault("Image", "");
                s.command = d.getOrDefault("CommandLine", "");
                s.parent = d.getOrDefault("ParentImage", "");
                s.user = d.getOrDefault("User", "unknown");
                s.skipLegacy = true;
                s.channel = "sysmon";
            } else if (id == 3) {
                s = new AegisSignal(AegisSignal.Kind.NETWORK);
                boolean initiated = "true".equalsIgnoreCase(d.getOrDefault("Initiated", "true"));
                s.direction = initiated ? "out" : "in";
                // Sysmon event 3 fields:
                //   Initiated=true  (outbound): Source* = this host,       Destination* = the remote server
                //   Initiated=false (inbound) : Source* = the remote client, Destination* = this host (its listening port)
                String remoteIp = initiated ? d.getOrDefault("DestinationIp", "") : d.getOrDefault("SourceIp", "");
                int remotePort = intOf(initiated ? d.get("DestinationPort") : d.get("SourcePort"), 0);
                int localPort = intOf(initiated ? d.get("SourcePort") : d.get("DestinationPort"), 0);
                applyIp(s, remoteIp);
                s.remotePort = remotePort;
                s.localPort = localPort;
                // "port" is the SERVICE port: the remote server's port for outbound traffic, the port that was
                // hit on this machine for inbound traffic (that is what port-scan logic must count).
                s.port = initiated ? remotePort : localPort;
                s.path = d.getOrDefault("Image", "");
                s.user = d.getOrDefault("User", "unknown");
                s.action = "ALLOW";
                s.skipLegacy = initiated;       // outbound: intel + rules only; inbound feeds port-scan logic
                s.channel = "sysmon";
            } else {
                return null;
            }
        } else {
            switch (id) {
                case 4625, 4624 -> {
                    s = new AegisSignal(AegisSignal.Kind.AUTH);
                    s.authFailure = id == 4625;
                    s.user = d.getOrDefault("TargetUserName", "unknown");
                    s.logonType = intOf(d.get("LogonType"), -1);
                    // Missing/invalid address ("-", "", garbage) is NOT localhost. Keep it empty and flag it so
                    // nothing is attributed to 127.0.0.1 and no block can ever target a made-up address.
                    applyIp(s, d.getOrDefault("IpAddress", ""));
                    s.path = d.getOrDefault("WorkstationName", "");
                    s.skipLegacy = false;
                    if (id == 4624 && s.logonType != 10 && s.logonType != 3) return null;   // skip noisy local logons
                }
                case 4740 -> {
                    s = new AegisSignal(AegisSignal.Kind.AUDIT);
                    s.user = d.getOrDefault("TargetUserName", "unknown");
                    s.path = d.getOrDefault("TargetDomainName", "");
                    s.skipLegacy = true;
                }
                case 4720 -> {
                    s = new AegisSignal(AegisSignal.Kind.AUDIT);
                    s.user = d.getOrDefault("SubjectUserName", "unknown");
                    s.path = d.getOrDefault("TargetUserName", "");
                    s.skipLegacy = true;
                }
                case 4728, 4732, 4756 -> {
                    s = new AegisSignal(AegisSignal.Kind.AUDIT);
                    s.user = d.getOrDefault("SubjectUserName", "unknown");
                    s.path = d.getOrDefault("TargetUserName", "");
                    s.skipLegacy = true;
                }
                case 1102 -> {
                    s = new AegisSignal(AegisSignal.Kind.AUDIT);
                    NodeList un = ev.getElementsByTagName("SubjectUserName");
                    s.user = un.getLength() > 0 ? un.item(0).getTextContent().trim() : d.getOrDefault("SubjectUserName", "unknown");
                    s.skipLegacy = true;
                }
                default -> {
                    return null;
                }
            }
            s.channel = "windows-security";
        }
        s.winEventId = id;
        s.host = computer;
        s.ts = ts;
        return new Parsed(s, record);
    }

    /** Sets the address when usable (IPv4-mapped IPv6 is unwrapped); otherwise leaves it empty and marks it missing. */
    static void applyIp(AegisSignal s, String raw) {
        String ip = raw == null ? "" : raw.trim();
        if (ip.regionMatches(true, 0, "::ffff:", 0, 7) && IpClassifier.isValid(ip.substring(7))) ip = ip.substring(7);
        if (IpClassifier.isValid(ip)) {
            s.ip = ip;
            s.ipMissing = false;
        } else {
            s.ip = "";
            s.ipMissing = true;
        }
    }

    private static String text(Element ev, String tag) {
        NodeList n = ev.getElementsByTagName(tag);
        if (n.getLength() == 0) return "";
        Node first = n.item(0);
        return first.getTextContent() == null ? "" : first.getTextContent().trim();
    }

    private static int intOf(String s, int fallback) {
        if (s == null) return fallback;
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return fallback; }
    }
}
