package com.threatdetection.aegis;

import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;

/**
 * One normalized security observation (a web request, a logon, a connection, a process start...).
 * Parsers produce signals; the pipeline turns the ones that map faithfully onto a core
 * {@link LogEvent} into core-engine events and analyses the rest with AEGIS rules only.
 */
public final class AegisSignal {
    public enum Kind { WEB, AUTH, NETWORK, PROCESS, AUDIT, EXTERNAL }

    public Kind kind = Kind.WEB;
    public long ts;                    // epoch ms, 0 = "now"
    public String ip = "";             // remote peer / source address, "" for host-local telemetry
    public String host = "";
    public String user = "unknown";
    public String path = "";           // URL, process image, group name ...
    public String command = "";        // request body or process command line
    public String parent = "";         // parent process image
    public String userAgent = "";
    public String country = "UNKNOWN";
    public int port;                   // service port involved (outbound: remote port, inbound: this host's listening port)
    public int remotePort;             // the peer's own port (0 = unknown); never used for scan logic
    public int localPort;              // this host's port (0 = unknown)
    public boolean ipMissing;          // the source supplied no usable address; ip is left empty on purpose
    public int status;                 // HTTP status
    public int winEventId;
    public int logonType = -1;
    public String action = "";         // ALLOW / DROP (firewall)
    public String direction = "";      // in / out
    public boolean authFailure;
    public boolean skipLegacy;         // analyse with AEGIS rules only, do not feed the core engine
    public String channel = "";        // web-access-log, firewall-log, windows-security, sysmon, legacy-api ...
    public String fileName = "";
    public String session = "";        // logon / session id when the source provides one
    // Alerts produced by another security product (Wazuh): analysed by AEGIS rules only
    public String extId = "", extDesc = "", extMitre = "";
    public int extLevel;

    public AegisSignal(Kind kind) {
        this.kind = kind;
    }

    /** Maps onto the core engine's event model, or null when no faithful mapping exists. */
    public LogEvent toLogEvent() {
        if (skipLegacy || ip == null || ip.isBlank()) return null;
        switch (kind) {
            case WEB:
                return new LogEvent(ip, user, path, userAgent, command, country,
                        fileName.isEmpty() ? EventType.HTTP_REQUEST : EventType.DOWNLOAD_REQUEST, port, fileName,
                        ts, session, host);
            case AUTH:
                return new LogEvent(ip, user, path.isEmpty() ? "/" : path, userAgent, command, country,
                        authFailure ? EventType.LOGIN_FAILED : EventType.LOGIN_SUCCESS, port, "", ts, session, host);
            case NETWORK:
                if ("out".equals(direction) || port <= 0) return null;
                return new LogEvent(ip, user, "/", "", "", country, EventType.PORT_ACCESS, port, "", ts, session, host);
            default:
                return null;
        }
    }

    /** Builds a signal from an event that already went through the core engine (API / simulators). */
    public static AegisSignal fromLogEvent(LogEvent e) {
        AegisSignal s;
        switch (e.eventType) {
            case LOGIN_FAILED -> { s = new AegisSignal(Kind.AUTH); s.authFailure = true; }
            case LOGIN_SUCCESS -> s = new AegisSignal(Kind.AUTH);
            case PORT_ACCESS -> { s = new AegisSignal(Kind.NETWORK); s.direction = "in"; }
            default -> s = new AegisSignal(Kind.WEB);
        }
        s.ts = e.timestamp;
        s.ip = e.ip;
        s.user = e.username;
        s.path = e.endpoint;
        s.command = e.requestBody;
        s.userAgent = e.userAgent;
        s.country = e.country;
        s.port = e.port;
        s.fileName = e.fileName;
        s.session = e.session;
        s.host = e.host;
        s.channel = "core-event";
        return s;
    }
}
