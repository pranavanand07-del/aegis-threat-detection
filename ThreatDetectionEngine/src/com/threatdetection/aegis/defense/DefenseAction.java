package com.threatdetection.aegis.defense;

import com.threatdetection.model.ThreatLevel;

import static com.threatdetection.aegis.JsonUtil.str;

/** One proposed or applied defensive action. Every action is reversible and (except quarantine) time-limited. */
public final class DefenseAction {
    public enum Type {
        FIREWALL_BLOCK("Block IP in Windows Firewall", true),
        QUARANTINE_FILE("Quarantine file", false),
        REVOKE_SESSION("Revoke application session", true),
        LOCK_ACCOUNT("Temporarily lock account", true),
        RATE_LIMIT("Rate-limit source", true);

        public final String label;
        public final boolean expires;

        Type(String label, boolean expires) {
            this.label = label;
            this.expires = expires;
        }
    }

    /** PENDING -> ACTIVE|REJECTED|EXPIRED ; ACTIVE -> EXPIRED (auto recovery) | REVERTED (analyst) ; FAILED / DRY_RUN are final. */
    public enum State { PENDING, ACTIVE, DRY_RUN, REJECTED, EXPIRED, REVERTED, FAILED }

    public final String id;
    public final Type type;
    public final String target;
    public final String reason;
    public final long eventId;
    public final String eventSource;
    public final ThreatLevel level;
    public final long createdAt;
    public volatile State state = State.PENDING;
    public volatile long expiresAt;          // 0 = no expiry (quarantine)
    public volatile String decidedBy = "";
    public volatile String result = "";
    public volatile String detail = "";      // quarantine id, firewall rule name ...

    public DefenseAction(String id, Type type, String target, String reason, long eventId, String eventSource,
                         ThreatLevel level, long createdAt) {
        this.id = id;
        this.type = type;
        this.target = target;
        this.reason = reason;
        this.eventId = eventId;
        this.eventSource = eventSource;
        this.level = level;
        this.createdAt = createdAt;
    }

    public String key() { return type + "|" + target; }

    public boolean live() { return state == State.PENDING || state == State.ACTIVE; }

    public String toJson() {
        return "{\"id\":" + str(id) + ",\"type\":" + str(type.name()) + ",\"label\":" + str(type.label)
                + ",\"target\":" + str(target) + ",\"reason\":" + str(reason) + ",\"eventId\":" + eventId
                + ",\"eventSource\":" + str(eventSource) + ",\"level\":" + str(level.name())
                + ",\"state\":" + str(state.name()) + ",\"created\":" + createdAt + ",\"expires\":" + expiresAt
                + ",\"decidedBy\":" + str(decidedBy) + ",\"result\":" + str(result) + ",\"detail\":" + str(detail) + "}";
    }
}
