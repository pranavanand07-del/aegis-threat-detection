package com.threatdetection.aegis.intel;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Extra intelligence attached to an event (the ENRICHED layer of the source-trust model). It never
 * changes what the event IS (Observed / API / Simulated); it only adds context, and says how far to trust it.
 *
 * verdict is MALICIOUS, SUSPICIOUS, MAPPED (a local mapping such as MITRE ATT&amp;CK) or NO_DATA.
 * There is deliberately no CLEAN/SAFE verdict: "nobody has reported this address" is not proof it is harmless.
 */
public final class Enrichment {
    public static final String OK = "OK", NO_DATA = "NO_DATA", NOT_CONFIGURED = "NOT_CONFIGURED", NOT_APPLICABLE = "NOT_APPLICABLE",
            OFFLINE = "OFFLINE", TIMEOUT = "TIMEOUT", RATE_LIMITED = "RATE_LIMITED", ERROR = "ERROR";

    public final String provider;
    public final String status;
    public final String verdict;
    public final int score;          // provider's own 0-100 style score, -1 when it has none
    public final String detail;
    public final long fetchedAt;
    public final boolean cached;

    public Enrichment(String provider, String status, String verdict, int score, String detail, long fetchedAt, boolean cached) {
        this.provider = provider;
        this.status = status;
        this.verdict = verdict;
        this.score = score;
        this.detail = detail;
        this.fetchedAt = fetchedAt;
        this.cached = cached;
    }

    public static Enrichment ok(String provider, String verdict, int score, String detail) {
        return new Enrichment(provider, OK, verdict, score, detail, System.currentTimeMillis(), false);
    }

    public static Enrichment unavailable(String provider, String status, String detail) {
        return new Enrichment(provider, status, "NO_DATA", -1, detail, System.currentTimeMillis(), false);
    }

    public Enrichment asCached() {
        return new Enrichment(provider, status, verdict, score, detail, fetchedAt, true);
    }

    public boolean usable() { return OK.equals(status); }

    public String toJson() {
        return "{\"provider\":" + str(provider) + ",\"trust\":\"ENRICHED\",\"status\":" + str(status) + ",\"verdict\":" + str(verdict)
                + ",\"score\":" + score + ",\"detail\":" + str(detail) + ",\"fetchedAt\":" + fetchedAt + ",\"cached\":" + cached + "}";
    }
}
