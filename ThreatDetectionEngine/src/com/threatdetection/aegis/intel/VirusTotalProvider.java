package com.threatdetection.aegis.intel;

import com.threatdetection.aegis.MiniJson;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/** VirusTotal v3 for IPs, file hashes and URLs. Key: -Daegis.vt.key or env VT_API_KEY. Free tier: 4 requests a minute. */
public final class VirusTotalProvider implements IntelProvider {
    private final String key = HttpJson.key("aegis.vt.key", "VT_API_KEY");
    private final String base = System.getProperty("aegis.vt.url", "https://www.virustotal.com/api/v3");

    @Override public String name() { return "VirusTotal"; }
    @Override public boolean configured() { return !key.isEmpty(); }
    @Override public int dailyLimit() { return Integer.getInteger("aegis.vt.daily", 450); }
    @Override public long minIntervalMs() { return Long.getLong("aegis.vt.minIntervalMs", 15_500L); }

    @Override
    public Enrichment lookupIp(String ip) throws Exception { return fetch("/ip_addresses/" + ip, "address"); }

    public Enrichment lookupHash(String hash) throws Exception {
        if (!hash.matches("[0-9a-fA-F]{32,64}")) return Enrichment.unavailable(name(), Enrichment.NOT_APPLICABLE, "not a file hash");
        return fetch("/files/" + hash, "file");
    }

    public Enrichment lookupUrl(String url) throws Exception {
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        return fetch("/urls/" + id, "URL");
    }

    private Enrichment fetch(String path, String what) throws Exception {
        HttpJson.Reply r = HttpJson.get(base + path, "x-apikey", key);
        if (r.status() == 404) return Enrichment.ok(name(), "NO_DATA", -1, "VirusTotal has no record of this " + what + " (unknown is not safe)");
        if (r.status() == 429) return Enrichment.unavailable(name(), Enrichment.RATE_LIMITED, "VirusTotal quota reached");
        if (r.status() == 401 || r.status() == 403) return Enrichment.unavailable(name(), Enrichment.ERROR, "VirusTotal rejected the API key");
        if (r.status() != 200) return Enrichment.unavailable(name(), Enrichment.ERROR, "VirusTotal HTTP " + r.status());
        Map<String, Object> attrs = MiniJson.obj(MiniJson.obj(r.json(), "data"), "attributes");
        Map<String, Object> st = MiniJson.obj(attrs, "last_analysis_stats");
        int mal = MiniJson.integer(st, "malicious", 0), sus = MiniJson.integer(st, "suspicious", 0);
        int total = mal + sus + MiniJson.integer(st, "harmless", 0) + MiniJson.integer(st, "undetected", 0);
        String verdict = mal >= 3 ? "MALICIOUS" : (mal >= 1 || sus >= 1) ? "SUSPICIOUS" : "NO_DATA";
        String detail = mal + " malicious / " + sus + " suspicious of " + total + " engines"
                + (verdict.equals("NO_DATA") ? " (not flagged does not mean safe)" : "");
        return Enrichment.ok(name(), verdict, mal + sus, detail);
    }
}
