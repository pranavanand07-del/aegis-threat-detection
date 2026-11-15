package com.threatdetection.aegis.intel;

import com.threatdetection.aegis.MiniJson;

import java.util.Map;

/** AbuseIPDB v2 "check". Key: -Daegis.abuseipdb.key or env ABUSEIPDB_API_KEY. Free tier is about 1000 checks a day. */
public final class AbuseIpDbProvider implements IntelProvider {
    private final String key = HttpJson.key("aegis.abuseipdb.key", "ABUSEIPDB_API_KEY");
    private final String base = System.getProperty("aegis.abuseipdb.url", "https://api.abuseipdb.com/api/v2/check");

    @Override public String name() { return "AbuseIPDB"; }
    @Override public boolean configured() { return !key.isEmpty(); }
    @Override public int dailyLimit() { return Integer.getInteger("aegis.abuseipdb.daily", 900); }
    @Override public long minIntervalMs() { return 500; }

    @Override
    public Enrichment lookupIp(String ip) throws Exception {
        HttpJson.Reply r = HttpJson.get(base + "?maxAgeInDays=90&ipAddress=" + java.net.URLEncoder.encode(ip, java.nio.charset.StandardCharsets.UTF_8), "Key", key);
        if (r.status() == 429) return Enrichment.unavailable(name(), Enrichment.RATE_LIMITED, "AbuseIPDB quota reached");
        if (r.status() == 401 || r.status() == 403) return Enrichment.unavailable(name(), Enrichment.ERROR, "AbuseIPDB rejected the API key");
        if (r.status() != 200) return Enrichment.unavailable(name(), Enrichment.ERROR, "AbuseIPDB HTTP " + r.status());
        Map<String, Object> d = MiniJson.obj(r.json(), "data");
        int score = MiniJson.integer(d, "abuseConfidenceScore", -1);
        int reports = MiniJson.integer(d, "totalReports", 0);
        String where = (MiniJson.text(d, "countryCode") + " " + MiniJson.text(d, "isp")).trim();
        String verdict = score >= 75 ? "MALICIOUS" : score >= 25 ? "SUSPICIOUS" : "NO_DATA";
        String detail = "abuse confidence " + score + "%, " + reports + " report(s) in 90 days" + (where.isEmpty() ? "" : ", " + where)
                + (verdict.equals("NO_DATA") ? " (not reported does not mean safe)" : "");
        return Enrichment.ok(name(), verdict, score, detail);
    }
}
