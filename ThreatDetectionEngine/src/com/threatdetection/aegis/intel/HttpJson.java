package com.threatdetection.aegis.intel;

import com.threatdetection.aegis.MiniJson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Small GET-JSON helper with hard timeouts. Keys travel only in headers and are never logged. */
final class HttpJson {
    static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build();

    record Reply(int status, Object json) {}

    private HttpJson() {}

    static Reply get(String url, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().header("Accept", "application/json");
        for (int i = 0; i + 1 < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        HttpResponse<String> r = CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Object json = null;
        if (r.statusCode() == 200) json = MiniJson.parse(r.body());
        return new Reply(r.statusCode(), json);
    }

    static String key(String prop, String env) {
        String k = System.getProperty(prop, "").trim();
        if (k.isEmpty()) k = System.getenv(env) == null ? "" : System.getenv(env).trim();
        return k;
    }
}
