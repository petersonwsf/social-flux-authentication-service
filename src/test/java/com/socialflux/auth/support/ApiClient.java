package com.socialflux.auth.support;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Cliente HTTP mínimo para os testes, com um "jar" de cookies manual (permite reenviar cookies antigos). */
public class ApiClient {

    public static final String ACCESS = "at";
    public static final String REFRESH = "rt";

    /** Cookies de um "navegador". */
    public static class Jar {
        public final Map<String, String> cookies = new HashMap<>();

        public Jar copy() {
            Jar copy = new Jar();
            copy.cookies.putAll(cookies);
            return copy;
        }

        public String access() {
            return cookies.get(ACCESS);
        }

        public String refresh() {
            return cookies.get(REFRESH);
        }
    }

    public record Response(int status, String body, HttpResponse<String> raw) {

        public Map<String, Object> json() {
            try {
                return JSONObjectUtils.parse(body);
            } catch (Exception e) {
                throw new IllegalStateException("Resposta não é JSON: " + body, e);
            }
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> obj(String key) {
            return (Map<String, Object>) json().get(key);
        }

        public String header(String name) {
            return raw.headers().firstValue(name).orElse(null);
        }
    }

    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;

    public ApiClient(int port) {
        this.baseUrl = "http://localhost:" + port;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public Response get(String path, Jar jar) {
        return send("GET", path, null, jar, Map.of());
    }

    public Response post(String path, String json, Jar jar) {
        return send("POST", path, json == null ? "" : json, jar, Map.of());
    }

    public Response post(String path, String json, Jar jar, Map<String, String> headers) {
        return send("POST", path, json == null ? "" : json, jar, headers);
    }

    public Response delete(String path, String json, Jar jar) {
        return send("DELETE", path, json, jar, Map.of());
    }

    public Response send(String method, String path, String body, Jar jar, Map<String, String> headers) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
            builder.header("Content-Type", "application/json");
            if (jar != null && !jar.cookies.isEmpty()) {
                StringBuilder cookie = new StringBuilder();
                jar.cookies.forEach((name, value) -> {
                    // O refresh só viaja para /auth (Path=/auth).
                    if (name.equals(REFRESH) && !path.startsWith("/auth")) {
                        return;
                    }
                    if (cookie.length() > 0) {
                        cookie.append("; ");
                    }
                    cookie.append(name).append('=').append(value);
                });
                if (cookie.length() > 0) {
                    builder.header("Cookie", cookie.toString());
                }
            }
            headers.forEach(builder::header);
            HttpRequest.BodyPublisher publisher = body == null
                    ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body);
            HttpResponse<String> raw = http.send(builder.method(method, publisher).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (jar != null) {
                absorbCookies(raw, jar);
            }
            return new Response(raw.statusCode(), raw.body(), raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void absorbCookies(HttpResponse<String> raw, Jar jar) {
        List<String> setCookies = raw.headers().allValues("Set-Cookie");
        for (String line : setCookies) {
            String[] parts = line.split(";");
            String[] nameValue = parts[0].split("=", 2);
            String name = nameValue[0].trim();
            String value = nameValue.length > 1 ? nameValue[1].trim() : "";
            boolean expired = line.toLowerCase().contains("max-age=0");
            if (expired || value.isEmpty()) {
                jar.cookies.remove(name);
            } else {
                jar.cookies.put(name, value);
            }
        }
    }

    // ------------------------------------------------------------------ atalhos

    public static String registerJson(String email, String username, String password) {
        return """
                {"email":"%s","senha":"%s","confirmarSenha":"%s","username":"%s","nome":"Pessoa Teste",
                 "telefone":"11 99999-8888","sexo":"F","data_nascimento":"1990-05-20"}
                """.formatted(email, password, password, username);
    }

    public static String loginJson(String email, String password) {
        return "{\"email\":\"%s\",\"senha\":\"%s\"}".formatted(email, password);
    }
}
