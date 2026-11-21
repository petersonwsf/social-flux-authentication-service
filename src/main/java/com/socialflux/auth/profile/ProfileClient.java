package com.socialflux.auth.profile;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.web.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Cliente HTTP do profile_service (rotas {@code /internal/**}, token de serviço, timeouts curtos).
 * Erros 4xx do perfil são repassados ao frontend com o mesmo código/mensagem; indisponibilidade vira 503.
 * Só chamadas idempotentes (PUT/DELETE) — por isso é seguro repetir/compensar.
 */
@Component
public class ProfileClient implements ProfilePort {

    private static final Logger log = LoggerFactory.getLogger(ProfileClient.class);

    private final RestClient client;
    private final ServiceTokenIssuer tokens;
    private final JsonMapper mapper;

    public ProfileClient(AuthProperties properties, ServiceTokenIssuer tokens, JsonMapper mapper) {
        AuthProperties.Profile profile = properties.profile();
        HttpClient http = HttpClient.newBuilder().connectTimeout(profile.connectTimeout()).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(profile.readTimeout());
        this.client = RestClient.builder().baseUrl(profile.baseUrl()).requestFactory(factory).build();
        this.tokens = tokens;
        this.mapper = mapper;
    }

    @Override
    public ProfileCreated create(UUID accountId, NewProfile profile) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", profile.username());
        body.put("nome", profile.nome());
        body.put("telefone", profile.telefone());
        body.put("sexo", profile.sexo());
        body.put("data_nascimento", profile.dataNascimento().toString());

        Result result = call(() -> client.put().uri("/internal/profiles/{id}", accountId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.forProfileService())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) -> new Result(response.getStatusCode().value(),
                        response.bodyTo(String.class))));
        if (result.status() / 100 != 2) {
            throw translate(result);
        }
        JsonNode json = mapper.readTree(result.body());
        return new ProfileCreated(json.path("created").asBoolean());
    }

    @Override
    public void discard(UUID accountId) {
        Result result = call(() -> client.delete().uri("/internal/profiles/{id}", accountId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.forProfileService())
                .exchange((request, response) -> new Result(response.getStatusCode().value(),
                        response.bodyTo(String.class))));
        if (result.status() / 100 != 2) {
            throw translate(result);
        }
    }

    // ------------------------------------------------------------------ helpers

    private record Result(int status, String body) {
    }

    private Result call(java.util.function.Supplier<Result> request) {
        try {
            return request.get();
        } catch (RuntimeException e) {
            // Rede/timeout/serialização: resultado DESCONHECIDO (o perfil pode ou não ter sido criado).
            log.warn("profile_service indisponível: {}", e.toString());
            throw unavailable();
        }
    }

    private ApiException translate(Result result) {
        HttpStatus status = HttpStatus.resolve(result.status());
        if (status != null && status.is4xxClientError()) {
            try {
                JsonNode json = mapper.readTree(result.body());
                String code = json.path("codigo").asString("profile_error");
                String message = json.path("mensagem").asString("Não foi possível criar o perfil");
                return new ApiException(status, code, message);
            } catch (RuntimeException e) {
                return new ApiException(status, "profile_error", "Não foi possível criar o perfil");
            }
        }
        log.warn("profile_service respondeu {}: {}", result.status(), result.body());
        return unavailable();
    }

    private static ApiException unavailable() {
        return new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "profile_unavailable",
                "Serviço temporariamente indisponível. Tente novamente em instantes.");
    }
}
