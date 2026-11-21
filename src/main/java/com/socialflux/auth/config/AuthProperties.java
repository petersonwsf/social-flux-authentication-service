package com.socialflux.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/** Toda a configuração do serviço, vinda de variáveis de ambiente (ver application.yml). */
@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull Cookie cookie,
        @DefaultValue List<String> allowedOrigins,
        @NotBlank String publicBaseUrl,
        @Valid @NotNull RateLimit rateLimit,
        @Valid @NotNull Mail mail,
        @Valid @NotNull Profile profile) {

    public record Jwt(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull Duration accessTtl,
            @NotNull Duration renewWindow,
            @NotNull Duration refreshGrace,
            @NotNull Duration sessionAbsoluteMax,
            @DefaultValue("PT10S") Duration refreshReuseTolerance,
            @DefaultValue("PT60S") Duration clockSkew,
            String privateKeyB64,
            String keyId,
            String previousPublicKeysB64,
            boolean allowEphemeralKey) {

        /** Tempo em que uma revogação precisa ser lembrada: vida máxima de um token de acesso emitido. */
        public Duration revocationMemory() {
            return accessTtl.plus(refreshGrace).plus(clockSkew).plus(Duration.ofMinutes(1));
        }
    }

    public record Cookie(
            boolean secure,
            @NotBlank String accessName,
            @NotBlank String refreshName,
            @NotBlank String refreshPath) {
    }

    public record RateLimit(
            @Min(1) int maxFailuresPerAccountIp,
            @Min(1) int maxFailuresPerIp,
            @NotNull Duration window) {
    }

    public record Mail(boolean enabled, @NotBlank String from) {
    }

    /** profile_service (D1: o auth orquestra o cadastro e cria o perfil por HTTP, com token de serviço). */
    public record Profile(
            @NotBlank String baseUrl,
            @NotBlank String serviceAudience,
            @DefaultValue("PT2S") Duration connectTimeout,
            @DefaultValue("PT5S") Duration readTimeout) {
    }
}
