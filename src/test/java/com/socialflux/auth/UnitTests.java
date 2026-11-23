package com.socialflux.auth;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.config.JwtKeys;
import com.socialflux.auth.util.Uuids;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UnitTests {

    private static AuthProperties props(String privateKeyB64, String previousB64, boolean ephemeral) {
        return new AuthProperties(
                new AuthProperties.Jwt("iss", "aud", Duration.ofHours(2), Duration.ofMinutes(10), Duration.ofMinutes(5),
                        Duration.ofDays(7), Duration.ofSeconds(10), Duration.ofSeconds(60),
                        privateKeyB64, "kid-1", previousB64, ephemeral),
                new AuthProperties.Cookie(false, "at", "rt", "/auth"),
                List.of(), "http://localhost",
                new AuthProperties.RateLimit(5, 50, Duration.ofMinutes(15)),
                new AuthProperties.Mail(false, "a@b.c"),
                new AuthProperties.Profile("http://localhost:8082", "profile-service", Duration.ofSeconds(2), Duration.ofSeconds(5)));
    }

    private static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    private static String b64(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes());
    }

    @Test
    void uuidV7HasVersionVariantAndIsTimeOrdered() {
        Clock early = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        Clock late = Clock.fixed(Instant.parse("2026-01-01T00:00:01Z"), ZoneOffset.UTC);
        UUID a = Uuids.v7(early);
        UUID b = Uuids.v7(late);

        assertThat(a.version()).isEqualTo(7);
        assertThat(a.variant()).isEqualTo(2);
        assertThat(a.getMostSignificantBits() >>> 16).isEqualTo(early.millis());
        assertThat(a.toString()).isLessThan(b.toString());
        assertThat(Uuids.v7(early)).isNotEqualTo(a);
    }

    @Test
    void keyLoadingFailsFastWithoutAKeyUnlessEphemeralIsAllowed() {
        assertThatThrownBy(() -> new JwtKeys(props("", "", false)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_PRIVATE_KEY_B64");
        assertThat(new JwtKeys(props("", "", true)).signingKey().isPrivate()).isTrue();
    }

    @Test
    void keyLoadingRejectsGarbageAndWeakKeys() throws Exception {
        assertThatThrownBy(() -> new JwtKeys(props("%%%não-é-base64", "", false))).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new JwtKeys(props(b64("não é um pem"), "", false))).isInstanceOf(IllegalStateException.class);

        KeyPairGenerator weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        KeyPair pair = weak.generateKeyPair();
        String weakPem = b64(pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        assertThatThrownBy(() -> new JwtKeys(props(weakPem, "", false))).hasMessageContaining("2048");
    }

    @Test
    void loadsConfiguredKeyAndPublishesPreviousKeysForRotation() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair current = generator.generateKeyPair();
        KeyPair previous = generator.generateKeyPair();

        String currentB64 = b64(pem("PRIVATE KEY", current.getPrivate().getEncoded()));
        String previousB64 = b64(pem("PUBLIC KEY", previous.getPublic().getEncoded()));
        JwtKeys keys = new JwtKeys(props(currentB64, previousB64, false));

        assertThat(keys.signingKey().getKeyID()).isEqualTo("kid-1");
        assertThat(keys.publicJwkSet().getKeys()).hasSize(2);
        assertThat(keys.publicJwkSet().getKeys()).noneMatch(key -> key.isPrivate());
        // A chave anterior só serve para verificar, nunca para assinar
        assertThat(keys.signingKey().toRSAPublicKey().getModulus())
                .isEqualTo(((java.security.interfaces.RSAPublicKey) current.getPublic()).getModulus());
    }
}
