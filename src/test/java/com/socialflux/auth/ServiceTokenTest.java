package com.socialflux.auth;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.socialflux.auth.config.JwtKeys;
import com.socialflux.auth.profile.ServiceTokenIssuer;
import com.socialflux.auth.support.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** O token de serviço que o auth usa para chamar o profile_service. */
class ServiceTokenTest extends AbstractIntegrationTest {

    @Autowired
    ServiceTokenIssuer issuer;

    @Autowired
    JwtKeys keys;

    @Test
    void serviceTokenIsASignedShortLivedTokenForTheProfileServiceOnly() throws Exception {
        String token = issuer.forProfileService();
        SignedJWT jwt = SignedJWT.parse(token);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jwt.verify(new RSASSAVerifier(((RSAKey) keys.publicJwkSet().getKeyByKeyId(jwt.getHeader().getKeyID()))
                .toRSAPublicKey()))).isTrue();
        assertThat(claims.getSubject()).isEqualTo("svc:authentication-service");
        assertThat(claims.getAudience()).containsExactly("profile-service");     // não serve na API pública
        assertThat(claims.getIssuer()).isEqualTo("http://auth.test");
        assertThat(claims.getStringClaim("scope")).isEqualTo("profiles:write profiles:read");
        assertThat(claims.getClaims()).doesNotContainKeys("roles", "sid", "ver");
        long ttl = claims.getExpirationTime().getTime() - claims.getIssueTime().getTime();
        assertThat(Duration.ofMillis(ttl)).isEqualTo(Duration.ofMinutes(5));

        // Reaproveitado enquanto válido; renovado perto do fim
        assertThat(issuer.forProfileService()).isEqualTo(token);
        clock.advance(Duration.ofMinutes(4).plusSeconds(40));
        assertThat(issuer.forProfileService()).isNotEqualTo(token);
    }

    @Test
    void userAccessTokensAreNotValidForTheProfileServiceAudience() throws Exception {
        // Um token de usuário tem aud = socialflux-api; o profile_service só aceita tokens de serviço em /internal/**
        // (escopos explícitos). O de serviço, por sua vez, não tem papéis e não passa em /api/**.
        SignedJWT service = SignedJWT.parse(issuer.forProfileService());
        assertThat(service.getJWTClaimsSet().getAudience()).doesNotContain("socialflux-api");
    }
}
