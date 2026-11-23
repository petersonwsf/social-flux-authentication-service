package com.socialflux.auth.profile;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.util.Uuids;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Emite tokens de SERVIÇO para chamadas serviço→serviço: JWT RS256 curto (5 min), assinado com a mesma chave do auth
 * (os serviços validam pelo JWKS), {@code sub = svc:authentication-service}, {@code aud} = serviço de destino e
 * {@code scope} explícito. Não carrega papéis de usuário, então não serve nas rotas de usuário.
 */
@Component
public class ServiceTokenIssuer {

    static final String SUBJECT = "svc:authentication-service";
    private static final Duration TTL = Duration.ofMinutes(5);
    private static final Duration REUSE_MARGIN = Duration.ofSeconds(30);

    private final JwtEncoder encoder;
    private final AuthProperties properties;
    private final Clock clock;

    private volatile String cached;
    private volatile Instant cachedExpiresAt = Instant.EPOCH;

    public ServiceTokenIssuer(JwtEncoder encoder, AuthProperties properties, Clock clock) {
        this.encoder = encoder;
        this.properties = properties;
        this.clock = clock;
    }

    /** Token para o profile_service (reaproveitado até perto de expirar). */
    public String forProfileService() {
        Instant now = clock.instant();
        String token = cached;
        if (token != null && now.plus(REUSE_MARGIN).isBefore(cachedExpiresAt)) {
            return token;
        }
        synchronized (this) {
            if (cached != null && now.plus(REUSE_MARGIN).isBefore(cachedExpiresAt)) {
                return cached;
            }
            Instant expiresAt = now.plus(TTL);
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer(properties.jwt().issuer())
                    .audience(List.of(properties.profile().serviceAudience()))
                    .subject(SUBJECT)
                    .issuedAt(now)
                    .notBefore(now)
                    .expiresAt(expiresAt)
                    .id(Uuids.v7(clock).toString())
                    .claim("scope", "profiles:write profiles:read")
                    .build();
            JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build();
            cached = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
            cachedExpiresAt = expiresAt;
            return cached;
        }
    }
}
