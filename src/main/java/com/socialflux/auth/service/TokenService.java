package com.socialflux.auth.service;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.domain.Account;
import com.socialflux.auth.domain.AccountRepository;
import com.socialflux.auth.domain.RefreshToken;
import com.socialflux.auth.domain.RefreshTokenRepository;
import com.socialflux.auth.util.Tokens;
import com.socialflux.auth.util.Uuids;
import com.socialflux.auth.web.ApiException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Emissão e renovação de sessões.
 * <ul>
 *   <li>Access token: JWT RS256 de curta duração (padrão 2 h).</li>
 *   <li>Refresh token: opaco, rotativo; cada uso gera um novo e invalida o anterior. O reuso de um token já
 *       girado (fora da tolerância) revoga a família inteira.</li>
 *   <li>Sessão deslizante: cada refresh vale {@code access TTL + tolerância}; o usuário só continua logado se
 *       agir na janela de expiração. O limite absoluto da sessão é {@code session-absolute-max}.</li>
 * </ul>
 */
@Service
public class TokenService {

    private final JwtEncoder encoder;
    private final AuthProperties properties;
    private final AccountRepository accounts;
    private final RefreshTokenRepository refreshTokens;
    private final RevocationRegistry revocations;
    private final AuditService audit;
    private final Clock clock;

    public TokenService(JwtEncoder encoder, AuthProperties properties, AccountRepository accounts,
                        RefreshTokenRepository refreshTokens, RevocationRegistry revocations,
                        AuditService audit, Clock clock) {
        this.encoder = encoder;
        this.properties = properties;
        this.accounts = accounts;
        this.refreshTokens = refreshTokens;
        this.revocations = revocations;
        this.audit = audit;
        this.clock = clock;
    }

    /** Inicia uma nova sessão (nova família de refresh tokens). */
    @Transactional
    public IssuedSession startSession(Account account, ClientInfo client) {
        UUID familyId = Uuids.v7(clock);
        Instant familyExpiresAt = clock.instant().plus(properties.jwt().sessionAbsoluteMax());
        return issue(account, familyId, familyExpiresAt, client);
    }

    /** Renova a sessão a partir do refresh token (rotação). */
    @Transactional(noRollbackFor = ApiException.class)
    public RefreshResult refresh(String refreshToken, ClientInfo client) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw ApiException.unauthorized("Sessão inválida");
        }
        RefreshToken current = refreshTokens.findByTokenHash(Tokens.sha256(refreshToken))
                .orElseThrow(() -> ApiException.unauthorized("Sessão inválida"));
        Instant now = clock.instant();

        if (current.getRevokedAt() != null) {
            throw ApiException.unauthorized("Sessão encerrada");
        }

        Account account = accounts.findById(current.getAccountId()).orElse(null);
        if (account == null || !account.isActive()) {
            refreshTokens.revokeFamily(current.getFamilyId(), now, "ACCOUNT_INACTIVE");
            throw ApiException.unauthorized("Sessão encerrada");
        }

        if (now.isAfter(current.getFamilyExpiresAt()) || now.isAfter(current.getExpiresAt())) {
            refreshTokens.revokeFamily(current.getFamilyId(), now, "EXPIRED");
            throw ApiException.unauthorized("Sessão expirada");
        }

        if (current.getRotatedAt() != null) {
            boolean withinTolerance = now.isBefore(current.getRotatedAt().plus(properties.jwt().refreshReuseTolerance()));
            if (!withinTolerance) {
                // Token já usado reapareceu: possível roubo. Derruba toda a família.
                refreshTokens.revokeFamily(current.getFamilyId(), now, "REUSE_DETECTED");
                audit.record(account.getId(), "REFRESH_REUSE", client, "family=" + current.getFamilyId());
                throw ApiException.unauthorized("Sessão encerrada");
            }
        } else {
            current.setRotatedAt(now);
        }

        IssuedSession session = issue(account, current.getFamilyId(), current.getFamilyExpiresAt(), client);
        if (current.getReplacedBy() == null) {
            refreshTokens.findByTokenHash(Tokens.sha256(session.refreshToken()))
                    .ifPresent(child -> current.setReplacedBy(child.getId()));
        }
        return new RefreshResult(account, session);
    }

    /** Encerra a sessão (família) à qual o refresh token pertence. */
    @Transactional
    public void logout(String refreshToken, UUID sessionIdFromAccess, ClientInfo client) {
        Instant now = clock.instant();
        UUID accountId = null;
        if (refreshToken != null && !refreshToken.isBlank()) {
            RefreshToken token = refreshTokens.findByTokenHash(Tokens.sha256(refreshToken)).orElse(null);
            if (token != null) {
                accountId = token.getAccountId();
                refreshTokens.revokeFamily(token.getFamilyId(), now, "LOGOUT");
            }
        }
        if (sessionIdFromAccess != null) {
            refreshTokens.revokeFamily(sessionIdFromAccess, now, "LOGOUT");
        }
        if (accountId != null) {
            audit.record(accountId, "LOGOUT", client, null);
        }
    }

    /**
     * Revoga TODAS as sessões da conta: incrementa {@code token_version} (derruba tokens de acesso já emitidos)
     * e revoga todos os refresh tokens.
     */
    @Transactional
    public void revokeAll(Account account, String reason) {
        Instant now = clock.instant();
        account.setTokenVersion(account.getTokenVersion() + 1);
        account.setTokenVersionChangedAt(now);
        account.setUpdatedAt(now);
        accounts.save(account);
        refreshTokens.revokeAllOfAccount(account.getId(), now, reason);
        revocations.revokeBelow(account.getId(), account.getTokenVersion());
    }

    // ----------------------------------------------------------------- internals

    private IssuedSession issue(Account account, UUID familyId, Instant familyExpiresAt, ClientInfo client) {
        Instant now = clock.instant();
        AuthProperties.Jwt jwt = properties.jwt();

        Instant accessExpiresAt = min(now.plus(jwt.accessTtl()), familyExpiresAt);
        Instant refreshExpiresAt = min(now.plus(jwt.accessTtl()).plus(jwt.refreshGrace()), familyExpiresAt);
        Instant renewAt = accessExpiresAt.minus(jwt.renewWindow());
        if (renewAt.isBefore(now)) {
            renewAt = now;
        }

        String access = signAccessToken(account, familyId, now, accessExpiresAt);

        String refresh = Tokens.random();
        refreshTokens.save(new RefreshToken(Uuids.v7(clock), familyId, account.getId(), Tokens.sha256(refresh),
                now, refreshExpiresAt, familyExpiresAt, client.ip(), truncate(client.userAgent())));

        return new IssuedSession(access, accessExpiresAt, renewAt, refresh, refreshExpiresAt);
    }

    private String signAccessToken(Account account, UUID sessionId, Instant issuedAt, Instant expiresAt) {
        AuthProperties.Jwt jwt = properties.jwt();
        List<String> roles = new ArrayList<>(account.getRoles());

        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(jwt.issuer())
                .audience(List.of(jwt.audience()))
                .subject(account.getId().toString())
                .issuedAt(issuedAt)
                .notBefore(issuedAt)
                .expiresAt(expiresAt)
                .id(Uuids.v7(clock).toString())
                .claim("sid", sessionId.toString())
                .claim("roles", roles)
                .claim("ver", account.getTokenVersion());

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build();
        return encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static String truncate(String value) {
        return value == null || value.length() <= 300 ? value : value.substring(0, 300);
    }

    public record RefreshResult(Account account, IssuedSession session) {
    }
}
