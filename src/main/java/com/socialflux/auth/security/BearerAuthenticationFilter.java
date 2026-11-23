package com.socialflux.auth.security;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.service.RevocationRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Autentica pela requisição: JWT em {@code Authorization: Bearer} (serviços/Caddy) ou no cookie de acesso (navegador).
 * Token inválido/expirado/revogado simplesmente deixa a requisição sem autenticação (o entry point responde 401).
 */
public class BearerAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";

    private final JwtDecoder decoder;
    private final RevocationRegistry revocations;
    private final AuthProperties properties;
    private final Clock clock;

    public BearerAuthenticationFilter(JwtDecoder decoder, RevocationRegistry revocations,
                                      AuthProperties properties, Clock clock) {
        this.decoder = decoder;
        this.revocations = revocations;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = resolveToken(request);
        if (token != null) {
            authenticate(token);
        }
        chain.doFilter(request, response);
    }

    private void authenticate(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            UUID accountId = UUID.fromString(jwt.getSubject());
            UUID sessionId = UUID.fromString(jwt.getClaimAsString("sid"));
            Long version = jwt.getClaim("ver");
            if (version == null || revocations.isRevoked(accountId, version.intValue(), clock.instant())) {
                return;
            }
            List<String> roles = jwt.getClaimAsStringList("roles");

            AuthenticatedAccount principal = new AuthenticatedAccount(
                    accountId, sessionId,
                    roles == null ? Set.of() : new HashSet<>(roles),
                    version.intValue(), jwt.getExpiresAt());
            SecurityContextHolder.getContext().setAuthentication(new AccountAuthentication(principal));
        } catch (JwtException | IllegalArgumentException | NullPointerException | ClassCastException e) {
            SecurityContextHolder.clearContext();
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            String value = header.substring(BEARER.length()).trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(properties.cookie().accessName()) && !cookie.getValue().isBlank()) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
