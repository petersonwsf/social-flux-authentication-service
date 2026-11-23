package com.socialflux.auth.web;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.service.IssuedSession;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Cookies de sessão: o JWT de acesso (todas as rotas) e o refresh token (somente {@code /auth}).
 * Ambos {@code HttpOnly}; nomes e {@code Secure} configuráveis (em produção: {@code __Host-at} / {@code __Secure-rt}).
 */
@Component
public class SessionCookies {

    private final AuthProperties.Cookie config;
    private final Clock clock;

    public SessionCookies(AuthProperties properties, Clock clock) {
        this.config = properties.cookie();
        this.clock = clock;
    }

    public void write(HttpServletResponse response, IssuedSession session) {
        response.addHeader(HttpHeaders.SET_COOKIE, build(config.accessName(), session.accessToken(), "/", "Lax",
                remaining(session.accessExpiresAt())).toString());
        response.addHeader(HttpHeaders.SET_COOKIE, build(config.refreshName(), session.refreshToken(),
                config.refreshPath(), "Strict", remaining(session.refreshExpiresAt())).toString());
    }

    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, build(config.accessName(), "", "/", "Lax", Duration.ZERO).toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                build(config.refreshName(), "", config.refreshPath(), "Strict", Duration.ZERO).toString());
    }

    public String refreshToken(HttpServletRequest request) {
        return read(request, config.refreshName());
    }

    private static String read(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(name) && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private ResponseCookie build(String name, String value, String path, String sameSite, Duration maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(config.secure())
                .sameSite(sameSite)
                .path(path)
                .maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge)
                .build();
    }

    private Duration remaining(Instant until) {
        return Duration.between(clock.instant(), until);
    }
}
