package com.socialflux.auth.security;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.web.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Defesa contra CSRF para métodos que alteram estado, somada ao {@code SameSite} dos cookies:
 * rejeita requisições cross-site (cabeçalho {@code Sec-Fetch-Site}) e {@code Origin} fora da lista permitida
 * (padrão: a própria origem do serviço, via X-Forwarded-*). Clientes sem cabeçalhos de navegador (curl, serviços) passam.
 */
public class OriginCheckFilter extends OncePerRequestFilter {

    private static final Set<String> SAFE = Set.of(HttpMethod.GET.name(), HttpMethod.HEAD.name(),
            HttpMethod.OPTIONS.name(), HttpMethod.TRACE.name());

    private final Set<String> allowedOrigins;

    public OriginCheckFilter(AuthProperties properties) {
        this.allowedOrigins = Set.copyOf(properties.allowedOrigins().stream()
                .filter(origin -> !origin.isBlank())
                .map(origin -> origin.trim().replaceAll("/+$", ""))
                .toList());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!SAFE.contains(request.getMethod()) && !isSameOrigin(request)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(ApiError.of("forbidden_origin", "Origem não permitida").toJson());
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isSameOrigin(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        if ("cross-site".equalsIgnoreCase(fetchSite)) {
            return false;
        }
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isBlank() || "null".equals(origin)) {
            return origin == null || origin.isBlank();
        }
        String normalized = origin.replaceAll("/+$", "");
        if (!allowedOrigins.isEmpty()) {
            return allowedOrigins.contains(normalized);
        }
        return normalized.equalsIgnoreCase(requestOrigin(request));
    }

    private static String requestOrigin(HttpServletRequest request) {
        String scheme = request.getScheme();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + request.getServerName() + (defaultPort || port <= 0 ? "" : ":" + port);
    }
}
