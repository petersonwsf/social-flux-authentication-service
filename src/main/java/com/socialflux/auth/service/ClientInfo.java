package com.socialflux.auth.service;

import jakarta.servlet.http.HttpServletRequest;

/** IP e user-agent do cliente (o IP real vem de X-Forwarded-For quando atrás do Caddy). */
public record ClientInfo(String ip, String userAgent) {

    public static ClientInfo from(HttpServletRequest request) {
        return new ClientInfo(request.getRemoteAddr(), request.getHeader("User-Agent"));
    }

    public static ClientInfo none() {
        return new ClientInfo(null, null);
    }
}
