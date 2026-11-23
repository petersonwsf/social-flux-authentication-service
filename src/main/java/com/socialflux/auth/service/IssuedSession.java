package com.socialflux.auth.service;

import java.time.Instant;

/** Tokens emitidos para uma sessão. Os valores em texto só existem em memória durante a resposta. */
public record IssuedSession(
        String accessToken,
        Instant accessExpiresAt,
        Instant renewAt,
        String refreshToken,
        Instant refreshExpiresAt) {
}
