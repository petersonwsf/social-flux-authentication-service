package com.socialflux.auth.security;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Identidade extraída de um JWT de acesso válido. */
public record AuthenticatedAccount(
        UUID accountId,
        UUID sessionId,
        Set<String> roles,
        int tokenVersion,
        Instant expiresAt) {
}
