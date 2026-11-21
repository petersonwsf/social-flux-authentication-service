package com.socialflux.auth.service;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.domain.Account;
import com.socialflux.auth.domain.AccountRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Revogação imediata de tokens de acesso (JWT é validado localmente, então "desligar" um token exige memória).
 * Guarda, só pelo tempo máximo de vida de um token, a versão mínima aceita por conta:
 * logout geral, troca de senha, banimento e exclusão incrementam {@code token_version}.
 * É reconstruído do banco ao iniciar.
 */
@Component
public class RevocationRegistry {

    private record Entry(int minVersion, Instant until) {
    }

    private final ConcurrentMap<UUID, Entry> entries = new ConcurrentHashMap<>();
    private final AccountRepository accounts;
    private final AuthProperties properties;
    private final Clock clock;

    public RevocationRegistry(AccountRepository accounts, AuthProperties properties, Clock clock) {
        this.accounts = accounts;
        this.properties = properties;
        this.clock = clock;
    }

    /** Tokens da conta com {@code ver} menor que {@code minVersion} passam a ser rejeitados. */
    public void revokeBelow(UUID accountId, int minVersion) {
        entries.put(accountId, new Entry(minVersion, clock.instant().plus(properties.jwt().revocationMemory())));
    }

    public boolean isRevoked(UUID accountId, int tokenVersion, Instant now) {
        Entry entry = entries.get(accountId);
        return entry != null && now.isBefore(entry.until()) && tokenVersion < entry.minVersion();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void reload() {
        Instant now = clock.instant();
        Instant since = now.minus(properties.jwt().revocationMemory());
        for (Account account : accounts.findByTokenVersionChangedAtAfter(since)) {
            Instant until = account.getTokenVersionChangedAt().plus(properties.jwt().revocationMemory());
            if (until.isAfter(now)) {
                entries.put(account.getId(), new Entry(account.getTokenVersion(), until));
            }
        }
    }

    @Scheduled(fixedDelayString = "PT10M")
    void cleanup() {
        Instant now = clock.instant();
        entries.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().until()));
    }
}
