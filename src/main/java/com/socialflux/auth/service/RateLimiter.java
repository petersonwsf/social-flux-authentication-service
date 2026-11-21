package com.socialflux.auth.service;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.web.ApiException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Limitador de janela deslizante em memória (adequado para 1 instância; trocar por Redis ao escalar).
 * Chaves combinam o alvo (e-mail) com o IP para que um atacante não consiga bloquear a conta de uma vítima.
 */
@Component
public class RateLimiter {

    private final ConcurrentMap<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final Duration window;
    private final Clock clock;

    public RateLimiter(AuthProperties properties, Clock clock) {
        this.window = properties.rateLimit().window();
        this.clock = clock;
    }

    /** Lança 429 se a chave já tiver {@code max} ocorrências dentro da janela. */
    public void assertBelow(String key, int max) {
        Deque<Instant> deque = hits.get(key);
        if (deque == null) {
            return;
        }
        Instant now = clock.instant();
        synchronized (deque) {
            prune(deque, now);
            if (deque.size() >= max) {
                long retry = Math.max(1, Duration.between(now, deque.peekFirst().plus(window)).toSeconds());
                throw new ApiException.TooManyRequests(retry);
            }
        }
    }

    public void hit(String key) {
        Deque<Instant> deque = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (deque) {
            deque.addLast(clock.instant());
        }
    }

    public void clear(String key) {
        hits.remove(key);
    }

    private void prune(Deque<Instant> deque, Instant now) {
        Instant limit = now.minus(window);
        while (!deque.isEmpty() && deque.peekFirst().isBefore(limit)) {
            deque.removeFirst();
        }
    }

    @Scheduled(fixedDelayString = "PT10M")
    void cleanup() {
        Instant now = clock.instant();
        hits.entrySet().removeIf(entry -> {
            synchronized (entry.getValue()) {
                prune(entry.getValue(), now);
                return entry.getValue().isEmpty();
            }
        });
    }
}
