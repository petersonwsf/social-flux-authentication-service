package com.socialflux.auth.service;

import com.socialflux.auth.domain.AccountRepository;
import com.socialflux.auth.domain.EmailTokenRepository;
import com.socialflux.auth.domain.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** Limpeza periódica de tokens vencidos e de contas excluídas há mais de 1 dia. */
@Component
public class MaintenanceJobs {

    private static final Logger log = LoggerFactory.getLogger(MaintenanceJobs.class);

    private final RefreshTokenRepository refreshTokens;
    private final EmailTokenRepository emailTokens;
    private final AccountRepository accounts;
    private final TransactionTemplate tx;
    private final Clock clock;

    public MaintenanceJobs(RefreshTokenRepository refreshTokens, EmailTokenRepository emailTokens,
                           AccountRepository accounts, PlatformTransactionManager txManager, Clock clock) {
        this.refreshTokens = refreshTokens;
        this.emailTokens = emailTokens;
        this.accounts = accounts;
        this.tx = new TransactionTemplate(txManager);
        this.clock = clock;
    }

    @Scheduled(cron = "0 17 * * * *")
    public void purge() {
        Instant now = clock.instant();
        tx.executeWithoutResult(status -> {
            int refresh = refreshTokens.purgeExpired(now.minus(Duration.ofDays(1)));
            int email = emailTokens.purgeExpired(now.minus(Duration.ofDays(1)));
            int deleted = accounts.purgeDeletedBefore(now.minus(Duration.ofDays(1)));
            if (refresh + email + deleted > 0) {
                log.info("Limpeza: {} refresh tokens, {} tokens de e-mail, {} contas excluídas", refresh, email, deleted);
            }
        });
    }
}
