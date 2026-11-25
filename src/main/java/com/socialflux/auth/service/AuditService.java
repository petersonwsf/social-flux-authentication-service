package com.socialflux.auth.service;

import com.socialflux.auth.domain.AuditEvent;
import com.socialflux.auth.domain.AuditEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Set;
import java.util.UUID;

/** Trilha de auditoria. Grava em transação própria para não se perder se a operação principal falhar. */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    /** Ações que merecem atenção em alertas: falha de login e reuso de refresh token (possível roubo de sessão). */
    private static final Set<String> SUSPICIOUS_ACTIONS = Set.of("LOGIN_FAILURE", "REFRESH_REUSE");

    private final AuditEventRepository repository;
    private final Clock clock;

    public AuditService(AuditEventRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(UUID accountId, String action, ClientInfo client, String detail) {
        repository.save(new AuditEvent(accountId, action, client.ip(), client.userAgent(), detail, clock.instant()));
        // Mesma trilha no log (para o Loki): só a ação e o id da conta; nunca IP, user-agent ou o detalhe.
        if (SUSPICIOUS_ACTIONS.contains(action)) {
            log.warn("Auditoria: {} (conta {})", action, accountId);
        } else {
            log.info("Auditoria: {} (conta {})", action, accountId);
        }
    }
}
