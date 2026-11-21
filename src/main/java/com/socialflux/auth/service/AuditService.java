package com.socialflux.auth.service;

import com.socialflux.auth.domain.AuditEvent;
import com.socialflux.auth.domain.AuditEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

/** Trilha de auditoria. Grava em transação própria para não se perder se a operação principal falhar. */
@Service
public class AuditService {

    private final AuditEventRepository repository;
    private final Clock clock;

    public AuditService(AuditEventRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(UUID accountId, String action, ClientInfo client, String detail) {
        repository.save(new AuditEvent(accountId, action, client.ip(), client.userAgent(), detail, clock.instant()));
    }
}
