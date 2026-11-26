package com.socialflux.auth.service;

import com.socialflux.audit.AuditEntry;
import com.socialflux.audit.AuditRecorder;
import com.socialflux.audit.Outcome;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Trilha de auditoria do auth: delega à biblioteca {@code socialflux-audit} (outbox local + envio ao audit-service).
 * <ul>
 *   <li>{@code LOGIN_FAILURE} e {@code REFRESH_REUSE} são gravados em transação própria ({@code independent}), para
 *   sobreviver ao rollback da operação que falhou;</li>
 *   <li>as demais ações entram na transação de quem chama ({@code inTransaction}, exige transação ativa).</li>
 * </ul>
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    /** Ações que merecem atenção em alertas: falha de login e reuso de refresh token (possível roubo de sessão). */
    private static final Set<String> SUSPICIOUS_ACTIONS = Set.of("LOGIN_FAILURE", "REFRESH_REUSE");

    private final AuditRecorder recorder;

    public AuditService(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    /** {@code detail} pode ser nulo; só ids e nomes, nunca dado pessoal. */
    public void record(UUID accountId, String action, ClientInfo client, Map<String, Object> detail) {
        AuditEntry entry = AuditEntry.of(action, outcomeOf(action)).actor(accountId)
                .client(client.ip(), client.userAgent());
        if (accountId != null) {
            entry = entry.target("ACCOUNT", accountId);
        }
        if (detail != null) {
            for (Map.Entry<String, Object> field : detail.entrySet()) {
                entry = entry.detail(field.getKey(), field.getValue());
            }
        }
        if (SUSPICIOUS_ACTIONS.contains(action)) {
            recorder.independent(entry);
            // Mesma trilha no log (para o Loki): só a ação e o id da conta; nunca IP, user-agent ou o detalhe.
            log.warn("Auditoria: {} (conta {})", action, accountId);
        } else {
            recorder.inTransaction(entry);
            log.info("Auditoria: {} (conta {})", action, accountId);
        }
    }

    private static Outcome outcomeOf(String action) {
        return switch (action) {
            case "LOGIN_FAILURE" -> Outcome.FAILURE;
            case "REFRESH_REUSE" -> Outcome.DENIED;
            default -> Outcome.SUCCESS;
        };
    }
}
