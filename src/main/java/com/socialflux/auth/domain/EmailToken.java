package com.socialflux.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** Token de uso único enviado por e-mail (verificação de e-mail ou redefinição de senha). */
@Entity
@Table(name = "email_token")
public class EmailToken {

    public enum Purpose { VERIFY_EMAIL, RESET_PASSWORD }

    @Id
    private UUID id;

    @Column(name = "account_id", nullable = false)
    private UUID accountId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Purpose purpose;

    @Column(name = "token_hash", nullable = false, unique = true)
    private byte[] tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    protected EmailToken() {
    }

    public EmailToken(UUID id, UUID accountId, Purpose purpose, byte[] tokenHash, Instant expiresAt) {
        this.id = id;
        this.accountId = accountId;
        this.purpose = purpose;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }

    public UUID getId() { return id; }
    public UUID getAccountId() { return accountId; }
    public Purpose getPurpose() { return purpose; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getUsedAt() { return usedAt; }
    public void setUsedAt(Instant usedAt) { this.usedAt = usedAt; }
}
