package com.socialflux.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_event")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_id")
    private UUID accountId;

    @Column(nullable = false)
    private String action;

    private String ip;

    @Column(name = "user_agent")
    private String userAgent;

    private String detail;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AuditEvent() {
    }

    public AuditEvent(UUID accountId, String action, String ip, String userAgent, String detail, Instant createdAt) {
        this.accountId = accountId;
        this.action = action;
        this.ip = ip;
        this.userAgent = truncate(userAgent, 300);
        this.detail = truncate(detail, 500);
        this.createdAt = createdAt;
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    public Long getId() { return id; }
    public UUID getAccountId() { return accountId; }
    public String getAction() { return action; }
    public String getDetail() { return detail; }
    public Instant getCreatedAt() { return createdAt; }
}
