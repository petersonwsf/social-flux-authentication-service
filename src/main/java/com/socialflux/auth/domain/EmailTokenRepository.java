package com.socialflux.auth.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface EmailTokenRepository extends JpaRepository<EmailToken, UUID> {

    Optional<EmailToken> findByTokenHash(byte[] tokenHash);

    @Modifying
    @Query("update EmailToken t set t.usedAt = :now where t.accountId = :accountId "
            + "and t.purpose = :purpose and t.usedAt is null")
    int invalidatePending(@Param("accountId") UUID accountId, @Param("purpose") EmailToken.Purpose purpose,
                          @Param("now") Instant now);

    @Modifying
    @Query("delete from EmailToken t where t.expiresAt < :before")
    int purgeExpired(@Param("before") Instant before);
}
