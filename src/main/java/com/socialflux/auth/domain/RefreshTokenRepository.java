package com.socialflux.auth.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(byte[] tokenHash);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokeReason = :reason "
            + "where t.familyId = :familyId and t.revokedAt is null")
    int revokeFamily(@Param("familyId") UUID familyId, @Param("now") Instant now, @Param("reason") String reason);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokeReason = :reason "
            + "where t.accountId = :accountId and t.revokedAt is null")
    int revokeAllOfAccount(@Param("accountId") UUID accountId, @Param("now") Instant now, @Param("reason") String reason);

    @Modifying
    @Query("delete from RefreshToken t where t.familyExpiresAt < :before or t.expiresAt < :before")
    int purgeExpired(@Param("before") Instant before);

    @Query("select count(t) from RefreshToken t where t.familyId = :familyId and t.revokedAt is null")
    long countActiveInFamily(@Param("familyId") UUID familyId);
}
