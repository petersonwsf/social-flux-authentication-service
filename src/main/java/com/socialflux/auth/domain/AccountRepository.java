package com.socialflux.auth.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AccountRepository extends JpaRepository<Account, UUID> {

    Optional<Account> findByEmail(String email);

    boolean existsByEmail(String email);

    List<Account> findByTokenVersionChangedAtAfter(Instant since);

    @Modifying
    @Query("delete from Account a where a.status = com.socialflux.auth.domain.AccountStatus.DELETED and a.updatedAt < :before")
    int purgeDeletedBefore(@Param("before") Instant before);
}
