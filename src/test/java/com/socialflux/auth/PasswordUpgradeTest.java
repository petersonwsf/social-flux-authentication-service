package com.socialflux.auth;

import com.socialflux.auth.domain.Account;
import com.socialflux.auth.domain.AccountRepository;
import com.socialflux.auth.support.AbstractIntegrationTest;
import com.socialflux.auth.support.ApiClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Hashes BCrypt importados do sistema legado continuam válidos e sobem para Argon2id no primeiro login. */
class PasswordUpgradeTest extends AbstractIntegrationTest {

    @Autowired
    AccountRepository accounts;

    @Test
    void importedBcryptHashLogsInAndIsUpgradedToArgon2() {
        String email = uniqueEmail();
        String legacyHash = new BCryptPasswordEncoder().encode("SenhaAntiga!123"); // $2a$10$...
        accounts.save(new Account(UUID.randomUUID(), email, "{bcrypt}" + legacyHash, Instant.now()));

        var response = api().post("/auth/login", ApiClient.loginJson(email, "SenhaAntiga!123"), new ApiClient.Jar());
        assertThat(response.status()).isEqualTo(200);

        assertThat(accounts.findByEmail(email).orElseThrow().getPasswordHash()).startsWith("{argon2}");
        // E continua entrando com a mesma senha
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, "SenhaAntiga!123"), null).status()).isEqualTo(200);
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, "errada-1234"), null).status()).isEqualTo(401);
    }
}
