package com.socialflux.auth;

import com.socialflux.audit.AuditMode;
import com.socialflux.audit.InMemoryAuditRecorder;
import com.socialflux.audit.InMemoryAuditRecorder.Recorded;
import com.socialflux.auth.support.AbstractIntegrationTest;
import com.socialflux.auth.support.ApiClient;
import com.socialflux.auth.support.ApiClient.Jar;
import com.socialflux.auth.support.ApiClient.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Eventos de auditoria do fluxo de autenticação (recorder em memória no lugar do audit-service). */
class AuditTest extends AbstractIntegrationTest {

    private static final String PASSWORD = "Str0ng!Passw0rd";

    @Autowired
    InMemoryAuditRecorder audit;

    @BeforeEach
    void clear() {
        audit.clear();
    }

    private Jar register(String email) {
        Jar jar = new Jar();
        Response response = api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), jar);
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return jar;
    }

    @Test
    void registerLoginAndRevocationAreAudited() {
        String email = uniqueEmail();
        Jar jar = register(email);
        assertThat(audit.recorded("REGISTER")).hasSize(1);
        Recorded registered = audit.recorded("REGISTER").get(0);
        assertThat(registered.mode()).isEqualTo(AuditMode.IN_TRANSACTION);
        assertThat(registered.payload()).containsEntry("outcome", "SUCCESS").containsEntry("actorType", "USER");
        assertThat(registered.entry().actorId()).isNotNull();

        Jar login = new Jar();
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), login).status()).isEqualTo(200);
        assertThat(audit.recorded("LOGIN_SUCCESS")).hasSize(1);

        assertThat(api().post("/auth/logout-all", null, jar).status()).isEqualTo(204);
        List<Recorded> revoked = audit.recorded("SESSION_REVOKED");
        assertThat(revoked).hasSize(1);
        assertThat(revoked.get(0).payload().get("detail").toString()).contains("LOGOUT_ALL");
    }

    @Test
    void loginFailureIsRecordedIndependentlyWithoutTheEmail() {
        String email = uniqueEmail();
        register(email);
        audit.clear();

        Response response = api().post("/auth/login", ApiClient.loginJson(email, "senha-errada-1A!"), new Jar());
        assertThat(response.status()).isEqualTo(401);

        List<Recorded> failures = audit.recorded("LOGIN_FAILURE");
        assertThat(failures).hasSize(1);
        assertThat(failures.get(0).mode()).isEqualTo(AuditMode.INDEPENDENT);
        assertThat(failures.get(0).payload()).containsEntry("outcome", "FAILURE");
        assertThat(audit.recorded()).allSatisfy(item -> assertThat(item.payload().toString())
                .doesNotContain(email).doesNotContain("senha-errada"));
    }

    @Test
    void unknownAccountLoginFailureIsAnonymous() {
        Response response = api().post("/auth/login", ApiClient.loginJson(uniqueEmail(), PASSWORD), new Jar());
        assertThat(response.status()).isEqualTo(401);

        assertThat(audit.recorded("LOGIN_FAILURE")).singleElement()
                .satisfies(item -> assertThat(item.payload()).containsEntry("actorType", "ANONYMOUS")
                        .doesNotContainKey("actorId"));
    }

    @Test
    void passwordChangeIsAuditedWithoutThePasswords() {
        Jar jar = register(uniqueEmail());

        Response changed = api().post("/auth/change-password",
                "{\"senhaAtual\":\"" + PASSWORD + "\",\"novaSenha\":\"N0va!Senha-Forte\"}", jar);
        assertThat(changed.status()).as(changed.body()).isEqualTo(200);
        assertThat(audit.recorded("PASSWORD_CHANGE")).hasSize(1);
        assertThat(audit.recorded()).extracting(r -> r.entry().action()).contains("SESSION_REVOKED");
        assertThat(audit.recorded()).allSatisfy(item -> assertThat(item.payload().toString())
                .doesNotContain(PASSWORD).doesNotContain("N0va!Senha"));
    }
}
