package com.socialflux.auth;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** A migração V4 copia o histórico de audit_event para a outbox, com eventId determinístico. */
class AuditBackfillMigrationTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Test
    void copiesTheLegacyHistoryIntoTheOutbox() throws IOException {
        try (EmbeddedPostgres postgres = EmbeddedPostgres.builder().start()) {
            DataSource ds = postgres.getPostgresDatabase();
            migrate(ds, "3");
            JdbcClient jdbc = JdbcClient.create(ds);
            UUID account = UUID.randomUUID();
            jdbc.sql("insert into audit_event (account_id, action, ip, user_agent, detail, created_at) values "
                    + "(:a, 'REGISTER', '203.0.113.1', 'Navegador', null, '2026-11-20T10:00:00Z'),"
                    + "(null, 'LOGIN_FAILURE', '203.0.113.2', null, null, '2026-11-20T11:00:00Z'),"
                    + "(:a, 'REFRESH_REUSE', null, null, 'family=0191a2b3-0000-7000-8000-000000000001', "
                    + "'2026-11-20T12:00:00Z')").param("a", account).update();

            migrate(ds, null);

            List<String> payloads = jdbc.sql("select payload from audit_outbox order by created_at")
                    .query(String.class).list();
            assertThat(payloads).hasSize(3);
            JsonNode register = MAPPER.readTree(payloads.get(0));
            assertThat(register.path("service").asString()).isEqualTo("auth");
            assertThat(register.path("action").asString()).isEqualTo("REGISTER");
            assertThat(register.path("outcome").asString()).isEqualTo("SUCCESS");
            assertThat(register.path("actorId").asString()).isEqualTo(account.toString());
            assertThat(register.path("occurredAt").asString()).isEqualTo("2026-11-20T10:00:00.000Z");
            assertThat(register.path("eventId").asString()).isEqualTo(
                    jdbc.sql("select id from audit_outbox order by created_at limit 1").query(UUID.class).single()
                            .toString());
            JsonNode failure = MAPPER.readTree(payloads.get(1));
            assertThat(failure.path("outcome").asString()).isEqualTo("FAILURE");
            assertThat(failure.path("actorType").asString()).isEqualTo("ANONYMOUS");
            assertThat(failure.has("actorId")).isFalse();
            JsonNode reuse = MAPPER.readTree(payloads.get(2));
            assertThat(reuse.path("outcome").asString()).isEqualTo("DENIED");
            assertThat(reuse.path("detail").path("familyId").asString())
                    .isEqualTo("0191a2b3-0000-7000-8000-000000000001");
            assertThat(jdbc.sql("select count(*) from audit_outbox where sent_at is null and failed_at is null")
                    .query(Long.class).single()).isEqualTo(3);
        }
    }

    private static void migrate(DataSource ds, String target) {
        var config = Flyway.configure().dataSource(ds).locations("classpath:db/migration");
        if (target != null) {
            config.target(target);
        }
        config.load().migrate();
    }
}
