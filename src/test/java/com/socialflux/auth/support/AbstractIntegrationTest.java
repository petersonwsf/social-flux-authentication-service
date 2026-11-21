package com.socialflux.auth.support;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.util.UUID;

/**
 * Base dos testes de integração: sobe o serviço completo em porta aleatória contra um PostgreSQL REAL embutido
 * (zonky embedded-postgres, sem precisar de Docker) e fala com ele por HTTP de verdade.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "auth.jwt.allow-ephemeral-key=true",
                "auth.cookie.secure=false",
                "auth.cookie.access-name=at",
                "auth.cookie.refresh-name=rt",
                "auth.rate-limit.max-failures-per-ip=100000",
                "auth.jwt.issuer=http://auth.test",
                "socialflux.events.enabled=false",
                "spring.flyway.enabled=true"
        })
@Import(TestSupportConfig.class)
public abstract class AbstractIntegrationTest {

    private static final EmbeddedPostgres POSTGRES;

    static {
        try {
            POSTGRES = EmbeddedPostgres.builder().start();
        } catch (IOException e) {
            throw new IllegalStateException("Não foi possível iniciar o PostgreSQL embutido", e);
        }
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
    }

    @Value("${local.server.port}")
    protected int port;

    @Autowired
    protected MutableClock clock;

    @Autowired
    protected TestSupportConfig.RecordingMailService mail;

    @Autowired
    protected TestSupportConfig.FakeProfile profiles;

    @Autowired
    protected TestSupportConfig.RecordingPublisher publisher;

    @Autowired
    protected com.socialflux.events.OutboxRelay relay;

    @Autowired
    protected org.springframework.jdbc.core.simple.JdbcClient jdbc;

    protected ApiClient api;

    protected ApiClient api() {
        if (api == null) {
            api = new ApiClient(port);
        }
        return api;
    }

    protected static String uniqueEmail() {
        return "user-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }

    protected static String uniqueUsername() {
        return "u" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }
}
