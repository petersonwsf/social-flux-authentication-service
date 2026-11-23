package com.socialflux.auth;

import com.socialflux.auth.profile.ProfilePort;
import com.socialflux.auth.mail.MailService;
import com.socialflux.auth.support.TestSupportConfig;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.io.IOException;

/**
 * Sobe o serviço SEM Docker, para desenvolvimento/depuração: PostgreSQL embutido (zonky), chave RSA efêmera,
 * perfil (profile_service) em memória e e-mails impressos no log (com o link de verificação/redefinição).
 *
 * <pre>
 *   mvn -q test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
 *   java -cp "target/test-classes;target/classes;$(cat target/cp.txt)" com.socialflux.auth.DevServer
 * </pre>
 * Variáveis opcionais: JWT_ACCESS_TTL, JWT_RENEW_WINDOW, JWT_REFRESH_GRACE, SERVER_PORT (ver application.yml).
 */
public class DevServer {

    public static void main(String[] args) throws IOException {
        EmbeddedPostgres postgres = EmbeddedPostgres.builder().start();
        // Argumentos de linha de comando têm precedência sobre o application.yml (que lê variáveis de ambiente).
        java.util.List<String> properties = new java.util.ArrayList<>(java.util.List.of(
                "--spring.datasource.url=" + postgres.getJdbcUrl("postgres", "postgres"),
                "--spring.datasource.username=postgres",
                "--spring.datasource.password=postgres",
                "--auth.jwt.allow-ephemeral-key=true",
                "--auth.cookie.secure=false",
                "--auth.cookie.access-name=at",
                "--auth.cookie.refresh-name=rt",
                "--socialflux.events.enabled=false"));
        properties.addAll(java.util.List.of(args));
        new SpringApplicationBuilder(AuthenticationServiceApplication.class, DevConfig.class)
                .run(properties.toArray(new String[0]));
    }

    // Sem @Configuration de propósito: é passada explicitamente ao SpringApplicationBuilder e NÃO pode ser
    // encontrada pela varredura de componentes dos testes (conflitaria com os beans @Primary de TestSupportConfig).
    static class DevConfig {

        private static final Logger log = LoggerFactory.getLogger(DevServer.class);

        @Bean
        @Primary
        ProfilePort devProfile() {
            return new TestSupportConfig.FakeProfile();
        }

        @Bean
        @Primary
        MailService devMail() {
            return (to, subject, text) -> log.info("\n=== E-MAIL para {} | {} ===\n{}\n", to, subject, text);
        }
    }
}
