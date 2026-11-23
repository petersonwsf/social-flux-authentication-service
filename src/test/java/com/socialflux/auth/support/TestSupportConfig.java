package com.socialflux.auth.support;

import com.socialflux.events.EventPublisher;
import com.socialflux.auth.mail.MailService;
import com.socialflux.auth.profile.NewProfile;
import com.socialflux.auth.profile.ProfileCreated;
import com.socialflux.auth.profile.ProfilePort;
import com.socialflux.auth.web.ApiException;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@TestConfiguration
public class TestSupportConfig {

    @Bean
    @Primary
    MutableClock testClock() {
        return new MutableClock();
    }

    @Bean
    @Primary
    RecordingMailService recordingMailService() {
        return new RecordingMailService();
    }

    @Bean
    @Primary
    FakeProfile fakeProfile() {
        return new FakeProfile();
    }

    @Bean
    @Primary
    RecordingPublisher recordingPublisher() {
        return new RecordingPublisher();
    }

    /** Guarda os e-mails enviados para os testes extraírem os links. */
    public static class RecordingMailService implements MailService {

        public record Sent(String to, String subject, String text) {
            /** Token do link ({@code ?token=...}) do e-mail. */
            public String token() {
                int index = text.indexOf("token=");
                String rest = text.substring(index + "token=".length());
                int end = 0;
                while (end < rest.length() && !Character.isWhitespace(rest.charAt(end))) {
                    end++;
                }
                return rest.substring(0, end);
            }
        }

        private final List<Sent> sent = new CopyOnWriteArrayList<>();

        @Override
        public void send(String to, String subject, String text) {
            sent.add(new Sent(to, subject, text));
        }

        public Sent lastTo(String email) {
            List<Sent> matches = new ArrayList<>(sent.stream().filter(m -> m.to().equals(email)).toList());
            return matches.isEmpty() ? null : matches.get(matches.size() - 1);
        }

        public long countTo(String email) {
            return sent.stream().filter(m -> m.to().equals(email)).count();
        }
    }

    /**
     * Substitui o profile_service. Aplica as MESMAS regras que o serviço real devolve ao auth (username em uso, menor de
     * idade...) para exercitar o repasse de erros, e permite simular indisponibilidade e falha depois da criação.
     */
    public static class FakeProfile implements ProfilePort {

        private final Map<UUID, NewProfile> profiles = new ConcurrentHashMap<>();
        public final Set<UUID> discarded = ConcurrentHashMap.newKeySet();
        public volatile String rejectUsername;       // -> 409 username_taken
        public volatile String unavailableForUsername;   // -> 503 e o perfil NÃO chega a ser criado
        public volatile String timeoutAfterCreateForUsername;   // cria e depois responde 503 (resultado desconhecido)
        public volatile Runnable afterCreate;        // gancho executado logo depois de criar (simula corrida)

        @Override
        public ProfileCreated create(UUID accountId, NewProfile profile) {
            if (profile.username().equals(rejectUsername)) {
                throw ApiException.conflict("username_taken", "Já existe um usuário com esse username");
            }
            if (profile.username().equals(unavailableForUsername)) {
                throw new ApiException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, "profile_unavailable", "indisponível");
            }
            profiles.put(accountId, profile);
            Runnable hook = afterCreate;
            if (hook != null) {
                hook.run();
            }
            if (profile.username().equals(timeoutAfterCreateForUsername)) {
                throw new ApiException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, "profile_unavailable", "timeout");
            }
            return new ProfileCreated(true);
        }

        @Override
        public void discard(UUID accountId) {
            discarded.add(accountId);
            profiles.remove(accountId);
        }

        public boolean has(UUID accountId) {
            return profiles.containsKey(accountId);
        }

        public NewProfile get(UUID accountId) {
            return profiles.get(accountId);
        }

        public int size() {
            return profiles.size();
        }
    }

    /** Substitui o RabbitMQ: guarda o que o relay publicou e permite simular o broker fora do ar. */
    public static class RecordingPublisher implements EventPublisher {

        public record Sent(UUID id, String routingKey, String json) {
        }

        public final List<Sent> sent = new CopyOnWriteArrayList<>();
        public volatile boolean down;

        @Override
        public void publish(UUID messageId, String routingKey, String json) {
            if (down) {
                throw new IllegalStateException("broker fora do ar (simulado)");
            }
            sent.add(new Sent(messageId, routingKey, json));
        }

        public List<Sent> forAccount(UUID accountId) {
            return sent.stream().filter(s -> s.json().contains(accountId.toString())).toList();
        }
    }

    /** Evita warning de "Clock" não usado quando o contexto não injeta o relógio de teste diretamente. */
    @SuppressWarnings("unused")
    private static Clock unused() {
        return Clock.systemUTC();
    }
}
