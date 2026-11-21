package com.socialflux.auth;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.socialflux.auth.support.AbstractIntegrationTest;
import com.socialflux.auth.support.ApiClient;
import com.socialflux.auth.support.ApiClient.Jar;
import com.socialflux.auth.support.ApiClient.Response;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFlowTest extends AbstractIntegrationTest {

    @org.springframework.beans.factory.annotation.Autowired
    com.socialflux.auth.domain.AccountRepository accounts;

    private void drain() {
        for (int i = 0; i < 100 && relay.publishPending() > 0; i++) {
            // esvazia o outbox em lotes
        }
    }

    private static final String PASSWORD = "Str0ng!Passw0rd";

    private Jar register(String email) {
        Jar jar = new Jar();
        Response response = api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), jar);
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return jar;
    }

    private Jar login(String email, String password) {
        Jar jar = new Jar();
        Response response = api().post("/auth/login", ApiClient.loginJson(email, password), jar);
        assertThat(response.status()).as(response.body()).isEqualTo(200);
        return jar;
    }

    @Test
    void registerSetsHttpOnlyCookiesAndIssuesAValidRs256Jwt() throws Exception {
        String email = uniqueEmail();
        Jar jar = new Jar();
        Response response = api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), jar);

        assertThat(response.status()).isEqualTo(201);
        assertThat(response.raw().headers().allValues("Set-Cookie"))
                .allSatisfy(cookie -> assertThat(cookie).contains("HttpOnly"))
                .anySatisfy(cookie -> assertThat(cookie).startsWith("at=").contains("SameSite=Lax").contains("Path=/"))
                .anySatisfy(cookie -> assertThat(cookie).startsWith("rt=").contains("SameSite=Strict").contains("Path=/auth"));

        // Claims do JWT
        SignedJWT jwt = SignedJWT.parse(jar.access());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jwt.getHeader().getKeyID()).isNotBlank();
        UUID sub = UUID.fromString(jwt.getJWTClaimsSet().getSubject());
        assertThat(sub.version()).isEqualTo(7);
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("socialflux-api");
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://auth.test");
        long ttl = jwt.getJWTClaimsSet().getExpirationTime().getTime() - jwt.getJWTClaimsSet().getIssueTime().getTime();
        assertThat(Duration.ofMillis(ttl)).isEqualTo(Duration.ofHours(2));
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("USER");
        assertThat(jwt.getJWTClaimsSet().getLongClaim("ver")).isEqualTo(1L);
        assertThat(jwt.getJWTClaimsSet().getClaims()).doesNotContainKeys("email", "nome", "telefone");

        // A assinatura confere com a chave pública publicada no JWKS
        Response jwks = api().get("/.well-known/jwks.json", null);
        assertThat(jwks.status()).isEqualTo(200);
        assertThat(jwks.body()).doesNotContain("\"d\"").doesNotContain("\"p\"").doesNotContain("\"q\"");
        RSAKey key = (RSAKey) JWKSet.parse(jwks.body()).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(key.toRSAPublicKey()))).isTrue();

        // /auth/me com o cookie
        Response me = api().get("/auth/me", jar);
        assertThat(me.status()).isEqualTo(200);
        // D4: /auth/me devolve só identidade; o perfil (username, nome, foto) vem do profile_service
        assertThat(me.obj("account").get("email")).isEqualTo(email);
        assertThat(me.obj("account").get("accountId")).isEqualTo(sub.toString());
        assertThat(me.obj("account").get("emailVerified")).isEqualTo(false);
        assertThat(me.json()).doesNotContainKeys("user");
        assertThat(me.body()).doesNotContain("username").doesNotContain("telefone").doesNotContain("nome");
    }

    @Test
    void accountRulesAreValidatedOnTheServer() {
        String email = uniqueEmail();
        Response weak = api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), "12345678"), null);
        assertThat(weak.status()).isEqualTo(400);
        assertThat(weak.json().get("codigo")).isEqualTo("weak_password");

        Response invalidEmail = api().post("/auth/register", ApiClient.registerJson("nao-e-email", uniqueUsername(), PASSWORD), null);
        assertThat(invalidEmail.status()).isEqualTo(400);

        // Nenhuma regra de conta falhou DEPOIS de criar perfil: nada para desfazer
        assertThat(profiles.discarded).isEmpty();

        register(email);
        Response duplicate = api().post("/auth/register", ApiClient.registerJson(email.toUpperCase(), uniqueUsername(), PASSWORD), null);
        assertThat(duplicate.status()).isEqualTo(409);
        assertThat(duplicate.json().get("codigo")).isEqualTo("email_taken");
    }

    @Test
    void profileRulesComeFromTheProfileServiceWithTheSameErrorContract() {
        String username = uniqueUsername();
        profiles.rejectUsername = username;
        try {
            Response response = api().post("/auth/register", ApiClient.registerJson(uniqueEmail(), username, PASSWORD), null);
            assertThat(response.status()).isEqualTo(409);
            assertThat(response.json().get("codigo")).isEqualTo("username_taken");
            assertThat(response.json().get("sucesso")).isEqualTo(false);
        } finally {
            profiles.rejectUsername = null;
        }
    }

    @Test
    void accountAndProfileShareTheSameUuidAndRegistrationIsAnnouncedExactlyOnce() throws Exception {
        String email = uniqueEmail();
        String username = uniqueUsername();
        Jar jar = new Jar();
        assertThat(api().post("/auth/register", ApiClient.registerJson(email, username, PASSWORD), jar).status()).isEqualTo(201);
        UUID accountId = UUID.fromString(SignedJWT.parse(jar.access()).getJWTClaimsSet().getSubject());

        assertThat(profiles.has(accountId)).as("o perfil é criado com o MESMO UUID da conta").isTrue();
        assertThat(profiles.get(accountId).username()).isEqualTo(username);

        drain();
        var events = publisher.forAccount(accountId);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).routingKey()).isEqualTo("account.registered.v1");
        // O evento não carrega e-mail, senha nem dados de perfil
        assertThat(events.get(0).json()).contains("\"aggregateId\":\"" + accountId + "\"")
                .doesNotContain(email).doesNotContain("senha").doesNotContain("password").doesNotContain(username);
    }

    @Test
    void profileServiceOutageLeavesNoAccountBehindAndAsksForRetry() {
        String email = uniqueEmail();
        String username = uniqueUsername();
        profiles.unavailableForUsername = username;
        try {
            Response response = api().post("/auth/register", ApiClient.registerJson(email, username, PASSWORD), null);
            assertThat(response.status()).isEqualTo(503);
            assertThat(response.json().get("codigo")).isEqualTo("profile_unavailable");
        } finally {
            profiles.unavailableForUsername = null;
        }
        // Nenhuma conta ficou para trás: o mesmo e-mail pode se cadastrar depois
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), null).status()).isEqualTo(401);
        assertThat(api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), null).status())
                .isEqualTo(201);
    }

    @Test
    void anUnknownOutcomeFromTheProfileServiceIsCompensated() {
        String email = uniqueEmail();
        String username = uniqueUsername();
        int before = profiles.discarded.size();
        profiles.timeoutAfterCreateForUsername = username;   // o perfil FOI criado, mas a resposta se perdeu
        try {
            Response response = api().post("/auth/register", ApiClient.registerJson(email, username, PASSWORD), null);
            assertThat(response.status()).isEqualTo(503);
        } finally {
            profiles.timeoutAfterCreateForUsername = null;
        }
        assertThat(profiles.discarded.size()).isEqualTo(before + 1);
        UUID orphan = profiles.discarded.stream().skip(before).findFirst().orElseThrow();
        assertThat(profiles.has(orphan)).as("o perfil órfão foi removido").isFalse();
    }

    @Test
    void ifSavingTheAccountFailsAfterTheProfileExistsTheProfileIsRemoved() {
        String email = uniqueEmail();
        // Corrida: outra requisição cria uma conta com o mesmo e-mail entre a checagem e o INSERT
        profiles.afterCreate = () -> accounts.save(new com.socialflux.auth.domain.Account(
                UUID.randomUUID(), email, "{noop}x", java.time.Instant.now()));
        int before = profiles.discarded.size();
        try {
            Response response = api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), null);
            assertThat(response.status()).isEqualTo(409);
            assertThat(response.json().get("codigo")).isEqualTo("email_taken");
        } finally {
            profiles.afterCreate = null;
        }
        assertThat(profiles.discarded.size()).isEqualTo(before + 1);
        UUID orphan = profiles.discarded.stream().skip(before).findFirst().orElseThrow();
        assertThat(profiles.has(orphan)).as("o perfil criado antes da falha foi compensado").isFalse();
        // e nenhum evento account.registered foi gravado para ele (a transação da conta foi desfeita)
        drain();
        assertThat(publisher.forAccount(orphan)).isEmpty();
    }

    @Test
    void eventsStayPendingWhileTheBrokerIsDownAndAreDeliveredInOrderAfterwards() {
        String email = uniqueEmail();
        publisher.down = true;
        Jar jar = new Jar();
        try {
            assertThat(api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), jar).status())
                    .isEqualTo(201);   // cadastrar não depende do broker
            relay.publishPending();
        } finally {
            publisher.down = false;
        }
        UUID accountId = UUID.fromString(jdbc.sql("select id from account where email = :e").param("e", email)
                .query(String.class).single());
        assertThat(publisher.forAccount(accountId)).isEmpty();
        drain();
        assertThat(publisher.forAccount(accountId)).hasSize(1);
        int total = publisher.sent.size();
        drain();
        assertThat(publisher.sent).as("nada é reenviado").hasSize(total);
    }

    @Test
    void loginErrorsAreUniformAndRateLimited() {
        String email = uniqueEmail();
        register(email);

        Response wrongPassword = api().post("/auth/login", ApiClient.loginJson(email, "senha-errada-123"), null);
        Response unknownEmail = api().post("/auth/login", ApiClient.loginJson(uniqueEmail(), "senha-errada-123"), null);
        assertThat(wrongPassword.status()).isEqualTo(401);
        assertThat(unknownEmail.status()).isEqualTo(401);
        assertThat(wrongPassword.json().get("mensagem")).isEqualTo(unknownEmail.json().get("mensagem"));

        // 5 falhas por e-mail+IP bloqueiam por um tempo (mesmo com a senha certa)
        for (int i = 0; i < 4; i++) {
            assertThat(api().post("/auth/login", ApiClient.loginJson(email, "senha-errada-123"), null).status()).isEqualTo(401);
        }
        Response blocked = api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), null);
        assertThat(blocked.status()).isEqualTo(429);
        assertThat(blocked.header("Retry-After")).isNotNull();

        // Passada a janela, volta a funcionar
        clock.advance(Duration.ofMinutes(16));
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), null).status()).isEqualTo(200);
    }

    @Test
    void refreshRotatesTokensAndDetectsReuse() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);
        String firstRefresh = jar.refresh();
        String firstAccess = jar.access();

        Response refreshed = api().post("/auth/refresh", null, jar);
        assertThat(refreshed.status()).isEqualTo(200);
        assertThat(jar.refresh()).isNotEqualTo(firstRefresh);
        assertThat(jar.access()).isNotEqualTo(firstAccess);
        assertThat(refreshed.json()).containsKeys("expiresAt", "renewAt");

        // Passada a tolerância, reapresentar o refresh antigo é tratado como roubo: derruba a família inteira
        clock.advance(Duration.ofSeconds(30));
        Jar attacker = new Jar();
        attacker.cookies.put(ApiClient.REFRESH, firstRefresh);
        assertThat(api().post("/auth/refresh", null, attacker).status()).isEqualTo(401);

        Jar victim = new Jar();
        victim.cookies.put(ApiClient.REFRESH, jar.refresh());
        assertThat(api().post("/auth/refresh", null, victim).status()).isEqualTo(401);
    }

    @Test
    void concurrentRefreshWithinToleranceIsAccepted() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);
        String original = jar.refresh();

        assertThat(api().post("/auth/refresh", null, jar).status()).isEqualTo(200);
        // Outra aba ainda com o cookie antigo, dentro de ~10 s
        Jar otherTab = new Jar();
        otherTab.cookies.put(ApiClient.REFRESH, original);
        assertThat(api().post("/auth/refresh", null, otherTab).status()).isEqualTo(200);
    }

    @Test
    void sessionSlidesWhileUserIsActiveAndEndsWhenIdle() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);

        // Perto do vencimento o token ainda vale e o servidor indica a janela de renovação
        clock.advance(Duration.ofHours(2).minusMinutes(5));
        assertThat(api().get("/auth/me", jar).status()).isEqualTo(200);

        // Passa do vencimento: o token de acesso expirou...
        clock.advance(Duration.ofMinutes(7));
        assertThat(api().get("/auth/me", jar).status()).isEqualTo(401);
        // ...mas o usuário estava ativo dentro da tolerância (5 min), então renova
        assertThat(api().post("/auth/refresh", null, jar).status()).isEqualTo(200);
        assertThat(api().get("/auth/me", jar).status()).isEqualTo(200);

        // Ocioso além do vencimento + tolerância: precisa entrar de novo
        clock.advance(Duration.ofHours(2).plusMinutes(6));
        assertThat(api().get("/auth/me", jar).status()).isEqualTo(401);
        assertThat(api().post("/auth/refresh", null, jar).status()).isEqualTo(401);
    }

    @Test
    void sessionHasAnAbsoluteLimitEvenWithConstantActivity() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);

        int refreshes = 0;
        int lastStatus = 200;
        while (lastStatus == 200 && refreshes < 200) {
            clock.advance(Duration.ofHours(1).plusMinutes(55));
            lastStatus = api().post("/auth/refresh", null, jar).status();
            refreshes++;
        }
        // 7 dias / 1h55 ≈ 88 renovações
        assertThat(lastStatus).isEqualTo(401);
        assertThat(refreshes).isBetween(80, 95);
    }

    @Test
    void logoutEndsOnlyThatSession() {
        String email = uniqueEmail();
        register(email);
        Jar a = login(email, PASSWORD);
        Jar b = login(email, PASSWORD);

        assertThat(api().post("/auth/logout", null, a).status()).isEqualTo(204);
        assertThat(a.cookies).isEmpty();
        Jar stale = new Jar();
        stale.cookies.put(ApiClient.REFRESH, "qualquer");
        assertThat(api().post("/auth/refresh", null, stale).status()).isEqualTo(401);
        assertThat(api().get("/auth/me", b).status()).isEqualTo(200);
    }

    @Test
    void logoutAllRevokesEveryAccessAndRefreshToken() {
        String email = uniqueEmail();
        register(email);
        Jar a = login(email, PASSWORD);
        Jar b = login(email, PASSWORD);
        Jar bBeforeLogout = b.copy();

        assertThat(api().post("/auth/logout-all", null, a).status()).isEqualTo(204);

        // O token de acesso de B ainda não expirou, mas a versão da conta mudou
        assertThat(api().get("/auth/me", bBeforeLogout).status()).isEqualTo(401);
        assertThat(api().post("/auth/refresh", null, bBeforeLogout).status()).isEqualTo(401);
        // Fazer login de novo funciona e o novo token tem a nova versão
        Jar again = login(email, PASSWORD);
        assertThat(api().get("/auth/me", again).status()).isEqualTo(200);
    }

    @Test
    void changePasswordRevokesOtherSessionsButKeepsTheCurrentOne() {
        String email = uniqueEmail();
        register(email);
        Jar current = login(email, PASSWORD);
        Jar other = login(email, PASSWORD);
        String newPassword = "N0va!Senha-Forte";

        Response wrong = api().post("/auth/change-password",
                "{\"senhaAtual\":\"errada-123\",\"novaSenha\":\"%s\"}".formatted(newPassword), current);
        assertThat(wrong.status()).isEqualTo(400);

        Response changed = api().post("/auth/change-password",
                "{\"senhaAtual\":\"%s\",\"novaSenha\":\"%s\"}".formatted(PASSWORD, newPassword), current);
        assertThat(changed.status()).isEqualTo(200);

        assertThat(api().get("/auth/me", current).status()).isEqualTo(200);   // sessão atual renovada
        assertThat(api().get("/auth/me", other).status()).isEqualTo(401);     // as demais caem
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), null).status()).isEqualTo(401);
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, newPassword), null).status()).isEqualTo(200);
    }

    @Test
    void forgotAndResetPasswordFlow() {
        String email = uniqueEmail();
        register(email);
        Jar session = login(email, PASSWORD);

        // Resposta idêntica para e-mail inexistente (sem enumeração)
        Response unknown = api().post("/auth/forgot-password", "{\"email\":\"%s\"}".formatted(uniqueEmail()), null);
        Response known = api().post("/auth/forgot-password", "{\"email\":\"%s\"}".formatted(email), null);
        assertThat(unknown.status()).isEqualTo(202);
        assertThat(known.status()).isEqualTo(202);
        assertThat(known.body()).isEqualTo(unknown.body());

        String token = mail.lastTo(email).token();
        assertThat(token).isNotBlank();

        String weak = "{\"token\":\"%s\",\"novaSenha\":\"12345678\"}".formatted(token);
        assertThat(api().post("/auth/reset-password", weak, null).status()).isEqualTo(400);

        String reset = "{\"token\":\"%s\",\"novaSenha\":\"Outra!Senha-Forte1\"}".formatted(token);
        assertThat(api().post("/auth/reset-password", reset, null).status()).isEqualTo(200);
        // Uso único
        assertThat(api().post("/auth/reset-password", reset, null).status()).isEqualTo(400);

        assertThat(api().get("/auth/me", session).status()).isEqualTo(401); // sessões antigas derrubadas
        assertThat(api().post("/auth/login", ApiClient.loginJson(email, "Outra!Senha-Forte1"), null).status()).isEqualTo(200);
    }

    @Test
    void emailVerificationFlow() {
        String email = uniqueEmail();
        Jar jar = register(email);
        assertThat(api().get("/auth/me", jar).obj("account").get("emailVerified")).isEqualTo(false);

        String token = mail.lastTo(email).token();
        assertThat(api().post("/auth/verify-email", "{\"token\":\"%s\"}".formatted(token), null).status()).isEqualTo(200);
        assertThat(api().get("/auth/me", jar).obj("account").get("emailVerified")).isEqualTo(true);
        assertThat(api().post("/auth/verify-email", "{\"token\":\"%s\"}".formatted(token), null).status()).isEqualTo(400);
    }

    @Test
    void deleteAccountRequiresPasswordAndInvalidatesEverything() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);
        UUID accountId = UUID.fromString(jdbc.sql("select id from account where email = :e").param("e", email)
                .query(String.class).single());

        assertThat(api().delete("/auth/account", "{\"senha\":\"errada-123\"}", jar).status()).isEqualTo(400);
        Response deleted = api().delete("/auth/account", "{\"senha\":\"%s\"}".formatted(PASSWORD), jar);
        assertThat(deleted.status()).isEqualTo(200);
        // A exclusão do perfil é feita pelo profile_service ao receber o evento (assíncrono, via outbox)
        drain();
        assertThat(publisher.forAccount(accountId)).extracting(sent -> sent.routingKey())
                .containsExactly("account.registered.v1", "account.deleted.v1");

        assertThat(api().post("/auth/login", ApiClient.loginJson(email, PASSWORD), null).status()).isEqualTo(401);
        // O token antigo ainda não expirou, mas a conta foi revogada
        Jar old = new Jar();
        old.cookies.put(ApiClient.ACCESS, "invalido");
        assertThat(api().get("/auth/me", old).status()).isEqualTo(401);
        // O e-mail volta a ficar disponível
        assertThat(api().post("/auth/register", ApiClient.registerJson(email, uniqueUsername(), PASSWORD), null).status())
                .isEqualTo(201);
    }

    @Test
    void deletedAccountsStoredTokenIsRejectedImmediately() {
        String email = uniqueEmail();
        register(email);
        Jar jar = login(email, PASSWORD);
        Jar copy = jar.copy();

        assertThat(api().delete("/auth/account", "{\"senha\":\"%s\"}".formatted(PASSWORD), jar).status()).isEqualTo(200);
        assertThat(api().get("/auth/me", copy).status()).isEqualTo(401);
        assertThat(api().get("/internal/auth/verify", copy).status()).isEqualTo(401);
    }

    @Test
    void internalVerifyReturnsIdentityHeadersForTheGateway() {
        String email = uniqueEmail();
        Jar jar = register(email);

        assertThat(api().get("/internal/auth/verify", null).status()).isEqualTo(401);

        // Via cookie (navegador) e via Bearer (serviço-a-serviço / Caddy)
        Response viaCookie = api().get("/internal/auth/verify", jar);
        assertThat(viaCookie.status()).isEqualTo(204);
        assertThat(viaCookie.header("X-User-Id")).isNull();   // o id inteiro legado não existe mais
        assertThat(viaCookie.header("X-Account-Id")).isNotBlank();

        Response viaBearer = api().send("GET", "/internal/auth/verify", null, null,
                Map.of("Authorization", "Bearer " + jar.access()));
        assertThat(viaBearer.status()).isEqualTo(204);
        assertThat(viaBearer.header("X-Account-Id")).isEqualTo(viaCookie.header("X-Account-Id"));
    }

    @Test
    void forgedOrTamperedTokensAreRejected() throws Exception {
        String email = uniqueEmail();
        Jar jar = register(email);
        String token = jar.access();

        // Assinatura adulterada
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + parts[2].substring(0, parts[2].length() - 4) + "AAAA";
        assertThat(bearer("/auth/me", tampered)).isEqualTo(401);

        // alg=none
        String none = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes()) + "." + parts[1] + ".";
        assertThat(bearer("/auth/me", none)).isEqualTo(401);

        // Assinado por OUTRA chave RSA (mesmo kid/claims)
        var generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        SignedJWT original = SignedJWT.parse(token);
        SignedJWT forged = new SignedJWT(original.getHeader(), original.getJWTClaimsSet());
        forged.sign(new com.nimbusds.jose.crypto.RSASSASigner(pair.getPrivate()));
        assertThat(bearer("/auth/me", forged.serialize())).isEqualTo(401);

        // Token válido de verdade continua funcionando
        assertThat(bearer("/auth/me", token)).isEqualTo(200);
    }

    @Test
    void crossSiteWritesAreRejectedButSameOriginAndNonBrowserClientsPass() {
        String body = ApiClient.loginJson(uniqueEmail(), "qualquer-senha-1");
        assertThat(api().post("/auth/login", body, null, Map.of("Origin", "http://evil.example")).status()).isEqualTo(403);
        assertThat(api().post("/auth/login", body, null, Map.of("Sec-Fetch-Site", "cross-site")).status()).isEqualTo(403);
        // Mesma origem: chega até a validação de credenciais (401, não 403)
        assertThat(api().post("/auth/login", body, null, Map.of("Origin", api().baseUrl())).status()).isEqualTo(401);
        assertThat(api().post("/auth/login", body, null).status()).isEqualTo(401);
    }

    @Test
    void protectedRoutesAnswerWithJson401() {
        Response response = api().get("/auth/me", null);
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.json()).containsEntry("sucesso", false).containsKey("mensagem");
    }

    private int bearer(String path, String token) {
        return api().send("GET", path, null, null, Map.of("Authorization", "Bearer " + token)).status();
    }

    @SuppressWarnings("unused")
    private static List<String> unused() {
        return List.of();
    }
}
