package com.socialflux.auth.service;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.domain.Account;
import com.socialflux.auth.domain.AccountRepository;
import com.socialflux.auth.domain.AccountStatus;
import com.socialflux.auth.domain.EmailToken;
import com.socialflux.auth.domain.EmailTokenRepository;
import com.socialflux.auth.domain.RefreshTokenRepository;
import com.socialflux.auth.profile.NewProfile;
import com.socialflux.auth.profile.ProfileCreated;
import com.socialflux.auth.profile.ProfilePort;
import com.socialflux.auth.mail.MailService;
import com.socialflux.auth.util.Tokens;
import com.socialflux.auth.util.Uuids;
import com.socialflux.auth.web.ApiException;
import com.socialflux.events.Outbox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** Regras de negócio de contas: cadastro, login, senha, verificação de e-mail e exclusão. */
@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);

    private static final Duration EMAIL_TOKEN_TTL_VERIFY = Duration.ofHours(48);
    private static final Duration EMAIL_TOKEN_TTL_RESET = Duration.ofHours(1);
    private static final String GENERIC_LOGIN_ERROR = "E-mail ou senha incorretos";

    private final AccountRepository accounts;
    private final EmailTokenRepository emailTokens;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordService passwords;
    private final PasswordPolicy passwordPolicy;
    private final TokenService tokens;
    private final RevocationRegistry revocations;
    private final RateLimiter rateLimiter;
    private final AuditService audit;
    private final ProfilePort profiles;
    private final Outbox outbox;
    private final MailService mail;
    private final AuthProperties properties;
    private final TransactionTemplate tx;
    private final Clock clock;

    public AccountService(AccountRepository accounts, EmailTokenRepository emailTokens,
                          RefreshTokenRepository refreshTokens, PasswordService passwords,
                          PasswordPolicy passwordPolicy, TokenService tokens, RevocationRegistry revocations,
                          RateLimiter rateLimiter, AuditService audit, ProfilePort profiles,
                          Outbox outbox, MailService mail, AuthProperties properties, PlatformTransactionManager txManager,
                          Clock clock) {
        this.accounts = accounts;
        this.emailTokens = emailTokens;
        this.refreshTokens = refreshTokens;
        this.passwords = passwords;
        this.passwordPolicy = passwordPolicy;
        this.tokens = tokens;
        this.revocations = revocations;
        this.rateLimiter = rateLimiter;
        this.audit = audit;
        this.profiles = profiles;
        this.outbox = outbox;
        this.mail = mail;
        this.properties = properties;
        this.tx = new TransactionTemplate(txManager);
        this.clock = clock;
    }

    // ------------------------------------------------------------------ cadastro

    public static final String EVENT_REGISTERED = "account.registered.v1";
    public static final String EVENT_DELETED = "account.deleted.v1";

    /**
     * Cria conta + perfil (D1: o auth orquestra). O perfil é de outro serviço/banco, então usamos uma "saga" simples:
     * (1) valida e-mail/senha; (2) cria o perfil no profile_service com o MESMO UUID da conta (ele valida username,
     * nome, telefone, sexo e idade); (3) grava a conta + o evento {@code account.registered.v1} na mesma transação;
     * se o passo 3 falhar, o perfil é removido (compensação). O evento confirma o perfil (PENDING → ACTIVE).
     */
    public Account register(RegisterCommand command, ClientInfo client) {
        String email = normalizeEmail(command.email());
        validateRegistration(email, command);

        if (accounts.existsByEmail(email)) {
            throw ApiException.conflict("email_taken", "Já existe um usuário com esse email");
        }

        UUID accountId = Uuids.v7(clock);
        ProfileCreated profile = createProfile(accountId, command);

        Account created;
        try {
            created = tx.execute(status -> {
                Instant now = clock.instant();
                Account account = new Account(accountId, email, passwords.hash(command.password()), now);
                Account saved = accounts.saveAndFlush(account);
                outbox.add(EVENT_REGISTERED, accountId, 1, Map.of(
                        "accountId", accountId.toString()));
                return saved;
            });
        } catch (RuntimeException e) {
            compensateProfile(accountId);
            if (e instanceof org.springframework.dao.DataIntegrityViolationException) {
                throw ApiException.conflict("email_taken", "Já existe um usuário com esse email");
            }
            throw e;
        }

        audit.record(created.getId(), "REGISTER", client, null);
        sendVerificationEmail(created);
        return created;
    }

    private ProfileCreated createProfile(UUID accountId, RegisterCommand c) {
        try {
            return profiles.create(accountId, new NewProfile(c.username(), c.nome(), c.telefone(), c.sexo(),
                    c.dataNascimento()));
        } catch (ApiException e) {
            if (e.status() == org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE) {
                // Resultado desconhecido (timeout depois de criar?): desfaz por garantia; é idempotente.
                compensateProfile(accountId);
            }
            throw e;
        }
    }

    /** Só e-mail e senha são regras da conta; o resto do cadastro é validado pelo profile_service. */
    private void validateRegistration(String email, RegisterCommand c) {
        if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") || email.length() > 254) {
            throw ApiException.badRequest("invalid_email", "Email inválido");
        }
        passwordPolicy.validate(c.password(), email);
    }

    private void compensateProfile(UUID accountId) {
        try {
            profiles.discard(accountId);
            log.warn("Cadastro desfeito: perfil {} removido por compensação", accountId);
        } catch (RuntimeException e) {
            log.error("Falha ao compensar o perfil {} após erro no cadastro; remover manualmente (perfil PENDING)",
                    accountId, e);
        }
    }

    // --------------------------------------------------------------------- login

    public Account authenticate(String rawEmail, String password, ClientInfo client) {
        String email = normalizeEmail(rawEmail);
        String accountIpKey = "login:" + email + "|" + client.ip();
        String ipKey = "login-ip:" + client.ip();
        rateLimiter.assertBelow(accountIpKey, properties.rateLimit().maxFailuresPerAccountIp());
        rateLimiter.assertBelow(ipKey, properties.rateLimit().maxFailuresPerIp());

        Account account = accounts.findByEmail(email).orElse(null);
        boolean ok;
        if (account == null || !account.isActive()) {
            passwords.spendTime(password == null ? "" : password);
            ok = false;
        } else {
            ok = passwords.matches(password == null ? "" : password, account.getPasswordHash());
        }

        if (!ok) {
            rateLimiter.hit(accountIpKey);
            rateLimiter.hit(ipKey);
            audit.record(account == null ? null : account.getId(), "LOGIN_FAILURE", client, null);
            throw ApiException.unauthorized(GENERIC_LOGIN_ERROR);
        }

        rateLimiter.clear(accountIpKey);
        return tx.execute(status -> {
            Account managed = accounts.findById(account.getId()).orElseThrow();
            if (passwords.needsUpgrade(managed.getPasswordHash())) {
                managed.setPasswordHash(passwords.hash(password));
            }
            Instant now = clock.instant();
            managed.setLastLoginAt(now);
            managed.setUpdatedAt(now);
            return accounts.save(managed);
        });
    }

    // -------------------------------------------------------------------- senha

    /** Troca a senha, derruba as demais sessões e devolve a conta (o chamador abre uma sessão nova). */
    public Account changePassword(UUID accountId, String currentPassword, String newPassword, ClientInfo client) {
        Account account = requireActive(accountId);
        String key = "change-password:" + accountId;
        rateLimiter.assertBelow(key, properties.rateLimit().maxFailuresPerAccountIp());
        if (!passwords.matches(currentPassword == null ? "" : currentPassword, account.getPasswordHash())) {
            rateLimiter.hit(key);
            throw ApiException.badRequest("wrong_password", "Senha atual incorreta");
        }
        rateLimiter.clear(key);
        passwordPolicy.validate(newPassword, account.getEmail());

        tx.executeWithoutResult(status -> {
            Account managed = accounts.findById(accountId).orElseThrow();
            managed.setPasswordHash(passwords.hash(newPassword));
            tokens.revokeAll(managed, "PASSWORD_CHANGED");
        });
        audit.record(accountId, "PASSWORD_CHANGE", client, null);
        return accounts.findById(accountId).orElseThrow();
    }

    /** Sempre responde igual, exista ou não a conta (evita enumeração de e-mails). */
    public void forgotPassword(String rawEmail, ClientInfo client) {
        rateLimiter.assertBelow("forgot:" + client.ip(), properties.rateLimit().maxFailuresPerAccountIp() * 2);
        rateLimiter.hit("forgot:" + client.ip());

        Account account = accounts.findByEmail(normalizeEmail(rawEmail)).orElse(null);
        if (account == null || !account.isActive()) {
            return;
        }
        String token = createEmailToken(account, EmailToken.Purpose.RESET_PASSWORD, EMAIL_TOKEN_TTL_RESET);
        String link = properties.publicBaseUrl() + "/reset-password?token=" + token;
        mail.send(account.getEmail(), "Redefinição de senha - Social Flux",
                "Recebemos um pedido para redefinir a sua senha.\n\n"
                        + "Use o link abaixo (válido por 1 hora):\n" + link + "\n\n"
                        + "Se você não fez esse pedido, ignore este e-mail.");
        audit.record(account.getId(), "PASSWORD_RESET_REQUESTED", client, null);
    }

    public void resetPassword(String token, String newPassword, ClientInfo client) {
        // A senha é validada ANTES de consumir o token: uma senha fraca não pode queimar o link de uso único.
        EmailToken pending = validEmailToken(token, EmailToken.Purpose.RESET_PASSWORD);
        Account account = requireActive(pending.getAccountId());
        passwordPolicy.validate(newPassword, account.getEmail());
        consumeEmailToken(token, EmailToken.Purpose.RESET_PASSWORD);

        tx.executeWithoutResult(status -> {
            Account managed = accounts.findById(account.getId()).orElseThrow();
            managed.setPasswordHash(passwords.hash(newPassword));
            managed.setEmailVerified(true); // quem recebeu o e-mail comprovou a posse
            tokens.revokeAll(managed, "PASSWORD_RESET");
        });
        audit.record(account.getId(), "PASSWORD_RESET", client, null);
    }

    // ------------------------------------------------------------------- e-mail

    public void verifyEmail(String token, ClientInfo client) {
        EmailToken emailToken = consumeEmailToken(token, EmailToken.Purpose.VERIFY_EMAIL);
        Account account = requireActive(emailToken.getAccountId());
        tx.executeWithoutResult(status -> {
            Account managed = accounts.findById(account.getId()).orElseThrow();
            managed.setEmailVerified(true);
            managed.setUpdatedAt(clock.instant());
            accounts.save(managed);
        });
        audit.record(account.getId(), "EMAIL_VERIFIED", client, null);
    }

    public void resendVerification(UUID accountId) {
        Account account = requireActive(accountId);
        if (account.isEmailVerified()) {
            return;
        }
        rateLimiter.assertBelow("resend:" + accountId, 3);
        rateLimiter.hit("resend:" + accountId);
        sendVerificationEmail(account);
    }

    private void sendVerificationEmail(Account account) {
        try {
            String token = createEmailToken(account, EmailToken.Purpose.VERIFY_EMAIL, EMAIL_TOKEN_TTL_VERIFY);
            String link = properties.publicBaseUrl() + "/verify-email?token=" + token;
            mail.send(account.getEmail(), "Confirme seu e-mail - Social Flux",
                    "Bem-vindo(a) ao Social Flux!\n\nConfirme o seu e-mail pelo link abaixo (válido por 48 horas):\n"
                            + link);
        } catch (RuntimeException e) {
            // O envio é "melhor esforço": falha de SMTP não deve impedir cadastro/login.
            log.warn("Não foi possível enviar o e-mail de verificação da conta {}: {}", account.getId(), e.toString());
        }
    }

    private String createEmailToken(Account account, EmailToken.Purpose purpose, Duration ttl) {
        return tx.execute(status -> {
            Instant now = clock.instant();
            emailTokens.invalidatePending(account.getId(), purpose, now);
            String token = Tokens.random();
            emailTokens.save(new EmailToken(Uuids.v7(clock), account.getId(), purpose, Tokens.sha256(token), now.plus(ttl)));
            return token;
        });
    }

    /** Localiza um token de e-mail válido (existente, do tipo certo, não usado e não expirado) sem consumi-lo. */
    private EmailToken validEmailToken(String token, EmailToken.Purpose purpose) {
        if (token == null || token.isBlank()) {
            throw ApiException.badRequest("invalid_token", "Link inválido ou expirado");
        }
        EmailToken emailToken = emailTokens.findByTokenHash(Tokens.sha256(token)).orElse(null);
        if (emailToken == null || emailToken.getPurpose() != purpose
                || emailToken.getUsedAt() != null || clock.instant().isAfter(emailToken.getExpiresAt())) {
            throw ApiException.badRequest("invalid_token", "Link inválido ou expirado");
        }
        return emailToken;
    }

    /** Marca o token como usado (uso único) na mesma transação em que o revalida. */
    private EmailToken consumeEmailToken(String token, EmailToken.Purpose purpose) {
        return tx.execute(status -> {
            EmailToken emailToken = validEmailToken(token, purpose);
            emailToken.setUsedAt(clock.instant());
            return emailToken;
        });
    }

    // ------------------------------------------------------------------ exclusão

    /** Exclui a conta (soft-delete imediato) e publica {@code account.deleted.v1}; o profile_service apaga o perfil. */
    public void deleteAccount(UUID accountId, String password, ClientInfo client) {
        Account account = requireActive(accountId);
        String key = "delete-account:" + accountId;
        rateLimiter.assertBelow(key, properties.rateLimit().maxFailuresPerAccountIp());
        if (!passwords.matches(password == null ? "" : password, account.getPasswordHash())) {
            rateLimiter.hit(key);
            throw ApiException.badRequest("wrong_password", "Senha incorreta");
        }
        rateLimiter.clear(key);

        tx.executeWithoutResult(status -> {
            Account managed = accounts.findById(accountId).orElseThrow();
            tokens.revokeAll(managed, "ACCOUNT_DELETED");
            managed.setStatus(AccountStatus.DELETED);
            managed.setEmail("deleted-" + managed.getId() + "@deleted.invalid");
            managed.setPasswordHash("{noop}!");
            managed.setEmailVerified(false);
            accounts.save(managed);
            refreshTokens.revokeAllOfAccount(accountId, clock.instant(), "ACCOUNT_DELETED");
            outbox.add(EVENT_DELETED, accountId, managed.getTokenVersion(), Map.of("accountId", accountId.toString()));
        });
        revocations.revokeBelow(accountId, Integer.MAX_VALUE);
        audit.record(accountId, "ACCOUNT_DELETED", client, null);
    }

    // ------------------------------------------------------------------- helpers

    public Account requireActive(UUID accountId) {
        Account account = accounts.findById(accountId).orElseThrow(() -> ApiException.unauthorized("Sessão inválida"));
        if (!account.isActive()) {
            throw ApiException.unauthorized("Sessão inválida");
        }
        return account;
    }

    static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }
}
