package com.socialflux.auth.web;

import com.socialflux.auth.config.AuthProperties;
import com.socialflux.auth.domain.Account;
import com.socialflux.auth.security.AuthenticatedAccount;
import com.socialflux.auth.service.AccountService;
import com.socialflux.auth.service.ClientInfo;
import com.socialflux.auth.service.IssuedSession;
import com.socialflux.auth.service.RegisterCommand;
import com.socialflux.auth.service.TokenService;
import com.socialflux.auth.web.Dtos.AuthResponse;
import com.socialflux.auth.web.Dtos.ChangePasswordRequest;
import com.socialflux.auth.web.Dtos.EmailRequest;
import com.socialflux.auth.web.Dtos.LoginRequest;
import com.socialflux.auth.web.Dtos.MessageResponse;
import com.socialflux.auth.web.Dtos.PasswordRequest;
import com.socialflux.auth.web.Dtos.RefreshResponse;
import com.socialflux.auth.web.Dtos.RegisterRequest;
import com.socialflux.auth.web.Dtos.ResetPasswordRequest;
import com.socialflux.auth.web.Dtos.TokenRequest;
import com.socialflux.auth.web.Dtos.AccountView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AccountService accounts;
    private final TokenService tokens;
    private final SessionCookies cookies;
    private final AuthProperties properties;

    public AuthController(AccountService accounts, TokenService tokens, SessionCookies cookies,
                          AuthProperties properties) {
        this.accounts = accounts;
        this.tokens = tokens;
        this.cookies = cookies;
        this.properties = properties;
    }

    @PostMapping("/register")
    ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest body, HttpServletRequest request,
                                          HttpServletResponse response) {
        ClientInfo client = ClientInfo.from(request);
        Account account = accounts.register(new RegisterCommand(body.email(), body.senha(), body.username(),
                body.nome(), body.telefone(), body.sexo(), body.data_nascimento()), client);
        IssuedSession session = tokens.startSession(account, client);
        cookies.write(response, session);
        return ResponseEntity.status(HttpStatus.CREATED).body(authResponse(account, session));
    }

    @PostMapping("/login")
    AuthResponse login(@Valid @RequestBody LoginRequest body, HttpServletRequest request, HttpServletResponse response) {
        ClientInfo client = ClientInfo.from(request);
        Account account = accounts.authenticate(body.email(), body.senha(), client);
        IssuedSession session = tokens.startSession(account, client);
        cookies.write(response, session);
        return authResponse(account, session);
    }

    /** Renova a sessão (rotação do refresh token). Se falhar, os cookies são removidos. */
    @PostMapping("/refresh")
    RefreshResponse refresh(HttpServletRequest request, HttpServletResponse response) {
        try {
            TokenService.RefreshResult result = tokens.refresh(cookies.refreshToken(request), ClientInfo.from(request));
            cookies.write(response, result.session());
            return new RefreshResponse(result.session().accessExpiresAt().toString(),
                    result.session().renewAt().toString());
        } catch (ApiException e) {
            cookies.clear(response);
            throw e;
        }
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(@AuthenticationPrincipal AuthenticatedAccount principal, HttpServletRequest request,
                                HttpServletResponse response) {
        tokens.logout(cookies.refreshToken(request), principal == null ? null : principal.sessionId(),
                ClientInfo.from(request));
        cookies.clear(response);
        return ResponseEntity.noContent().build();
    }

    /** "Sair de todos os dispositivos". */
    @PostMapping("/logout-all")
    ResponseEntity<Void> logoutAll(@AuthenticationPrincipal AuthenticatedAccount principal, HttpServletRequest request,
                                   HttpServletResponse response) {
        Account account = accounts.requireActive(principal.accountId());
        tokens.revokeAll(account, "LOGOUT_ALL");
        cookies.clear(response);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    AuthResponse me(@AuthenticationPrincipal AuthenticatedAccount principal) {
        Account account = accounts.requireActive(principal.accountId());
        Instant expiresAt = principal.expiresAt();
        Instant renewAt = expiresAt.minus(properties.jwt().renewWindow());
        return new AuthResponse(accountView(account), expiresAt.toString(), renewAt.toString());
    }

    @PostMapping("/verify-email")
    MessageResponse verifyEmail(@Valid @RequestBody TokenRequest body, HttpServletRequest request) {
        accounts.verifyEmail(body.token(), ClientInfo.from(request));
        return MessageResponse.ok("E-mail confirmado com sucesso!");
    }

    @PostMapping("/resend-verification")
    MessageResponse resendVerification(@AuthenticationPrincipal AuthenticatedAccount principal) {
        accounts.resendVerification(principal.accountId());
        return MessageResponse.ok("Se o e-mail ainda não foi confirmado, enviamos um novo link.");
    }

    @PostMapping("/forgot-password")
    ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody EmailRequest body, HttpServletRequest request) {
        accounts.forgotPassword(body.email(), ClientInfo.from(request));
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(MessageResponse.ok("Se o e-mail estiver cadastrado, enviaremos as instruções para redefinir a senha."));
    }

    @PostMapping("/reset-password")
    MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest body, HttpServletRequest request) {
        accounts.resetPassword(body.token(), body.novaSenha(), ClientInfo.from(request));
        return MessageResponse.ok("Senha redefinida com sucesso! Entre com a nova senha.");
    }

    /** Troca a senha, encerra as demais sessões e mantém esta (abre uma sessão nova). */
    @PostMapping("/change-password")
    AuthResponse changePassword(@AuthenticationPrincipal AuthenticatedAccount principal,
                                @Valid @RequestBody ChangePasswordRequest body, HttpServletRequest request,
                                HttpServletResponse response) {
        ClientInfo client = ClientInfo.from(request);
        Account account = accounts.changePassword(principal.accountId(), body.senhaAtual(), body.novaSenha(), client);
        IssuedSession session = tokens.startSession(account, client);
        cookies.write(response, session);
        return authResponse(account, session);
    }

    @DeleteMapping("/account")
    MessageResponse deleteAccount(@AuthenticationPrincipal AuthenticatedAccount principal,
                                  @Valid @RequestBody PasswordRequest body, HttpServletRequest request,
                                  HttpServletResponse response) {
        accounts.deleteAccount(principal.accountId(), body.senha(), ClientInfo.from(request));
        cookies.clear(response);
        return MessageResponse.ok("Conta removida com sucesso!");
    }

    // ------------------------------------------------------------------ helpers

    private AuthResponse authResponse(Account account, IssuedSession session) {
        return new AuthResponse(accountView(account), session.accessExpiresAt().toString(),
                session.renewAt().toString());
    }

    private AccountView accountView(Account account) {
        return new AccountView(account.getId().toString(), account.getEmail(), account.isEmailVerified());
    }
}
