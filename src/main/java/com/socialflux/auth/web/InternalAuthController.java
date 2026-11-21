package com.socialflux.auth.web;

import com.socialflux.auth.security.AuthenticatedAccount;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint de {@code forward_auth} do gateway (Caddy). Valida o token (assinatura, validade, audiência e revogação)
 * e devolve a identidade no cabeçalho {@code X-Account-Id} (o UUID da conta, o {@code sub}).
 * Os serviços não dependem dele: validam o JWT sozinhos e identificam o usuário pelo {@code sub}.
 * NÃO deve ser acessível pela internet: o Caddy bloqueia {@code /internal/*}.
 */
@RestController
public class InternalAuthController {

    @GetMapping("/internal/auth/verify")
    ResponseEntity<Void> verify(@AuthenticationPrincipal AuthenticatedAccount principal) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.NO_CONTENT);
        response.header("X-Account-Id", principal.accountId().toString());
        return response.build();
    }
}
