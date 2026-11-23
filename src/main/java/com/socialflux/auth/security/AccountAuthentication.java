package com.socialflux.auth.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.stream.Collectors;

/** Authentication já validada (o filtro verifica assinatura, validade e versão do token). */
public class AccountAuthentication extends AbstractAuthenticationToken {

    private final AuthenticatedAccount principal;

    public AccountAuthentication(AuthenticatedAccount principal) {
        super(principal.roles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList()));
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public AuthenticatedAccount getPrincipal() {
        return principal;
    }
}
