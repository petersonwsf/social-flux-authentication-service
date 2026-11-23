package com.socialflux.auth.service;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Hash de senha: Argon2id como padrão; hashes BCrypt importados do sistema legado ({@code {bcrypt}$2a$...})
 * continuam válidos e são regravados em Argon2id no próximo login bem-sucedido.
 */
@Component
public class PasswordService {

    private final PasswordEncoder encoder;
    private final String dummyHash;

    public PasswordService() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        this.encoder = new DelegatingPasswordEncoder("argon2", encoders);
        // Usado para gastar o mesmo tempo quando o e-mail não existe (evita enumeração por tempo de resposta).
        this.dummyHash = encoder.encode("dummy-password-for-timing");
    }

    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String encodedPassword) {
        try {
            return encoder.matches(rawPassword, encodedPassword);
        } catch (IllegalArgumentException e) {
            return false; // hash em formato desconhecido
        }
    }

    public boolean needsUpgrade(String encodedPassword) {
        return encoder.upgradeEncoding(encodedPassword);
    }

    public void spendTime(String rawPassword) {
        encoder.matches(rawPassword, dummyHash);
    }
}
