package com.socialflux.auth.service;

import com.socialflux.auth.web.ApiException;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Set;

/** Política de senha validada no servidor (o frontend só duplica por conveniência). */
@Component
public class PasswordPolicy {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;
    private static final Set<String> COMMON = Set.of(
            "12345678", "123456789", "1234567890", "password", "password1", "senha123", "senha1234",
            "qwertyui", "qwerty123", "abcd1234", "11111111", "00000000", "iloveyou", "admin123", "mudar123");

    public void validate(String password, String email) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw ApiException.badRequest("weak_password", "A senha deve conter no mínimo " + MIN_LENGTH + " caracteres");
        }
        if (password.length() > MAX_LENGTH) {
            throw ApiException.badRequest("weak_password", "A senha deve conter no máximo " + MAX_LENGTH + " caracteres");
        }
        String lower = password.toLowerCase(Locale.ROOT);
        if (COMMON.contains(lower)) {
            throw ApiException.badRequest("weak_password", "Senha muito comum, escolha outra");
        }
        if (email != null) {
            String normalized = email.toLowerCase(Locale.ROOT);
            String local = normalized.contains("@") ? normalized.substring(0, normalized.indexOf('@')) : normalized;
            if (lower.equals(normalized) || lower.equals(local)) {
                throw ApiException.badRequest("weak_password", "A senha não pode ser igual ao e-mail");
            }
        }
    }
}
