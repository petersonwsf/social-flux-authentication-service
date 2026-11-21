package com.socialflux.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/** DTOs da API. Os nomes de campo em português/snake_case acompanham o contrato que o frontend já usa. */
public final class Dtos {

    private Dtos() {
    }

    public record RegisterRequest(
            @NotBlank(message = "Informe o email") @Size(max = 254) String email,
            @NotBlank(message = "Informe a senha") @Size(max = 128, message = "Senha muito longa") String senha,
            @NotBlank(message = "Informe o username") @Size(max = 60) String username,
            @NotBlank(message = "Informe o nome") @Size(max = 120) String nome,
            @NotBlank(message = "Informe o telefone") @Size(max = 40) String telefone,
            @NotBlank(message = "Selecione uma opção de sexo") String sexo,
            @NotNull(message = "Informe a data de nascimento") LocalDate data_nascimento) {
    }

    public record LoginRequest(
            @NotBlank(message = "Preencha o campo de email") @Size(max = 254) String email,
            @NotBlank(message = "Preencha o campo de senha") @Size(max = 128) String senha) {
    }

    public record EmailRequest(@NotBlank(message = "Informe o email") @Size(max = 254) String email) {
    }

    public record TokenRequest(@NotBlank(message = "Token ausente") @Size(max = 200) String token) {
    }

    public record ResetPasswordRequest(
            @NotBlank(message = "Token ausente") @Size(max = 200) String token,
            @NotBlank(message = "Informe a nova senha") @Size(max = 128) String novaSenha) {
    }

    public record ChangePasswordRequest(
            @NotBlank(message = "Informe a senha atual") @Size(max = 128) String senhaAtual,
            @NotBlank(message = "Informe a nova senha") @Size(max = 128) String novaSenha) {
    }

    public record PasswordRequest(@NotBlank(message = "Informe a senha") @Size(max = 128) String senha) {
    }

    /**
     * Identidade da conta (D4: o /auth/me devolve só identidade). O perfil (username, nome, foto...) é do
     * profile_service: o frontend o busca em {@code GET /api/usuarios/me}.
     */
    public record AccountView(String accountId, String email, boolean emailVerified) {
    }

    /**
     * Resposta de login/cadastro/me. {@code expiresAt} e {@code renewAt} (ISO-8601) permitem ao frontend renovar a sessão
     * mesmo sem ler o cookie HttpOnly: a partir de {@code renewAt}, a próxima ação do usuário dispara {@code /auth/refresh}.
     */
    public record AuthResponse(AccountView account, String expiresAt, String renewAt) {
    }

    public record RefreshResponse(String expiresAt, String renewAt) {
    }

    public record MessageResponse(String mensagem, boolean sucesso) {
        public static MessageResponse ok(String mensagem) {
            return new MessageResponse(mensagem, true);
        }
    }
}
