package com.socialflux.auth.profile;

import java.time.LocalDate;

/** Dados do perfil informados no cadastro. A validação é do profile_service (dono do domínio). */
public record NewProfile(String username, String nome, String telefone, String sexo, LocalDate dataNascimento) {
}
