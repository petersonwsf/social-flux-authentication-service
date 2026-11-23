package com.socialflux.auth.service;

import java.time.LocalDate;

/** Dados de cadastro já extraídos da requisição. */
public record RegisterCommand(
        String email,
        String password,
        String username,
        String nome,
        String telefone,
        String sexo,
        LocalDate dataNascimento) {
}
