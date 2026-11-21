package com.socialflux.auth.profile;

/** Resultado da criação do perfil: {@code created} é falso quando o perfil já existia (a chamada é idempotente). */
public record ProfileCreated(boolean created) {
}
