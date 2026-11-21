package com.socialflux.auth.profile;

import java.util.UUID;

/**
 * Porta para o {@code profile_service} (D1: o auth orquestra o cadastro). A conta tem o mesmo UUID do perfil.
 * Implementação real: {@link ProfileClient} (HTTP + token de serviço). Falhas de negócio do perfil (username em uso,
 * menor de idade...) chegam como {@code ApiException} com o mesmo código/mensagem que o frontend já trata.
 */
public interface ProfilePort {

    /** Cria o perfil (idempotente). Devolve o id inteiro legado, usado na ponte com o backend Javalin. */
    ProfileCreated create(UUID accountId, NewProfile profile);

    /** Compensação do cadastro: remove um perfil que ainda não foi confirmado. Idempotente. */
    void discard(UUID accountId);
}
