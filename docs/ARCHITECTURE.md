# Arquitetura — authentication_service

Serviço de **identidade e acesso**: cadastro, login, sessão deslizante (JWT RS256 + refresh token rotativo em cookies
HttpOnly), logout, troca/recuperação de senha, verificação de e-mail, exclusão de conta, JWKS e o `forward_auth` do gateway.
Spring Boot 4 · Java 21 · Spring Security · JPA + Flyway · PostgreSQL (banco `identity`) · RabbitMQ (outbox) · porta **8081**.

Rotas, variáveis de ambiente e fluxo de cadastro: [`../README.md`](../README.md). Visão do monorepo: [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md).

## Camadas

```
web (controllers, DTOs, erros, cookies)
  └─► service (regras: contas, tokens, senhas, revogação, limites)
        ├─► domain (entidades JPA + repositórios) ─► PostgreSQL
        ├─► Outbox (libs/socialflux-events) ─► OutboxRelay ─► RabbitMQ
        ├─► profile (cliente HTTP do profile_service + token de serviço)
        └─► mail (e-mails transacionais)
security (filtros JWT/Origin + SecurityConfig) envolve tudo; config carrega propriedades e chaves.
```

## Árvore de diretórios

```
authentication_service/
├── Dockerfile                    build Maven multi-stage (contexto = raiz do repo, para incluir libs/socialflux-events); runtime Temurin 21 JRE Alpine, usuário sem root
├── .gitignore                    exclui target/, IDE, *.pem e .env (o .dockerignore é o da raiz)
├── pom.xml                       dependências (Spring Boot 4.1, Security, OAuth2 JOSE, JPA, Flyway, AMQP, Mail, BouncyCastle; testes: embedded-postgres, H2)
├── README.md                     decisões, API, configuração, rotação de chaves, cadastro e eventos
├── docs/ARCHITECTURE.md          este arquivo
├── scripts/
│   └── generate-jwt-key.sh       gera a chave RSA 3072 (PKCS#8) e imprime JWT_PRIVATE_KEY_B64 / JWT_KEY_ID
└── src/
    ├── main/java/com/socialflux/auth/
    │   ├── config/               propriedades tipadas, chaves RSA, JwtEncoder/Decoder
    │   ├── domain/               entidades JPA e repositórios
    │   ├── events/               outbox transacional e publicação no RabbitMQ
    │   ├── mail/                 envio de e-mails
    │   ├── profile/              integração com o profile_service (cadastro)
    │   ├── security/             filtros de autenticação/CSRF e cadeia do Spring Security
    │   ├── service/              regras de negócio
    │   ├── util/                 geradores de tokens opacos e UUIDv7
    │   └── web/                  controllers, DTOs e tratamento de erros
    ├── main/resources/
    │   ├── application.yml       configuração (tudo vem de variáveis de ambiente, com padrões de desenvolvimento)
    │   └── db/migration/         migrations Flyway
    └── test/java/com/socialflux/auth/   testes de integração/unidade e servidor de desenvolvimento
```

## Arquivos

### Raiz do pacote

| Arquivo | O que representa |
| --- | --- |
| `AuthenticationServiceApplication.java` | Classe `main`; habilita `@ConfigurationPropertiesScan` e `@EnableScheduling` (relay do outbox e limpezas) |

### `config/`

| Arquivo | O que representa |
| --- | --- |
| `AuthProperties.java` | Record `@ConfigurationProperties(prefix = "auth")` validado: JWT (issuer, audience, TTLs, janela de renovação, chaves), cookies, origens permitidas, URL pública, limites de tentativa, e-mail, profile_service e eventos |
| `JwtConfig.java` | Beans `Clock` (UTC), `JwtEncoder` (Nimbus, chave atual) e `JwtDecoder` (RS256, valida issuer/audience/expiração com tolerância de relógio) |
| `JwtKeys.java` | Carrega a chave privada atual e as públicas anteriores de variáveis de ambiente, calcula o `kid` e monta o JWKS público; gera chave efêmera só com `allow-ephemeral-key` |

### `domain/`

| Arquivo | O que representa |
| --- | --- |
| `Account.java` | Entidade `account`: UUID, e-mail, hash da senha, e-mail verificado, status, `token_version` (revogação), datas |
| `AccountRepository.java` | Busca por e-mail, contas com versão de token alterada recentemente e expurgo de contas excluídas |
| `AccountStatus.java` | Enum `ACTIVE`, `DISABLED`, `DELETED` |
| `RefreshToken.java` | Entidade `refresh_token`: família (sessão), hash SHA-256, emissão/expiração, rotação e motivo de revogação |
| `RefreshTokenRepository.java` | Busca por hash, revogação da família/da conta inteira e expurgo de tokens vencidos |
| `EmailToken.java` | Entidade `email_token`: token de uso único (`VERIFY_EMAIL` ou `RESET_PASSWORD`), só o hash é guardado |
| `EmailTokenRepository.java` | Busca por hash, invalidação dos pendentes e expurgo dos vencidos |
| `AuditEvent.java` | Entidade `audit_event`: trilha de auditoria (ação, IP, user-agent, detalhe) |
| `AuditEventRepository.java` | Repositório JPA da auditoria |

### Eventos (sem pacote próprio)

Outbox, relay e publicador RabbitMQ vêm da biblioteca [`libs/socialflux-events`](../../libs/socialflux-events/README.md)
(`com.socialflux.events.*`), configurada em `socialflux.events.*` no `application.yml` com `mandatory=true` (evento sem fila
fica pendente). `AccountService` grava `account.registered.v1` e `account.deleted.v1` com `Outbox.add` na transação da conta.

### `mail/`

| Arquivo | O que representa |
| --- | --- |
| `MailService.java` | Interface de envio de e-mails transacionais |
| `MailConfig.java` | Cria o `MailService`: SMTP real quando habilitado, senão um que só registra no log |

### `profile/`

| Arquivo | O que representa |
| --- | --- |
| `ProfilePort.java` | Porta para o profile_service: criar perfil (idempotente) e descartar perfil pendente (compensação) |
| `ProfileClient.java` | Implementação HTTP (`PUT`/`DELETE /internal/profiles/{uuid}`) com timeouts curtos; repassa erros 4xx com o mesmo código e converte indisponibilidade em `503 profile_unavailable` |
| `ServiceTokenIssuer.java` | Emite o token de serviço (JWT RS256 de 5 min, `sub=svc:authentication-service`, `aud=profile-service`, `scope` explícito), com reutilização enquanto válido |
| `NewProfile.java` | Dados de perfil informados no cadastro (username, nome, telefone, sexo, nascimento) |
| `ProfileCreated.java` | Resposta da criação: se o perfil foi criado agora (a chamada é idempotente) |

### `security/`

| Arquivo | O que representa |
| --- | --- |
| `SecurityConfig.java` | Cadeia do Spring Security: rotas públicas (`/auth/register`, `/login`, `/refresh`, `/logout`, `/verify-email`, `/forgot-password`, `/reset-password`, JWKS), sessão stateless, entry point JSON 401, filtros abaixo |
| `BearerAuthenticationFilter.java` | Autentica pelo JWT em `Authorization: Bearer` ou no cookie de acesso; checa assinatura, validade e revogação |
| `OriginCheckFilter.java` | Defesa CSRF em métodos não seguros: rejeita `Sec-Fetch-Site: cross-site` e `Origin` fora da lista |
| `AccountAuthentication.java` | `Authentication` do Spring já validada, com papéis `ROLE_*` |
| `AuthenticatedAccount.java` | Identidade extraída do token: conta, sessão, papéis, versão do token, expiração |

### `service/`

| Arquivo | O que representa |
| --- | --- |
| `AccountService.java` | Regras de conta: cadastro (orquestra o profile_service + outbox + compensação), login, verificação de e-mail, esqueci/redefinir/trocar senha e exclusão |
| `TokenService.java` | Emissão de sessão (access + refresh), renovação deslizante, rotação com detecção de reuso, logout e logout geral |
| `RevocationRegistry.java` | Memória da versão mínima de token aceita por conta (pelo tempo de vida do token), reconstruída do banco ao subir |
| `PasswordService.java` | Hash Argon2id; aceita BCrypt legado (`{bcrypt}`) e indica quando regravar; hash fictício contra ataques de tempo |
| `PasswordPolicy.java` | Política de senha no servidor (8–128 caracteres, recusa senhas comuns e senha igual ao e-mail ou à parte local dele) |
| `RateLimiter.java` | Janela deslizante em memória: falhas por e-mail+IP e por IP (1 instância) |
| `AuditService.java` | Grava eventos de auditoria em transação própria |
| `MaintenanceJobs.java` | Limpeza agendada de tokens vencidos e de contas excluídas há mais de 1 dia |
| `RegisterCommand.java` | Dados de cadastro já extraídos da requisição |
| `IssuedSession.java` | Tokens emitidos e seus instantes (`expiresAt`, `renewAt`), só em memória |
| `ClientInfo.java` | IP e user-agent do cliente (IP real via `X-Forwarded-For` atrás do Caddy) |

### `util/`

| Arquivo | O que representa |
| --- | --- |
| `Tokens.java` | Tokens opacos de 256 bits (base64url) e hash SHA-256 |
| `Uuids.java` | Gerador de UUIDv7 (ordenável no tempo) |

### `web/`

| Arquivo | O que representa |
| --- | --- |
| `AuthController.java` | API pública `/auth/*`: register, login, refresh, logout, logout-all, me, verify-email, resend-verification, forgot-password, reset-password, change-password, `DELETE /account` |
| `InternalAuthController.java` | `GET /internal/auth/verify` — `forward_auth` do gateway: `204` + `X-Account-Id` ou `401` |
| `JwksController.java` | `GET /.well-known/jwks.json` — chaves públicas, com cache de 5 min |
| `SessionCookies.java` | Monta/limpa os cookies de acesso (`Path=/`, `SameSite=Lax`) e de refresh (`Path=/auth`, `SameSite=Strict`) |
| `Dtos.java` | Records de requisição/resposta com validação (campos em português/snake_case do contrato do frontend) |
| `ApiError.java` | Corpo de erro `{ mensagem, sucesso: false, codigo }` (e versão JSON manual para filtros) |
| `ApiException.java` | Erro de negócio com status HTTP e código estável (inclui `TooManyRequests` com `Retry-After`) |
| `GlobalExceptionHandler.java` | `@RestControllerAdvice` que converte exceções em `ApiError` sem vazar detalhes |

### `src/main/resources/`

| Arquivo | O que representa |
| --- | --- |
| `application.yml` | Datasource, JPA (`ddl-auto: validate`), Flyway, SMTP, RabbitMQ, Actuator (só `health`) e o bloco `auth.*` |
| `db/migration/V1__identity.sql` | Tabelas `account`, `account_role`, `refresh_token`, `email_token`, `audit_event` |
| `db/migration/V2__outbox.sql` | Tabela `outbox_event` |
| `db/migration/V3__remove_legacy_user_id.sql` | Remove `account.legacy_user_id`: o id inteiro temporário não existe mais, só o UUID (`sub`) |

### `src/test/java/com/socialflux/auth/`

| Arquivo | O que representa |
| --- | --- |
| `AuthFlowTest.java` | Integração ponta a ponta: cadastro, login, refresh/rotação, revogação, senhas, e-mail, exclusão e eventos |
| `PasswordUpgradeTest.java` | Hash BCrypt importado faz login e é regravado em Argon2id |
| `ServiceTokenTest.java` | Formato e restrições do token de serviço para o profile_service |
| `UnitTests.java` | Testes de unidade: UUIDv7 e carregamento/validação das chaves RSA (inclusive rotação) |
| `DevServer.java` | Sobe o serviço sem Docker: Postgres embutido, chave efêmera, perfil em memória, e-mails no log |
| `support/AbstractIntegrationTest.java` | Base: serviço em porta aleatória contra PostgreSQL real embutido (zonky) |
| `support/ApiClient.java` | Cliente HTTP dos testes com "jar" de cookies manual |
| `support/MutableClock.java` | Relógio controlável (avança no tempo sem esperar) |
| `support/TestSupportConfig.java` | Substitutos de teste: relógio, e-mail gravado, perfil e publicador em memória |

## `.github/workflows/`

| Arquivo | O que faz |
| --- | --- |
| `ci.yml` | CI em cada pull request: lint e, só se passar, testes |
| `cd.yml` | CD após o merge na `main`: repete os testes, publica a imagem no GHCR e atualiza o container na VPS por SSH (secrets listados no `docs/ARCHITECTURE.md` da raiz) |
