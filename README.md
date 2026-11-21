# authentication_service

Serviço de **identidade e acesso** do Social Flux: cadastro, login, sessão, recuperação de senha e verificação de e-mail.
Spring Boot · Spring Security · PostgreSQL · Flyway · JWT **RS256** em **cookies HttpOnly** · outbox + RabbitMQ.

Plano completo: [`../docs/plano-dominio-identidade-servico-proprio.md`](../docs/plano-dominio-identidade-servico-proprio.md).

## Como funciona

| Item | Decisão |
| --- | --- |
| Token de acesso | JWT **RS256**, **2 h** (`JWT_ACCESS_TTL`), `sub` = **UUIDv7 da conta**, claims mínimas (`sid`, `roles`, `ver`, `jti`, `aud`, `iss`) |
| Refresh token | Opaco, **rotativo** (cada uso gera outro; reuso fora da tolerância revoga a sessão inteira); só o hash SHA-256 fica no banco |
| Sessão deslizante | O usuário continua logado se agir de `exp − 10 min` até `exp + 5 min` (`JWT_RENEW_WINDOW`/`JWT_REFRESH_GRACE`); limite absoluto de 7 dias (`SESSION_ABSOLUTE_MAX`) |
| Cookies | `HttpOnly`; acesso: `Path=/`, `SameSite=Lax`; refresh: `Path=/auth`, `SameSite=Strict`. Em produção: `__Host-at` / `__Secure-rt` + `Secure` |
| Revogação | `token_version` por conta (logout geral, troca/reset de senha, exclusão) verificada no gateway; memória só pelo tempo de vida do token |
| Senhas | Argon2id; hashes BCrypt importados (`{bcrypt}…`) continuam válidos e sobem para Argon2id no próximo login |
| Limite de tentativas | 5 falhas/15 min por **e-mail+IP** (não bloqueia a conta da vítima) e 50 por IP; mensagem de erro uniforme |
| CSRF | `SameSite` + checagem de `Origin`/`Sec-Fetch-Site` em métodos não seguros |
| Chaves | Variáveis de ambiente; JWKS em `/.well-known/jwks.json` (chave atual + anteriores, para rotação) |

## API

| Rota | Método | Descrição |
| --- | --- | --- |
| `/auth/register` | POST | Cadastro (mesmos campos do formulário atual): valida e-mail/senha, **cria o perfil no `profile_service`** com o mesmo UUID e publica `account.registered.v1`; define cookies |
| `/auth/login` | POST | Login → `{ account: {accountId, email, emailVerified}, expiresAt, renewAt }` + cookies |
| `/auth/refresh` | POST | Renova a sessão (cookie `rt`) → `{ expiresAt, renewAt }` |
| `/auth/logout` · `/auth/logout-all` | POST | Encerra esta sessão / todas |
| `/auth/me` | GET | **Só identidade** da conta (mesmo formato do login). O perfil vem de `GET /api/usuarios/me` (profile_service) |
| `/auth/verify-email` · `/auth/resend-verification` | POST | Confirmação de e-mail |
| `/auth/forgot-password` · `/auth/reset-password` | POST | Recuperação de senha (resposta sempre genérica) |
| `/auth/change-password` | POST | Troca a senha, encerra as outras sessões e mantém esta |
| `/auth/account` | DELETE | Exclui a conta (exige a senha) e publica `account.deleted.v1` (o profile_service apaga o perfil) |
| `/.well-known/jwks.json` | GET | Chaves públicas |
| `/internal/auth/verify` | GET | **forward_auth do gateway**: `204` + `X-Account-Id` ou `401`. Bloqueado ao público |

Erros: `{ "mensagem": "...", "sucesso": false, "codigo": "..." }`.

## Rodando

### Com Docker (ambiente completo, na raiz do repositório)
```bash
cp .env.example .env              # ajuste as senhas
docker compose up -d --build      # http://localhost:8080 (caixa de e-mail: http://localhost:8025)
```

### Sem Docker (testes e depuração)
Os testes de integração usam um **PostgreSQL real embutido** (zonky), sem precisar de Docker:
```bash
mvn test        # na pasta do serviço, depois de instalar a biblioteca: mvn -f ../libs/socialflux-events/pom.xml install
# ou, na raiz: mvn -pl authentication_service -am test
```
E há um servidor de desenvolvimento com Postgres embutido, chave efêmera, perfil em memória e e-mails no log:
```bash
mvn -q test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
java -cp "target/test-classes;target/classes;$(cat target/cp.txt)" com.socialflux.auth.DevServer   # (use ':' no Linux/macOS)
```

## Configuração (variáveis de ambiente)

Veja `src/main/resources/application.yml` e o `.env.example` da raiz. Principais:

| Variável | Descrição |
| --- | --- |
| `JWT_PRIVATE_KEY_B64` | PEM PKCS#8 da chave RSA (≥ 2048 bits) em base64 de uma linha. **Obrigatória** (a app não sobe sem ela) |
| `JWT_KEY_ID` | `kid` atual (padrão: thumbprint da chave) |
| `JWT_PUBLIC_KEYS_B64` | Chaves públicas **anteriores** (base64 de PEM), separadas por vírgula, durante a rotação |
| `AUTH_ALLOW_EPHEMERAL_KEY` | `true` só em desenvolvimento: gera chave em memória se a privada estiver vazia |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `iss` e `aud` dos tokens |
| `AUTH_COOKIE_SECURE` / `AUTH_COOKIE_ACCESS_NAME` / `AUTH_COOKIE_REFRESH_NAME` | Produção: `true`, `__Host-at`, `__Secure-rt` |
| `IDENTITY_DB_URL/USER/PASSWORD` | PostgreSQL |
| `AUTH_MAIL_ENABLED`, `SMTP_*`, `MAIL_FROM` | E-mail |
| `PROFILE_SERVICE_URL`, `PROFILE_SERVICE_AUDIENCE` | profile_service (cadastro) e a audiência do token de serviço |
| `RABBITMQ_HOST/PORT/USER/PASSWORD`, `EVENTS_EXCHANGE`, `AUTH_EVENTS_ENABLED`, `AUTH_EVENTS_MANDATORY` | Eventos de conta (outbox → RabbitMQ) |
| `AUTH_ALLOWED_ORIGINS` | Origens permitidas em métodos não seguros (vazio = a própria origem) |

### Gerar a chave
```bash
./scripts/generate-jwt-key.sh >> ../.env
```

### Rotação de chave (sem derrubar sessões)
1. Gere a nova chave e coloque a **pública** dela no `JWT_PUBLIC_KEYS_B64` de todos os ambientes (continua assinando com a antiga);
   espere o cache do JWKS (~10 min).
2. Troque `JWT_PRIVATE_KEY_B64`/`JWT_KEY_ID` para a nova e mova a pública da antiga para `JWT_PUBLIC_KEYS_B64`.
3. Depois de `2 h + tolerância + skew` (≈ 2h10), remova a pública antiga.

### Cuidados com segredos em variáveis de ambiente
Ficam visíveis em `docker inspect`/`/proc` e exigem reinício para trocar. Mantenha o `.env` fora do Git (já no `.gitignore`),
com permissão restrita; não exponha `env`/`configprops` no Actuator (já só `health`); nunca logue propriedades.

## Cadastro, perfil e eventos (D1: o auth orquestra)

1. `POST /auth/register` valida e-mail e senha e gera o UUID da conta.
2. Chama `PUT /internal/profiles/{uuid}` no `profile_service` com um **token de serviço** (JWT RS256 de 5 min, `sub=svc:authentication-service`,
   `aud=profile-service`, `scope=profiles:write profiles:read`, assinado com a mesma chave do JWKS). O profile valida username, nome,
   telefone, sexo e idade (o UUID da conta é o id do perfil).
   Erros 4xx do perfil chegam ao frontend com o mesmo `codigo`/`mensagem` (`username_taken`, `underage`...); indisponibilidade vira `503 profile_unavailable`.
3. Grava a conta e o evento `account.registered.v1` na **mesma transação** (outbox). Se isso falhar, o perfil é removido (compensação;
   também quando a resposta do perfil se perde por timeout). O evento confirma o perfil (`PENDING → ACTIVE`).
4. `DELETE /auth/account` grava `account.deleted.v1`; o profile_service apaga os dados pessoais.

Eventos nunca carregam e-mail, senha ou dados de perfil. Com `AUTH_EVENTS_MANDATORY=true` (padrão), um evento sem nenhuma fila
ligada fica **pendente** no outbox em vez de ser descartado (o profile_service é consumidor obrigatório); o cadastro não depende do broker.

## Estrutura

```
src/main/java/com/socialflux/auth/
  config/     propriedades (env), chaves RSA, JwtEncoder/Decoder
  domain/     entidades JPA e repositórios (account, refresh_token, email_token, audit_event)
  service/    AccountService, TokenService, RevocationRegistry, RateLimiter, PasswordService...
  security/   filtros (JWT em Bearer/cookie, Origin), SecurityConfig
  web/        controllers, DTOs, tratamento de erros
  profile/    cliente HTTP do profile_service + emissor de token de serviço
  events/     outbox transacional, relay e publicação no RabbitMQ
  mail/       envio de e-mails
src/main/resources/db/migration/   Flyway
```

## O que ainda não está nesta versão
Verificação de senha vazada (HaveIBeenPwned), MFA/TOTP, limitador de tentativas em Redis (hoje em memória, 1 instância),
e consumidores de eventos (o auth só publica). Não há importação de usuários: ainda não existem dados reais.
