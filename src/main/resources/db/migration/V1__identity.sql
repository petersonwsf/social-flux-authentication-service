-- Esquema do serviço de identidade (PostgreSQL). Mantido portável para testes.
-- E-mails são gravados em minúsculas pela aplicação (índice único simples).

create table account (
    id                       uuid         primary key,           -- UUIDv7 gerado pela aplicação; é o `sub` do JWT
    email                    varchar(254) not null unique,
    password_hash            varchar(255) not null,              -- {argon2}... | {bcrypt}...
    email_verified           boolean      not null default false,
    status                   varchar(20)  not null default 'ACTIVE'
                             check (status in ('ACTIVE', 'DISABLED', 'DELETED')),
    token_version            integer      not null default 1,
    token_version_changed_at timestamp with time zone,
    last_login_at            timestamp with time zone,
    legacy_user_id           integer      unique,                -- TEMPORÁRIO: usuario.id no MySQL legado
    created_at               timestamp with time zone not null,
    updated_at               timestamp with time zone not null
);

create table account_role (
    account_id uuid        not null references account (id) on delete cascade,
    role       varchar(30) not null,
    primary key (account_id, role)
);

create table refresh_token (
    id                 uuid primary key,
    family_id          uuid         not null,                    -- = `sid` do JWT de acesso
    account_id         uuid         not null references account (id) on delete cascade,
    token_hash         bytea        not null unique,             -- SHA-256 do token opaco
    issued_at          timestamp with time zone not null,
    expires_at         timestamp with time zone not null,
    family_expires_at  timestamp with time zone not null,        -- limite absoluto da sessão
    rotated_at         timestamp with time zone,
    replaced_by        uuid,
    revoked_at         timestamp with time zone,
    revoke_reason      varchar(40),
    ip                 varchar(64),
    user_agent         varchar(300)
);
create index idx_refresh_token_account on refresh_token (account_id);
create index idx_refresh_token_family on refresh_token (family_id);

create table email_token (
    id          uuid        primary key,
    account_id  uuid        not null references account (id) on delete cascade,
    purpose     varchar(20) not null check (purpose in ('VERIFY_EMAIL', 'RESET_PASSWORD')),
    token_hash  bytea       not null unique,
    expires_at  timestamp with time zone not null,
    used_at     timestamp with time zone
);
create index idx_email_token_account on email_token (account_id);

create table audit_event (
    id          bigint generated always as identity primary key,
    account_id  uuid,
    action      varchar(40) not null,
    ip          varchar(64),
    user_agent  varchar(300),
    detail      varchar(500),
    created_at  timestamp with time zone not null
);
create index idx_audit_event_account on audit_event (account_id, created_at);
