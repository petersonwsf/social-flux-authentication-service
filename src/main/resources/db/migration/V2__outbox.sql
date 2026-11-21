-- Transactional outbox: o evento é gravado na mesma transação da mudança da conta e publicado depois no RabbitMQ.
create table outbox_event (
    seq                bigint generated always as identity primary key,   -- ordem de publicação (não depende de relógio)
    id                 uuid        not null unique,
    type               varchar(80) not null,
    aggregate_id       uuid        not null,
    aggregate_version  bigint      not null,
    payload            text        not null,
    created_at         timestamp with time zone not null,
    published_at       timestamp with time zone
);
create index idx_outbox_unpublished on outbox_event (seq) where published_at is null;
