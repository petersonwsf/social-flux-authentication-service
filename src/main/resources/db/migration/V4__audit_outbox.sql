-- Auditoria central (libs/socialflux-audit): cada evento é gravado aqui, na transação da ação, e um relay o envia em lote ao
-- audit-service. A tabela audit_event deixa de receber gravações; ela é removida numa migração posterior, depois de conferido
-- que o histórico chegou ao audit-service.
create table audit_outbox (
    id         uuid primary key,                       -- eventId (chave de idempotência no audit-service)
    payload    text not null,                          -- JSON do evento
    created_at timestamp with time zone not null,
    sent_at    timestamp with time zone,
    attempts   integer not null default 0,
    last_error varchar(300),
    failed_at  timestamp with time zone                -- recusado ou esgotou as tentativas: não é mais reenviado
);
create index idx_audit_outbox_pending on audit_outbox (created_at, id) where sent_at is null and failed_at is null;
create index idx_audit_outbox_sent on audit_outbox (sent_at) where sent_at is not null;

-- Histórico: copia o audit_event para a outbox (serviço "auth"). O eventId é determinístico (md5 do id da linha), então
-- rodar a cópia de novo não duplica nada (on conflict) nem no audit-service. O audit-service só aceita eventos com até 180 dias
-- (AUDIT_MAX_PAST_AGE): os mais antigos voltam em "rejected" e ficam como falhos na outbox, sem reenvio.
insert into audit_outbox (id, payload, created_at)
select md5('social-flux:auth:audit_event:' || e.id)::uuid,
       jsonb_strip_nulls(jsonb_build_object(
               'eventId', md5('social-flux:auth:audit_event:' || e.id)::uuid,
               'occurredAt', to_char(e.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
               'service', 'auth',
               'action', e.action,
               'outcome', case e.action when 'LOGIN_FAILURE' then 'FAILURE' when 'REFRESH_REUSE' then 'DENIED'
                                        else 'SUCCESS' end,
               'actorId', e.account_id,
               'actorType', case when e.account_id is null then 'ANONYMOUS' else 'USER' end,
               'targetType', case when e.account_id is null then null else 'ACCOUNT' end,
               'targetId', e.account_id,
               'ip', e.ip,
               'userAgent', e.user_agent,
               'schemaVersion', 1,
               'detail', case when e.detail like 'family=%'
                                  then jsonb_build_object('familyId', substr(e.detail, 8)) end
       ))::text,
       e.created_at
from audit_event e
on conflict (id) do nothing;
