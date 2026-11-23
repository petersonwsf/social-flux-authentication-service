-- O id inteiro temporário (ponte com o backend legado em MySQL) não tem mais uso: o legado foi desligado e todos os
-- serviços identificam o usuário só pelo UUID da conta (o `sub` do token). O token deixa de levar a claim legacy_uid.
alter table account drop column legacy_user_id;
