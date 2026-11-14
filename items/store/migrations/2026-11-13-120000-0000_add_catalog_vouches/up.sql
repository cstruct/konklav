-- Vouches: a catalog action or group (`action`) vouches for another
-- (`vouched`). An allowed route decision that required `action` lets the
-- request's later decisions treat `vouched` as satisfied. Both sides are
-- catalog names, so neither can be removed while a vouch names it; a
-- vouch goes with its vouching action.
create table catalog_vouch (
    action text not null references catalog_action (name) on delete cascade,
    vouched text not null references catalog_action (name),
    primary key (action, vouched),
    constraint catalog_vouch_not_self check (action <> vouched),
    constraint catalog_vouch_reserved check (vouched not like 'konklav:%' and action not like 'konklav:%')
);

create index catalog_vouch_vouched_idx on catalog_vouch (vouched);

-- Entitlement sets carry vouches, so changing one invalidates every set,
-- as any other catalog change does.
create trigger catalog_vouch_changed after insert or update or delete on catalog_vouch
for each statement execute function definitions_changed();

-- Compilation and decision explanations read vouches, so history versions
-- them like the rest of the catalog.
insert into history_table (relation, key_columns) values ('catalog_vouch', '{action,vouched}');
create trigger history_record after insert or update or delete on catalog_vouch
for each row execute function history_record('action', 'vouched');
