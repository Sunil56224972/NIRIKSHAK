-- Nirikshak : Cyber Fraud Analysis System
-- Supabase / PostgreSQL schema.
-- Apply once per project (SQL editor or `apply_migration`).
--
-- Security model: RLS is enabled on every table and NO policies are created,
-- so the public anon / authenticated keys cannot read or write anything.
-- The application server talks to PostgREST with the service_role key,
-- which bypasses RLS. Never ship the service_role key to a browser.

create sequence if not exists public.nk_case_no_seq;

create table if not exists public.nk_users (
    id           bigint generated always as identity primary key,
    username     text not null unique,
    full_name    text not null,
    rank         text not null default '',
    badge_no     text not null default '',
    unit         text not null default '',
    role         text not null default 'officer' check (role in ('admin','officer')),
    pw_hash      text not null,
    active       boolean not null default true,
    created_at   timestamptz not null default now(),
    last_login   timestamptz
);

create table if not exists public.nk_cases (
    id               bigint generated always as identity primary key,
    case_no          text not null unique default
                     ('NRK/' || to_char(now() at time zone 'Asia/Kolkata','YYYY') || '/' ||
                      lpad(nextval('public.nk_case_no_seq')::text, 6, '0')),
    kind             text not null check (kind in ('message','url','website','apk')),
    title            text not null,
    source           text not null default 'officer' check (source in ('officer','citizen')),
    submitted_by     bigint references public.nk_users(id),
    reporter_name    text not null default '',
    reporter_contact text not null default '',
    channel          text not null default '',
    input_text       text not null default '',
    risk_score       integer not null default 0,
    risk_level       text not null default 'LOW' check (risk_level in ('LOW','MEDIUM','HIGH')),
    category         text not null default '',
    status           text not null default 'open'
                     check (status in ('open','investigating','closed_fraud','closed_benign')),
    notes            text not null default '',
    result           jsonb not null default '{}'::jsonb,
    shingles         bigint[] not null default '{}',
    content_sha256   text not null default '',
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now()
);
create index if not exists nk_cases_created_idx on public.nk_cases (created_at desc);
create index if not exists nk_cases_kind_idx    on public.nk_cases (kind);
create index if not exists nk_cases_risk_idx    on public.nk_cases (risk_level);
create index if not exists nk_cases_status_idx  on public.nk_cases (status);
create index if not exists nk_cases_sha_idx     on public.nk_cases (content_sha256);

create table if not exists public.nk_entities (
    id          bigint generated always as identity primary key,
    etype       text not null,
    value       text not null,
    display     text not null default '',
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now(),
    case_count  integer not null default 0,
    unique (etype, value)
);
create index if not exists nk_entities_value_idx on public.nk_entities (value);
create index if not exists nk_entities_count_idx on public.nk_entities (case_count desc);

create table if not exists public.nk_case_entities (
    case_id    bigint not null references public.nk_cases(id) on delete cascade,
    entity_id  bigint not null references public.nk_entities(id) on delete cascade,
    context    text not null default '',
    created_at timestamptz not null default now(),
    primary key (case_id, entity_id)
);
create index if not exists nk_case_entities_entity_idx on public.nk_case_entities (entity_id);

create table if not exists public.nk_evidence (
    id           bigint generated always as identity primary key,
    case_id      bigint not null references public.nk_cases(id) on delete cascade,
    label        text not null,
    filename     text not null,
    mime         text not null default 'application/octet-stream',
    size_bytes   bigint not null default 0,
    sha256       text not null,
    storage_path text not null default '',
    created_at   timestamptz not null default now()
);
create index if not exists nk_evidence_case_idx on public.nk_evidence (case_id);

create table if not exists public.nk_blocklist (
    id        bigint generated always as identity primary key,
    etype     text not null,
    value     text not null,
    source    text not null,
    note      text not null default '',
    added_by  text not null default '',
    added_at  timestamptz not null default now(),
    unique (etype, value)
);

create table if not exists public.nk_audit (
    id        bigint generated always as identity primary key,
    user_id   bigint,
    username  text not null default '',
    action    text not null,
    target    text not null default '',
    detail    text not null default '',
    ip        text not null default '',
    at        timestamptz not null default now()
);
create index if not exists nk_audit_at_idx on public.nk_audit (at desc);

-- Link extracted identifiers to a case in one transaction.
-- p_items: [{"etype":"phone","value":"+919812345678","display":"+91 98123 45678","context":"message body"}, ...]
create or replace function public.nk_link_entities(p_case_id bigint, p_items jsonb)
returns void
language plpgsql
set search_path = public
as $$
declare
    it  jsonb;
    eid bigint;
    inserted boolean;
begin
    for it in select * from jsonb_array_elements(coalesce(p_items, '[]'::jsonb)) loop
        insert into nk_entities (etype, value, display)
        values (it->>'etype', it->>'value', coalesce(it->>'display', it->>'value'))
        on conflict (etype, value) do update set last_seen = now()
        returning id into eid;

        insert into nk_case_entities (case_id, entity_id, context)
        values (p_case_id, eid, coalesce(it->>'context', ''))
        on conflict do nothing;
        get diagnostics inserted = row_count;

        if inserted then
            update nk_entities set case_count = case_count + 1, last_seen = now() where id = eid;
        end if;
    end loop;
end;
$$;

-- Most frequently reported identifiers within a time window.
create or replace function public.nk_heatlist(p_days integer default 30, p_limit integer default 15, p_etype text default null)
returns table (entity_id bigint, etype text, value text, display text, reports bigint,
               high_risk bigint, first_seen timestamptz, last_seen timestamptz)
language sql
stable
set search_path = public
as $$
    select e.id, e.etype, e.value, e.display,
           count(distinct ce.case_id)                                         as reports,
           count(distinct ce.case_id) filter (where c.risk_level = 'HIGH')    as high_risk,
           min(c.created_at), max(c.created_at)
    from nk_case_entities ce
    join nk_entities e on e.id = ce.entity_id
    join nk_cases    c on c.id = ce.case_id
    where c.created_at >= now() - make_interval(days => p_days)
      and (p_etype is null or e.etype = p_etype)
      and c.status <> 'closed_benign'
    group by e.id
    having count(distinct ce.case_id) >= 1
    order by reports desc, high_risk desc, max(c.created_at) desc
    limit p_limit;
$$;

-- Dashboard counters in one round trip.
create or replace function public.nk_stats()
returns jsonb
language sql
stable
set search_path = public
as $$
    select jsonb_build_object(
        'total',        (select count(*) from nk_cases),
        'today',        (select count(*) from nk_cases where created_at >= date_trunc('day', now() at time zone 'Asia/Kolkata') at time zone 'Asia/Kolkata'),
        'high_open',    (select count(*) from nk_cases where risk_level = 'HIGH' and status in ('open','investigating')),
        'citizen_open', (select count(*) from nk_cases where source = 'citizen' and status = 'open'),
        'confirmed',    (select count(*) from nk_cases where status = 'closed_fraud'),
        'entities',     (select count(*) from nk_entities),
        'linked',       (select count(*) from nk_entities where case_count > 1),
        'blocklist',    (select count(*) from nk_blocklist),
        'by_kind',      (select coalesce(jsonb_object_agg(kind, n), '{}'::jsonb)
                         from (select kind, count(*) n from nk_cases group by kind) k)
    );
$$;

alter table public.nk_users         enable row level security;
alter table public.nk_cases         enable row level security;
alter table public.nk_entities      enable row level security;
alter table public.nk_case_entities enable row level security;
alter table public.nk_evidence      enable row level security;
alter table public.nk_blocklist     enable row level security;
alter table public.nk_audit         enable row level security;

revoke all on function public.nk_link_entities(bigint, jsonb)       from public, anon, authenticated;
revoke all on function public.nk_heatlist(integer, integer, text)   from public, anon, authenticated;
revoke all on function public.nk_stats()                            from public, anon, authenticated;
grant execute on function public.nk_link_entities(bigint, jsonb)     to service_role;
grant execute on function public.nk_heatlist(integer, integer, text) to service_role;
grant execute on function public.nk_stats()                          to service_role;
grant usage on sequence public.nk_case_no_seq to service_role;

-- Private storage bucket for evidence files (APKs, HTML snapshots, uploads).
insert into storage.buckets (id, name, public)
values ('nk-evidence', 'nk-evidence', false)
on conflict (id) do nothing;
