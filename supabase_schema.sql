-- AI Cyber Shield — Supabase Schema
-- Run once in: Supabase Dashboard → SQL Editor → New Query

-- ── Profiles (extends auth.users) ────────────────────────────────────────────
create table if not exists public.profiles (
    id             uuid references auth.users(id) on delete cascade primary key,
    email          text not null,
    role           text not null default 'user' check (role in ('user', 'admin')),
    pt_approved    boolean not null default false,
    pt_approved_by text,
    pt_approved_at timestamptz,
    created_at     timestamptz not null default now()
);

-- ── Per-hour scan quota ───────────────────────────────────────────────────────
create table if not exists public.scan_quotas (
    id           uuid default gen_random_uuid() primary key,
    user_id      uuid references auth.users(id) on delete cascade not null,
    window_start timestamptz not null,
    scan_count   integer not null default 0,
    unique(user_id, window_start)
);

-- ── Audit logs ────────────────────────────────────────────────────────────────
create table if not exists public.audit_logs (
    id          uuid default gen_random_uuid() primary key,
    user_id     uuid references auth.users(id) on delete set null,
    user_email  text,
    action      text not null,
    target      text,
    details     jsonb default '{}',
    severity    text default 'info' check (severity in ('info', 'warning', 'error')),
    created_at  timestamptz not null default now()
);

-- ── Row-Level Security ────────────────────────────────────────────────────────
alter table public.profiles    enable row level security;
alter table public.scan_quotas enable row level security;
alter table public.audit_logs  enable row level security;

-- Profiles: own row read/update; admin reads all
create policy "profile_select_own" on public.profiles
    for select using (auth.uid() = id);
create policy "profile_insert_own" on public.profiles
    for insert with check (auth.uid() = id);
create policy "profile_update_own" on public.profiles
    for update using (auth.uid() = id)
    with check (role = (select role from public.profiles where id = auth.uid()));
create policy "admin_all_profiles" on public.profiles
    for all using (
        exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')
    );

-- Quotas: own rows only
create policy "quota_own" on public.scan_quotas
    for all using (auth.uid() = user_id)
    with check (auth.uid() = user_id);

-- Logs: insert own; admin selects all
create policy "log_insert_own" on public.audit_logs
    for insert with check (auth.uid() = user_id);
create policy "admin_read_logs" on public.audit_logs
    for select using (
        exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')
    );

-- ── Atomic quota increment (avoids race condition) ───────────────────────────
create or replace function public.increment_scan_quota(p_user_id uuid, p_window timestamptz)
returns void language plpgsql security definer as $$
begin
    insert into public.scan_quotas (user_id, window_start, scan_count)
    values (p_user_id, p_window, 1)
    on conflict (user_id, window_start)
    do update set scan_count = public.scan_quotas.scan_count + 1;
end;
$$;

-- ── Auto-create profile on signup ─────────────────────────────────────────────
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
    insert into public.profiles (id, email)
    values (new.id, new.email)
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();
