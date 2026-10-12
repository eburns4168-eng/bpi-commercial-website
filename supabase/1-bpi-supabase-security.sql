-- ============================================================================
-- BPI Commercial — Supabase security hardening
-- Run once in: Supabase Dashboard → SQL Editor → New query → paste → Run
-- Safe to re-run. Does not delete any inquiries, listings, photos or settings.
--
-- What it does
--   1. Creates an admin allow-list (public.admin_users) and public.is_admin().
--      Only accounts on this list can read/delete inquiries or change
--      listings, settings and photos. Being "logged in" is no longer enough.
--   2. Replaces every policy on properties, inquiries and site_settings.
--      (Photo storage is handled by 2-bpi-storage-security.sql.)
--   3. Visitors can still: view listings, view settings (broker photo URL),
--      view photos, and submit the contact form. Nothing else.
--   4. Adds size/format limits to inquiries so the public insert can't be
--      used to stuff huge or malformed data into the database.
-- ============================================================================

-- ── 1. Admin allow-list ─────────────────────────────────────────────────────
create table if not exists public.admin_users (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  email      text,
  created_at timestamptz not null default now()
);
alter table public.admin_users enable row level security;
-- No policies on purpose: the allow-list is not readable or writable through
-- the public API. Manage it only here in the SQL editor.
revoke all on public.admin_users from anon, authenticated;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.admin_users a where a.user_id = auth.uid());
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- Add the admin account(s). Only accounts that already exist under
-- Authentication → Users are added; edit the list if a different email is used.
insert into public.admin_users (user_id, email)
select id, email from auth.users
where lower(email) in ('aburns@burnspropertiesinc.com', 'eburns4168@gmail.com')
on conflict (user_id) do nothing;

-- ── 2. Make sure RLS is on ──────────────────────────────────────────────────
alter table public.properties    enable row level security;
alter table public.inquiries     enable row level security;
alter table public.site_settings enable row level security;

-- ── 3. Drop every existing policy on the three tables ──────────────────────
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname from pg_policies
    where schemaname = 'public' and tablename in ('properties', 'inquiries', 'site_settings')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

-- ── 4. New table policies ───────────────────────────────────────────────────
-- properties: public read, admin-only write
create policy "properties: public read"   on public.properties for select to anon, authenticated using (true);
create policy "properties: admin insert"  on public.properties for insert to authenticated with check ((select public.is_admin()));
create policy "properties: admin update"  on public.properties for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "properties: admin delete"  on public.properties for delete to authenticated using ((select public.is_admin()));

-- inquiries: anyone may submit; only admins may read or delete; nobody may edit
create policy "inquiries: public submit"  on public.inquiries for insert to anon, authenticated with check (true);
create policy "inquiries: admin read"     on public.inquiries for select to authenticated using ((select public.is_admin()));
create policy "inquiries: admin delete"   on public.inquiries for delete to authenticated using ((select public.is_admin()));

-- site_settings: public read (broker photo URL), admin-only write
create policy "site_settings: public read"  on public.site_settings for select to anon, authenticated using (true);
create policy "site_settings: admin insert" on public.site_settings for insert to authenticated with check ((select public.is_admin()));
create policy "site_settings: admin update" on public.site_settings for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "site_settings: admin delete" on public.site_settings for delete to authenticated using ((select public.is_admin()));

-- ── 5. Inquiry limits (checked by the database on every new row) ────────────
-- NOT VALID = existing rows are left alone; all new rows must pass.
alter table public.inquiries drop constraint if exists inquiries_limits;
alter table public.inquiries add constraint inquiries_limits check (
      char_length(coalesce(first_name, ''))       between 1 and 100
  and char_length(coalesce(last_name, ''))        between 1 and 100
  and char_length(coalesce(email, ''))            between 3 and 254
  and email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]{2,}$'
  and char_length(coalesce(phone, ''))            <= 40
  and char_length(coalesce(company, ''))          <= 200
  and char_length(coalesce(inquiry_type, ''))     <= 100
  and char_length(coalesce(property_address, '')) <= 300
  and char_length(coalesce(message, ''))          between 1 and 5000
) not valid;

-- ── 6. Show the result (check this output) ─────────────────────────────────
select 'admin account' as item, email as detail from public.admin_users
union all
select 'RLS ' || case when c.relrowsecurity then 'ON' else 'OFF  <-- PROBLEM' end, c.relname
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relname in ('properties', 'inquiries', 'site_settings', 'admin_users')
union all
select 'policy', schemaname || '.' || tablename || ' | ' || cmd || ' | ' || array_to_string(roles, ',') || ' | ' || policyname
from pg_policies
where (schemaname = 'public' and tablename in ('properties', 'inquiries', 'site_settings'))
order by 1, 2;
