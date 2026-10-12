-- ============================================================================
-- BPI Commercial — security check (read-only: everything is rolled back)
-- Run AFTER scripts 1 and 2. Every row in the result should say PASS.
-- It acts as (a) a website visitor and (b) a logged-in account that is NOT on
-- the admin list, tries to read/change data, and reports what happened.
-- ============================================================================
begin;

create temporary table _bpi_results (check_name text, result text) on commit drop;

do $$
declare
  n bigint;
  names text[] := '{}';
  results text[] := '{}';
begin
  -- ── (a) as an anonymous website visitor ─────────────────────────────────
  set local role anon;

  select count(*) into n from public.inquiries;
  names := names || 'visitor cannot read inquiries'::text; results := results || (case when n = 0 then 'PASS' else 'FAIL: saw ' || n || ' rows' end)::text;

  begin
    update public.properties set name = name where true;
    get diagnostics n = row_count;
    names := names || 'visitor cannot edit listings'::text; results := results || (case when n = 0 then 'PASS' else 'FAIL: changed ' || n || ' rows' end)::text;
  exception when others then
    names := names || 'visitor cannot edit listings'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  begin
    delete from public.properties where true;
    get diagnostics n = row_count;
    names := names || 'visitor cannot delete listings'::text; results := results || (case when n = 0 then 'PASS' else 'FAIL: deleted ' || n || ' rows (rolled back)' end)::text;
  exception when others then
    names := names || 'visitor cannot delete listings'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  begin
    insert into public.site_settings (key, value) values ('_security_check', 'x');
    names := names || 'visitor cannot change site settings'::text; results := results || ('FAIL: insert allowed (rolled back)')::text;
  exception when others then
    names := names || 'visitor cannot change site settings'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  begin
    insert into public.inquiries (first_name, last_name, email, message)
    values ('Check', 'Visitor', 'visitor@example.com', 'Security check row (rolled back)');
    names := names || 'visitor CAN submit a normal inquiry'::text; results := results || ('PASS')::text;
  exception when others then
    names := names || 'visitor CAN submit a normal inquiry'::text; results := results || ('FAIL: ' || sqlerrm)::text;
  end;

  begin
    insert into public.inquiries (first_name, last_name, email, message)
    values ('x', 'x', 'not-an-email', repeat('x', 6000));
    names := names || 'oversized/invalid inquiry rejected'::text; results := results || ('FAIL: accepted (rolled back)')::text;
  exception when others then
    names := names || 'oversized/invalid inquiry rejected'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  -- ── (b) as a logged-in account that is not an admin ─────────────────────
  reset role;
  perform set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated"}', true);
  set local role authenticated;

  select count(*) into n from public.inquiries;
  names := names || 'non-admin account cannot read inquiries'::text; results := results || (case when n = 0 then 'PASS' else 'FAIL: saw ' || n || ' rows' end)::text;

  begin
    update public.properties set name = name where true;
    get diagnostics n = row_count;
    names := names || 'non-admin account cannot edit listings'::text; results := results || (case when n = 0 then 'PASS' else 'FAIL: changed ' || n || ' rows' end)::text;
  exception when others then
    names := names || 'non-admin account cannot edit listings'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  begin
    insert into public.site_settings (key, value) values ('_security_check', 'x');
    names := names || 'non-admin account cannot change site settings'::text; results := results || ('FAIL: insert allowed (rolled back)')::text;
  exception when others then
    names := names || 'non-admin account cannot change site settings'::text; results := results || ('PASS (' || sqlstate || ')')::text;
  end;

  reset role;
  insert into _bpi_results select unnest(names), unnest(results);
end $$;

-- ── (c) configuration facts ────────────────────────────────────────────────
do $$
declare v text;
begin
  if to_regclass('public.admin_users') is null then
    insert into _bpi_results values ('admin accounts on allow-list', 'FAIL: admin_users table missing — run script 1');
  else
    execute 'select string_agg(email, '', '') from public.admin_users' into v;
    insert into _bpi_results values ('admin accounts on allow-list',
      case when v is not null then 'PASS: ' || v else 'FAIL: none — admin login will not work' end);
  end if;
end $$;

insert into _bpi_results
select 'storage write policies require admin',
       case when count(*) filter (where cmd in ('INSERT','UPDATE','DELETE','ALL')
                                    and coalesce(qual,'') || coalesce(with_check,'') like '%property-photos%'
                                    and coalesce(qual,'') || coalesce(with_check,'') not like '%is_admin%') = 0
            then 'PASS' else 'FAIL: a property-photos write policy does not check is_admin()' end
from pg_policies where schemaname = 'storage' and tablename = 'objects';

select * from _bpi_results;
rollback;
