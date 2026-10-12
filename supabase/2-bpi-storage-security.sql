-- ============================================================================
-- BPI Commercial — photo storage security (run AFTER 1-bpi-supabase-security.sql)
-- Supabase Dashboard → SQL Editor → New query → paste → Run. Safe to re-run.
-- Public can view photos; only approved admins can upload, replace or delete.
-- If you get "must be owner of table objects", use the Storage → Policies
-- screen instead (steps in the launch notes).
-- ============================================================================

-- Remove existing policies that mention this bucket, then re-create:
-- public can view photos; only admins can upload, replace or delete.
do $$
declare p record;
begin
  for p in
    select policyname from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and (coalesce(qual, '') like '%property-photos%' or coalesce(with_check, '') like '%property-photos%')
  loop
    execute format('drop policy if exists %I on storage.objects', p.policyname);
  end loop;
end $$;

create policy "property-photos: public read"   on storage.objects for select to anon, authenticated using (bucket_id = 'property-photos');
create policy "property-photos: admin upload"  on storage.objects for insert to authenticated with check (bucket_id = 'property-photos' and (select public.is_admin()));
create policy "property-photos: admin update"  on storage.objects for update to authenticated using (bucket_id = 'property-photos' and (select public.is_admin())) with check (bucket_id = 'property-photos' and (select public.is_admin()));
create policy "property-photos: admin delete"  on storage.objects for delete to authenticated using (bucket_id = 'property-photos' and (select public.is_admin()));

-- Limit uploads to images up to 5 MB
update storage.buckets
set file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp']
where id = 'property-photos';

select policyname, cmd, roles from pg_policies
where schemaname = 'storage' and tablename = 'objects' order by policyname;
