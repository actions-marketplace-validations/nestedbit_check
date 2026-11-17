create table public.notes (id uuid primary key, user_id uuid not null, body text);
create index on public.notes (user_id);
alter table public.notes enable row level security;
create policy notes_select on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy notes_insert on public.notes for insert to authenticated with check ((select auth.uid()) = user_id);
create policy notes_update on public.notes for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy notes_delete on public.notes for delete to authenticated using ((select auth.uid()) = user_id);
