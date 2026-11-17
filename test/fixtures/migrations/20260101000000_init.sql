-- Notes: made and secured in this migration.
create table public.notes (id uuid primary key, user_id uuid not null, body text);
create index on public.notes (user_id);
alter table public.notes enable row level security;
create policy notes_select on public.notes for select to authenticated using ((select auth.uid()) = user_id);

-- Profiles: made here, secured in the next migration.
create table public.profiles (id uuid primary key references auth.users, name text);
