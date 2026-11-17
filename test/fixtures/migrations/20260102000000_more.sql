alter table public.profiles enable row level security;
create policy profiles_select on public.profiles for select to authenticated using ((select auth.uid()) = id);

-- Payments: row-level security forgotten.
create table public.payments (id uuid primary key, amount int);
