-- Noor Jobs production starter schema for Supabase
-- Run this in Supabase SQL Editor before publishing the website.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  account_id bigint generated always as identity unique,
  name text not null default '',
  address text not null default '',
  email text,
  role text not null default 'applicant' check (role in ('applicant','owner')),
  created_at timestamptz not null default now()
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  application_id bigint generated always as identity unique,
  user_id uuid not null references public.profiles(id) on delete cascade,
  job_title text not null,
  education text not null,
  experience text not null default '',
  cover_letter text not null,
  cv_url text,
  reply text,
  replied_at timestamptz,
  created_at timestamptz not null default now()
);

-- Automatically create a profile and a unique sequential account ID after signup.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, name, address, email)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'name', ''),
    coalesce(new.raw_user_meta_data ->> 'address', ''),
    new.email
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- SECURITY DEFINER helper avoids recursive RLS checks on profiles.
create or replace function public.is_owner()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'owner'
  );
$$;
grant execute on function public.is_owner() to authenticated;

alter table public.profiles enable row level security;
alter table public.applications enable row level security;

-- Profile owners can read their own profile; owners can read all profiles.
drop policy if exists "read own profile or owner" on public.profiles;
create policy "read own profile or owner" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or public.is_owner());

-- Applicants can update only their own basic profile fields.
drop policy if exists "update own profile" on public.profiles;
create policy "update own profile" on public.profiles
for update to authenticated
using (id = (select auth.uid()) and role = 'applicant')
with check (id = (select auth.uid()) and role = 'applicant');

-- Only the owner can promote an account to owner. Do this from SQL editor, not the website.
revoke insert, delete on public.profiles from authenticated;
grant select, update on public.profiles to authenticated;

drop policy if exists "read own applications or owner" on public.applications;
create policy "read own applications or owner" on public.applications
for select to authenticated
using (user_id = (select auth.uid()) or public.is_owner());

drop policy if exists "applicants create own applications" on public.applications;
create policy "applicants create own applications" on public.applications
for insert to authenticated
with check (user_id = (select auth.uid()) and not public.is_owner());

drop policy if exists "owner replies to applications" on public.applications;
create policy "owner replies to applications" on public.applications
for update to authenticated
using (public.is_owner())
with check (public.is_owner());

grant select, insert, update on public.applications to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- IMPORTANT: after creating your own account through the website, run:
-- update public.profiles set role = 'owner' where email = 'YOUR-OWNER-EMAIL-HERE';
-- Replace with the exact email you used. Never share the service_role key.
