-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- PROFILES (Users)
-- Supabase Auth handles authentication, but we need a public profile table.
-- This table mirrors key user info and links to auth.users.
create table public.profiles (
  id uuid references auth.users not null primary key,
  email text,
  name text,
  role text default 'fisher', -- 'admin', 'fisher'
  barangay text,
  created_at timestamptz default now()
);

-- RLS for Profiles
alter table public.profiles enable row level security;
create policy "Public profiles are viewable by everyone" on public.profiles for select using (true);
create policy "Users can insert their own profile" on public.profiles for insert with check (auth.uid() = id);
create policy "Users can update their own profile" on public.profiles for update using (auth.uid() = id);

-- TRACKS
create table public.tracks (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references public.profiles(id),
  lat float not null,
  lng float not null,
  accuracy float,
  speed float,
  heading float,
  active boolean default true,
  status text, -- 'transit', 'port'
  status_at timestamptz,
  recorded_at timestamptz default now(),
  created_at timestamptz default now()
);
alter table public.tracks enable row level security;
create policy "Tracks are viewable by everyone" on public.tracks for select using (true);
create policy "Users can insert their own tracks" on public.tracks for insert with check (auth.uid() = user_id);

-- STATUS EVENTS
create table public.status_events (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references public.profiles(id),
  status text not null,
  lat float,
  lng float,
  at timestamptz default now(),
  created_at timestamptz default now()
);
alter table public.status_events enable row level security;
create policy "Status events viewable by everyone" on public.status_events for select using (true);
create policy "Users can insert status events" on public.status_events for insert with check (auth.uid() = user_id);

-- CATCHES
create table public.catches (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references public.profiles(id),
  species text,
  weight float,
  length float,
  net_type text,
  gear text,
  vessel text,
  image_url text,
  lat float,
  lng float,
  notes text,
  status text default 'pending', -- 'pending', 'verified'
  recorded_at timestamptz default now(),
  created_at timestamptz default now()
);
alter table public.catches enable row level security;
create policy "Catches viewable by everyone" on public.catches for select using (true);
create policy "Users can insert catches" on public.catches for insert with check (auth.uid() = user_id);

-- ALERTS
create table public.alerts (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid references public.profiles(id),
  type text, -- 'SOS', 'Zone Entry', etc.
  status text default 'pending', -- 'pending', 'acknowledged', 'resolved'
  lat float,
  lng float,
  note text,
  zone_id text,
  recorded_at timestamptz default now(),
  created_at timestamptz default now()
);
alter table public.alerts enable row level security;
create policy "Alerts viewable by everyone" on public.alerts for select using (true);
create policy "Users can insert alerts" on public.alerts for insert with check (auth.uid() = user_id);
create policy "Admins can update alerts" on public.alerts for update using (
  exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
);

-- ZONES
create table public.zones (
  id uuid default uuid_generate_v4() primary key,
  name text,
  type text,
  color text,
  coordinates jsonb, -- GeoJSON or array of points
  created_at timestamptz default now()
);
alter table public.zones enable row level security;
create policy "Zones viewable by everyone" on public.zones for select using (true);

-- SPECIES
create table public.species (
  id uuid default uuid_generate_v4() primary key,
  name text,
  scientific_name text,
  image_url text,
  description text,
  created_at timestamptz default now()
);
alter table public.species enable row level security;
create policy "Species viewable by everyone" on public.species for select using (true);

-- STORAGE BUCKETS
-- You need to create a storage bucket named 'uploads' in the Supabase Dashboard
-- and set policy to public read, authenticated insert.

-- FUNCTION to handle new user signup (Trigger)
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, name, role)
  values (new.id, new.email, new.raw_user_meta_data->>'name', coalesce(new.raw_user_meta_data->>'role', 'fisher'));
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
