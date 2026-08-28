-- =====================================================================
-- BFAR Monitoring — Supabase / Postgres Schema — FIXED VERSION
-- Main fixes:
--   1. Do not DROP POLICY before the tables exist.
--   2. Create vessels before catches because catches references vessels(id).
--   3. Split public SELECT and admin write policies for zones/protected_areas/species.
-- =====================================================================

-- Supports BOTH authentication models:
--   1. Supabase GoTrue auth (recommended if you enable it in the project)
--        profiles.id  = auth.users.id (UUID stored as TEXT)
--   2. Local / app-level JWT auth (default when SUABASE AUTH not used)
--        profiles.id  = nanoid TEXT (e.g. "yRecQ4dZf5-K8gLK4Ahcs")
-- All other `id` / `user_id` columns are TEXT — works for both.
--
-- Also enables Row Level Security (RLS) on every user-owned table
-- using `app.current_user_id` / `app.current_role` Postgres GUCs.
-- In server.supabase.js auth() middleware we SET these config vars
-- for every request so policies resolve to the logged-in inspector.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------
-- 1. PROFILES (users: inspectors + admin)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id            TEXT PRIMARY KEY,                -- Accepts UUID or nanoid TEXT
  email         TEXT UNIQUE NOT NULL,
  name          TEXT,
  role          TEXT NOT NULL DEFAULT 'inspector' CHECK (role IN ('admin','inspector')),
  password_hash TEXT,                            -- NULL if you use Supabase GoTrue auth;
                                                  --   filled when using local JWT auth.
  barangay      TEXT,
  fisher_id     TEXT,                            -- BFAR Registration No.
  municipality  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_profiles_role  ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Seed a default BFAR admin account (local JWT auth).
-- Password = "admin123" (bcrypt $2a$10$...)
-- Re-runnable (ON CONFLICT DO NOTHING).
INSERT INTO public.profiles (id, email, name, role, password_hash)
VALUES (
  'gzkhv4SkYxnffdWDbMT61',
  'admin@local.test',
  'BFAR System Admin',
  'admin',
  '$2a$10$CwTycUXWue0Thq9StjUM0uJ8b9n4CqGzr/Ke/5B2nKbYxRqBnUqYW'
) ON CONFLICT (id) DO NOTHING;

-- Seed two known inspector logins (alviar@gmail.com, altarejos@gmail.com — both use bcrypt hash for "alviar123")
INSERT INTO public.profiles (id, email, name, role, password_hash)
VALUES
  ('yRecQ4dZf5-K8gLK4Ahcs', 'alviar@gmail.com',     'Eugene Alviar',        'inspector', '$2a$10$p7s05XmYlV1e5qPzrH2V0OaZ3VQfX7b2mHq3nN4kKjY8lZxYwRuOu'),
  ('Kq3BZObqmXRmLtFcNfpEr', 'altarejos@gmail.com', 'Rocel T. Altarejos',   'inspector', '$2a$10$p7s05XmYlV1e5qPzrH2V0OaZ3VQfX7b2mHq3nN4kKjY8lZxYwRuOu')
ON CONFLICT (id) DO NOTHING;

-- RLS: Admin sees every profile; Inspector sees ONLY his own row.
DROP POLICY IF EXISTS profiles_policy ON public.profiles;
CREATE POLICY profiles_policy ON public.profiles
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 3. VESSELS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.vessels (
  id                        TEXT PRIMARY KEY,
  user_id                   TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  vessel_registration_number TEXT UNIQUE,
  name                      TEXT NOT NULL,
  owner_name                TEXT,
  type                      TEXT,
  capacity                  NUMERIC(12,3),
  contact                   TEXT,
  home_port                 TEXT,
  barangay                  TEXT,
  engine_gear               TEXT,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vessels_user_id ON public.vessels(user_id);
CREATE INDEX IF NOT EXISTS idx_vessels_name    ON public.vessels(name);

ALTER TABLE IF EXISTS public.vessels ADD COLUMN IF NOT EXISTS engine_gear TEXT;

ALTER TABLE public.vessels ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vessels_set_updated_at ON public.vessels;
CREATE TRIGGER vessels_set_updated_at
  BEFORE UPDATE ON public.vessels
  FOR EACH ROW EXECUTE PROCEDURE public.set_updated_at();

DROP POLICY IF EXISTS vessels_policy ON public.vessels;
CREATE POLICY vessels_policy ON public.vessels
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 2. CATCHES (core: every fish catch logged by an inspector)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.catches (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  vessel_id     TEXT REFERENCES public.vessels(id) ON DELETE SET NULL,
  species       TEXT NOT NULL,
  weight        NUMERIC(12,3) NOT NULL CHECK (weight > 0),
  length_cm     NUMERIC(12,2),
  net_type      TEXT,
  gear          TEXT,
  vessel_registration_number TEXT,
  vessel_name   TEXT,
  owner_name    TEXT,
  image_url     TEXT,
  latitude      DOUBLE PRECISION,
  longitude     DOUBLE PRECISION,
  location      TEXT,
  note          TEXT,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','rejected')),
  recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  captured_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_catches_user_id     ON public.catches(user_id);
CREATE INDEX IF NOT EXISTS idx_catches_vessel_id   ON public.catches(vessel_id);
CREATE INDEX IF NOT EXISTS idx_catches_recorded_at ON public.catches(recorded_at);
CREATE INDEX IF NOT EXISTS idx_catches_captured_at ON public.catches(captured_at);
CREATE INDEX IF NOT EXISTS idx_catches_species     ON public.catches(species);
CREATE INDEX IF NOT EXISTS idx_catches_status      ON public.catches(status);

ALTER TABLE public.catches ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS catches_policy ON public.catches;
CREATE POLICY catches_policy ON public.catches
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 4. TRACKS (GPS breadcrumb points)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.tracks (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  vessel_id    TEXT,
  latitude     DOUBLE PRECISION NOT NULL,
  longitude    DOUBLE PRECISION NOT NULL,
  lat          DOUBLE PRECISION GENERATED ALWAYS AS (latitude) STORED,
  lng          DOUBLE PRECISION GENERATED ALWAYS AS (longitude) STORED,
  accuracy     DOUBLE PRECISION,
  speed        DOUBLE PRECISION,
  speed_knots  DOUBLE PRECISION,
  heading      DOUBLE PRECISION,
  active       BOOLEAN NOT NULL DEFAULT true,
  status       TEXT, -- 'transit' | 'port' | 'fishing'
  status_at    TIMESTAMPTZ,
  recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tracks_user_id     ON public.tracks(user_id);
CREATE INDEX IF NOT EXISTS idx_tracks_recorded_at ON public.tracks(recorded_at);

ALTER TABLE public.tracks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tracks_policy ON public.tracks;
CREATE POLICY tracks_policy ON public.tracks
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 5. STATUS EVENTS (vessel status transitions, SSE broadcast)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.status_events (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  vessel_id   TEXT,
  status      TEXT NOT NULL,
  message     TEXT,
  latitude    DOUBLE PRECISION,
  longitude   DOUBLE PRECISION,
  lat         DOUBLE PRECISION GENERATED ALWAYS AS (latitude) STORED,
  lng         DOUBLE PRECISION GENERATED ALWAYS AS (longitude) STORED,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_status_events_user_id    ON public.status_events(user_id);
CREATE INDEX IF NOT EXISTS idx_status_events_created_at ON public.status_events(created_at);
CREATE INDEX IF NOT EXISTS idx_status_events_status      ON public.status_events(status);

ALTER TABLE public.status_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS status_events_policy ON public.status_events;
CREATE POLICY status_events_policy ON public.status_events
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 6. ACTIVITY LOGS (inspector actions: catches, logins, alerts ack, etc.)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.activity_logs (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  action      TEXT NOT NULL,
  category    TEXT,
  details     JSONB NOT NULL DEFAULT '{}'::JSONB,
  latitude    DOUBLE PRECISION,
  longitude   DOUBLE PRECISION,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id    ON public.activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON public.activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_logs_category   ON public.activity_logs(category);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action     ON public.activity_logs(action);

ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS activity_logs_policy ON public.activity_logs;
CREATE POLICY activity_logs_policy ON public.activity_logs
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 7. ALERTS (SOS, zone-entry, IUU, etc.)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alerts (
  id          TEXT PRIMARY KEY,
  user_id     TEXT REFERENCES public.profiles(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','acknowledged','resolved')),
  title       TEXT NOT NULL,
  message     TEXT,
  latitude    DOUBLE PRECISION,
  longitude   DOUBLE PRECISION,
  lat         DOUBLE PRECISION GENERATED ALWAYS AS (latitude) STORED,
  lng         DOUBLE PRECISION GENERATED ALWAYS AS (longitude) STORED,
  zone_id     TEXT,
  read        BOOLEAN NOT NULL DEFAULT false,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id    ON public.alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON public.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON public.alerts(created_at);

ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS alerts_policy ON public.alerts;
CREATE POLICY alerts_policy ON public.alerts
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id IS NULL)   -- global alerts (visible to all admin, non-personal)
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 8. ZONES (municipal waters, commercial zones, closed areas)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.zones (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL, -- municipal / commercial / closed / seasonal-closure / no-take
  color       TEXT,
  coordinates JSONB,
  geometry    JSONB NOT NULL DEFAULT '{}'::JSONB,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.zones ENABLE ROW LEVEL SECURITY;

-- Admin manages; inspectors may READ only.
DROP POLICY IF EXISTS zones_policy ON public.zones;
DROP POLICY IF EXISTS zones_select_policy ON public.zones;
DROP POLICY IF EXISTS zones_admin_policy ON public.zones;

CREATE POLICY zones_select_policy ON public.zones
  FOR SELECT USING (true);

CREATE POLICY zones_admin_policy ON public.zones
  FOR ALL
  USING (current_setting('app.current_role', true) = 'admin')
  WITH CHECK (current_setting('app.current_role', true) = 'admin');

-- ---------------------------------------------------------------------
-- 9. PROTECTED AREAS (MPA, critical habitat, etc.)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.protected_areas (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  category    TEXT,
  coordinates JSONB,
  geometry    JSONB NOT NULL DEFAULT '{}'::JSONB,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.protected_areas ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS protected_areas_policy ON public.protected_areas;
DROP POLICY IF EXISTS protected_areas_select_policy ON public.protected_areas;
DROP POLICY IF EXISTS protected_areas_admin_policy ON public.protected_areas;

CREATE POLICY protected_areas_select_policy ON public.protected_areas
  FOR SELECT USING (true);

CREATE POLICY protected_areas_admin_policy ON public.protected_areas
  FOR ALL
  USING (current_setting('app.current_role', true) = 'admin')
  WITH CHECK (current_setting('app.current_role', true) = 'admin');

-- ---------------------------------------------------------------------
-- 10. SPECIES (reference catalog: names, limits, conservation status)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.species (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  scientific_name    TEXT,
  image_url          TEXT,
  description        TEXT,
  min_length_cm      NUMERIC(10,2),
  max_length_cm      NUMERIC(10,2),
  price_per_kg       NUMERIC(12,2),
  conservation       TEXT, -- NONE / PROTECTED / ENDANGERED / CRITICALLY_ENDANGERED
  seasonal_allowed   TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.species ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS species_policy ON public.species;
DROP POLICY IF EXISTS species_select_policy ON public.species;
DROP POLICY IF EXISTS species_admin_policy ON public.species;

CREATE POLICY species_select_policy ON public.species
  FOR SELECT USING (true);

CREATE POLICY species_admin_policy ON public.species
  FOR ALL
  USING (current_setting('app.current_role', true) = 'admin')
  WITH CHECK (current_setting('app.current_role', true) = 'admin');

-- ---------------------------------------------------------------------
-- 11. IMAGES (catch evidence, activity proofs, vessel photos)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.images (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  catch_id    TEXT REFERENCES public.catches(id) ON DELETE SET NULL,
  url         TEXT NOT NULL,
  storage_key TEXT NOT NULL,  -- Supabase Storage key inside 'uploads' bucket
  width_px    INTEGER,
  height_px   INTEGER,
  exif        JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_images_user_id  ON public.images(user_id);
CREATE INDEX IF NOT EXISTS idx_images_catch_id ON public.images(catch_id);

ALTER TABLE public.images ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS images_policy ON public.images;
CREATE POLICY images_policy ON public.images
  FOR ALL
  USING (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  )
  WITH CHECK (
    (current_setting('app.current_role', true) = 'admin')
    OR (user_id = current_setting('app.current_user_id', true)::TEXT)
  );

-- ---------------------------------------------------------------------
-- 12. PUSH (web-push subscriptions for browser push notifications)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.push (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  subscription JSONB NOT NULL,
  user_agent   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_push_user_id ON public.push(user_id);

ALTER TABLE public.push ENABLE ROW LEVEL SECURITY;

-- THIS IS THE POLICY THAT WAS RETURNING HTTP 400 before —
-- because ENABLE ROW LEVEL SECURITY on public.push had not been run yet.
DROP POLICY IF EXISTS push_policy ON public.push;
CREATE POLICY push_policy ON public.push
  FOR ALL
  USING    (user_id = current_setting('app.current_user_id', true)::TEXT)
  WITH CHECK (user_id = current_setting('app.current_user_id', true)::TEXT);

-- =====================================================================
-- SUPABASE AUTH TRIGGER (OPTIONAL, SAFE TO RUN)
-- If you later enable GoTrue (Supabase Auth) for email/password or
-- social logins, this trigger auto-creates a public.profiles row from
-- auth.users on signup so local app code continues to work.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, role, barangay, fisher_id)
  VALUES (
    NEW.id::TEXT,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'name', NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'role', 'inspector'),
    NEW.raw_user_meta_data->>'barangay',
    NEW.raw_user_meta_data->>'fisher_id'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- =====================================================================
-- SUGGESTED STORAGE BUCKET
-- Run this manually once the bucket UI supports it OR run:
--   insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true);
-- Then enable storage policies for authenticated writes.
-- =====================================================================
