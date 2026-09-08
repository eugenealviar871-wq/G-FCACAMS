-- =====================================================================
-- Migration 002: Add snap_enumerator to valid profile roles
-- Extends the role CHECK constraint without removing existing values
-- so that existing users are not affected.
-- =====================================================================

ALTER TABLE public.profiles
  DROP CONSTRAINT IF EXISTS profiles_role_check;

ALTER TABLE public.profiles
  ADD CONSTRAINT profiles_role_check
  CHECK (role IN ('admin','inspector','snap_enumerator'));
