-- Add is_archived column to tracks table if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'tracks' AND column_name = 'is_archived'
  ) THEN
    ALTER TABLE public.tracks
      ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT false;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tracks_is_archived ON public.tracks(is_archived);
