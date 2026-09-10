-- Canonical baseline for the Where production database.
-- This migration is intentionally idempotent so it can safely adopt databases
-- that were originally initialized by application startup code.

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username VARCHAR(20) NOT NULL UNIQUE,
  name VARCHAR(20) NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  provider TEXT NOT NULL DEFAULT 'password',
  role TEXT NOT NULL DEFAULT 'user',
  profile_image TEXT NOT NULL DEFAULT '',
  source_site TEXT NOT NULL DEFAULT 'legacy',
  email TEXT,
  provider_user_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS source_site TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_user_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ALTER COLUMN password_salt DROP NOT NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));

CREATE UNIQUE INDEX IF NOT EXISTS users_provider_identity_idx
  ON users (provider, provider_user_id)
  WHERE provider_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_source_site_idx ON users (source_site);
CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at DESC);

CREATE TABLE IF NOT EXISTS friendships (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, friend_id),
  CHECK (user_id <> friend_id)
);

CREATE TABLE IF NOT EXISTS relationship_requests (
  id UUID PRIMARY KEY,
  sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL CHECK (relationship_type IN ('friend', 'couple', 'family')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  responded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS relationship_requests_recipient_idx
  ON relationship_requests (recipient_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS trips (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(120) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  start_area TEXT NOT NULL DEFAULT '',
  date_start DATE,
  date_end DATE,
  companion TEXT NOT NULL DEFAULT 'alone',
  headcount SMALLINT NOT NULL DEFAULT 1 CHECK (headcount >= 1 AND headcount <= 100),
  budget_per_person INTEGER NOT NULL DEFAULT 0 CHECK (budget_per_person >= 0),
  transport TEXT NOT NULL DEFAULT 'public' CHECK (transport IN ('public', 'car')),
  weather TEXT NOT NULL DEFAULT 'sunny',
  likes JSONB NOT NULL DEFAULT '[]'::jsonb,
  dislikes JSONB NOT NULL DEFAULT '[]'::jsonb,
  route_coordinates JSONB NOT NULL DEFAULT '[]'::jsonb,
  is_public BOOLEAN NOT NULL DEFAULT FALSE,
  share_token TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Legacy databases created before managed migrations do not have the sharing
-- columns above. Add them before creating indexes so this baseline can safely
-- adopt those databases as well as initialize a new one.
ALTER TABLE trips ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE trips ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE trips ADD COLUMN IF NOT EXISTS share_token TEXT;

CREATE INDEX IF NOT EXISTS trips_user_updated_idx ON trips (user_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS trips_share_token_unique_idx
  ON trips (share_token)
  WHERE share_token IS NOT NULL;

CREATE TABLE IF NOT EXISTS trip_stops (
  id UUID PRIMARY KEY,
  trip_id UUID NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
  stop_order SMALLINT NOT NULL CHECK (stop_order >= 0),
  place_id TEXT,
  place_name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'tour',
  area TEXT NOT NULL DEFAULT '',
  latitude DOUBLE PRECISION NOT NULL CHECK (latitude >= -90 AND latitude <= 90),
  longitude DOUBLE PRECISION NOT NULL CHECK (longitude >= -180 AND longitude <= 180),
  estimated_cost INTEGER NOT NULL DEFAULT 0 CHECK (estimated_cost >= 0),
  duration_min INTEGER NOT NULL DEFAULT 0 CHECK (duration_min >= 0),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (trip_id, stop_order)
);

CREATE INDEX IF NOT EXISTS trip_stops_trip_order_idx ON trip_stops (trip_id, stop_order);

CREATE TABLE IF NOT EXISTS seoul_areas (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS seoul_areas_name_idx ON seoul_areas (name);
INSERT INTO seoul_areas (name) VALUES
  ('강남구'), ('강동구'), ('강북구'), ('강서구'), ('관악구'),
  ('광진구'), ('구로구'), ('금천구'), ('노원구'), ('도봉구'),
  ('동대문구'), ('동작구'), ('마포구'), ('서대문구'), ('서초구'),
  ('성동구'), ('성북구'), ('송파구'), ('양천구'), ('영등포구'),
  ('용산구'), ('은평구'), ('종로구'), ('중구'), ('중랑구')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS favorites (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  place_id TEXT NOT NULL,
  place_name VARCHAR(255) NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  category VARCHAR(100) NOT NULL DEFAULT 'tour',
  image_url TEXT NOT NULL DEFAULT '',
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  place_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, place_id)
);

CREATE INDEX IF NOT EXISTS favorites_user_created_idx ON favorites (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS place_reviews (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  place_id TEXT NOT NULL,
  place_name TEXT NOT NULL DEFAULT '',
  rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  content TEXT NOT NULL CHECK (char_length(content) <= 1000),
  image_url TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE place_reviews ADD COLUMN IF NOT EXISTS place_name TEXT NOT NULL DEFAULT '';
ALTER TABLE place_reviews ADD COLUMN IF NOT EXISTS image_url TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS place_reviews_place_created_idx
  ON place_reviews (place_id, created_at DESC);
CREATE INDEX IF NOT EXISTS place_reviews_user_created_idx
  ON place_reviews (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS place_reviews_created_idx ON place_reviews (created_at DESC);

UPDATE place_reviews AS review
SET place_name = favorite.place_name
FROM favorites AS favorite
WHERE review.user_id = favorite.user_id
  AND review.place_id = favorite.place_id
  AND review.place_name = '';
