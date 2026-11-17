-- Friendsgiving 2026 potluck: one row per dish someone is bringing.
CREATE TABLE IF NOT EXISTS items (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,      -- who is bringing it
  dish        TEXT NOT NULL,      -- what they are bringing
  category    TEXT NOT NULL,      -- main | side | dessert | drink | other
  qty         INTEGER NOT NULL,   -- how many (servings, bottles, trays...)
  note        TEXT NOT NULL DEFAULT '',
  pw_hash     TEXT,               -- PBKDF2 of the optional password, or NULL
  pw_salt     TEXT,
  creator     TEXT NOT NULL,      -- salted hash of the creator's IP (for limits only)
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- Edit tokens: a device that created (or unlocked) an entry keeps a random token.
-- Only its SHA-256 is stored.
CREATE TABLE IF NOT EXISTS tokens (
  token_hash  TEXT PRIMARY KEY,
  item_id     TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_item ON tokens(item_id);

-- Fixed-window counters for rate limits.
CREATE TABLE IF NOT EXISTS limits (
  key     TEXT PRIMARY KEY,   -- "<kind>:<ip hash>[:<item>]:<window>"
  count   INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
