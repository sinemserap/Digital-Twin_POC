-- Apply once to existing Part 1 databases before starting this version.
-- Current rights state is deliberately not reconstructed from historical claims.
ALTER TABLE subject ADD COLUMN restricted boolean NOT NULL DEFAULT false;
