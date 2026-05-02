-- Migration: hash-chain anchoring on proof_drills.
--
-- Why: crypto_hash already proves a single row is internally consistent
-- (sha256 of commit + BOM + Annex IV), but a privileged SQL caller — a
-- compromised Supabase admin session, a rogue DBA, a leaked connection
-- string with write access — could silently delete or replace a historical
-- row and recompute its hash to match the new payload. Auditors would have
-- no way to tell the row had been altered.
--
-- We anchor each row to the previous one (per user_id) so any tampering
-- breaks the chain at every later row. Verification walks the chain and
-- reports the first link where stored hash != recomputed hash.
--
-- prev_hash is NULL on the genesis row of a user's chain. Existing rows
-- (from before this migration) are left with NULL — they form a "legacy"
-- prefix that was unchained at write time. /api/verify-chain treats those
-- as a single unverified anchor point so historical rows aren't reported
-- as tampered when in fact they were just written before the feature shipped.
ALTER TABLE proof_drills
    ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64);

-- Index supports the per-user "latest row" lookup that save-proof runs on
-- every insert to find the chain head. Composite (user_id, created_at DESC)
-- is what the query plans against.
CREATE INDEX IF NOT EXISTS idx_proof_drills_user_created_desc
    ON proof_drills(user_id, created_at DESC);
