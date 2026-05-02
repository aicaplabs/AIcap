-- Migration: idempotency on proof_drills by (user_id, commit_sha).
--
-- Why: a CI flake or re-run currently creates a second proof_drills row
-- for the same commit, producing duplicate audit entries with different
-- crypto_hashes (the BOM may differ slightly between runs because of
-- timestamps in the scanner output). Auditors then see two "proofs" for
-- the same commit and have no way to know which is canonical.
--
-- Fix: enforce one proof_drill per (user_id, commit_sha) at the DB
-- level, and have /api/save-proof short-circuit a retry by returning
-- the existing row's crypto_hash. The DB constraint is the backstop —
-- the application layer prefers the SELECT-first short-circuit so a
-- retry returns 200 OK with the existing hash instead of a 23505
-- unique-violation error.
--
-- Local-dev mode runs without auth and writes user_id = NULL. Postgres
-- treats NULLs as non-conflicting in UNIQUE indexes, which is the
-- behaviour we want here: local devs can re-run without hitting
-- production-grade idempotency. We use a partial index that excludes
-- NULL user_ids so the constraint applies only to authenticated rows.

-- 1. Deduplicate any existing collisions before adding the constraint.
--    Keep the earliest row per (user_id, commit_sha), drop the rest.
--    This will break the hash chain at the deletion points, but that
--    chain was already inconsistent (dup rows with different hashes)
--    so we're trading a visible break for a silent corruption — the
--    right call. /api/verify-chain will surface the legacy break and
--    new chains will not have this problem.
DELETE FROM proof_drills a
USING proof_drills b
WHERE a.id > b.id
  AND a.user_id = b.user_id
  AND a.commit_sha = b.commit_sha
  AND a.user_id IS NOT NULL;

-- 2. Partial unique index — applies to authenticated rows only.
--    Wrapped in DO block so re-runs against an already-migrated DB
--    don't fail on duplicate index name.
CREATE UNIQUE INDEX IF NOT EXISTS idx_proof_drills_user_commit_unique
    ON proof_drills(user_id, commit_sha)
    WHERE user_id IS NOT NULL;
