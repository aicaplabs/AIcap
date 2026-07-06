-- Migration: shareable public report links.
--
-- Why: the Annex IV report only creates value when it reaches an
-- auditor, a customer's procurement team, or a notified body — none of
-- whom have an AIcap login. A proof drill owner can now mint an
-- unguessable share token; anyone holding the token can read that one
-- report (markdown + provenance) through a public, unauthenticated
-- endpoint. Every shared page carries AIcap branding, so shared
-- reports double as organic distribution.
--
-- Design:
--   * share_token stays NULL until the owner explicitly shares — no
--     report is ever public by default.
--   * The token is 32 random bytes hex-encoded (256 bits), generated
--     server-side with crypto/rand. It is a capability, not an ID:
--     possession grants read access to exactly one row.
--   * Partial unique index keeps the (majority) unshared rows out of
--     the index and lets the public lookup be an index scan.

ALTER TABLE proof_drills ADD COLUMN IF NOT EXISTS share_token TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_proof_drills_share_token
    ON proof_drills (share_token)
    WHERE share_token IS NOT NULL;
