# --- Scaleway placement --------------------------------------------------

variable "project_id" {
  type        = string
  description = "Scaleway Project UUID. The aicap-prod project from Wave-13 setup."
}

variable "region" {
  type        = string
  default     = "fr-par"
  description = "Scaleway region. fr-par (Paris) is the EU AI Act flagship — French SAS, EU-domiciled processor, lowest latency to Supabase eu-west-1 (Ireland)."
}

variable "zone" {
  type        = string
  default     = "fr-par-1"
  description = "Default Scaleway zone. Used by non-serverless resources (we have none today, but the provider wants it set)."
}

# --- Image -----------------------------------------------------------------

variable "image_tag" {
  type        = string
  default     = "latest"
  description = "Container image tag to deploy. Pin to v1.1.0 / v1.2.0 in prod; 'latest' is fine while iterating."
}

# --- Scaling -- free-tier knobs -------------------------------------------
# Defaults below keep you inside the Scaleway Serverless Containers free
# tier (400k vCPU-s + 1.6M GB-s/month) by scaling the container down to
# zero when idle. Cold start: ~2-4s for a Go binary.
#
# When real clients arrive, bump in terraform.tfvars:
#   min_scale = 1   # always-on, no cold starts
#   max_scale = 3   # autoscale ceiling under load

variable "min_scale" {
  type        = number
  default     = 0
  description = "Minimum container replicas. 0 = scale-to-zero (free tier). 1+ = always-on."
}

variable "max_scale" {
  type        = number
  default     = 1
  description = "Maximum container replicas. Keep at 1 for free tier; raise when traffic warrants."
}

variable "cpu_limit_mvcpu" {
  type    = number
  default = 512
  # Scaleway constraint: memory_limit_bytes must be between 1x and 4x the
  # mvCPU value (e.g. 512 mvCPU permits 512-2048 MB). We run a 1:1 ratio
  # (512 mvCPU / 512 MB) — plenty for a Go binary and the cheapest combo
  # that stays responsive. Bump both proportionally for heavier workloads.
  description = "vCPU limit in milli-vCPU. Must satisfy memory_limit_mb ∈ [cpu, 4*cpu]."
}

variable "memory_limit_mb" {
  type        = number
  default     = 512
  description = "Memory ceiling in MB. Matches the Helm chart's 512Mi limit. Must be ≥ cpu_limit_mvcpu and ≤ 4× it."
}

# --- App config (non-secret) ----------------------------------------------

variable "vite_frontend_url" {
  type        = string
  description = "CORS allowlist for the dashboard frontend. Comma-separated for multiple origins."
}

variable "stripe_price_id" {
  type        = string
  default     = "price_1Pdtg1E5iL2Zl43n5G4YhI9t"
  description = "Stripe price ID for the Pro subscription tier."
}

variable "log_level" {
  type        = string
  default     = "info"
  description = "slog log level. 'debug' for troubleshooting, 'info' for prod."
}

variable "run_migrations" {
  type        = string
  default     = "true"
  description = "When 'true', the pod runs embedded migrations on startup. Safe to leave on for single-tenant deploys."
}

# --- Secrets — NEVER commit terraform.tfvars -----------------------------
# These are written into Scaleway's KMS-encrypted secret_environment_variables
# and injected at container runtime. The Terraform state file still holds
# them in plaintext — keep tfstate gitignored and treat it like a credential.

variable "supabase_db_url" {
  type        = string
  sensitive   = true
  description = "Postgres connection string for Supabase eu-west-1. Use the connection-pooler URL (port 6543) unless you need session-mode."
}

variable "supabase_jwt_secret" {
  type        = string
  sensitive   = true
  description = "HS256 secret Supabase uses to sign session JWTs. Found in Supabase dashboard → Settings → API → JWT secret."
}

variable "stripe_secret_key" {
  type        = string
  sensitive   = true
  description = "Stripe API secret key. sk_live_... in prod, sk_test_... in staging."
}

variable "stripe_webhook_secret" {
  type        = string
  sensitive   = true
  default     = ""
  description = <<-EOT
    Stripe webhook signing secret (whsec_...). OPTIONAL — the backend has
    a fallback path (/api/verify-checkout calls Stripe directly) so
    checkouts work even when this is unset. However, subscription lifecycle
    events (cancellations, payment failures, tier downgrades) are ONLY
    delivered via webhook. Leaving this empty means cancelled subscribers
    silently stay on the Pro tier until manual intervention.

    Wire this up in the Stripe dashboard (Developers → Webhooks → add
    endpoint https://<container_url>/api/stripe-webhook) before onboarding
    your first paying user. See Wave 13 follow-ups.
  EOT
}

variable "ledger_signing_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = <<-EOT
    Base64 Ed25519 seed used to sign proof-drill ledger entries. Generate
    one with `aicap --gen-ledger-key`.

    OPTIONAL in the sense that the backend runs without it — entries are
    written unsigned and /api/verify-chain reports them as such. But the
    paid tier's central claim is that an auditor can verify a report
    without taking the customer's word for it, and an unsigned ledger
    cannot support that claim: the hash chain proves the rows are
    consistent with each other, not that this service wrote them. Anyone
    with write access to the database can recompute the whole chain.

    Keep it out of the database and out of version control. This variable
    lives in the gitignored terraform.tfvars; Scaleway stores it as a
    secret environment variable (encrypted at rest in KMS), which is what
    makes possession of the database insufficient to forge history.

    Rotation: setting a new key does not invalidate existing entries, but
    they can only be verified with the public key that signed them — so
    publish retired public keys rather than discarding them.
  EOT
}
