# =============================================================================
# AIcap — Scaleway EU production stack
#
# Wave-13 migration target: Render (US) → Scaleway Serverless Containers (Paris).
# Database stays on Supabase eu-west-1 (Ireland) — already EU-resident.
#
# Cost model:
#   min_scale=0 → effectively €0/month within the free tier (400k vCPU-s +
#   1.6M GB-s). Bump min_scale=1 when paying customers arrive (~€20-25/mo).
# =============================================================================

# --- Container Registry --------------------------------------------------
# Private namespace at rg.<region>.scw.cloud/aicap. The Serverless Container
# below pulls from this registry over Scaleway's internal network — no
# egress out to GHCR or Docker Hub, no US infrastructure in the deploy path.
resource "scaleway_registry_namespace" "aicap" {
  name        = "aicap"
  description = "AIcap backend container images (Wave 13 — EU sovereignty)"
  is_public   = false
  project_id  = var.project_id
  region      = var.region
}

# --- Serverless Container Namespace --------------------------------------
# Groups one or more containers under a shared config + IAM scope. We only
# have the backend today; staging / preview envs would be siblings here.
resource "scaleway_container_namespace" "aicap" {
  name        = "aicap"
  description = "AIcap backend serverless containers"
  project_id  = var.project_id
  region      = var.region
}

# --- Backend container ---------------------------------------------------
# The Go HTTP API. Public so the dashboard frontend + GitHub Action CLI
# can hit it directly; auth happens inside the app (Supabase JWT for
# dashboard routes, hashed API key for /api/save-proof).
resource "scaleway_container" "backend" {
  name         = "aicap-backend"
  description  = "AIcap Go HTTP API — Wave 13 EU migration"
  namespace_id = scaleway_container_namespace.aicap.id
  region       = var.region

  # Image — built locally and pushed to the registry above.
  # See deploy/terraform/scaleway/README.md for the staged-apply procedure.
  registry_image = "${scaleway_registry_namespace.aicap.endpoint}/aicap:${var.image_tag}"

  # Network
  port     = 8080
  protocol = "http1"
  privacy  = "public"

  # Resources — provider 2.7x deprecated memory_limit (MB) in favour of
  # memory_limit_bytes. We keep var.memory_limit_mb for human readability
  # and multiply here.
  cpu_limit          = var.cpu_limit_mvcpu
  memory_limit_bytes = var.memory_limit_mb * 1024 * 1024

  # Scaling — see variables.tf for the free-tier vs paid trade-off.
  min_scale = var.min_scale
  max_scale = var.max_scale

  # Request timeout (seconds). 60s comfortably covers the slowest scan-save
  # path; raise to 300 if a large repo's /api/save-proof ever times out.
  timeout = 60

  # Note: `deploy = true` used to be required to roll a new revision on
  # config change. Scaleway's provider 2.7x deploys automatically on every
  # diff, so the attribute is deprecated and was removed here.

  # --- Non-secret env vars -----------------------------------------------
  # NOTE: PORT is a RESERVED env var on Scaleway Serverless Containers —
  # it is injected automatically from the `port` field above (8080) and
  # cannot be set here. The app reads PORT at runtime and gets it from
  # Scaleway's injection, so no explicit entry is needed.
  environment_variables = {
    LOG_LEVEL         = var.log_level
    RUN_MIGRATIONS    = var.run_migrations
    VITE_FRONTEND_URL = var.vite_frontend_url
    STRIPE_PRICE_ID   = var.stripe_price_id
  }

  # --- Secrets (encrypted at rest in Scaleway's KMS) ---------------------
  secret_environment_variables = {
    SUPABASE_DB_URL       = var.supabase_db_url
    SUPABASE_JWT_SECRET   = var.supabase_jwt_secret
    STRIPE_SECRET_KEY     = var.stripe_secret_key
    STRIPE_WEBHOOK_SECRET = var.stripe_webhook_secret
  }
}
