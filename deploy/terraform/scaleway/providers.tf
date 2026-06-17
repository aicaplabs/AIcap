# Terraform + provider pinning.
#
# Auth is picked up from ~/.config/scw/config.yaml — the same file the
# `scw` CLI uses. No need to duplicate access_key / secret_key here.
# The provider falls back to SCW_* env vars if the config is missing.

terraform {
  required_version = ">= 1.5"

  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.40"
    }
  }
}

provider "scaleway" {
  region     = var.region
  zone       = var.zone
  project_id = var.project_id
}
