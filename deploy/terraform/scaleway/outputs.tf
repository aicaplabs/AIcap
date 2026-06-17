output "registry_endpoint" {
  value       = scaleway_registry_namespace.aicap.endpoint
  description = "Push images here. Example: docker tag aicap:latest $(terraform output -raw registry_endpoint)/aicap:latest"
}

output "registry_image_full" {
  value       = "${scaleway_registry_namespace.aicap.endpoint}/aicap:${var.image_tag}"
  description = "Full image reference the container deploys from. Useful for double-checking the push target before docker push."
}

output "container_url" {
  # public_endpoint already includes the scheme (https://...). Older
  # provider versions exposed `domain_name` (hostname only); that field
  # was deprecated in 2.7x.
  value       = scaleway_container.backend.public_endpoint
  description = "Public URL of the backend. Use this as the frontend's API base in VITE_API_BASE_URL (or equivalent)."
}

output "container_status" {
  value       = scaleway_container.backend.status
  description = "Current container status. 'ready' = healthy. 'error' / 'creating' / 'pending' during deploys."
}
