# Scaleway Terraform module — AIcap EU backend

Provisions the production stack for the **Wave 13** EU sovereignty migration.

## What this creates

| Resource | Purpose |
|---|---|
| `scaleway_registry_namespace.aicap` | Private container registry at `rg.fr-par.scw.cloud/aicap` |
| `scaleway_container_namespace.aicap` | Logical grouping for serverless containers |
| `scaleway_container.backend` | The Go HTTP API, scale-to-zero by default |

Database stays on **Supabase eu-west-1 (Ireland)** — not managed by this module.

## Prerequisites

- `terraform >= 1.5`
- `scw` CLI configured at `~/.config/scw/config.yaml` (the provider reads from the same file)
- Docker running locally — needed for the one-time image build & push
- Your `terraform.tfvars` created from the template

## First deploy — staged apply

The container references an image that does not exist on the first apply. Use a
two-phase apply: registry first, image push next, container last.

```bash
cd deploy/terraform/scaleway
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars     # fill in project_id, secrets, vite_frontend_url

terraform init

# Phase 1 — create just the registry namespace.
terraform apply -target=scaleway_registry_namespace.aicap

# Phase 2 — build + push the image (from project root).
cd ../../..
REGISTRY=$(cd deploy/terraform/scaleway && terraform output -raw registry_endpoint)

docker build -t aicap:latest .
docker tag aicap:latest "$REGISTRY/aicap:latest"

# Log in to Scaleway Registry. Username can be anything; password is the
# Scaleway secret key from your IAM application API key.
docker login "$REGISTRY" -u nologin -p "$SCW_SECRET_KEY"

docker push "$REGISTRY/aicap:latest"

# Phase 3 — apply the rest (creates the container).
cd deploy/terraform/scaleway
terraform apply
```

After phase 3, `terraform output container_url` gives you the public URL —
something like `https://aicap-backend-aicap-xxxxx.functions.fnc.fr-par.scw.cloud`.

## Updating the image (subsequent deploys)

```bash
docker build -t aicap:v1.2.0 .
docker tag aicap:v1.2.0 "$REGISTRY/aicap:v1.2.0"
docker push "$REGISTRY/aicap:v1.2.0"

# Bump the tag and roll a new revision.
terraform apply -var image_tag=v1.2.0
```

Scaleway's deploy pulls the new image and rolls it in. Old revision is
kept for instant rollback via the console.

## Free tier → paid

Defaults (`min_scale=0`, `max_scale=1`) keep you on the free tier with
scale-to-zero. First request after idle takes ~2–4s (cold start).

When paying customers arrive, set in `terraform.tfvars`:

```hcl
min_scale = 1
max_scale = 3
```

Then `terraform apply`. Cost jumps to ~€20–25/month for always-on with
3-container ceiling.

## What's NOT in here (yet)

- **CI/CD** — image push is manual today. A follow-up GitHub Action will
  build + push to Scaleway Registry on every merge to `main`.
- **Custom domain + TLS** — Scaleway's `*.scw.cloud` URL ships with a valid
  cert. Custom domain via `scaleway_container_domain` is a future commit.
- **Frontend** — still on Vercel/Render. Static assets aren't data-sovereignty-
  critical; only the API backend was the gap.
