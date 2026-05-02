# AIcap Helm chart

Self-hosted deployment of the AIcap backend for Kubernetes. Targets the
"Enterprise / Sovereign tier" use case described in the project blueprint:
data stays in your cluster, the binary connects to *your* PostgreSQL,
and Stripe / Supabase secrets stay under your control.

## What this chart deploys

- A single `Deployment` running the `aicap` HTTP API (Go, distroless,
  non-root, read-only root filesystem)
- A `Service` (ClusterIP by default) on port 80 → container 8080
- An optional `Ingress` (disabled by default — bring your own controller)
- A `ConfigMap` for non-secret config (CORS origin, log level, port,
  Stripe price ID, migration mode)
- A `Secret` for `SUPABASE_DB_URL` / `SUPABASE_JWT_SECRET` /
  `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` — or pull from an
  externally-managed Secret via `secrets.existingSecret`
- An optional `HorizontalPodAutoscaler`
- An optional `PodDisruptionBudget`
- An optional pre-upgrade `Job` that runs `aicap --migrate` before the
  Deployment rolls (alternative to in-pod migration on startup)

## What this chart does **not** deploy

- **PostgreSQL** — bring your own. AIcap is designed to run against
  Supabase, RDS, Cloud SQL, or an in-cluster CloudNativePG cluster.
  Bundling Postgres into the same chart would conflict with the
  durable-storage choices each operator should make explicitly.
- **Frontend** — the React dashboard is a static site. Host it on
  Vercel, Cloudflare Pages, or as a separate `Deployment` + `Ingress`.
  The chart's `viteFrontendUrl` value is the CORS allowlist for that
  origin.

## Quick start

```bash
helm install aicap ./deploy/helm/aicap \
  --namespace aicap --create-namespace \
  --set secrets.supabaseDbUrl='postgres://aicap:secret@db.example.com:5432/aicap?sslmode=require' \
  --set secrets.supabaseJwtSecret='your-hs256-secret' \
  --set secrets.stripeSecretKey='sk_live_…' \
  --set secrets.stripeWebhookSecret='whsec_…' \
  --set config.viteFrontendUrl='https://aicap.your-corp.com'
```

Better: `helm install -f my-values.yaml` with the secret block populated
by sealed-secrets or external-secrets.

## Probes

The chart wires `/livez` and `/readyz` (Wave 4 split):

- `/livez` always returns 200 if the process can serve. A failing
  database **does not** trigger a pod restart — we want the orchestrator
  to leave the pod running and fix DNS / DB / network instead of
  restart-looping.
- `/readyz` returns 503 when the DB ping fails so the LB pulls the
  pod out of rotation.

## Migrations

Two modes — pick one and disable the other:

| Mode | When to use | How |
|---|---|---|
| Auto on startup (default) | Single-tenant, simple deployments | `config.runMigrations=true` |
| Pre-upgrade Helm hook Job | Multi-replica, want migration failure to block the rollout | `config.runMigrations=false` + `migrationJob.enabled=true` |

The `Job` runs `aicap --migrate`, exits, and is GC'd by Helm via
`hook-delete-policy: hook-succeeded` plus a `ttlSecondsAfterFinished`.

## Security defaults

- Runs as non-root (uid 65532) with `readOnlyRootFilesystem: true`
- All capabilities dropped, `allowPrivilegeEscalation: false`
- `automountServiceAccountToken: false` — the binary doesn't talk to
  the Kubernetes API
- `seccompProfile: RuntimeDefault`
- A throwaway `emptyDir` is mounted at `/tmp` to satisfy stdlib helpers
  that may write under read-only root

## Upgrading

`helm upgrade` will roll the pods automatically when ConfigMap or Secret
content changes — the chart hashes their rendered manifests into pod
annotations, so a value change yields a new pod template hash.

## Roadmap

- Optional `ServiceMonitor` for Prometheus when AIcap exposes `/metrics`
- Optional `NetworkPolicy` (currently delegated to the cluster's default)
- Helm test hook that curls `/livez` post-install
