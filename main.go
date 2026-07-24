package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aicap/pkg/api"
	"aicap/pkg/compliance"
	"aicap/pkg/finops"
	"aicap/pkg/httplog"
	"aicap/pkg/imagescan"
	"aicap/pkg/migrate"
	"aicap/pkg/scanner"
	"aicap/pkg/types"

	_ "github.com/lib/pq"
)

func main() {
	// --migrate runs schema migrations against SUPABASE_DB_URL and exits.
	// Intended for use as a pre-deploy step or a one-shot local command. We
	// also auto-run migrations at server boot when RUN_MIGRATIONS=true, but a
	// dedicated subcommand is useful for CI pipelines that want to fail the
	// deploy before the new binary starts taking traffic.
	if len(os.Args) > 1 && os.Args[1] == "--migrate" {
		dbURL := os.Getenv("SUPABASE_DB_URL")
		if dbURL == "" {
			log.Fatal("--migrate requires SUPABASE_DB_URL to be set")
		}
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			log.Fatalf("ping db: %v", err)
		}
		if err := migrate.Apply(db); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		fmt.Println("migrations applied")
		return
	}

	// Headless CLI Mode for CI/CD Pipelines
	if len(os.Args) > 1 && os.Args[1] == "--cli" {
		opts := parseCLIArgs(os.Args[2:])
		scanDir, imageRefs, tarballPaths, wantCycloneDX :=
			opts.ScanDir, opts.ImageRefs, opts.TarballPaths, opts.WantCycloneDX
		fmt.Printf("Running AIcap in CI/CD CLI mode on directory: %s\n", scanDir)
		loadRemoteCatalogs()
		bom := scanner.PerformScan(scanDir)

		// Wave 10 — daemonless container-image scanning. Either
		// flag may be repeated, so a pipeline that builds + saves
		// a tarball AND wants to cross-check against the most
		// recently pushed tag can pass both. Failures (unreachable
		// registry, malformed tarball) are surfaced as warnings
		// without aborting the directory scan that already ran.
		if len(imageRefs) > 0 || len(tarballPaths) > 0 {
			fmt.Printf("Scanning %d container image(s) and %d tarball(s)\n", len(imageRefs), len(tarballPaths))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			imgDeps, scannedImages, imgErrs := imagescan.ScanRefs(ctx, imageRefs, tarballPaths)
			cancel()
			for _, e := range imgErrs {
				fmt.Printf("[-] Warning: container-image scan: %s\n", e)
			}
			bom.Dependencies = append(bom.Dependencies, imgDeps...)
			bom.ScannedImages = append(bom.ScannedImages, scannedImages...)
		}

		// Pull exact repository and commit data from GitHub Actions environment
		if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
			bom.ProjectName = repo
		}
		if sha := os.Getenv("GITHUB_SHA"); sha != "" {
			bom.CommitSha = sha
		}

		// Re-evaluate compliance after image findings are merged
		// so a high-risk model weight discovered in a layer flips
		// the BOM to "Action Required" the same as one found on
		// disk would. Mirrors PerformScan's posture loop.
		for _, dep := range bom.Dependencies {
			if dep.RiskLevel == "High" && bom.Compliance == "Passed" {
				bom.Compliance = "Action Required (Annex IV Documentation Missing)"
				break
			}
		}

		bomJSON, _ := json.MarshalIndent(bom, "", "  ")

		if wantCycloneDX {
			cdx := compliance.GenerateCycloneDXBOM(bom)
			cdxJSON, _ := json.MarshalIndent(cdx, "", "  ")
			fmt.Println(string(cdxJSON))
		} else {
			fmt.Println(string(bomJSON))
		}

		// Article 9 risk register + Annex IV draft (Wave 16).
		//
		// Both were previously computed only inside /api/save-proof, so a
		// free CLI run emitted neither — while action.yml and the
		// Marketplace listing promised "AI-BOM, risk register, and Annex
		// IV documentation on every push". Both are pure functions that
		// need no server, and the paid boundary is the hosted ledger,
		// the shareable report, and history — none of which this gives
		// away. § 5 of a locally generated document states plainly that
		// it is unattested.
		if !opts.NoAnnexIV {
			register := compliance.ComputeRiskRegister(bom)

			// OSV enrichment runs from the caller's own runner against a
			// public API. Opt out with AICAP_OSV_DISABLED=true; the
			// register still renders from the local catalog.
			if osvClient := compliance.NewOSVClient(); osvClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				compliance.EnrichWithOSV(ctx, &register, bom, osvClient)
				cancel()
			}

			annexIV := compliance.GenerateAnnexIVMarkdownWithAttestation(
				bom, register, types.Attestation{Anchored: false})

			fmt.Printf("\n[+] Article 9 risk register: %d finding(s) — High: %d, Medium: %d, Low: %d\n",
				register.Summary.Total, register.Summary.High,
				register.Summary.Medium, register.Summary.Low)
			for _, f := range register.Findings {
				for _, v := range f.LiveVulns {
					if v.FixedVersion != "" {
						fmt.Printf("    %s %s — %s — fixed in %s\n",
							f.Component, f.Version, v.ID, v.FixedVersion)
					}
				}
			}

			if opts.AnnexIVPath != "" {
				if err := os.WriteFile(opts.AnnexIVPath, []byte(annexIV), 0o644); err != nil {
					fmt.Printf("[-] Warning: could not write Annex IV draft to %s: %v\n", opts.AnnexIVPath, err)
				} else {
					fmt.Printf("[+] Annex IV draft written to %s (unattested — see § 5)\n", opts.AnnexIVPath)
				}
			} else {
				fmt.Println("[+] Annex IV draft available — pass --annex-iv <path> to write it out.")
			}
		}

		// Phase 7: Sync to SaaS if Pro API Key is present
		apiKey := os.Getenv("AICAP_API_KEY")

		if apiKey != "" {
			fmt.Println("\n[+] Pro API Key detected. Syncing AI-BOM and Proof Drill to AIcap Cloud...")
			apiURL := os.Getenv("AICAP_API_URL")
			if apiURL == "" {
				// EU-hosted backend (Wave 13 — Scaleway, fr-par/Paris).
				// Overridable via AICAP_API_URL. Switch to the api.aicap.dev
				// custom domain here once it's wired, so a binary release
				// pins the stable domain rather than the .scw.cloud URL.
				apiURL = "https://aicap9ceb68db-aicap-backend.functions.fnc.fr-par.scw.cloud/api/save-proof"
			}
			req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(bomJSON))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+apiKey)
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					fmt.Println("[-] Warning: Failed to sync with AIcap Cloud (Is the server reachable?).")
				} else {
					fmt.Println(syncStatusMessage(resp.StatusCode))
					resp.Body.Close()
				}
			}
		}

		// Wave 12: differentiate exit codes so CI tooling can react
		// differently to "high-risk dep, no policy" (exit 1) vs an
		// explicit .aicap.yml policy breach (exit 2). Allows pipelines
		// to skip notification noise on warnings while still failing
		// loudly on blocker-severity violations.
		exitCode := complianceExitCode(bom)

		// README badge snippet: printed after the verdict so it shows
		// the posture of this scan. Every badge in a customer README
		// links back to aicap.dev — organic distribution.
		fmt.Printf("\n[+] Add the compliance badge to your README:\n    %s\n", badgeMarkdown(bom))

		os.Exit(exitCode)
	}

	httplog.Init()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info("starting AIcap server", slog.String("port", port))

	var db *sql.DB
	isCloudSaaS := false

	// Connect to Supabase
	dbURL := os.Getenv("SUPABASE_DB_URL")
	if dbURL != "" {
		isCloudSaaS = true
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			slog.Error("opening database", slog.Any("error", err))
			os.Exit(1)
		}
		if err = db.Ping(); err != nil {
			slog.Error("connecting to database", slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("connected to Supabase PostgreSQL")

		// RUN_MIGRATIONS=true tells the server to apply any pending schema
		// migrations before it starts accepting traffic. Opt-in (not default)
		// because some deployment flows prefer a separate `aicap --migrate`
		// step in CI so a bad migration fails the pipeline rather than a
		// running pod. Safe to enable on the staging/Render setup where a
		// single instance boots on each deploy.
		if os.Getenv("RUN_MIGRATIONS") == "true" {
			if err := migrate.Apply(db); err != nil {
				slog.Error("applying migrations", slog.Any("error", err))
				os.Exit(1)
			}
		}
	} else {
		if os.Getenv("RENDER") == "true" || os.Getenv("VERCEL") == "true" {
			slog.Error("SUPABASE_DB_URL not set in cloud environment — database required for SaaS features")
			os.Exit(1)
		}
		slog.Warn("SUPABASE_DB_URL not set; running without a database")
		db = nil
	}

	// AICAP_GPU_COSTS_URL: optional remote catalog that replaces the embedded
	// gpu_costs.json. Allows pricing data to be refreshed without a binary
	// release. Falls back to the embedded catalog on any fetch or parse error.
	if gpuCostsURL := os.Getenv("AICAP_GPU_COSTS_URL"); gpuCostsURL != "" {
		if err := finops.LoadCatalogFromURL(gpuCostsURL); err != nil {
			slog.Warn("remote GPU cost catalog unavailable, using embedded catalog",
				slog.String("url", gpuCostsURL),
				slog.Any("error", err))
		} else {
			slog.Info("loaded remote GPU cost catalog", slog.String("url", gpuCostsURL))
		}
	}

	loadRemoteCatalogs()

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, db, isCloudSaaS)

	// Wrap the mux in request-ID + logger middleware so every handler call
	// produces structured log lines correlated by request_id.
	handler := httplog.Middleware(mux)

	// Timeouts are set to sane production values. Without them a slow client
	// (or a misbehaving Stripe webhook retry) can hold a goroutine open
	// indefinitely. Write timeout is generous to cover the largest expected
	// response (a full proof-drill ledger page).
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: catch SIGINT/SIGTERM (Render sends SIGTERM before
	// redeploy), stop accepting new connections, and give in-flight requests
	// up to 25s to finish. We intentionally pick a timeout shorter than
	// Render's 30s kill window so our own log line about which requests we
	// abandoned still makes it out before the process dies.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		slog.Error("server exited", slog.Any("error", err))
		os.Exit(1)
	case sig := <-stop:
		slog.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed; forcing close", slog.Any("error", err))
		_ = srv.Close()
	} else {
		slog.Info("server shut down cleanly")
	}
	if db != nil {
		_ = db.Close()
	}
}

// loadRemoteCatalogs applies an optional remote refresh of the detection
// catalogs (AI libraries, model literals, model families, model
// licences) named by AICAP_CATALOG_URL.
//
// Detection quality is a function of catalog freshness, and tying that to
// release cadence is how a scanner ends up reporting that a codebase
// using this quarter's models contains no AI components. This is the
// same contract pkg/finops uses for GPU pricing: fetch once at startup,
// keep the embedded catalogs on any failure.
//
// Diagnostics go to slog (stderr) rather than stdout — CLI stdout is
// parsed as JSON by the GitHub Action and must stay clean.
func loadRemoteCatalogs() {
	url := os.Getenv("AICAP_CATALOG_URL")
	if url == "" {
		return
	}
	applied, err := scanner.LoadCatalogsFromURL(url)
	if err != nil {
		slog.Warn("remote detection catalog unavailable, using embedded catalogs",
			slog.String("url", url),
			slog.Any("error", err))
		return
	}
	slog.Info("loaded remote detection catalogs",
		slog.String("url", url),
		slog.Any("catalogs", applied))
}

// complianceExitCode maps the post-scan BOM state to a CI exit code.
// The contract (Wave 12):
//
//	0 — scan passed; pipeline approved
//	1 — non-policy compliance failure (e.g. high-risk dependency with
//	    no matching mitigation, or no .aicap.yml on file)
//	2 — explicit .aicap.yml policy breach with at least one Blocker-
//	    severity violation (blocked model, allowlist miss, BlockOnHighRisk)
//
// Policy *warnings* (missing license, license not in allowlist) do not
// trigger exit 2 on their own — they're surfaced in the BOM but the
// pipeline keeps running. CI tooling can grep the JSON output if it
// wants to fail on warnings too.
func complianceExitCode(bom types.AIBOM) int {
	hasBlocker := false
	for _, v := range bom.PolicyViolations {
		if v.Severity == "Blocker" {
			hasBlocker = true
			break
		}
	}
	if hasBlocker {
		fmt.Println("\n[!] Policy breach detected. .aicap.yml Blocker rule(s) tripped — failing pipeline (exit 2).")
		for _, v := range bom.PolicyViolations {
			if v.Severity == "Blocker" {
				fmt.Printf("    - [%s] %s\n", v.Rule, v.Description)
			}
		}
		return 2
	}
	if bom.Compliance != "Passed" {
		fmt.Println("\n[!] Compliance scan failed. High-risk dependencies detected without active mitigation. Blocking pipeline.")
		return 1
	}
	fmt.Println("\n[+] Compliance scan passed. Pipeline approved.")
	return 0
}

// syncStatusMessage maps the save-proof HTTP status to the line shown
// in the CI log. Both 201 (new ledger entry) and 200 (Wave 6
// idempotent replay of a commit already recorded) are success — a
// workflow re-run on the same commit must not read as a sync failure.
// Known rejections name their cause instead of blaming connectivity.
func syncStatusMessage(statusCode int) string {
	switch statusCode {
	case http.StatusCreated:
		return "[+] Successfully synced Immutable Proof Drill to your dashboard!"
	case http.StatusOK:
		return "[+] Proof Drill for this commit is already in your ledger (idempotent re-run) — nothing new to record."
	case http.StatusPaymentRequired:
		return "[-] Warning: Sync rejected — free-tier scan quota exhausted (HTTP 402). Upgrade to Pro or wait for the rolling 30-day window to free a slot."
	case http.StatusUnauthorized:
		return "[-] Warning: Sync rejected — API key invalid or revoked (HTTP 401). Rotate the key in your dashboard and update the CI secret."
	default:
		return fmt.Sprintf("[-] Warning: Failed to sync with AIcap Cloud (HTTP %d).", statusCode)
	}
}

// badgeMarkdown renders a shields.io badge snippet reflecting the scan
// posture, mirroring the complianceExitCode contract: Blocker policy
// violations outrank a non-Passed posture, which outranks "passing".
// Colors follow CI badge idiom (green/amber/red) so the badge reads at
// a glance in a README.
func badgeMarkdown(bom types.AIBOM) string {
	message, color := "passing", "10b981"
	for _, v := range bom.PolicyViolations {
		if v.Severity == "Blocker" {
			message, color = "policy%20breach", "ef4444"
			break
		}
	}
	if message == "passing" && bom.Compliance != "Passed" {
		message, color = "action%20required", "f59e0b"
	}
	return fmt.Sprintf(
		"[![EU AI Act — scanned by AIcap](https://img.shields.io/badge/EU%%20AI%%20Act-%s-%s)](https://aicap.dev)",
		message, color,
	)
}

// parseCLIArgs parses the --cli subcommand's tail (everything after
// the "--cli" token). The first positional argument is the scan
// cliOptions is the parsed form of the `--cli` argument list. A struct
// rather than a return tuple because the flag set has outgrown what is
// readable as positional results.
type cliOptions struct {
	ScanDir       string
	ImageRefs     []string
	TarballPaths  []string
	WantCycloneDX bool
	// AnnexIVPath, when non-empty, is where the Annex IV markdown draft
	// is written. Empty means "don't write a file"; the draft is still
	// generated and summarised on stdout.
	AnnexIVPath string
	// NoAnnexIV suppresses Annex IV generation entirely, for pipelines
	// that only want the BOM and don't want the OSV lookups that
	// enrichment performs.
	NoAnnexIV bool
}

// directory (defaults to "."). Recognised flags:
//
//	--image <ref>      Remote registry reference. Repeatable.
//	--image-tar <path> Local docker-save tarball. Repeatable.
//	--cyclonedx        Emit CycloneDX-formatted SBOM instead of AICAP JSON.
//	--annex-iv <path>  Write the Annex IV markdown draft to <path>.
//	--no-annex-iv      Skip Annex IV generation (and its OSV lookups).
//
// Unknown flags are ignored to preserve forward compatibility with
// the GitHub Action wrapper: a new action.yml release can pass new
// flags to an older binary without breaking the pipeline.
func parseCLIArgs(args []string) cliOptions {
	opts := cliOptions{ScanDir: "."}
	sawDir := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--image":
			if i+1 < len(args) {
				opts.ImageRefs = append(opts.ImageRefs, args[i+1])
				i++
			}
		case "--image-tar":
			if i+1 < len(args) {
				opts.TarballPaths = append(opts.TarballPaths, args[i+1])
				i++
			}
		case "--cyclonedx":
			opts.WantCycloneDX = true
		case "--annex-iv":
			if i+1 < len(args) {
				opts.AnnexIVPath = args[i+1]
				i++
			}
		case "--no-annex-iv":
			opts.NoAnnexIV = true
		default:
			if strings.HasPrefix(arg, "--") {
				// Unknown flag — skip it AND its value if the
				// next token looks like a value (not another
				// flag, not the trailing arg list). Keeps the
				// CLI forward-compatible with newer action.yml
				// versions that might pass flags the binary
				// doesn't yet recognise.
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
					i++
				}
				continue
			}
			if !sawDir {
				opts.ScanDir = arg
				sawDir = true
			}
		}
	}
	return opts
}
