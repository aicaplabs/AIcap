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
		scanDir, imageRefs, tarballPaths, wantCycloneDX := parseCLIArgs(os.Args[2:])
		fmt.Printf("Running AIcap in CI/CD CLI mode on directory: %s\n", scanDir)
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

		// Phase 7: Sync to SaaS if Pro API Key is present
		apiKey := os.Getenv("AICAP_API_KEY")

		if apiKey != "" {
			fmt.Println("\n[+] Pro API Key detected. Syncing AI-BOM and Proof Drill to AIcap Cloud...")
			apiURL := os.Getenv("AICAP_API_URL")
			if apiURL == "" {
				apiURL = "https://aicap.onrender.com/api/save-proof"
			}
			req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(bomJSON))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+apiKey)
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil || resp.StatusCode != 201 {
					fmt.Println("[-] Warning: Failed to sync with AIcap Cloud (Is the server reachable?).")
				} else {
					fmt.Println("[+] Successfully synced Immutable Proof Drill to your dashboard!")
				}
			}
		}

		if bom.Compliance != "Passed" {
			fmt.Println("\n[!] Compliance scan failed. High-risk dependencies detected without active mitigation. Blocking pipeline.")
			os.Exit(1)
		}
		fmt.Println("\n[+] Compliance scan passed. Pipeline approved.")
		os.Exit(0)
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

// parseCLIArgs parses the --cli subcommand's tail (everything after
// the "--cli" token). The first positional argument is the scan
// directory (defaults to "."). Recognised flags:
//
//	--image <ref>      Remote registry reference. Repeatable.
//	--image-tar <path> Local docker-save tarball. Repeatable.
//	--cyclonedx        Emit CycloneDX-formatted SBOM instead of AICAP JSON.
//
// Unknown flags are ignored to preserve forward compatibility with
// the GitHub Action wrapper: a new action.yml release can pass new
// flags to an older binary without breaking the pipeline.
func parseCLIArgs(args []string) (scanDir string, imageRefs []string, tarballPaths []string, wantCycloneDX bool) {
	scanDir = "."
	sawDir := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--image":
			if i+1 < len(args) {
				imageRefs = append(imageRefs, args[i+1])
				i++
			}
		case "--image-tar":
			if i+1 < len(args) {
				tarballPaths = append(tarballPaths, args[i+1])
				i++
			}
		case "--cyclonedx":
			wantCycloneDX = true
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
				scanDir = arg
				sawDir = true
			}
		}
	}
	return scanDir, imageRefs, tarballPaths, wantCycloneDX
}
