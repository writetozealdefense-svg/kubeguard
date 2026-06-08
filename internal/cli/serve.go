package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/internal/loader/live"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/internal/server"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var (
		addr         string
		input        string
		profile      string
		schedule     string
		historyPath  string
		kubeContext  string
		assumeBreach bool
		liveMode     bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the KubeGuard service: REST API, dashboard, metrics, scheduler",
		Long: "Serve /v1/scan, /v1/findings, /v1/posture, an HTML dashboard, Prometheus " +
			"/metrics, and /healthz + /readyz. Optionally re-scan on a cron schedule.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loader, err := buildLoader(input, liveMode, kubeContext)
			if err != nil {
				return err
			}
			var store history.Store
			if historyPath != "" {
				store, err = history.Open(historyPath)
				if err != nil {
					return fmt.Errorf("open history: %w", err)
				}
				defer func() { _ = store.Close() }()
			}
			s, err := server.New(server.Config{
				Loader:       loader,
				Profile:      profile,
				AssumeBreach: assumeBreach,
				Schedule:     schedule,
				Store:        store,
			})
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			return s.Start(ctx, addr)
		},
	}
	f := cmd.Flags()
	f.StringVar(&addr, "addr", ":8080", "address to listen on")
	f.StringVarP(&input, "input", "i", "", "manifest path to scan (offline mode)")
	f.StringVarP(&profile, "profile", "p", "zeal-default", "check profile: cis|zeal-default")
	f.StringVar(&schedule, "schedule", "", "cron schedule for recurring scans, e.g. \"0 * * * *\"")
	f.StringVar(&historyPath, "history", "", "history store path (.sqlite/.db/.kgdb → SQLite, else JSONL)")
	f.BoolVar(&assumeBreach, "assume-breach", false, "seed every workload as reachable from an in-cluster foothold")
	f.BoolVar(&liveMode, "live", false, "scan a live cluster read-only instead of files")
	f.StringVar(&kubeContext, "context", "", "kubeconfig context to use with --live")
	return cmd
}

func buildLoader(input string, liveMode bool, kubeContext string) (server.Loader, error) {
	if liveMode {
		return func(ctx context.Context) ([]model.Resource, string, error) {
			cs, err := live.NewClientset(kubeContext)
			if err != nil {
				return nil, "", err
			}
			rs, err := live.Load(ctx, cs)
			return rs, "live cluster", err
		}, nil
	}
	if input == "" {
		return nil, fmt.Errorf("serve requires --input or --live")
	}
	return func(_ context.Context) ([]model.Resource, string, error) {
		rs, err := offline.Load(input)
		if err != nil {
			return nil, "", fmt.Errorf("load %q: %w", input, err)
		}
		return rs, input, nil
	}, nil
}
