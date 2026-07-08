// Package cli wires the kubeguard cobra command tree and shared concerns
// (logging, exit-code mapping) for every deployment mode.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Build metadata. Overridden at release time via:
//
//	-ldflags "-X github.com/kubeguard/kubeguard/internal/cli.version=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// logLevel is bound to the persistent --log-level flag.
var logLevel string

// Exit codes (ARCHITECTURE.md §17.3).
const (
	exitOK      = 0 // success / gate not breached
	exitError   = 1 // runtime error
	exitGateHit = 2 // --fail-on threshold breached (wired in later squads)
)

// NewRootCmd builds the kubeguard command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kubeguard",
		Short: "Kubernetes attack-surface, posture & compliance scanner",
		Long: "KubeGuard detects misconfigurations, chains them into attack paths, and " +
			"emits hardening guidance for Kubernetes workloads.\n" +
			"Offline-first, read-only against clusters, and free of telemetry.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return setupLogger(cmd)
		},
	}
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info",
		"log level: debug|info|warn|error")
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newHardenCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newDashboardCmd())
	root.AddCommand(newDashboardAdminCmd())
	root.AddCommand(newWebhookCmd())
	return root
}

// Execute runs the root command and maps the result to a process exit code.
func Execute() int {
	if err := NewRootCmd().ExecuteContext(context.Background()); err != nil {
		var ce *codedError
		if errors.As(err, &ce) {
			// An expected gate breach, not a runtime failure.
			fmt.Fprintln(os.Stderr, ce.msg)
			return ce.code
		}
		slog.Error("command failed", "err", err)
		return exitError
	}
	return exitOK
}

// setupLogger configures the default slog logger from the --log-level flag,
// writing structured logs to the command's stderr.
func setupLogger(cmd *cobra.Command) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("invalid --log-level %q: %w", logLevel, err)
	}
	handler := slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
	return nil
}
