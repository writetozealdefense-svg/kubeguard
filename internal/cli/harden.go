package cli

import (
	"fmt"

	"github.com/kubeguard/kubeguard/internal/harden"
	"github.com/spf13/cobra"
)

func newHardenCmd() *cobra.Command {
	var (
		outDir string
		opts   harden.Options
	)
	cmd := &cobra.Command{
		Use:   "harden",
		Short: "Emit a hardened baseline manifest bundle",
		Long: "Generate a least-privilege baseline bundle (PSA, default-deny NetworkPolicy, " +
			"scoped RBAC, Kyverno/Gatekeeper policies, a hardened Deployment, and a checklist). " +
			"Applying it and re-scanning yields zero findings.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			written, err := harden.Write(outDir, opts)
			if err != nil {
				return fmt.Errorf("emit bundle: %w", err)
			}
			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "Wrote %d files to %s:\n", len(written), outDir); err != nil {
				return err
			}
			for _, p := range written {
				if _, err := fmt.Fprintf(out, "  %s\n", p); err != nil {
					return err
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&outDir, "output", "o", "kubeguard-baseline", "directory to write the bundle into")
	f.StringVar(&opts.Namespace, "namespace", "", "target namespace (default: secure-app)")
	f.StringVar(&opts.App, "app", "", "workload/app name (default: app)")
	f.StringVar(&opts.Image, "image", "", "digest-pinned image (default: a placeholder digest)")
	f.StringVar(&opts.ServiceAccount, "service-account", "", "service account name (default: app-sa)")
	return cmd
}
