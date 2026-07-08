package cli

import (
	"fmt"
	"os"

	"github.com/kubeguard/kubeguard/internal/dashboard/pg"
	"github.com/spf13/cobra"
)

// newDashboardAdminCmd groups out-of-band operator actions against the dashboard
// Postgres store — the air-gapped path for DSAR/DPDP execution that does not go
// through the HTTP API.
func newDashboardAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard-admin",
		Short: "Out-of-band operator actions against the dashboard Postgres store",
		Long: "Operator/DSAR actions executed directly against the Postgres store (no HTTP API): " +
			"tenant erasure for DPDP right-to-erasure requests, runnable in an air-gapped context.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newDeleteTenantCmd())
	return cmd
}

func newDeleteTenantCmd() *cobra.Command {
	var (
		tenant      string
		postgresDSN string
	)
	cmd := &cobra.Command{
		Use:   "delete-tenant",
		Short: "Hard-delete all of a tenant's data (DPDP right-to-erasure)",
		Long: "Erase every row belonging to a tenant (clusters, scans, history, lifecycle, audit) " +
			"from the Postgres store. Irreversible. Intended for out-of-band DSAR execution.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tenant == "" {
				return fmt.Errorf("--tenant is required")
			}
			if postgresDSN == "" {
				postgresDSN = os.Getenv("KUBEGUARD_POSTGRES_DSN")
			}
			if postgresDSN == "" {
				return fmt.Errorf("--postgres (or KUBEGUARD_POSTGRES_DSN) is required")
			}
			store, err := pg.Open(cmd.Context(), postgresDSN)
			if err != nil {
				return fmt.Errorf("postgres: %w", err)
			}
			defer store.Close()
			if err := store.DeleteTenant(cmd.Context(), tenant); err != nil {
				return fmt.Errorf("delete tenant %q: %w", tenant, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "erased all data for tenant %q\n", tenant)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&tenant, "tenant", "", "tenant id to erase (required)")
	f.StringVar(&postgresDSN, "postgres", "", "Postgres DSN (or KUBEGUARD_POSTGRES_DSN)")
	return cmd
}
