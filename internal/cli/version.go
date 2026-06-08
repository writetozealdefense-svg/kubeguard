package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// newVersionCmd prints build and runtime metadata.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date and runtime",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"kubeguard %s\n  commit: %s\n  built:  %s\n  go:     %s %s/%s\n",
				version, commit, date,
				runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
