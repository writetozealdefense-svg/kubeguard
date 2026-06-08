// Command kubectl-kubeguard is the kubectl plugin entrypoint. Installed on PATH,
// it is invoked as `kubectl kubeguard ...` and shares the kubeguard CLI, so
// `kubectl kubeguard scan --live` scans the current kube context read-only.
package main

import (
	"os"

	"github.com/kubeguard/kubeguard/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
