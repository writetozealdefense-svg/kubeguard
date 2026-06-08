// Command kubeguard is the CLI entrypoint for the KubeGuard scanner.
//
// It is intentionally thin: all command wiring and logic live in
// internal/cli. main maps the resulting exit code onto the process.
package main

import (
	"os"

	"github.com/kubeguard/kubeguard/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
