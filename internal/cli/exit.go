package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func isCodedError(err error, target **codedError) bool { return errors.As(err, target) }

// codedError carries a specific process exit code (e.g. the --fail-on gate),
// distinguishing an expected gate breach from a runtime failure.
type codedError struct {
	code int
	msg  string
}

func (e *codedError) Error() string { return e.msg }

func gateBreach(threshold api.Severity, n int) *codedError {
	return &codedError{
		code: exitGateHit,
		msg:  fmt.Sprintf("--fail-on %s: %d finding(s) at or above threshold", threshold, n),
	}
}

// isTerminal reports whether f is an interactive terminal (a character device).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func parseSeverity(s string) (api.Severity, error) {
	switch api.Severity(s) {
	case api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow:
		return api.Severity(s), nil
	default:
		return "", fmt.Errorf("invalid severity %q (want critical|high|medium|low)", s)
	}
}

func countAtOrAbove(findings []api.Finding, threshold api.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity.Rank() >= threshold.Rank() {
			n++
		}
	}
	return n
}
