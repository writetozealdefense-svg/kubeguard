package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kubeguard/kubeguard/internal/analyzer"
	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/compliance"
	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/internal/loader/live"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/internal/policy"
	"github.com/kubeguard/kubeguard/internal/report"
	"github.com/kubeguard/kubeguard/internal/waiver"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/spf13/cobra"
)

type scanParams struct {
	input        string
	format       string
	profileName  string
	output       string
	assumeBreach bool
	failOn       string
	historyPath  string
	watch        bool
	live         bool
	kubeContext  string
	waiversPath  string
	policyPath   string
}

func newScanCmd() *cobra.Command {
	var p scanParams
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Kubernetes manifests for misconfigurations and attack paths",
		Long:  "Load Kubernetes resources from a path and report findings, attack paths, and compliance posture.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if p.watch {
				if p.live {
					return fmt.Errorf("--watch is not supported with --live")
				}
				return watchLoop(cmd, p)
			}
			return runScan(cmd, p)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&p.input, "input", "i", "", "path to a manifest file, directory, or snapshot (required)")
	f.StringVarP(&p.format, "format", "f", "console", "output format: console|json|sarif|asff|html|evidence|gitops")
	f.StringVarP(&p.profileName, "profile", "p", "zeal-default", "check profile: cis|zeal-default")
	f.StringVarP(&p.output, "output", "o", "", "write output to a file instead of stdout")
	f.BoolVar(&p.assumeBreach, "assume-breach", false, "seed every workload as reachable from an in-cluster foothold")
	f.StringVar(&p.failOn, "fail-on", "", "exit non-zero if any finding is at or above this severity: critical|high|medium|low")
	f.StringVar(&p.waiversPath, "waivers", "", "offline waiver file (YAML/JSON); actively-waived findings don't trip --fail-on but are logged")
	f.StringVar(&p.policyPath, "policy", "", "custom policy pack file or directory (CEL, kubeguard.io/policy/v1); runs alongside the built-in checks")
	f.StringVar(&p.historyPath, "history", "", "append this scan to a history store (.sqlite/.db/.kgdb → SQLite, else JSONL)")
	f.BoolVar(&p.watch, "watch", false, "re-scan when the input changes")
	f.BoolVar(&p.live, "live", false, "scan a live cluster read-only via kubeconfig instead of files")
	f.StringVar(&p.kubeContext, "context", "", "kubeconfig context to use with --live")
	return cmd
}

// loadResources ingests from a live cluster (read-only) or from files, and
// returns the resources plus a source label for the report.
func loadResources(cmd *cobra.Command, p scanParams) ([]model.Resource, string, error) {
	if p.live {
		cs, err := live.NewClientset(p.kubeContext)
		if err != nil {
			return nil, "", err
		}
		resources, err := live.Load(cmd.Context(), cs)
		if err != nil {
			return nil, "", fmt.Errorf("live scan: %w", err)
		}
		src := "live cluster"
		if p.kubeContext != "" {
			src = "live cluster (" + p.kubeContext + ")"
		}
		return resources, src, nil
	}
	if p.input == "" {
		return nil, "", fmt.Errorf("either --input/-i or --live is required")
	}
	resources, err := offline.Load(p.input)
	if err != nil {
		return nil, "", fmt.Errorf("load %q: %w", p.input, err)
	}
	return resources, p.input, nil
}

func runScan(cmd *cobra.Command, p scanParams) error {
	resources, source, err := loadResources(cmd, p)
	if err != nil {
		return err
	}
	var extra []analyzer.ExtraChecks
	if p.policyPath != "" {
		policies, err := policy.Load(p.policyPath)
		if err != nil {
			return err
		}
		extra = append(extra, policies.Evaluate)
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "loaded %d custom policies from %s\n", policies.Len(), p.policyPath)
	}
	rep, err := analyzer.Analyze(resources, p.profileName, p.assumeBreach, extra...)
	if err != nil {
		return err
	}
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	rep.Source = source
	findings := rep.Findings

	// Waiver-aware gating (K7): actively-waived findings still appear in the
	// report (transparency) but are excluded from the --fail-on gate. Every
	// applied waiver is logged so a suppression is never silent.
	var waiverSet *waiver.Set
	if p.waiversPath != "" {
		waiverSet, err = waiver.Load(p.waiversPath)
		if err != nil {
			return err
		}
	}

	var hist []history.Record
	if p.historyPath != "" {
		store, err := history.Open(p.historyPath)
		if err != nil {
			return fmt.Errorf("open history: %w", err)
		}
		defer func() { _ = store.Close() }()
		if err := store.Append(history.FromReport(rep)); err != nil {
			return err
		}
		if hist, err = store.All(); err != nil {
			return err
		}
	}

	if p.format == "evidence" {
		if err := exportEvidence(cmd, p, rep); err != nil {
			return err
		}
	} else {
		out := cmd.OutOrStdout()
		color := false
		if p.output != "" {
			fh, err := os.Create(p.output) //nolint:gosec // operator-specified output path
			if err != nil {
				return fmt.Errorf("create %q: %w", p.output, err)
			}
			defer func() { _ = fh.Close() }()
			out = fh
		} else if f, ok := out.(*os.File); ok {
			color = (p.format == "console" || p.format == "") && os.Getenv("NO_COLOR") == "" && isTerminal(f)
		}

		if err := render(out, p.format, rep, hist, color); err != nil {
			return err
		}
	}

	if p.failOn != "" {
		thr, err := parseSeverity(p.failOn)
		if err != nil {
			return err
		}
		blocking := findings
		if !waiverSet.Empty() {
			var waived []waiver.WaivedFinding
			blocking, waived = waiverSet.Partition(findings, time.Now().UTC())
			for _, wf := range waived {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "waived: %s %s (%s %s) until %s — %s\n",
					wf.Finding.ID, wf.Finding.Title, wf.Finding.Resource.Kind, resourceLoc(wf.Finding.Resource),
					wf.Entry.Expires, wf.Entry.Justification)
			}
		}
		if n := countAtOrAbove(blocking, thr); n > 0 {
			return gateBreach(thr, n)
		}
	}
	return nil
}

func resourceLoc(r api.ResourceRef) string {
	if r.Namespace != "" {
		return r.Namespace + "/" + r.Name
	}
	return r.Name
}

func render(out io.Writer, format string, rep api.Report, hist []history.Record, color bool) error {
	switch format {
	case "json":
		return report.JSON(out, rep)
	case "sarif":
		return report.SARIF(out, rep)
	case "asff":
		return report.ASFF(out, rep)
	case "html":
		return report.HTML(out, rep, hist)
	case "gitops":
		return report.GitOpsAnnotations(out, rep)
	case "console", "":
		return report.Console(out, rep, color)
	default:
		return fmt.Errorf("unknown format %q (want console|json|sarif|asff|html|evidence|gitops)", format)
	}
}

// exportEvidence writes one self-contained, offline HTML evidence pack per
// framework plus a machine-readable JSON sibling into the -o directory. Output
// is deterministic: filenames derive from the pack id and the single
// rep.GeneratedAt is the only wall-clock timestamp.
func exportEvidence(cmd *cobra.Command, p scanParams, rep api.Report) error {
	if p.output == "" {
		return fmt.Errorf("-f evidence requires -o <dir> (a directory to write evidence packs into)")
	}
	packs, err := compliance.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("load packs: %w", err)
	}
	prof, err := checks.ProfileByName(p.profileName)
	if err != nil {
		return err
	}
	evs := compliance.BuildEvidence(rep, packs, prof.RunnableIDs())

	if err := os.MkdirAll(p.output, 0o750); err != nil {
		return fmt.Errorf("create %q: %w", p.output, err)
	}
	for _, ev := range evs {
		if err := writeEvidenceFile(filepath.Join(p.output, ev.ID+".evidence.html"), func(w io.Writer) error {
			return report.EvidenceHTML(w, ev)
		}); err != nil {
			return err
		}
		if err := writeEvidenceFile(filepath.Join(p.output, ev.ID+".evidence.json"), func(w io.Writer) error {
			return report.EvidenceJSON(w, ev)
		}); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d evidence packs (HTML + JSON) to %s\n", len(evs), p.output)
	return nil
}

func writeEvidenceFile(path string, render func(io.Writer) error) error {
	fh, err := os.Create(path) //nolint:gosec // operator-specified output directory
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer func() { _ = fh.Close() }()
	if err := render(fh); err != nil {
		return err
	}
	return nil
}

// watchLoop re-runs the scan whenever the input's modification time advances,
// until the command context is cancelled. A gate breach is reported but does
// not stop watching; a real error does.
func watchLoop(cmd *cobra.Command, p scanParams) error {
	ctx := cmd.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last time.Time
	for {
		if fi, err := os.Stat(p.input); err == nil && fi.ModTime().After(last) {
			last = fi.ModTime()
			if err := runScan(cmd, p); err != nil {
				var ce *codedError
				if !isCodedError(err, &ce) {
					return err
				}
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), ce.msg)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
