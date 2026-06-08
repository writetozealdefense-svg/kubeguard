package cli

import (
	"log/slog"
	"os"
	"os/signal"

	wh "github.com/kubeguard/kubeguard/internal/webhook"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes/scheme"
	crwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func newWebhookCmd() *cobra.Command {
	var (
		host     string
		port     int
		certDir  string
		path     string
		failOpen bool
	)
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Run the validating admission webhook",
		Long: "Serve a validating admission webhook that denies pods violating the restricted " +
			"profile (privileged, hostPath, hostNetwork/PID/IPC, run-as-root, dangerous " +
			"capabilities). TLS certs are read from --cert-dir (provision via cert-manager).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			validator := wh.NewValidator(admission.NewDecoder(scheme.Scheme), wh.Config{FailOpen: failOpen})
			srv := crwebhook.NewServer(crwebhook.Options{Host: host, Port: port, CertDir: certDir})
			srv.Register(path, &admission.Webhook{Handler: validator})

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			slog.Info("kubeguard webhook serving", "port", port, "path", path, "failOpen", failOpen)
			return srv.Start(ctx)
		},
	}
	f := cmd.Flags()
	f.StringVar(&host, "host", "", "host to bind (default all interfaces)")
	f.IntVar(&port, "port", 9443, "port to serve TLS on")
	f.StringVar(&certDir, "cert-dir", "/tmp/k8s-webhook-server/serving-certs", "directory with tls.crt and tls.key")
	f.StringVar(&path, "path", "/validate-pods", "URL path to serve the webhook on")
	f.BoolVar(&failOpen, "fail-open", false, "admit pods when evaluation fails (default fail-closed)")
	return cmd
}
