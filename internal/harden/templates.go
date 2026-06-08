package harden

// All manifests are fully hardened: loading the bundle through the KubeGuard
// engine yields zero findings (ARCHITECTURE.md §11 acceptance).

const nsTemplate = `apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
`

const denyTemplate = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {{.Namespace}}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`

const dnsTemplate = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: {{.Namespace}}
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
`

const saTemplate = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{.ServiceAccount}}
  namespace: {{.Namespace}}
automountServiceAccountToken: false
`

const rbacTemplate = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{.App}}-reader
  namespace: {{.Namespace}}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{.App}}-reader-binding
  namespace: {{.Namespace}}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{.App}}-reader
subjects:
  - kind: ServiceAccount
    name: {{.ServiceAccount}}
    namespace: {{.Namespace}}
`

const deployTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.App}}
  namespace: {{.Namespace}}
  labels:
    app: {{.App}}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {{.App}}
  template:
    metadata:
      labels:
        app: {{.App}}
    spec:
      serviceAccountName: {{.ServiceAccount}}
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: {{.App}}
          image: {{.Image}}
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          securityContext:
            privileged: false
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
`

const svcTemplate = `apiVersion: v1
kind: Service
metadata:
  name: {{.App}}
  namespace: {{.Namespace}}
spec:
  type: ClusterIP
  selector:
    app: {{.App}}
  ports:
    - port: 80
      targetPort: 8080
`

const kyvernoTemplate = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: kubeguard-baseline
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: disallow-privileged
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            =(securityContext):
              =(privileged): "false"
            containers:
              - =(securityContext):
                  =(privileged): "false"
    - name: require-runasnonroot
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Containers must run as non-root."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
`

const gatekeeperTemplate = `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowprivileged
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged
          msg := "Privileged containers are not allowed"
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowPrivileged
metadata:
  name: disallow-privileged
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
`

const checklistTemplate = `# KubeGuard hardening checklist — namespace ` + "`{{.Namespace}}`" + `

Apply the bundle in order (` + "`kubectl apply -f .`" + `), then re-scan with
` + "`kubeguard scan -i .`" + ` to confirm zero findings.

- [ ] **Namespace PSA** (` + "`00-namespace.yaml`" + `) — enforce ` + "`restricted`" + ` Pod Security.
- [ ] **Default-deny NetworkPolicy** (` + "`10-…`" + `) + **DNS egress** (` + "`11-…`" + `).
- [ ] **Dedicated ServiceAccount**, token auto-mount disabled (` + "`20-serviceaccount.yaml`" + `).
- [ ] **Least-privilege RBAC** — no secrets, no pod-create, no wildcards (` + "`21-rbac.yaml`" + `).
- [ ] **Hardened Deployment** — non-root, read-only rootfs, drop ALL caps, seccomp
      RuntimeDefault, resource limits, digest-pinned image (` + "`30-deployment.yaml`" + `).
- [ ] **ClusterIP Service** — no direct LoadBalancer/NodePort exposure (` + "`40-service.yaml`" + `).
- [ ] **Admission policy** — Kyverno (` + "`50-…`" + `) and/or Gatekeeper (` + "`51-…`" + `).
- [ ] Replace the placeholder image digest with your signed image.
`
