{{- define "kgd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kgd.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "kgd.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kgd.labels" -}}
app.kubernetes.io/name: {{ include "kgd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "kgd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kgd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kgd.serviceAccountName" -}}
{{ include "kgd.fullname" . }}
{{- end -}}

{{- define "kgd.apiImage" -}}
{{- $img := .Values.image.api -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ $img.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "kgd.webImage" -}}
{{- $img := .Values.image.web -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ $img.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "kgd.secretName" -}}
{{ include "kgd.fullname" . }}-secrets
{{- end -}}
