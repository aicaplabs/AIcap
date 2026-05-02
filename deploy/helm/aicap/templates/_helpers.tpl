{{/*
Expand the name of the chart.
*/}}
{{- define "aicap.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name. Truncated to 63 chars (DNS-1123).
*/}}
{{- define "aicap.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label (chart-version pair, sanitised for Kubernetes labels).
*/}}
{{- define "aicap.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard labels — applied to every resource.
*/}}
{{- define "aicap.labels" -}}
helm.sh/chart: {{ include "aicap.chart" . }}
{{ include "aicap.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels — used to match Pods to Services / Deployments.
Stable across upgrades; do not add release-specific values here.
*/}}
{{- define "aicap.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aicap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name to use.
*/}}
{{- define "aicap.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "aicap.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Secret name — either an existing one provided by the user, or the
chart-managed default.
*/}}
{{- define "aicap.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "aicap.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
ConfigMap name — chart-managed.
*/}}
{{- define "aicap.configMapName" -}}
{{- printf "%s-config" (include "aicap.fullname" .) -}}
{{- end -}}

{{/*
Container image reference. Falls back to .Chart.AppVersion when
image.tag is empty so chart upgrades that bump appVersion roll forward
without forcing every consumer to set image.tag.
*/}}
{{- define "aicap.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
