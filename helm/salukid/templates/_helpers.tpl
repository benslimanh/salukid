{{/*
Expand the name of the chart.
*/}}
{{- define "salukid.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "salukid.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride }}
{{- else -}}{{ printf "%s-%s" .Release.Name (include "salukid.name" .) | trimSuffix "-" }}
{{- end }}{{- end }}

{{- define "salukid.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "salukid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "salukid.selectorLabels" -}}
app.kubernetes.io/name: {{ include "salukid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
