{{- define "code-sandbox.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "code-sandbox.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "code-sandbox.labels" -}}
app.kubernetes.io/name: {{ include "code-sandbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "code-sandbox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "code-sandbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
