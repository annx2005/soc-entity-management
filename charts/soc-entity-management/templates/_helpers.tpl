{{- define "soc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soc.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "soc.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "soc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "soc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "soc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "soc.secretName" -}}
{{- if .Values.secrets.name -}}
{{- .Values.secrets.name -}}
{{- else -}}
{{- include "soc.fullname" . }}-secret
{{- end -}}
{{- end -}}

{{- define "soc.backendName" -}}
{{- include "soc.fullname" . }}-backend
{{- end -}}

{{- define "soc.frontendName" -}}
{{- include "soc.fullname" . }}-frontend
{{- end -}}

{{- define "soc.ingestionWorkerName" -}}
{{- include "soc.fullname" . }}-kafka-ingestion-worker
{{- end -}}

{{- define "soc.graphWorkerName" -}}
{{- include "soc.fullname" . }}-kafka-graph-worker
{{- end -}}

{{- define "soc.postgresqlName" -}}
{{- include "soc.fullname" . }}-postgresql
{{- end -}}

{{- define "soc.redisName" -}}
{{- include "soc.fullname" . }}-redis
{{- end -}}

{{- define "soc.kafkaName" -}}
{{- include "soc.fullname" . }}-kafka
{{- end -}}

{{- define "soc.neo4jName" -}}
{{- include "soc.fullname" . }}-neo4j
{{- end -}}

{{- define "soc.backendImage" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.images.backend.repository .Values.global.imageTag -}}
{{- end -}}

{{- define "soc.frontendImage" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.images.frontend.repository .Values.global.imageTag -}}
{{- end -}}
