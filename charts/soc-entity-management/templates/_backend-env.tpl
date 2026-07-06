{{- define "soc.backendEnv" -}}
- name: APP_NAME
  value: {{ .Values.app.name | quote }}
- name: ENVIRONMENT
  value: {{ .Values.app.environment | quote }}
- name: TENANT_ID_DEFAULT
  value: {{ .Values.app.tenantIdDefault | quote }}
- name: JWT_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: JWT_SECRET_KEY
- name: JWT_ALGORITHM
  value: {{ .Values.app.jwtAlgorithm | quote }}
- name: ACCESS_TOKEN_EXPIRE_MINUTES
  value: {{ .Values.app.accessTokenExpireMinutes | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: POSTGRES_PASSWORD
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: DATABASE_URL
- name: REDIS_URL
  value: "redis://{{ include "soc.redisName" . }}:6379/0"
- name: NEO4J_URI
  value: "bolt://{{ include "soc.neo4jHeadlessName" . }}:7687"
- name: NEO4J_USER
  value: {{ .Values.neo4j.auth.username | quote }}
- name: NEO4J_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: NEO4J_PASSWORD
- name: KAFKA_BOOTSTRAP_SERVERS
  value: "{{ include "soc.kafkaHeadlessName" . }}:9092"
- name: KAFKA_RAW_EVENTS_TOPIC
  value: {{ .Values.kafka.topics.rawEvents | quote }}
- name: KAFKA_NORMALIZED_EVENTS_TOPIC
  value: {{ .Values.kafka.topics.normalizedEvents | quote }}
- name: KAFKA_OCSF_EVENTS_TOPIC
  value: {{ .Values.kafka.topics.ocsfEvents | quote }}
- name: KAFKA_DEAD_LETTER_TOPIC
  value: {{ .Values.kafka.topics.deadLetter | quote }}
- name: KAFKA_INGESTION_GROUP_ID
  value: {{ .Values.kafka.groupIds.ingestion | quote }}
- name: KAFKA_GRAPH_GROUP_ID
  value: {{ .Values.kafka.groupIds.graph | quote }}
- name: ENRICHMENT_PROVIDER_MODE
  value: {{ .Values.enrichment.providerMode | quote }}
- name: ENRICHMENT_IP_SOURCE_PATH
  value: {{ .Values.enrichment.ipSourcePath | quote }}
- name: ENRICHMENT_FILE_HASH_SOURCE_PATH
  value: {{ .Values.enrichment.fileHashSourcePath | quote }}
- name: ENRICHMENT_IPINFO_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: ENRICHMENT_IPINFO_TOKEN
- name: ENRICHMENT_IPINFO_BASE_URL
  value: {{ .Values.enrichment.ipinfoBaseUrl | quote }}
- name: ENRICHMENT_MALWARE_BAZAAR_AUTH_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "soc.secretName" . }}
      key: ENRICHMENT_MALWARE_BAZAAR_AUTH_KEY
- name: ENRICHMENT_MALWARE_BAZAAR_URL
  value: {{ .Values.enrichment.malwareBazaarUrl | quote }}
- name: ENRICHMENT_HTTP_TIMEOUT_SECONDS
  value: {{ .Values.enrichment.httpTimeoutSeconds | quote }}
- name: ENRICHMENT_CACHE_TTL_SECONDS
  value: {{ .Values.enrichment.cacheTtlSeconds | quote }}
- name: ENRICHMENT_ENABLED
  value: {{ .Values.enrichment.enabled | quote }}
- name: METRICS_ENABLED
  value: {{ .Values.monitoring.enabled | quote }}
- name: METRICS_PORT
  value: {{ .Values.monitoring.workerMetricsPort | quote }}
{{- end -}}
