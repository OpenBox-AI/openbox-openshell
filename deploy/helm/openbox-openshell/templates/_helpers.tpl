{{- define "obx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "obx.fullname" -}}
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

{{- define "obx.doorGuard" -}}{{ include "obx.fullname" . | trunc 52 | trimSuffix "-" }}-door-guard{{- end -}}
{{- define "obx.frontDesk" -}}{{ include "obx.fullname" . | trunc 52 | trimSuffix "-" }}-front-desk{{- end -}}
{{- define "obx.redis" -}}{{ include "obx.fullname" . | trunc 57 | trimSuffix "-" }}-redis{{- end -}}

{{- define "obx.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "obx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "obx.selector" -}}
app.kubernetes.io/name: {{ include "obx.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "obx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "obx.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "obx.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "obx.credentialsSecret" -}}
{{- default (printf "%s-credentials" (include "obx.fullname" .)) .Values.credentials.existingSecret -}}
{{- end -}}

{{- define "obx.gatewayKeyConfigMap" -}}
{{- default (printf "%s-gateway-key" (include "obx.fullname" .)) .Values.gateway.publicKeyConfigMap -}}
{{- end -}}

{{- define "obx.doorGuardTlsSecret" -}}
{{- if .Values.tls.certManager.enabled -}}
{{- printf "%s-tls" (include "obx.doorGuard" .) -}}
{{- else -}}
{{- .Values.tls.doorGuard.existingSecret -}}
{{- end -}}
{{- end -}}

{{- define "obx.frontDeskTlsSecret" -}}
{{- if .Values.tls.certManager.enabled -}}
{{- printf "%s-tls" (include "obx.frontDesk" .) -}}
{{- else -}}
{{- .Values.tls.frontDesk.existingSecret -}}
{{- end -}}
{{- end -}}

{{/* True when a shared Redis is configured. */}}
{{- define "obx.hasRedis" -}}
{{- if or .Values.redis.enabled .Values.externalRedis.url .Values.externalRedis.existingSecret -}}true{{- end -}}
{{- end -}}

{{- define "obx.redisSecret" -}}
{{- if .Values.externalRedis.existingSecret -}}
{{- .Values.externalRedis.existingSecret -}}
{{- else -}}
{{- printf "%s-redis-url" (include "obx.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "obx.redisSecretKey" -}}
{{- if .Values.externalRedis.existingSecret -}}
{{- .Values.externalRedis.existingSecretKey -}}
{{- else -}}redis-url{{- end -}}
{{- end -}}

{{- define "obx.redisUrl" -}}
{{- if .Values.externalRedis.url -}}
{{- .Values.externalRedis.url -}}
{{- else -}}
{{- $auth := "" -}}
{{- if .Values.redis.password -}}{{- $auth = printf ":%s@" .Values.redis.password -}}{{- end -}}
{{- printf "redis://%s%s.%s.svc:6379/%v" $auth (include "obx.redis" .) .Release.Namespace .Values.redis.database -}}
{{- end -}}
{{- end -}}

{{/* DNS names a service certificate must carry. */}}
{{- define "obx.dnsNames" -}}
- {{ .name }}
- {{ .name }}.{{ .root.Release.Namespace }}
- {{ .name }}.{{ .root.Release.Namespace }}.svc
- {{ .name }}.{{ .root.Release.Namespace }}.svc.cluster.local
{{- range .root.Values.tls.certManager.extraDnsNames }}
- {{ . }}
{{- end }}
{{- end -}}

{{/* Environment shared by both services: Core credentials and the gateway API. */}}
{{- define "obx.credentialEnv" -}}
- name: OPENBOX_API_KEY_FILE
  value: /var/run/openbox/credentials/api-key
{{- if eq .Values.credentials.identity "workload" }}
- name: OPENBOX_WORKLOAD_KEY_FILE
  value: /var/run/openbox/credentials/workload.pem
- name: OPENBOX_WORKLOAD_KID
  valueFrom:
    secretKeyRef:
      name: {{ include "obx.credentialsSecret" . }}
      key: workload-kid
{{- end }}
{{- end -}}

{{- define "obx.gatewayApiEnv" -}}
{{- if .Values.gateway.api.endpoint }}
- name: OPENBOX_GATEWAY_ENDPOINT
  value: {{ .Values.gateway.api.endpoint | quote }}
- name: OPENBOX_GATEWAY_MTLS_DIR
  value: /var/run/openbox/gateway-mtls
{{- end }}
{{- end -}}

{{- define "obx.redisEnv" -}}
{{- if include "obx.hasRedis" . }}
- name: OPENBOX_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "obx.redisSecret" . }}
      key: {{ include "obx.redisSecretKey" . }}
{{- end }}
{{- end -}}

{{/* Volumes shared by both services. */}}
{{- define "obx.commonVolumes" -}}
- name: credentials
  secret:
    secretName: {{ include "obx.credentialsSecret" . }}
    defaultMode: 0400
- name: gateway-key
  configMap:
    name: {{ include "obx.gatewayKeyConfigMap" . }}
    items:
      - key: public-key.pem
        path: public-key.pem
{{- if .Values.gateway.api.endpoint }}
- name: gateway-mtls
  secret:
    secretName: {{ .Values.gateway.api.mtlsSecret }}
    defaultMode: 0400
    items:
      - key: ca.crt
        path: ca.crt
      - key: tls.crt
        path: tls.crt
      - key: tls.key
        path: tls.key
{{- end }}
{{- end -}}

{{- define "obx.commonMounts" -}}
- name: credentials
  mountPath: /var/run/openbox/credentials
  readOnly: true
- name: gateway-key
  mountPath: /var/run/openbox/gateway-key
  readOnly: true
{{- if .Values.gateway.api.endpoint }}
- name: gateway-mtls
  mountPath: /var/run/openbox/gateway-mtls
  readOnly: true
{{- end }}
- name: tls
  mountPath: /var/run/openbox/tls
  readOnly: true
{{- end -}}

{{- define "obx.topologySpread" -}}
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      {{- include "obx.selector" . | nindent 6 }}
{{- end -}}
