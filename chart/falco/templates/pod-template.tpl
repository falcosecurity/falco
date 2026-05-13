{{- define "falco.podTemplate" -}}
metadata:
  name: {{ include "falco.fullname" . }}
  labels:
    {{- include "falco.selectorLabels" . | nindent 4 }}
    {{- with .Values.podLabels }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
  annotations:
    checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
    checksum/rules: {{ include (print $.Template.BasePath "/rules-configmap.yaml") . | sha256sum }}
    {{- if and .Values.certs (not .Values.certs.existingSecret) }}
    checksum/certs: {{ include (print $.Template.BasePath "/certs-secret.yaml") . | sha256sum }}
    {{- end }}
    {{- if .Values.driver.enabled }}
    {{- if (or (eq .Values.driver.kind "modern_ebpf") (eq .Values.driver.kind "modern-bpf")) }}
    {{- if .Values.driver.modernEbpf.leastPrivileged }}
    container.apparmor.security.beta.kubernetes.io/{{ .Chart.Name }}: unconfined
    {{- end }}
    {{- end }}
    {{- end }}
    {{- with .Values.podAnnotations }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  {{- if .Values.falco.podHostname }}
  hostname: {{ .Values.falco.podHostname }}
  {{- end }}
  serviceAccountName: {{ include "falco.serviceAccountName" . }}
  {{- with .Values.podSecurityContext }}
  securityContext:
    {{- toYaml . | nindent 4}}
  {{- end }}
  {{- if .Values.podPriorityClassName }}
  priorityClassName: {{ .Values.podPriorityClassName }}
  {{- end }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets: 
    {{- toYaml . | nindent 4 }}
  {{- end }}
  containers:
    - name: {{ .Chart.Name }}
      image: {{ include "falco.image" . }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      securityContext:
        {{- include "falco.securityContext" . | nindent 8 }}
      args:
        - /usr/bin/falco
        {{- include "falco.configSyscallSource" . | indent 8 }}
    {{- with .Values.extra.args }}
      {{- toYaml . | nindent 8 }}
    {{- end }}
      env:
        - name: HOST_ROOT
          value: /host
        {{- /*
          Detect a user-provided FALCO_HOSTNAME in extra.env. If present, suppress the
          chart-default below to avoid a Kubernetes strategic-merge-patch collision on
          UPDATE (env[].name is the merge key; duplicate entries collapse server-side
          into a single invalid EnvVar with both `value` and `valueFrom` set).
        */}}
        {{- $userHostnameOverride := false }}
        {{- range .Values.extra.env }}
          {{- if eq .name "FALCO_HOSTNAME" }}
            {{- $userHostnameOverride = true }}
          {{- end }}
        {{- end }}
        {{- if and .Values.falcoHostnameEnv (not $userHostnameOverride) }}
        - name: FALCO_HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        {{- end }}
        - name: FALCO_K8S_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      {{- if .Values.extra.env }}
      {{- include "falco.renderTemplate" ( dict "value" .Values.extra.env "context" $) | nindent 8 }}
      {{- end }}
      tty: {{ .Values.tty }}
      {{- if .Values.falco.webserver.enabled }}
      ports:
        - containerPort: {{ .Values.falco.webserver.listen_port }}
          name: web
          protocol: TCP
      startupProbe:
        initialDelaySeconds: {{ .Values.healthChecks.startupProbe.initialDelaySeconds }}
        timeoutSeconds: {{ .Values.healthChecks.startupProbe.timeoutSeconds }}
        periodSeconds: {{ .Values.healthChecks.startupProbe.periodSeconds }}
        failureThreshold: {{ .Values.healthChecks.startupProbe.failureThreshold }}
        httpGet:
          path: {{ .Values.falco.webserver.k8s_healthz_endpoint }}
          port: {{ .Values.falco.webserver.listen_port }}
          {{- if .Values.falco.webserver.ssl_enabled }}
          scheme: HTTPS
          {{- end }}
      livenessProbe:
        initialDelaySeconds: {{ .Values.healthChecks.livenessProbe.initialDelaySeconds }}
        timeoutSeconds: {{ .Values.healthChecks.livenessProbe.timeoutSeconds }}
        periodSeconds: {{ .Values.healthChecks.livenessProbe.periodSeconds }}
        failureThreshold: {{ .Values.healthChecks.livenessProbe.failureThreshold }}
        httpGet:
          path: {{ .Values.falco.webserver.k8s_healthz_endpoint }}
          port: {{ .Values.falco.webserver.listen_port }}
          {{- if .Values.falco.webserver.ssl_enabled }}
          scheme: HTTPS
          {{- end }}
      readinessProbe:
        initialDelaySeconds: {{ .Values.healthChecks.readinessProbe.initialDelaySeconds }}
        timeoutSeconds: {{ .Values.healthChecks.readinessProbe.timeoutSeconds }}
        periodSeconds: {{ .Values.healthChecks.readinessProbe.periodSeconds }}
        failureThreshold: {{ .Values.healthChecks.readinessProbe.failureThreshold }}
        httpGet:
          path: {{ .Values.falco.webserver.k8s_healthz_endpoint }}
          port: {{ .Values.falco.webserver.listen_port }}
          {{- if .Values.falco.webserver.ssl_enabled }}
          scheme: HTTPS
          {{- end }}
      {{- end }}
      volumeMounts:
      {{- include "falco.containerPluginVolumeMounts" . | nindent 8 -}}
      {{- if or .Values.falcoctl.artifact.install.enabled .Values.falcoctl.artifact.follow.enabled }}
      {{- if has "rulesfile" .Values.falcoctl.config.artifact.allowedTypes }}
        - mountPath: /etc/falco
          name: rulesfiles-install-dir
      {{- end }}
      {{- if has "plugin" .Values.falcoctl.config.artifact.allowedTypes }}
        - mountPath: /usr/share/falco/plugins
          name: plugins-install-dir
      {{- end }}
      {{- end }}
      {{- if eq (include "driverLoader.enabled" .) "true" }}
        - mountPath: /etc/falco/config.d
          name: specialized-falco-configs
      {{- end }}
        - mountPath: /root/.falco
          name: root-falco-fs
        {{- if eq (include "falco.procfsMount.enabled" .) "true" }}
        - mountPath: /host/proc
          name: proc-fs
        {{- if and .Values.driver.enabled (not .Values.driver.loader.enabled) }}
          readOnly: true
        {{- end }}
        {{- end }}
        {{- if and .Values.driver.enabled (not .Values.driver.loader.enabled) }}
        - mountPath: /host/boot
          name: boot-fs
          readOnly: true
        - mountPath: /host/lib/modules
          name: lib-modules
        - mountPath: /host/usr
          name: usr-fs
          readOnly: true
        {{- end }}
        {{- if .Values.driver.enabled }}
        - mountPath: /host/etc
          name: etc-fs
          readOnly: true
        {{- end -}}
        {{- if and .Values.driver.enabled (or (eq .Values.driver.kind "kmod") (eq .Values.driver.kind "module") (eq .Values.driver.kind "auto")) }}
        - mountPath: /host/dev
          name: dev-fs
          readOnly: true
        - name: sys-module-fs
          mountPath: /sys/module
        {{- end }}
        {{- if eq (include "falco.sysfsMount.enabled" .) "true" }}
        - mountPath: {{ .Values.driver.sysfsMountPath }}
          name: sys-fs
          readOnly: true
        {{- end }}
        - mountPath: /etc/falco/falco.yaml
          name: falco-yaml
          subPath: falco.yaml
        {{- if .Values.customRules }}
        - mountPath: /etc/falco/rules.d
          name: rules-volume
        {{- end }}
        {{- if or .Values.certs.existingSecret (and .Values.certs.server.key .Values.certs.server.crt .Values.certs.ca.crt) }}
        - mountPath: /etc/falco/certs
          name: certs-volume
          readOnly: true
        {{- end }}
        {{- if or .Values.certs.existingClientSecret (and .Values.certs.client.key .Values.certs.client.crt .Values.certs.ca.crt) }}
        - mountPath: /etc/falco/certs/client
          name: client-certs-volume
          readOnly: true
        {{- end }}
        {{- with .Values.mounts.volumeMounts }}
          {{- toYaml . | nindent 8 }}
        {{- end }}
  {{- if .Values.falcoctl.artifact.follow.enabled }}
    {{- include "falcoctl.sidecar" . | nindent 4 }}
  {{- end }}
  initContainers:
  {{- with .Values.extra.initContainers }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- if eq (include "driverLoader.enabled" .) "true" }}
    {{- include "falco.driverLoader.initContainer" . | nindent 4 }}
  {{- end }}
  {{- if .Values.falcoctl.artifact.install.enabled }}
    {{- include "falcoctl.initContainer" . | nindent 4 }}
  {{- end }}
  volumes:
    {{- include "falco.containerPluginVolumes" . | nindent 4 -}}
    {{- if eq (include "driverLoader.enabled" .) "true" }}
    - name: specialized-falco-configs
      emptyDir: {}
    {{- end }}
    {{- if or .Values.falcoctl.artifact.install.enabled .Values.falcoctl.artifact.follow.enabled }}
    - name: plugins-install-dir
      emptyDir: {}
    - name: rulesfiles-install-dir
      emptyDir: {}
    - name: artifact-state-dir
      emptyDir: {}
    {{- end }}
    - name: root-falco-fs
      emptyDir: {}
    {{- if .Values.driver.enabled }}  
    - name: boot-fs
      hostPath:
        path: /boot
    - name: lib-modules
      hostPath:
        path: /lib/modules
    - name: usr-fs
      hostPath:
        path: /usr
    - name: etc-fs
      hostPath:
        path: /etc
    {{- end }}
    {{- if and .Values.driver.enabled (or (eq .Values.driver.kind "kmod") (eq .Values.driver.kind "module") (eq .Values.driver.kind "auto")) }}
    - name: dev-fs
      hostPath:
        path: /dev
    - name: sys-module-fs
      hostPath:
        path: /sys/module
    {{- end }}
    {{- if eq (include "falco.sysfsMount.enabled" .) "true" }}
    - name: sys-fs
      hostPath:
        path: {{ .Values.driver.sysfsMountPath }}
    {{- end }}
    {{- if eq (include "falco.procfsMount.enabled" .) "true" }}
    - name: proc-fs
      hostPath:
        path: /proc
    {{- end }}
    - name: falcoctl-config-volume
      configMap: 
        name: {{ include "falco.fullname" . }}-falcoctl
        items:
          - key: falcoctl.yaml
            path: falcoctl.yaml
    - name: falco-yaml
      configMap:
        name: {{ include "falco.fullname" . }}
        items:
        - key: falco.yaml
          path: falco.yaml
    {{- if .Values.customRules }}
    - name: rules-volume
      configMap:
        name: {{ include "falco.fullname" . }}-rules
    {{- end }}
    {{- if or .Values.certs.existingSecret (and .Values.certs.server.key .Values.certs.server.crt .Values.certs.ca.crt) }}
    - name: certs-volume
      secret:
        {{- if .Values.certs.existingSecret }}
        secretName: {{ .Values.certs.existingSecret }}
        {{- else }}
        secretName: {{ include "falco.fullname" . }}-certs
        {{- end }}
    {{- end }}
    {{- if or .Values.certs.existingClientSecret (and .Values.certs.client.key .Values.certs.client.crt .Values.certs.ca.crt) }}
    - name: client-certs-volume
      secret:
        {{- if .Values.certs.existingClientSecret }}
        secretName: {{ .Values.certs.existingClientSecret }}
        {{- else }}
        secretName: {{ include "falco.fullname" . }}-client-certs
        {{- end }}
    {{- end }}
    {{- with .Values.mounts.volumes }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    {{- end -}}

{{- define "falco.driverLoader.initContainer" -}}
- name: {{ .Chart.Name }}-driver-loader
  image: {{ include "falco.driverLoader.image" . }}
  imagePullPolicy: {{ .Values.driver.loader.initContainer.image.pullPolicy }}
  args:
  {{- with .Values.driver.loader.initContainer.args }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- if eq .Values.driver.kind "module" }}
    - kmod
  {{- else if eq .Values.driver.kind "modern-bpf"}}
    - modern_ebpf
  {{- else }}
    - {{ .Values.driver.kind }}
  {{- end }}
  {{- with .Values.driver.loader.initContainer.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
  {{- if .Values.driver.loader.initContainer.securityContext }}
    {{- toYaml .Values.driver.loader.initContainer.securityContext | nindent 4 }}
  {{- else if (or (eq .Values.driver.kind "kmod") (eq .Values.driver.kind "module") (eq .Values.driver.kind "auto")) }}
    privileged: true
  {{- end }}
  volumeMounts:
    - mountPath: /root/.falco
      name: root-falco-fs
    - mountPath: /host/proc
      name: proc-fs
      readOnly: true
    - mountPath: /host/boot
      name: boot-fs
      readOnly: true
    - mountPath: /host/lib/modules
      name: lib-modules
    - mountPath: /host/usr
      name: usr-fs
      readOnly: true
    - mountPath: /host/etc
      name: etc-fs
      readOnly: true
    - mountPath: /etc/falco/config.d
      name: specialized-falco-configs
  env:
    - name: HOST_ROOT
      value: /host
  {{- if .Values.driver.loader.initContainer.env }}
  {{- include "falco.renderTemplate" ( dict "value" .Values.driver.loader.initContainer.env "context" $) | nindent 4 }}
  {{- end }}
  {{- if eq .Values.driver.kind "auto" }}
    - name: FALCOCTL_DRIVER_CONFIG_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace
    - name: FALCOCTL_DRIVER_CONFIG_CONFIGMAP
      value: {{ include "falco.fullname" . }}
  {{- else }}
    - name: FALCOCTL_DRIVER_CONFIG_UPDATE_FALCO
      value: "false"
  {{- end }}
{{- end -}}

{{- define "falco.securityContext" -}}
{{- $securityContext := dict -}}
{{- if .Values.driver.enabled -}}
  {{- if (or (eq .Values.driver.kind "kmod") (eq .Values.driver.kind "module") (eq .Values.driver.kind "auto")) -}}
    {{- $securityContext := set $securityContext "privileged" true -}}
  {{- end -}}
  {{- if (or (eq .Values.driver.kind "modern_ebpf") (eq .Values.driver.kind "modern-bpf")) -}}
    {{- if .Values.driver.modernEbpf.leastPrivileged -}}
      {{- $securityContext := set $securityContext "capabilities" (dict "add" (list "BPF" "SYS_RESOURCE" "PERFMON" "SYS_PTRACE")) -}}
    {{- else -}}
      {{- $securityContext := set $securityContext "privileged" true -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- if not (empty (.Values.containerSecurityContext)) -}}
  {{-  toYaml .Values.containerSecurityContext }}
{{- else -}}
  {{- toYaml $securityContext }}
{{- end -}}
{{- end -}}
