{{/*
Expand the name of the chart.
*/}}
{{- define "falco.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "falco.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "falco.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Allow the release namespace to be overridden
*/}}
{{- define "falco.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "falco.labels" -}}
helm.sh/chart: {{ include "falco.chart" . }}
{{ include "falco.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "falco.selectorLabels" -}}
app.kubernetes.io/name: {{ include "falco.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Renders a value that contains template.
Usage:
{{ include "falco.renderTemplate" ( dict "value" .Values.path.to.the.Value "context" $) }}
*/}}
{{- define "falco.renderTemplate" -}}
    {{- if typeIs "string" .value }}
        {{- tpl .value .context }}
    {{- else }}
        {{- tpl (.value | toYaml) .context }}
    {{- end }}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "falco.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "falco.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the proper Falco image name
*/}}
{{- define "falco.image" -}}
{{- with .Values.image.registry -}}
    {{- . }}/
{{- end -}}
{{- .Values.image.repository }}:
{{- .Values.image.tag | default .Chart.AppVersion -}}
{{- end -}}

{{/*
Return the proper Falco driver loader image name
*/}}
{{- define "falco.driverLoader.image" -}}
{{- with .Values.driver.loader.initContainer.image.registry -}}
    {{- . }}/
{{- end -}}
{{- .Values.driver.loader.initContainer.image.repository }}:
{{- .Values.driver.loader.initContainer.image.tag | default .Chart.AppVersion -}}
{{- end -}}

{{/*
Return the proper Falcoctl image name
*/}}
{{- define "falcoctl.image" -}}
{{ printf "%s/%s:%s" .Values.falcoctl.image.registry .Values.falcoctl.image.repository .Values.falcoctl.image.tag }}
{{- end -}}

{{/*
Extract the unixSocket's directory path
*/}}
{{- define "falco.unixSocketDir" -}}
{{- if and .Values.falco.grpc.enabled .Values.falco.grpc.bind_address (hasPrefix "unix://" .Values.falco.grpc.bind_address) -}}
{{- .Values.falco.grpc.bind_address | trimPrefix "unix://" | dir -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for rbac.
*/}}
{{- define "rbac.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1" }}
{{- print "rbac.authorization.k8s.io/v1" -}}
{{- else -}}
{{- print "rbac.authorization.k8s.io/v1beta1" -}}
{{- end -}}
{{- end -}}

{{/*
 Build http url for falcosidekick.
*/}}
{{- define "falcosidekick.url" -}}
{{- if not .Values.falco.http_output.url -}}
    {{- $falcoName := include "falco.fullname" . -}}
    {{- $listenPort := .Values.falcosidekick.listenport | default "2801" -}}
    {{- if .Values.falcosidekick.fullfqdn -}}
       {{- printf "http://%s-falcosidekick.%s.svc.cluster.local:%s" $falcoName .Release.Namespace $listenPort -}}
    {{- else -}}
        {{- printf "http://%s-falcosidekick:%s" $falcoName $listenPort -}}
    {{- end -}}
{{- else -}}
    {{- .Values.falco.http_output.url -}}
{{- end -}}
{{- end -}}


{{/*
Set appropriate falco configuration if falcosidekick has been configured.
*/}}
{{- define "falco.falcosidekickConfig" -}}
{{- if .Values.falcosidekick.enabled  -}}
    {{- $_ := set .Values.falco "json_output" true -}}
    {{- $_ := set .Values.falco "json_include_output_property" true -}}
    {{- $_ := set .Values.falco.http_output "enabled" true -}}
    {{- $_ := set .Values.falco.http_output "url" (include "falcosidekick.url" .) -}}
{{- end -}}
{{- end -}}

{{/*
Get port from .Values.falco.grpc.bind_addres.
*/}}
{{- define "grpc.port" -}}
{{- $error := "unable to extract listenPort from .Values.falco.grpc.bind_address. Make sure it is in the correct format" -}}
{{- if and .Values.falco.grpc.enabled .Values.falco.grpc.bind_address (not (hasPrefix "unix://" .Values.falco.grpc.bind_address)) -}}
    {{- $tokens := split ":" .Values.falco.grpc.bind_address -}}
    {{- if $tokens._1 -}}
        {{- $tokens._1 -}}
    {{- else -}}
        {{- fail $error -}}
    {{- end -}}
{{- else -}}
    {{- fail $error -}}
{{- end -}}
{{- end -}}

{{/*
Disable the syscall source if some conditions are met.
By default the syscall source is always enabled in falco. If no syscall source is enabled, falco
exits. Here we check that no producers for syscalls event has been configured, and if true
we just disable the sycall source.
*/}}
{{- define "falco.configSyscallSource" -}}
{{- $userspaceDisabled := true -}}
{{- $gvisorDisabled := (not .Values.gvisor.enabled) -}}
{{- $driverDisabled :=  (not .Values.driver.enabled) -}}
{{- if or (has "-u" .Values.extra.args) (has "--userspace" .Values.extra.args) -}}
{{- $userspaceDisabled = false -}}
{{- end -}}
{{- if and $driverDisabled $userspaceDisabled $gvisorDisabled }}
- --disable-source
- syscall
{{- end -}}
{{- end -}}

{{/*
We need the falco binary in order to generate the configuration for gVisor. This init container
is deployed within the Falco pod when gVisor is enabled. The image is the same as the one of Falco we are
deploying and the configuration logic is a bash script passed as argument on the fly. This solution should
be temporary and will stay here until we move this logic to the falcoctl tool.
*/}}
{{- define "falco.gvisor.initContainer" -}}
- name: {{ .Chart.Name }}-gvisor-init
  image: {{ include "falco.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
    - /bin/bash
    - -c
    - |
      set -o errexit
      set -o nounset
      set -o pipefail

      root={{ .Values.gvisor.runsc.root }}
      config={{ .Values.gvisor.runsc.config }}

      echo "* Configuring Falco+gVisor integration...".
      # Check if gVisor is configured on the node.
      echo "* Checking for /host${config} file..."
      if [[ -f /host${config} ]]; then
          echo "* Generating the Falco configuration..."
          /usr/bin/falco --gvisor-generate-config=${root}/falco.sock > /host${root}/pod-init.json
          sed -E -i.orig '/"ignore_missing" : true,/d' /host${root}/pod-init.json
          if [[ -z $(grep pod-init-config /host${config}) ]]; then
            echo "* Updating the runsc config file /host${config}..."
            echo "  pod-init-config = \"${root}/pod-init.json\"" >> /host${config}
          fi
          # Endpoint inside the container is different from outside, add
          # "/host" to the endpoint path inside the container.
          echo "* Setting the updated Falco configuration to /gvisor-config/pod-init.json..."
          sed 's/"endpoint" : "\/run/"endpoint" : "\/host\/run/' /host${root}/pod-init.json > /gvisor-config/pod-init.json
      else
          echo "* File /host${config} not found."
          echo "* Please make sure that the gVisor is configured in the current node and/or the runsc root and config file path are correct"
          exit -1
      fi
      echo "* Falco+gVisor correctly configured."
      exit 0
  volumeMounts:
    - mountPath: /host{{ .Values.gvisor.runsc.path }}
      name: runsc-path
      readOnly: true
    - mountPath: /host{{ .Values.gvisor.runsc.root }}
      name: runsc-root
    - mountPath: /host{{ .Values.gvisor.runsc.config }}
      name: runsc-config
    - mountPath: /gvisor-config
      name: falco-gvisor-config
{{- end -}}


{{- define "falcoctl.initContainer" -}}
- name: falcoctl-artifact-install
  image: {{ include "falcoctl.image" . }}
  imagePullPolicy: {{ .Values.falcoctl.image.pullPolicy }}
  args: 
    - artifact
    - install
  {{- with .Values.falcoctl.artifact.install.args }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.falcoctl.artifact.install.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
  {{- if .Values.falcoctl.artifact.install.securityContext }}
    {{- toYaml .Values.falcoctl.artifact.install.securityContext | nindent 4 }}
  {{- end }}
  volumeMounts:
    - mountPath: {{ .Values.falcoctl.config.artifact.install.pluginsDir }}
      name: plugins-install-dir
    - mountPath: {{ .Values.falcoctl.config.artifact.install.rulesfilesDir }}
      name: rulesfiles-install-dir
    - mountPath: /etc/falcoctl
      name: falcoctl-config-volume
      {{- with .Values.falcoctl.artifact.install.mounts.volumeMounts }}
        {{- toYaml . | nindent 4 }}
      {{- end }}
  env:
  {{- if .Values.falcoctl.artifact.install.env }}
  {{- include "falco.renderTemplate" ( dict "value" .Values.falcoctl.artifact.install.env "context" $) | nindent 4 }}
  {{- end }}
{{- end -}}

{{- define "falcoctl.sidecar" -}}
- name: falcoctl-artifact-follow
  image: {{ include "falcoctl.image" . }}
  imagePullPolicy: {{ .Values.falcoctl.image.pullPolicy }}
  args:
    - artifact
    - follow
  {{- with .Values.falcoctl.artifact.follow.args }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.falcoctl.artifact.follow.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
  {{- if .Values.falcoctl.artifact.follow.securityContext }}
    {{- toYaml .Values.falcoctl.artifact.follow.securityContext | nindent 4 }}
  {{- end }}
  volumeMounts:
    - mountPath: {{ .Values.falcoctl.config.artifact.follow.pluginsDir }}
      name: plugins-install-dir
    - mountPath: {{ .Values.falcoctl.config.artifact.follow.rulesfilesDir }}
      name: rulesfiles-install-dir
    - mountPath: /etc/falcoctl
      name: falcoctl-config-volume
      {{- with .Values.falcoctl.artifact.follow.mounts.volumeMounts }}
        {{- toYaml . | nindent 4 }}
      {{- end }}
  env:
  {{- if .Values.falcoctl.artifact.follow.env }}
  {{- include "falco.renderTemplate" ( dict "value" .Values.falcoctl.artifact.follow.env "context" $) | nindent 4 }}
  {{- end }}
{{- end -}}