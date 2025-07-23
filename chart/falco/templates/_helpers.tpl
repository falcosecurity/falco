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
{{- .Values.image.tag | default (printf "%s" .Chart.AppVersion) -}}
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
{{- $gvisorDisabled := (ne .Values.driver.kind  "gvisor") -}}
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

      root={{ .Values.driver.gvisor.runsc.root }}
      config={{ .Values.driver.gvisor.runsc.config }}

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
    - mountPath: /host{{ .Values.driver.gvisor.runsc.path }}
      name: runsc-path
      readOnly: true
    - mountPath: /host{{ .Values.driver.gvisor.runsc.root }}
      name: runsc-root
    - mountPath: /host{{ .Values.driver.gvisor.runsc.config }}
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
  {{- if .Values.falcoctl.artifact.install.env }}
  env:
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
  {{- if .Values.falcoctl.artifact.follow.env }}
  env:
  {{- include "falco.renderTemplate" ( dict "value" .Values.falcoctl.artifact.follow.env "context" $) | nindent 4 }}
  {{- end }}
{{- end -}}


{{/*
 Build configuration for k8smeta plugin and update the relevant variables.
 * The configuration that needs to be built up is the initconfig section:
    init_config:
     collectorPort: 0
     collectorHostname: ""
     nodeName: ""
    The falco chart exposes this configuriotino through two variable:
       * collectors.kubenetetes.collectorHostname;
       * collectors.kubernetes.collectorPort;
    If those two variable are not set, then we take those values from the k8smetacollector subchart.
    The hostname is built using the name of the service that exposes the collector endpoints and the
    port is directly taken form the service's port that exposes the gRPC endpoint.
    We reuse the helpers from the k8smetacollector subchart, by passing down the variables. There is a
    hardcoded values that is the chart name for the k8s-metacollector chart.

 * The falcoctl configuration is updated to allow  plugin artifacts to be installed. The refs in the install
   section are updated by adding the reference for the k8s meta plugin that needs to be installed.
 NOTE: It seems that the named templates run during the validation process. And then again during the
 render fase. In our case we are setting global variable that persist during the various phases.
 We need to make the helper idempotent.
*/}}
{{- define "k8smeta.configuration" -}}
{{- if and .Values.collectors.kubernetes.enabled .Values.driver.enabled -}}
{{- $hostname := "" -}}
{{- if .Values.collectors.kubernetes.collectorHostname -}}
{{- $hostname = .Values.collectors.kubernetes.collectorHostname -}}
{{- else -}}
{{- $collectorContext := (dict "Release" .Release "Values" (index .Values "k8s-metacollector") "Chart" (dict "Name" "k8s-metacollector")) -}}
{{- $hostname = printf "%s.%s.svc" (include "k8s-metacollector.fullname" $collectorContext) (include "k8s-metacollector.namespace" $collectorContext) -}}
{{- end -}}
{{- $hasConfig := false -}}
{{- range .Values.falco.plugins -}}
{{- if eq (get . "name") "k8smeta" -}}
{{ $hasConfig = true -}}
{{- end -}}
{{- end -}}
{{- if not $hasConfig -}}
{{- $listenPort := default (index .Values "k8s-metacollector" "service" "ports" "broker-grpc" "port") .Values.collectors.kubernetes.collectorPort -}}
{{- $listenPort = int $listenPort -}}
{{- $pluginConfig := dict "name" "k8smeta" "library_path" "libk8smeta.so" "init_config" (dict "collectorHostname" $hostname "collectorPort" $listenPort "nodeName" "${FALCO_K8S_NODE_NAME}" "verbosity" .Values.collectors.kubernetes.verbosity "hostProc" .Values.collectors.kubernetes.hostProc) -}}
{{- $newConfig := append .Values.falco.plugins $pluginConfig -}}
{{- $_ := set .Values.falco "plugins" ($newConfig | uniq) -}}
{{- $loadedPlugins := append .Values.falco.load_plugins "k8smeta" -}}
{{- $_ = set .Values.falco "load_plugins" ($loadedPlugins | uniq) -}}
{{- end -}}
{{- $_ := set .Values.falcoctl.config.artifact.install "refs" ((append .Values.falcoctl.config.artifact.install.refs .Values.collectors.kubernetes.pluginRef) | uniq)}}
{{- $_ = set .Values.falcoctl.config.artifact "allowedTypes" ((append .Values.falcoctl.config.artifact.allowedTypes "plugin") | uniq)}}
{{- end -}}
{{- end -}}

{{/*
Based on the user input it populates the driver configuration in the falco config map.
*/}}
{{- define "falco.engineConfiguration" -}}
{{- if .Values.driver.enabled -}}
{{- $supportedDrivers := list "kmod" "ebpf" "modern_ebpf" "gvisor" "auto" -}}
{{- $aliasDrivers := list "module" "modern-bpf" -}}
{{- if and (not (has .Values.driver.kind $supportedDrivers)) (not (has .Values.driver.kind $aliasDrivers)) -}}
{{- fail (printf "unsupported driver kind: \"%s\". Supported drivers %s, alias %s" .Values.driver.kind $supportedDrivers $aliasDrivers) -}}
{{- end -}}
{{- if or (eq .Values.driver.kind "kmod") (eq .Values.driver.kind "module") -}}
{{- $kmodConfig := dict "kind" "kmod" "kmod" (dict "buf_size_preset" .Values.driver.kmod.bufSizePreset "drop_failed_exit" .Values.driver.kmod.dropFailedExit) -}}
{{- $_ := set .Values.falco "engine" $kmodConfig -}}
{{- else if eq .Values.driver.kind "ebpf" -}}
{{- $ebpfConfig := dict "kind" "ebpf" "ebpf" (dict "buf_size_preset" .Values.driver.ebpf.bufSizePreset "drop_failed_exit" .Values.driver.ebpf.dropFailedExit "probe" .Values.driver.ebpf.path) -}}
{{- $_ := set .Values.falco "engine" $ebpfConfig -}}
{{- else if or (eq .Values.driver.kind "modern_ebpf") (eq .Values.driver.kind "modern-bpf") -}}
{{- $ebpfConfig := dict "kind" "modern_ebpf" "modern_ebpf" (dict "buf_size_preset" .Values.driver.modernEbpf.bufSizePreset "drop_failed_exit" .Values.driver.modernEbpf.dropFailedExit "cpus_for_each_buffer" .Values.driver.modernEbpf.cpusForEachBuffer) -}}
{{- $_ := set .Values.falco "engine" $ebpfConfig -}}
{{- else if eq .Values.driver.kind "gvisor" -}}
{{- $root := printf "/host%s/k8s.io" .Values.driver.gvisor.runsc.root -}}
{{- $gvisorConfig := dict "kind" "gvisor" "gvisor" (dict "config" "/gvisor-config/pod-init.json" "root" $root) -}}
{{- $_ := set .Values.falco "engine" $gvisorConfig -}}
{{- else if eq .Values.driver.kind "auto" -}}
{{- $engineConfig := dict "kind" "modern_ebpf" "kmod" (dict "buf_size_preset" .Values.driver.kmod.bufSizePreset "drop_failed_exit" .Values.driver.kmod.dropFailedExit) "ebpf" (dict "buf_size_preset" .Values.driver.ebpf.bufSizePreset "drop_failed_exit" .Values.driver.ebpf.dropFailedExit "probe" .Values.driver.ebpf.path) "modern_ebpf" (dict "buf_size_preset" .Values.driver.modernEbpf.bufSizePreset "drop_failed_exit" .Values.driver.modernEbpf.dropFailedExit "cpus_for_each_buffer" .Values.driver.modernEbpf.cpusForEachBuffer) -}}
{{- $_ := set .Values.falco "engine" $engineConfig -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
It returns "true" if the driver loader has to be enabled, otherwise false.
*/}}
{{- define "driverLoader.enabled" -}}
{{- if or (eq .Values.driver.kind "modern_ebpf") (eq .Values.driver.kind "modern-bpf") (eq .Values.driver.kind "gvisor") (not .Values.driver.enabled) (not .Values.driver.loader.enabled) -}}
false
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
Based on the user input it populates the metrics configuration in the falco config map.
*/}}
{{- define "falco.metricsConfiguration" -}}
{{- if .Values.metrics.enabled -}}
{{- $_ := set .Values.falco.webserver "prometheus_metrics_enabled" true -}}
{{- $_ = set .Values.falco.webserver "enabled" true -}}
{{- $_ = set .Values.falco.metrics "enabled" .Values.metrics.enabled -}}
{{- $_ = set .Values.falco.metrics "interval" .Values.metrics.interval -}}
{{- $_ = set .Values.falco.metrics "output_rule" .Values.metrics.outputRule -}}
{{- $_ = set .Values.falco.metrics "rules_counters_enabled" .Values.metrics.rulesCountersEnabled -}}
{{- $_ = set .Values.falco.metrics "resource_utilization_enabled" .Values.metrics.resourceUtilizationEnabled -}}
{{- $_ = set .Values.falco.metrics "state_counters_enabled" .Values.metrics.stateCountersEnabled -}}
{{- $_ = set .Values.falco.metrics "kernel_event_counters_enabled" .Values.metrics.kernelEventCountersEnabled -}}
{{- $_ = set .Values.falco.metrics "kernel_event_counters_per_cpu_enabled" .Values.metrics.kernelEventCountersPerCPUEnabled -}}
{{- $_ = set .Values.falco.metrics "libbpf_stats_enabled" .Values.metrics.libbpfStatsEnabled -}}
{{- $_ = set .Values.falco.metrics "convert_memory_to_mb" .Values.metrics.convertMemoryToMB -}}
{{- $_ = set .Values.falco.metrics "include_empty_values" .Values.metrics.includeEmptyValues -}}
{{- end -}}
{{- end -}}

{{/*
This helper is used to add the container plugin to the falco configuration.
*/}}
{{ define "falco.containerPlugin" -}}
{{ if and .Values.driver.enabled .Values.collectors.enabled -}}
{{ if and (or .Values.collectors.docker.enabled .Values.collectors.crio.enabled .Values.collectors.containerd.enabled) .Values.collectors.containerEngine.enabled -}}
{{ fail "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated." }}
{{ else if or .Values.collectors.docker.enabled .Values.collectors.crio.enabled .Values.collectors.containerd.enabled .Values.collectors.containerEngine.enabled -}}
{{ if or .Values.collectors.docker.enabled .Values.collectors.crio.enabled .Values.collectors.containerd.enabled -}}
{{ $_ := set .Values.collectors.containerEngine.engines.docker "enabled" .Values.collectors.docker.enabled -}}
{{ $_ = set .Values.collectors.containerEngine.engines.docker "sockets" (list .Values.collectors.docker.socket) -}}
{{ $_ = set .Values.collectors.containerEngine.engines.containerd "enabled" .Values.collectors.containerd.enabled -}}
{{ $_ = set .Values.collectors.containerEngine.engines.containerd "sockets" (list .Values.collectors.containerd.socket) -}}
{{ $_ = set .Values.collectors.containerEngine.engines.cri "enabled" .Values.collectors.crio.enabled -}}
{{ $_ = set .Values.collectors.containerEngine.engines.cri "sockets" (list .Values.collectors.crio.socket) -}}
{{ $_ = set .Values.collectors.containerEngine.engines.podman "enabled" false -}}
{{ $_ = set .Values.collectors.containerEngine.engines.lxc "enabled" false -}}
{{ $_ = set .Values.collectors.containerEngine.engines.libvirt_lxc "enabled" false -}}
{{ $_ = set .Values.collectors.containerEngine.engines.bpm "enabled" false -}}
{{ end -}}
{{ $hasConfig := false -}}
{{ range .Values.falco.plugins -}}
{{ if eq (get . "name") "container" -}}
{{ $hasConfig = true -}}
{{ end -}}
{{ end -}}
{{ if not $hasConfig -}}
{{ $pluginConfig := dict -}}
{{ with .Values.collectors.containerEngine -}}
{{ $pluginConfig = dict "name" "container" "library_path" "libcontainer.so" "init_config" (dict "label_max_len" .labelMaxLen "with_size" .withSize "hooks" .hooks "engines" .engines) -}}
{{ end -}}
{{ $newConfig := append .Values.falco.plugins $pluginConfig -}}
{{ $_ := set .Values.falco "plugins" ($newConfig | uniq) -}}
{{ $loadedPlugins := append .Values.falco.load_plugins "container" -}}
{{ $_ = set .Values.falco "load_plugins" ($loadedPlugins | uniq) -}}
{{ end -}}
{{ $_ := set .Values.falcoctl.config.artifact.install "refs" ((append .Values.falcoctl.config.artifact.install.refs .Values.collectors.containerEngine.pluginRef) | uniq) -}}
{{ $_ = set .Values.falcoctl.config.artifact "allowedTypes" ((append .Values.falcoctl.config.artifact.allowedTypes "plugin") | uniq) -}}
{{ end -}}
{{ end -}}
{{ end -}}

{{/*
This helper is used to add container plugin volumes to the falco pod.
*/}}
{{- define "falco.containerPluginVolumes" -}}
{{- if and .Values.driver.enabled .Values.collectors.enabled -}}
{{- if and (or .Values.collectors.docker.enabled .Values.collectors.crio.enabled .Values.collectors.containerd.enabled) .Values.collectors.containerEngine.enabled -}}
{{ fail "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated." }}
{{- end -}}
{{ $volumes := list -}}
{{- if .Values.collectors.docker.enabled -}}
{{ $volumes = append $volumes (dict "name" "docker-socket" "hostPath" (dict "path" .Values.collectors.docker.socket)) -}}
{{- end -}}
{{- if .Values.collectors.crio.enabled -}}
{{ $volumes = append $volumes (dict "name" "crio-socket" "hostPath" (dict "path" .Values.collectors.crio.socket)) -}}
{{- end -}}
{{- if .Values.collectors.containerd.enabled -}}
{{ $volumes = append $volumes (dict "name" "containerd-socket" "hostPath" (dict "path" .Values.collectors.containerd.socket)) -}}
{{- end -}}
{{- if .Values.collectors.containerEngine.enabled -}}
{{- $seenPaths := dict -}}
{{- $idx := 0 -}}
{{- $engineOrder := list "docker" "podman" "containerd" "cri" "lxc" "libvirt_lxc" "bpm" -}}
{{- range $engineName := $engineOrder -}}
{{- $val := index $.Values.collectors.containerEngine.engines $engineName -}}
{{- if and $val $val.enabled -}}
{{- range $index, $socket := $val.sockets -}}
{{- $mountPath := print "/host" $socket -}}
{{- if not (hasKey $seenPaths $mountPath) -}}
{{ $volumes = append $volumes (dict "name" (printf "container-engine-socket-%d" $idx) "hostPath" (dict "path" $socket)) -}}
{{- $idx = add $idx 1 -}}
{{- $_ := set $seenPaths $mountPath true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if gt (len $volumes) 0 -}}
{{ toYaml $volumes -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
This helper is used to add container plugin volumeMounts to the falco pod.
*/}}
{{- define "falco.containerPluginVolumeMounts" -}}
{{- if and .Values.driver.enabled .Values.collectors.enabled -}}
{{- if and (or .Values.collectors.docker.enabled .Values.collectors.crio.enabled .Values.collectors.containerd.enabled) .Values.collectors.containerEngine.enabled -}}
{{ fail "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated." }}
{{- end -}}
{{ $volumeMounts := list -}}
{{- if .Values.collectors.docker.enabled -}}
{{ $volumeMounts = append $volumeMounts (dict "name" "docker-socket" "mountPath" (print "/host" .Values.collectors.docker.socket)) -}}
{{- end -}}
{{- if .Values.collectors.crio.enabled -}}
{{ $volumeMounts = append $volumeMounts (dict "name" "crio-socket" "mountPath" (print "/host" .Values.collectors.crio.socket)) -}}
{{- end -}}
{{- if .Values.collectors.containerd.enabled -}}
{{ $volumeMounts = append $volumeMounts (dict "name" "containerd-socket" "mountPath" (print "/host" .Values.collectors.containerd.socket)) -}}
{{- end -}}
{{- if .Values.collectors.containerEngine.enabled -}}
{{- $seenPaths := dict -}}
{{- $idx := 0 -}}
{{- $engineOrder := list "docker" "podman" "containerd" "cri" "lxc" "libvirt_lxc" "bpm" -}}
{{- range $engineName := $engineOrder -}}
{{- $val := index $.Values.collectors.containerEngine.engines $engineName -}}
{{- if and $val $val.enabled -}}
{{- range $index, $socket := $val.sockets -}}
{{- $mountPath := print "/host" $socket -}}
{{- if not (hasKey $seenPaths $mountPath) -}}
{{ $volumeMounts = append $volumeMounts (dict "name" (printf "container-engine-socket-%d" $idx) "mountPath" $mountPath) -}}
{{- $idx = add $idx 1 -}}
{{- $_ := set $seenPaths $mountPath true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if gt (len $volumeMounts) 0 -}}
{{ toYaml ($volumeMounts) }}
{{- end -}}
{{- end -}}
{{- end -}}
