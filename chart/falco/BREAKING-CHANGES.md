# Helm chart Breaking Changes

- [8.0.0](#800)
  - [Deprecated gRPC output and server](#deprecated-grpc-output-and-server)
  - [Deprecated Legacy eBPF probe and gVisor engine](#deprecated-legacy-ebpf-probe-and-gvisor-engine)
- [7.0.0](#700)
  - [Deprecated container metadata collectors removed](#deprecated-container-metadata-collectors-have-been-removed)
- [5.0.0](#500)
  - [Default Falco Image](#default-falco-image)
- [4.0.0](#400)
  - [Drivers](#drivers)
  - [K8s Collector](#k8s-collector)
  - [Plugins](#plugins)
- [3.0.0](#300)
  - [Falcoctl](#falcoctl-support)
  - [Rulesfiles](#rulesfiles)
  - [Falco Images](#drop-support-for-falcosecurityfalco-image)
  - [Driver Loader Init Container](#driver-loader-simplified-logic)

## 8.0.0

### Deprecated gRPC output and server

Starting with Falco 0.43.0, the gRPC output and gRPC server are **deprecated**. The gRPC server deprecation is a consequence of the gRPC output deprecation.

If you have `falco.grpc.enabled=true` or `falco.grpc_output.enabled=true`, Falco will emit a warning at startup. Consider migrating to alternative outputs such as:

- HTTP output (`falco.http_output`)
- File output (`falco.file_output`)
- Stdout output (`falco.stdout_output`)
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) for advanced integrations

### Deprecated Legacy eBPF probe and gVisor engine

Starting with Falco 0.43.0, the following engines are **deprecated**:

- **Legacy eBPF probe** (`driver.kind=ebpf`): Consider using the Modern eBPF probe (`driver.kind=modern_ebpf`) instead
- **gVisor engine** (`driver.kind=gvisor`): Consider using alternative monitoring approaches

If you are using either of these engines, Falco will emit a warning at startup. The Modern eBPF probe is recommended as it provides better performance and wider kernel compatibility.

## 7.0.0

### Deprecated container metadata collectors have been removed

The following collectors options were deprecated in the Falco chart v4.22 and have been removed from the chart:
- `collectors.containerd`
- `collectors.cri`
- `collectors.docker`

Please use the `collectors.containerEngine` instead.

## 6.0.0

### Falco Talon configuration changes

The following backward-incompatible changes have been made to `values.yaml`:

- `falcotalon` configuration has been renamed to `falco-talon`
- `falcotalon.enabled` has been renamed to `responseActions.enabled`

## 5.0.0

### Default Falco Image

**Starting with version 5.0.0, the Helm chart now uses the default Falco container image, which is a distroless image without any additional tools installed.**
Previously, the chart used the `debian` image with the several tools included to avoid breaking changes during upgrades. The new image is more secure and lightweight, but it does not include these tools.

If you rely on some tool—for example, when using the `program_output` feature—you can manually override the `image.tag` value to use a different image flavor. For instance, setting `image.tag` to `0.41.0-debian` will restore access to the tools available in the Debian-based image.

## 4.0.0

### Drivers

The `driver` section has been reworked based on the following PR: https://github.com/falcosecurity/falco/pull/2413.
It is an attempt to uniform how a driver is configured in Falco.
It also groups the configuration based on the driver type.
Some of the drivers has been renamed:

- kernel modules has been renamed from `module` to `kmod`;
- the ebpf probe has not been changed. It's still `ebpf`;
- the modern ebpf probe has been renamed from `modern-bpf` to `modern_ebpf`.

The `gvisor` configuration has been moved under the `driver` section since it is considered a driver on its own.

### K8s Collector

The old Kubernetes client has been removed in Falco 0.37.0. For more info checkout this issue: https://github.com/falcosecurity/falco/issues/2973#issuecomment-1877803422.
The [k8s-metacollector](https://github.com/falcosecurity/k8s-metacollector) and [k8s-meta](https://github.com/falcosecurity/plugins/tree/master/plugins/k8smeta) substitute
the old implementation.

The following resources needed by Falco to connect to the API server are no longer needed and has been removed from the chart:

- service account;
- cluster role;
- cluster role binding.

When the `collectors.kubernetes` is enabled the chart deploys the [k8s-metacollector](https://github.com/falcosecurity/k8s-metacollector) and configures Falco to load the
[k8s-meta](https://github.com/falcosecurity/plugins/tree/master/plugins/k8smeta) plugin.

By default, the `collectors.kubernetes.enabled` is off; for more info, see the following issue: https://github.com/falcosecurity/falco/issues/2995.

### Plugins

The Falco docker image does not ship anymore the plugins: https://github.com/falcosecurity/falco/pull/2997.
For this reason, the `resolveDeps` is now enabled in relevant values files (ie. `values-k8saudit.yaml`).
When installing `rulesfile` artifacts `falcoctl` will try to resolve its dependencies and install the required plugins.

## 3.0.0

The new chart deploys new _k8s_ resources and new configuration variables have been added to the `values.yaml` file. People upgrading the chart from `v2.x.y` have to port their configuration variables to the new `values.yaml` file used by the `v3.0.0` chart.

If you still want to use the old values, because you do not want to take advantage of the new and shiny **falcoctl** tool then just run:

```bash=
helm upgrade falco falcosecurity/falco \
    --namespace=falco \
    --reuse-values \
    --set falcoctl.artifact.install.enabled=false \
    --set falcoctl.artifact.follow.enabled=false
```

This way you will upgrade Falco to `v0.34.0`.

**NOTE**: The new version of Falco itself, installed by the chart, does not introduce breaking changes. You can port your previous Falco configuration to the new `values.yaml` by copy-pasting it.

### Falcoctl support

[Falcoctl](https://github.com/falcosecurity/falcoctl) is a new tool born to automatize operations when deploying Falco.

Before the `v3.0.0` of the charts _rulesfiles_ and _plugins_ were shipped bundled in the Falco docker image. It precluded the possibility to update the _rulesfiles_ and _plugins_ until a new version of Falco was released. Operators had to manually update the _rulesfiles_ or add new _plugins_ to Falco. The process was cumbersome and error-prone. Operators had to create their own Falco docker images with the new plugins baked into it or wait for a new Falco release.

Starting from the `v3.0.0` chart release, we add support for **falcoctl** in the charts. By deploying it alongside Falco it allows to:

- _install_ artifacts of the Falco ecosystem (i.e plugins and rules at the moment of writing)
- _follow_ those artifacts(only _rulesfile_ artifacts are recommended), to keep them up-to-date with the latest releases of the Falcosecurity organization. This allows, for instance, to update rules detecting new vulnerabilities or security issues without the need to redeploy Falco.

The chart deploys _falcoctl_ using an _init container_ and/or _sidecar container_. The first one is used to install artifacts and make them available to Falco at start-up time, the latter runs alongside Falco and updates the local artifacts when new updates are detected.

Based on your deployment scenario:

1. Falco without _plugins_ and you just want to upgrade to the new Falco version:
   ```bash=
   helm upgrade falco falcosecurity/falco \
       --namespace=falco \
       --reuse-values \
       --set falcoctl.artifact.install.enabled=false \
       --set falcoctl.artifact.follow.enabled=false
   ```
   When upgrading an existing release, _helm_ uses the new chart version. Since we added new template files and changed the values schema(added new parameters) we explicitly disable the **falcoctl** tool. By doing so, the command will reuse the existing configuration but will deploy Falco version `0.34.0`
2. Falco without _plugins_ and you want to automatically get new _falco-rules_ as soon as they are released:

   ```bash=
   helm upgrade falco falcosecurity/falco \
       --namespace=falco \
   ```

   Helm first applies the values coming from the new chart version, then overrides them using the values of the previous release. The outcome is a new release of Falco that:
   - uses the previous configuration;
   - runs Falco version `0.34.0`;
   - uses **falcoctl** to install and automatically update the [_falco-rules_](https://github.com/falcosecurity/rules/);
   - checks for new updates every 6h (default value).

3. Falco with _plugins_ and you want just to upgrade Falco:
   ```bash=
   helm upgrade falco falcosecurity/falco \
       --namespace=falco \
       --reuse-values \
       --set falcoctl.artifact.install.enabled=false \
       --set falcoctl.artifact.follow.enabled=false
   ```
   Very similar to scenario `1.`
4. Falco with plugins and you want to use **falcoctl** to download the plugins' _rulesfiles_:
   - Save **falcoctl** configuration to file:

     ```yaml=
     cat << EOF > ./falcoctl-values.yaml
     ####################
     # falcoctl config  #
     ####################
     falcoctl:
       image:
         # -- The image pull policy.
         pullPolicy: IfNotPresent
         # -- The image registry to pull from.
         registry: docker.io
         # -- The image repository to pull from.
         repository: falcosecurity/falcoctl
         #  -- Overrides the image tag whose default is the chart appVersion.
         tag: "main"
       artifact:
         # -- Runs "falcoctl artifact install" command as an init container. It is used to install artfacts before
         # Falco starts. It provides them to Falco by using an emptyDir volume.
         install:
           enabled: true
           # -- Extra environment variables that will be pass onto falcoctl-artifact-install init container.
           env: {}
           # -- Arguments to pass to the falcoctl-artifact-install init container.
           args: ["--verbose"]
           # -- Resources requests and limits for the falcoctl-artifact-install init container.
           resources: {}
           # -- Security context for the falcoctl init container.
           securityContext: {}
         # -- Runs "falcoctl artifact follow" command as a sidecar container. It is used to automatically check for
         # updates given a list of artifacts. If an update is found it downloads and installs it in a shared folder (emptyDir)
         # that is accessible by Falco. Rulesfiles are automatically detected and loaded by Falco once they are installed in the
         # correct folder by falcoctl. To prevent new versions of artifacts from breaking Falco, the tool checks if it is compatible
         # with the running version of Falco before installing it.
         follow:
           enabled: true
           # -- Extra environment variables that will be pass onto falcoctl-artifact-follow sidecar container.
           env: {}
           # -- Arguments to pass to the falcoctl-artifact-follow sidecar container.
           args: ["--verbose"]
           # -- Resources requests and limits for the falcoctl-artifact-follow sidecar container.
           resources: {}
           # -- Security context for the falcoctl-artifact-follow sidecar container.
           securityContext: {}
       # -- Configuration file of the falcoctl tool. It is saved in a configmap and mounted on the falcotl containers.
       config:
         # -- List of indexes that falcoctl downloads and uses to locate and download artiafcts. For more info see:
         # https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md#index-file-overview
         indexes:
         - name: falcosecurity
           url: https://falcosecurity.github.io/falcoctl/index.yaml
         # -- Configuration used by the artifact commands.
         artifact:

           # -- List of artifact types that falcoctl will handle. If the configured refs resolves to an artifact whose type is not contained
           # in the list it will refuse to downloade and install that artifact.
           allowedTypes:
             - rulesfile
           install:
             # -- Do not resolve the depenencies for artifacts. By default is true, but for our use carse we disable it.
             resolveDeps: false
             # -- List of artifacts to be installed by the falcoctl init container.
             refs: [k8saudit-rules:0.5]
             # -- Directory where the *rulesfiles* are saved. The path is relative to the container, which in this case is an emptyDir
             # mounted also by the Falco pod.
             rulesfilesDir: /rulesfiles
             # -- Same as the one above but for the artifacts.
             pluginsDir: /plugins
           follow:
              # -- List of artifacts to be installed by the falcoctl init container.
             refs: [k8saudit-rules:0.5]
             # -- Directory where the *rulesfiles* are saved. The path is relative to the container, which in this case is an emptyDir
             # mounted also by the Falco pod.
             rulesfilesDir: /rulesfiles
             # -- Same as the one above but for the artifacts.
             pluginsDir: /plugins
     EOF
     ```

   - Set `falcoctl.artifact.install.enabled=true` to install _rulesfiles_ of the loaded plugins. Configure **falcoctl** to install the _rulesfiles_ of the plugins you are loading with Falco. For example, if you are loading **k8saudit** plugin then you need to set `falcoctl.config.artifact.install.refs=[k8saudit-rules:0.5]`. When Falco is deployed the **falcoctl** init container will download the specified artifacts based on their tag.
   - Set `falcoctl.artifact.follow.enabled=true` to keep updated _rulesfiles_ of the loaded plugins.
   - Proceed to upgrade your Falco release by running:
     ```bash=
     helm upgrade falco falcosecurity/falco \
         --namespace=falco \
         --reuse-values \
         --values=./falcoctl-values.yaml
     ```

5. Falco with **multiple sources** enabled (syscalls + plugins):
   1. Upgrading Falco to the new version:
      ```bash=
      helm upgrade falco falcosecurity/falco \
          --namespace=falco \
          --reuse-values \
          --set falcoctl.artifact.install.enabled=false \
          --set falcoctl.artifact.follow.enabled=false
      ```
   2. Upgrading Falco and leveraging **falcoctl** for rules and plugins. Refer to point 4. for **falcoctl** configuration.

### Rulesfiles

Starting from `v0.3.0`, the chart drops the bundled **rulesfiles**. The previous version was used to create a configmap containing the following **rulesfiles**:

- application_rules.yaml
- aws_cloudtrail_rules.yaml
- falco_rules.local.yaml
- falco_rules.yaml
- k8s_audit_rules.yaml

The reason why we are dropping them is pretty simple, the files are already shipped within the Falco image and do not apport any benefit. On the other hand, we had to manually update those files for each Falco release.

For users out there, do not worry, we have you covered. As said before the **rulesfiles** are already shipped inside
the Falco image. Still, this solution has some drawbacks such as users having to wait for the next releases of Falco
to get the latest version of those **rulesfiles**. Or they could manually update them by using the [custom rules](.
/README.md#loading-custom-rules).

We came up with a better solution and that is **falcoctl**. Users can configure the **falcoctl** tool to fetch and install the latest **rulesfiles** as provided by the _falcosecurity_ organization. For more info, please check the **falcoctl** section.

**NOTE**: if any user (wrongly) used to customize those files before deploying Falco please switch to using the
[custom rules](./README.md#loading-custom-rules).

### Drop support for `falcosecurity/falco` image

Starting from version `v2.0.0` of the chart the`falcosecurity/falco-no-driver` is the default image. We were still supporting the `falcosecurity/falco` image in `v2.0.0`. But in `v2.2.0` we broke the chart when using the `falcosecurity/falco` image. For more info please check out the following issue: https://github.com/falcosecurity/charts/issues/419

#### Driver-loader simplified logic

There is only one switch to **enable/disable** the driver-loader init container: driver.loader.enabled=true. This simplification comes as a direct consequence of dropping support for the `falcosecurity/falco` image. For more info: https://github.com/falcosecurity/charts/issues/418
