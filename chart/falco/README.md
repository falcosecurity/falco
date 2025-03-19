# Falco

[Falco](https://falco.org) is a *Cloud Native Runtime Security* tool designed to detect anomalous activity in your applications. You can use Falco to monitor runtime security of your Kubernetes applications and internal components.

## Introduction

The deployment of Falco in a Kubernetes cluster is managed through a **Helm chart**. This chart manages the lifecycle of Falco in a cluster by handling all the k8s objects needed by Falco to be seamlessly integrated in your environment. Based on the configuration in [values.yaml](./values.yaml) file, the chart will render and install the required k8s objects. Keep in mind that Falco could be deployed in your cluster using a `daemonset` or a `deployment`. See next sections for more info.

## Attention

Before installing Falco in a Kubernetes cluster, a user should check that the kernel version used in the nodes is supported by the community. Also, before reporting any issue with Falco (missing kernel image, CrashLoopBackOff and similar), make sure to read [about the driver](#about-the-driver) section and adjust your setup as required.

## Adding `falcosecurity` repository

Before installing the chart, add the `falcosecurity` charts repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

## Installing the Chart

To install the chart with the release name `falco` in namespace `falco` run:

```bash
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco
```

After a few minutes Falco instances should be running on all your nodes. The status of Falco pods can be inspected through *kubectl*:
```bash
kubectl get pods -n falco -o wide
```
If everything went smoothly, you should observe an output similar to the following, indicating that all Falco instances are up and running in you cluster:

```bash
NAME          READY   STATUS    RESTARTS   AGE     IP          NODE            NOMINATED NODE   READINESS GATES
falco-57w7q   1/1     Running   0          3m12s   10.244.0.1   control-plane   <none>           <none>
falco-h4596   1/1     Running   0          3m12s   10.244.1.2   worker-node-1   <none>           <none>
falco-kb55h   1/1     Running   0          3m12s   10.244.2.3   worker-node-2   <none>           <none>
```
The cluster in our example has three nodes, one *control-plane* node and two *worker* nodes. The default configuration in [values.yaml](./values.yaml) of our helm chart deploys Falco using a `daemonset`. That's the reason why we have one Falco pod in each node.
> **Tip**: List Falco release using `helm list -n falco`, a release is a name used to track a specific deployment.

### Falco, Event Sources and Kubernetes
Starting from Falco 0.31.0 the [new plugin system](https://falco.org/docs/plugins/) is stable and production ready. The **plugin system** can be seen as the next step in the evolution of Falco. Historically, Falco monitored system events from the **kernel** trying to detect malicious behaviors on Linux systems. It also had the capability to process k8s Audit Logs to detect suspicious activities in Kubernetes clusters. Since Falco 0.32.0 all the related code to the k8s Audit Logs in Falco was removed and ported in a [plugin](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit). At the time being Falco supports different event sources coming from **plugins** or **drivers** (system events).

Note that **a Falco instance can handle multiple event sources in parallel**. you can deploy Falco leveraging **drivers** for syscall events and at the same time loading **plugins**. A step by step guide on how to deploy Falco with multiple sources can be found [here](https://falco.org/docs/getting-started/learning-environments/#falco-with-multiple-sources).

#### About Drivers

Falco needs a **driver** to analyze the system workload and pass security events to userspace. The supported drivers are:

* [Modern eBPF probe](https://falco.org/docs/concepts/event-sources/kernel/#modern-ebpf-probe)
* [Kernel module](https://falco.org/docs/concepts/event-sources/kernel/#kernel-module)
* [Legacy eBPF probe](https://falco.org/docs/concepts/event-sources/kernel/#legacy-ebpf-probe)

The driver must be loaded on the node where Falco is running. Falco now prefers the **Modern eBPF probe** by default. When using **falcoctl** with `driver.kind=auto`, it will automatically choose the best driver for your system. Specifically, it first attempts to use the Modern eBPF probe (which is shipped directly within the Falco binary) and will fall back to the _kernel module_ or the _original eBPF probe_ if the necessary BPF features are not available.

##### Pre-built drivers

The [kernel-crawler](https://github.com/falcosecurity/kernel-crawler) automatically discovers kernel versions and flavors. At the time being, it runs weekly. We have a site where users can check for the discovered kernel flavors and versions, [example for Amazon Linux 2](https://falcosecurity.github.io/kernel-crawler/?arch=x86_64&target=AmazonLinux2).

The discovery of a kernel version by the [kernel-crawler](https://falcosecurity.github.io/kernel-crawler/) does not imply that pre-built kernel modules and bpf probes are available. That is because once kernel-crawler has discovered new kernels versions, the drivers need to be built by jobs running on our [Driver Build Grid infra](https://github.com/falcosecurity/test-infra#dbg). Please keep in mind that the building process is based on best effort. Users can check the existence of prebuilt modules at the following [link](https://download.falco.org/driver/site/index.html?lib=3.0.1%2Bdriver&target=all&arch=all&kind=all).

##### Building the driver on the fly (fallback)

If a prebuilt driver is not available for your distribution/kernel, users can build the driver by them self or install the kernel headers on the nodes, and the init container (falco-driver-loader) will try and build the driver on the fly.

Falco needs **kernel headers** installed on the host as a prerequisite to build the driver on the fly correctly. You can find instructions for installing the kernel headers for your system under the [Install section](https://falco.org/docs/getting-started/installation/) of the official documentation.

##### Selecting a different driver loader image

Note that since Falco 0.36.0 and Helm chart version 3.7.0 the driver loader image has been updated to be compatible with newer kernels (5.x and above) meaning that if you have an older kernel version and you are trying to build the kernel module you may experience issues. In that case you can use the `falco-driver-loader-legacy` image to use the previous version of the toolchain. To do so you can set the appropriate value, i.e. `--set driver.loader.initContainer.image.repository=falcosecurity/falco-driver-loader-legacy`.

#### About Plugins
[Plugins](https://falco.org/docs/plugins/) are used to extend Falco to support new **data sources**. The current **plugin framework** supports *plugins* with the following *capabilities*:

* Event sourcing capability;
* Field extraction capability;

Plugin capabilities are *composable*, we can have a single plugin with both capabilities. Or on the other hand, we can load two different plugins each with its capability, one plugin as a source of events and another as an extractor. A good example of this is the [Kubernetes Audit Events](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) and the [Falcosecurity Json](https://github.com/falcosecurity/plugins/tree/master/plugins/json) *plugins*. By deploying them both we have support for the **K8s Audit Logs** in Falco

Note that **the driver is not required when using plugins**.

#### About gVisor
gVisor is an application kernel, written in Go, that implements a substantial portion of the Linux system call interface. It provides an additional layer of isolation between running applications and the host operating system. For more information please consult the [official docs](https://gvisor.dev/docs/). In version `0.32.1`, Falco first introduced support for gVisor by leveraging the stream of system call information coming from gVisor.
Falco requires the version of [runsc](https://gvisor.dev/docs/user_guide/install/) to be equal to or above `20220704.0`. The following snippet shows the gVisor configuration variables found in [values.yaml](./values.yaml):
```yaml
driver:
  gvisor:
    enabled: true
    runsc:
      path: /home/containerd/usr/local/sbin
      root: /run/containerd/runsc
      config: /run/containerd/runsc/config.toml
```
Falco uses the [runsc](https://gvisor.dev/docs/user_guide/install/) binary to interact with sandboxed containers. The following variables need to be set:
* `runsc.path`: absolute path of the `runsc` binary in the k8s nodes;
* `runsc.root`: absolute path of the root directory of the `runsc` container runtime. It is of vital importance for Falco since `runsc` stores there the information of the workloads handled by it;
* `runsc.config`: absolute path of the `runsc` configuration file, used by Falco to set its configuration and make aware `gVisor` of its presence.

If you want to know more how Falco uses those configuration paths please have a look at the `falco.gvisor.initContainer` helper in [helpers.tpl](./templates/_helpers.tpl).
A preset `values.yaml` file [values-gvisor-gke.yaml](./values-gvisor-gke.yaml) is provided and can be used as it is to deploy Falco with gVisor support in a [GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods) cluster. It is also a good starting point for custom deployments.

##### Example: running Falco on GKE, with or without gVisor-enabled pods

If you use GKE with k8s version at least `1.24.4-gke.1800` or `1.25.0-gke.200` with gVisor sandboxed pods, you can install a Falco instance to monitor them with, e.g.:

```
helm install falco-gvisor falcosecurity/falco \
    --create-namespace \
    --namespace falco-gvisor \
    -f https://raw.githubusercontent.com/falcosecurity/charts/master/charts/falco/values-gvisor-gke.yaml
```

Note that the instance of Falco above will only monitor gVisor sandboxed workloads on gVisor-enabled node pools. If you also need to monitor regular workloads on regular node pools you can use the eBPF driver as usual:

```
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set driver.kind=ebpf
```

The two instances of Falco will operate independently and can be installed, uninstalled or configured as needed. If you were already monitoring your regular node pools with eBPF you don't need to reinstall it.

##### Falco+gVisor additional resources
An exhaustive blog post about Falco and gVisor can be found on the [Falco blog](https://falco.org/blog/intro-gvisor-falco/).
If you need help on how to set gVisor in your environment please have a look at the [gVisor official docs](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)

### About Falco Artifacts
Historically **rules files** and **plugins** used to be shipped inside the Falco docker image and/or inside the chart. Starting from version `v0.3.0` of the chart, the [**falcoctl tool**](https://github.com/falcosecurity/falcoctl) can be used to install/update **rules files** and **plugins**. When referring to such objects we will use the term **artifact**.  For more info please check out the following [proposal](https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md).

The default configuration of the chart for new installations is to use the **falcoctl** tool to handle **artifacts**. The chart will deploy two new containers along the Falco one:
* `falcoctl-artifact-install` an init container that makes sure to install the configured **artifacts** before the Falco container starts;
* `falcoctl-artifact-follow` a sidecar container that periodically checks for new artifacts (currently only *falco-rules*) and downloads them;

For more info on how to enable/disable and configure the **falcoctl** tool checkout the config values [here](./README.md#Configuration) and the [upgrading notes](./BREAKING-CHANGES.md#300)

### Deploying Falco in Kubernetes
After the clarification of the different [**event sources**](#falco-event-sources-and-kubernetes) and how they are consumed by Falco using the **drivers** and the **plugins**, now let us discuss how Falco is deployed in Kubernetes.

The chart deploys Falco using a `daemonset` or a `deployment` depending on the **event sources**.

#### Daemonset
When using the [drivers](#about-the-driver), Falco is typically deployed as a `DaemonSet`. By using a DaemonSet, Kubernetes ensures that a Falco instance is running on each node even as new nodes are added to your cluster. This makes it a perfect fit for monitoring across the entire cluster.

By default, with `driver.kind=auto`, the correct driver will will be automatically selected for each node. This is accomplished through the **driver loader** (implemented by `falcoctl`), which generates a new Falco configuration file and picks the right engine driver (Modern eBPF, kmod, or legacy eBPF) based on the underlying environment. If you prefer to manually force a specific driver, see the other available options below.

**Kernel module**

To run Falco with the [eBPF probe](https://falco.org/docs/concepts/event-sources/kernel/#kernel-module) you just need to set `driver.kind=kmod` as shown in the following snippet:

```bash
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco
    --set driver.kind=kmod
```

**Legacy eBPF probe**

To run Falco with the [eBPF probe](http://falco.org/docs/concepts/event-sources/kernel/#legacy-ebpf-probe) you just need to set `driver.kind=ebpf` as shown in the following snippet:

```bash
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set driver.kind=ebpf
```

There are other configurations related to the eBPF probe, for more info please check the [values.yaml](./values.yaml) file. After you have made your changes to the configuration file you just need to run:

```bash
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace "your-custom-name-space" \
    -f "path-to-custom-values.yaml-file"
```

**Modern eBPF probe**

To run Falco with the [modern eBPF probe](https://falco.org/docs/concepts/event-sources/kernel/#modern-ebpf-probe) you just need to set `driver.kind=modern_bpf` as shown in the following snippet:

```bash
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set driver.kind=modern_ebpf
```

#### Deployment
In the scenario when Falco is used with **plugins** as data sources, then the best option is to deploy it as a k8s `deployment`. **Plugins** could be of two types, the ones that follow the **push model** or the **pull model**. A plugin that adopts the firs model expects to receive the data from a remote source in a given endpoint. They just expose and endpoint and wait for data to be posted, for example [Kubernetes Audit Events](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) expects the data to be sent by the *k8s api server* when configured in such way. On the other hand other plugins that abide by the **pull model** retrieves the data from a given remote service.
The following points explain why a k8s `deployment` is suitable when deploying Falco with plugins:

* need to be reachable when ingesting logs directly from remote services;
* need only one active replica, otherwise events will be sent/received to/from different Falco instances;

## Uninstalling the Chart

To uninstall a Falco release from your Kubernetes cluster always you helm. It will take care to remove all components deployed by the chart and clean up your environment. The following command will remove a release called `falco` in namespace `falco`;

```bash
helm uninstall falco --namespace falco
```

## Showing logs generated by Falco container
There are many reasons why we would have to inspect the messages emitted by the Falco container. When deployed in Kubernetes the Falco logs can be inspected through:
```bash
kubectl logs -n falco falco-pod-name
```
where `falco-pods-name` is the name of the Falco pod running in your cluster.
The command described above will just display the logs emitted by falco until the moment you run the command. The `-f` flag comes handy when we are doing live testing or debugging and we want to have the Falco logs as soon as they are emitted. The following command:
```bash
kubectl logs -f -n falco falco-pod-name
```
The `-f (--follow)` flag follows the logs and live stream them to your terminal and it is really useful when you are debugging a new rule and want to make sure that the rule is triggered when some actions are performed in the system.

If we need to access logs of a previous Falco run we do that by adding the `-p (--previous)` flag:
```bash
kubectl logs -p -n falco falco-pod-name
```
A scenario when we need the `-p (--previous)` flag is when we have a restart of a Falco pod and want to check what went wrong.

### Enabling real time logs
By default in Falco the output is buffered. When live streaming logs we will notice delays between the logs output (rules triggering) and the event happening.
In order to enable the logs to be emitted without delays you need to set `.Values.tty=true` in [values.yaml](./values.yaml) file.

## K8s-metacollector
Starting from Falco `0.37` the old [k8s-client](https://github.com/falcosecurity/falco/issues/2973) has been removed.
A new component named [k8s-metacollector](https://github.com/falcosecurity/k8s-metacollector) replaces it.
The *k8s-metacollector* is a self-contained module that can be deployed within a Kubernetes cluster to perform the task of gathering metadata
from various Kubernetes resources and subsequently transmitting this collected metadata to designated subscribers.

Kubernetes' resources for which metadata will be collected and sent to Falco:
* pods;
* namespaces;
* deployments;
* replicationcontrollers;
* replicasets;
* services;

### Plugin
Since the *k8s-metacollector* is standalone, deployed in the cluster as a deployment, Falco instances need to connect to the component
in order to retrieve the `metadata`. Here it comes the [k8smeta](https://github.com/falcosecurity/plugins/tree/master/plugins/k8smeta) plugin.
The plugin gathers details about Kubernetes resources from the *k8s-metacollector*. It then stores this information
in tables and provides access to Falco upon request. The plugin specifically acquires data for the node where the
associated Falco instance is deployed, resulting in node-level granularity.

### Exported Fields: Old and New
The old [k8s-client](https://github.com/falcosecurity/falco/issues/2973) used to populate the
[k8s](https://falco.org/docs/reference/rules/supported-fields/#field-class-k8s) fields. The **k8s** field class is still
available in Falco, for compatibility reasons, but most of the fields will return `N/A`. The following fields are still
usable and will return meaningful data when the `container runtime collectors` are enabled:
* k8s.pod.name;
* k8s.pod.id;
* k8s.pod.label;
* k8s.pod.labels;
* k8s.pod.ip;
* k8s.pod.cni.json;
* k8s.pod.namespace.name;

The [k8smeta](https://github.com/falcosecurity/plugins/tree/master/plugins/k8smeta) plugin exports a whole new
[field class]https://github.com/falcosecurity/plugins/tree/master/plugins/k8smeta#supported-fields. Note that the new
`k8smeta.*` fields are usable only when the **k8smeta** plugin is loaded in Falco.

### Enabling the k8s-metacollector
The following command will deploy Falco + k8s-metacollector + k8smeta:
```bash
helm install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --set collectors.kubernetes.enabled=true
```

## Loading custom rules

Falco ships with a nice default ruleset. It is a good starting point but sooner or later, we are going to need to add custom rules which fit our needs.

So the question is: How can we load custom rules in our Falco deployment?

We are going to create a file that contains custom rules so that we can keep it in a Git repository.

```bash
cat custom-rules.yaml
```

And the file looks like this one:

```yaml
customRules:
  rules-traefik.yaml: |-
    - macro: traefik_consider_syscalls
      condition: (evt.num < 0)

    - macro: app_traefik
      condition: container and container.image startswith "traefik"

    # Restricting listening ports to selected set

    - list: traefik_allowed_inbound_ports_tcp
      items: [443, 80, 8080]

    - rule: Unexpected inbound tcp connection traefik
      desc: Detect inbound traffic to traefik using tcp on a port outside of expected set
      condition: inbound and evt.rawres >= 0 and not fd.sport in (traefik_allowed_inbound_ports_tcp) and app_traefik
      output: Inbound network connection to traefik on unexpected port (command=%proc.cmdline pid=%proc.pid connection=%fd.name sport=%fd.sport user=%user.name %container.info image=%container.image)
      priority: NOTICE

    # Restricting spawned processes to selected set

    - list: traefik_allowed_processes
      items: ["traefik"]

    - rule: Unexpected spawned process traefik
      desc: Detect a process started in a traefik container outside of an expected set
      condition: spawned_process and not proc.name in (traefik_allowed_processes) and app_traefik
      output: Unexpected process spawned in traefik container (command=%proc.cmdline pid=%proc.pid user=%user.name %container.info image=%container.image)
      priority: NOTICE
```

So next step is to use the custom-rules.yaml file for installing the Falco Helm chart.

```bash
helm install falco -f custom-rules.yaml falcosecurity/falco
```

And we will see in our logs something like:

```bash
Tue Jun  5 15:08:57 2018: Loading rules from file /etc/falco/rules.d/rules-traefik.yaml:
```

And this means that our Falco installation has loaded the rules and is ready to help us.

## Kubernetes Audit Log

The Kubernetes Audit Log is now supported via the built-in [k8saudit](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) plugin. It is entirely up to you to set up the [webhook backend](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend) of the Kubernetes API server to forward the Audit Log event to the Falco listening port.

The following snippet shows how to deploy Falco with the [k8saudit](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) plugin:
```yaml
# -- Disable the drivers since we want to deploy only the k8saudit plugin.
driver:
  enabled: false

# -- Disable the collectors, no syscall events to enrich with metadata.
collectors:
  enabled: false

# -- Deploy Falco as a deployment. One instance of Falco is enough. Anyway the number of replicas is configurable.
controller:
  kind: deployment
  deployment:
    # -- Number of replicas when installing Falco using a deployment. Change it if you really know what you are doing.
    # For more info check the section on Plugins in the README.md file.
    replicas: 1

falcoctl:
  artifact:
    install:
      # -- Enable the init container. We do not recommend installing (or following) plugins for security reasons since they are executable objects.
      enabled: true
    follow:
      # -- Enable the sidecar container. We do not support it yet for plugins. It is used only for rules feed such as k8saudit-rules rules.
      enabled: true
  config:
    artifact:
      install:
        # -- Resolve the dependencies for artifacts.
        resolveDeps: true
        # -- List of artifacts to be installed by the falcoctl init container.
        # Only rulesfile, the plugin will be installed as a dependency.
        refs: [k8saudit-rules:0.5]
      follow:
        # -- List of artifacts to be followed by the falcoctl sidecar container.
        refs: [k8saudit-rules:0.5]

services:
  - name: k8saudit-webhook
    type: NodePort
    ports:
      - port: 9765 # See plugin open_params
        nodePort: 30007
        protocol: TCP

falco:
  rules_files:
    - /etc/falco/k8s_audit_rules.yaml
    - /etc/falco/rules.d
  plugins:
    - name: k8saudit
      library_path: libk8saudit.so
      init_config:
        ""
        # maxEventBytes: 1048576
        # sslCertificate: /etc/falco/falco.pem
      open_params: "http://:9765/k8s-audit"
    - name: json
      library_path: libjson.so
      init_config: ""
  # Plugins that Falco will load. Note: the same plugins are installed by the falcoctl-artifact-install init container.
  load_plugins: [k8saudit, json]

```
Here is the explanation of the above configuration:
* disable the drivers by setting `driver.enabled=false`;
* disable the collectors by setting `collectors.enabled=false`;
* deploy the Falco using a k8s *deployment* by setting `controller.kind=deployment`;
* make our Falco instance reachable by the `k8s api-server` by configuring a service for it in `services`;
* enable the `falcoctl-artifact-install` init container;
* configure `falcoctl-artifact-install` to install the required plugins;
* disable the `falcoctl-artifact-follow` sidecar container;
* load the correct ruleset for our plugin in `falco.rulesFile`;
* configure the plugins to be loaded, in this case, the `k8saudit` and `json`;
* and finally we add our plugins in the `load_plugins` to be loaded by Falco.

The configuration can be found in the [values-k8saudit.yaml(./values-k8saudit.yaml] file ready to be used:

```bash
#make sure the falco namespace exists
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    -f ./values-k8saudit.yaml
```
After a few minutes a Falco instance should be running on your cluster. The status of Falco pod can be inspected through *kubectl*:
```bash
kubectl get pods -n falco -o wide
```
If everything went smoothly, you should observe an output similar to the following, indicating that the Falco instance is up and running:

```bash
NAME                     READY   STATUS    RESTARTS   AGE    IP           NODE            NOMINATED NODE   READINESS GATES
falco-64484d9579-qckms   1/1     Running   0          101s   10.244.2.2   worker-node-2   <none>           <none>
```

Furthermore you can check that Falco logs through *kubectl logs*

```bash
kubectl logs -n falco falco-64484d9579-qckms
```
In the logs you should have something similar to the following, indicating that Falco has loaded the required plugins:
```bash
Fri Jul  8 16:07:24 2022: Falco version 0.32.0 (driver version 39ae7d40496793cf3d3e7890c9bbdc202263836b)
Fri Jul  8 16:07:24 2022: Falco initialized with configuration file /etc/falco/falco.yaml
Fri Jul  8 16:07:24 2022: Loading plugin (k8saudit) from file /usr/share/falco/plugins/libk8saudit.so
Fri Jul  8 16:07:24 2022: Loading plugin (json) from file /usr/share/falco/plugins/libjson.so
Fri Jul  8 16:07:24 2022: Loading rules from file /etc/falco/k8s_audit_rules.yaml:
Fri Jul  8 16:07:24 2022: Starting internal webserver, listening on port 8765
```
*Note that the support for the dynamic backend (also known as the `AuditSink` object) has been deprecated from Kubernetes and removed from this chart.*

### Manual setup with NodePort on kOps

Using `kops edit cluster`, ensure these options are present, then run `kops update cluster` and `kops rolling-update cluster`:
```yaml
spec:
  kubeAPIServer:
    auditLogMaxBackups: 1
    auditLogMaxSize: 10
    auditLogPath: /var/log/k8s-audit.log
    auditPolicyFile: /srv/kubernetes/assets/audit-policy.yaml
    auditWebhookBatchMaxWait: 5s
    auditWebhookConfigFile: /srv/kubernetes/assets/webhook-config.yaml
  fileAssets:
  - content: |
      # content of the webserver CA certificate
      # remove this fileAsset and certificate-authority from webhook-config if using http
    name: audit-ca.pem
    roles:
    - Master
  - content: |
      apiVersion: v1
      kind: Config
      clusters:
      - name: falco
        cluster:
          # remove 'certificate-authority' when using 'http'
          certificate-authority: /srv/kubernetes/assets/audit-ca.pem
          server: https://localhost:32765/k8s-audit
      contexts:
      - context:
          cluster: falco
          user: ""
        name: default-context
      current-context: default-context
      preferences: {}
      users: []
    name: webhook-config.yaml
    roles:
    - Master
  - content: |
      # ... paste audit-policy.yaml here ...
      # https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/k8saudit/configs/audit-policy.yaml
    name: audit-policy.yaml
    roles:
    - Master
```
## Enabling gRPC

The Falco gRPC server and the Falco gRPC Outputs APIs are not enabled by default.
Moreover, Falco supports running a gRPC server with two main binding types:
- Over a local **Unix socket** with no authentication
- Over the **network** with mandatory mutual TLS authentication (mTLS)

### gRPC over unix socket (default)

The preferred way to use the gRPC is over a Unix socket.

To install Falco with gRPC enabled over a **unix socket**, you have to:

```shell
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set falco.grpc.enabled=true \
    --set falco.grpc_output.enabled=true
```

### gRPC over network

The gRPC server over the network can only be used with mutual authentication between the clients and the server using TLS certificates.
How to generate the certificates is [documented here](https://falco.org/docs/grpc/#generate-valid-ca).

To install Falco with gRPC enabled over the **network**, you have to:

```shell
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set falco.grpc.enabled=true \
    --set falco.grpc_output.enabled=true \
    --set falco.grpc.unixSocketPath="" \
    --set-file certs.server.key=/path/to/server.key \
    --set-file certs.server.crt=/path/to/server.crt \
    --set-file certs.ca.crt=/path/to/ca.crt

```

## Enable http_output

HTTP output enables Falco to send events through HTTP(S) via the following configuration:

```shell
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set falco.http_output.enabled=true \
    --set falco.http_output.url="http://some.url/some/path/" \
    --set falco.json_output=true \
    --set json_include_output_property=true
```

Additionally, you can enable mTLS communication and load HTTP client cryptographic material via:

```shell
helm install falco falcosecurity/falco \
    --create-namespace \
    --namespace falco \
    --set falco.http_output.enabled=true \
    --set falco.http_output.url="https://some.url/some/path/" \
    --set falco.json_output=true \
    --set json_include_output_property=true \
    --set falco.http_output.mtls=true \
    --set falco.http_output.client_cert="/etc/falco/certs/client/client.crt" \
    --set falco.http_output.client_key="/etc/falco/certs/client/client.key" \
    --set falco.http_output.ca_cert="/etc/falco/certs/client/ca.crt" \
    --set-file certs.client.key="/path/to/client.key",certs.client.crt="/path/to/client.crt",certs.ca.crt="/path/to/cacert.crt"
```

Or instead of directly setting the files via `--set-file`, mounting an existing volume with the `certs.existingClientSecret` value.

## Deploy Falcosidekick with Falco

[`Falcosidekick`](https://github.com/falcosecurity/falcosidekick) can be installed with `Falco` by setting `--set falcosidekick.enabled=true`. This setting automatically configures all options of `Falco` for working with `Falcosidekick`.
All values for the configuration of `Falcosidekick` are available by prefixing them with `falcosidekick.`. The full list of available values is [here](https://github.com/falcosecurity/charts/tree/master/charts/falcosidekick#configuration).
For example, to enable the deployment of [`Falcosidekick-UI`](https://github.com/falcosecurity/falcosidekick-ui), add `--set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true`.

If you use a Proxy in your cluster, the requests between `Falco` and `Falcosidekick` might be captured, use the full FQDN of `Falcosidekick` by using `--set falcosidekick.fullfqdn=true` to avoid that.

## Configuration

The following table lists the main configurable parameters of the falco chart v4.21.3 and their default values. See [values.yaml](./values.yaml) for full list.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity constraint for pods' scheduling. |
| certs | object | `{"ca":{"crt":""},"client":{"crt":"","key":""},"existingClientSecret":"","existingSecret":"","server":{"crt":"","key":""}}` | certificates used by webserver and grpc server. paste certificate content or use helm with --set-file or use existing secret containing key, crt, ca as well as pem bundle |
| certs.ca.crt | string | `""` | CA certificate used by gRPC, webserver and AuditSink validation. |
| certs.client.crt | string | `""` | Certificate used by http mTLS client. |
| certs.client.key | string | `""` | Key used by http mTLS client. |
| certs.existingSecret | string | `""` | Existing secret containing the following key, crt and ca as well as the bundle pem. |
| certs.server.crt | string | `""` | Certificate used by gRPC and webserver. |
| certs.server.key | string | `""` | Key used by gRPC and webserver. |
| collectors.containerd.enabled | bool | `true` | Enable ContainerD support. |
| collectors.containerd.socket | string | `"/run/containerd/containerd.sock"` | The path of the ContainerD socket. |
| collectors.crio.enabled | bool | `true` | Enable CRI-O support. |
| collectors.crio.socket | string | `"/run/crio/crio.sock"` | The path of the CRI-O socket. |
| collectors.docker.enabled | bool | `true` | Enable Docker support. |
| collectors.docker.socket | string | `"/var/run/docker.sock"` | The path of the Docker daemon socket. |
| collectors.enabled | bool | `true` | Enable/disable all the metadata collectors. |
| collectors.kubernetes | object | `{"collectorHostname":"","collectorPort":"","enabled":false,"hostProc":"/host","pluginRef":"ghcr.io/falcosecurity/plugins/plugin/k8smeta:0.2.1","verbosity":"info"}` | kubernetes holds the configuration for the kubernetes collector. Starting from version 0.37.0 of Falco, the legacy kubernetes client has been removed. A new standalone component named k8s-metacollector and a Falco plugin have been developed to solve the issues that were present in the old implementation. More info here: https://github.com/falcosecurity/falco/issues/2973 |
| collectors.kubernetes.collectorHostname | string | `""` | collectorHostname is the address of the k8s-metacollector. When not specified it will be set to match k8s-metacollector service. e.x: falco-k8smetacollecto.falco.svc. If for any reason you need to override it, make sure to set here the address of the k8s-metacollector. It is used by the k8smeta plugin to connect to the k8s-metacollector. |
| collectors.kubernetes.collectorPort | string | `""` | collectorPort designates the port on which the k8s-metacollector gRPC service listens. If not specified the value of the port named `broker-grpc` in k8s-metacollector.service.ports is used. The default values is 45000. It is used by the k8smeta plugin to connect to the k8s-metacollector. |
| collectors.kubernetes.enabled | bool | `false` | enabled specifies whether the Kubernetes metadata should be collected using the k8smeta plugin and the k8s-metacollector component. It will deploy the k8s-metacollector external component that fetches Kubernetes metadata and pushes them to Falco instances. For more info see: https://github.com/falcosecurity/k8s-metacollector https://github.com/falcosecurity/charts/tree/master/charts/k8s-metacollector When this option is disabled, Falco falls back to the container annotations to grab the metadata. In such a case, only the ID, name, namespace, labels of the pod will be available. |
| collectors.kubernetes.pluginRef | string | `"ghcr.io/falcosecurity/plugins/plugin/k8smeta:0.2.1"` | pluginRef is the OCI reference for the k8smeta plugin. It could be a full reference such as: "ghcr.io/falcosecurity/plugins/plugin/k8smeta:0.1.0". Or just name + tag: k8smeta:0.1.0. |
| containerSecurityContext | object | `{}` | Set securityContext for the Falco container.For more info see the "falco.securityContext" helper in "pod-template.tpl" |
| controller.annotations | object | `{}` |  |
| controller.daemonset.updateStrategy.type | string | `"RollingUpdate"` | Perform rolling updates by default in the DaemonSet agent ref: https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/ |
| controller.deployment.replicas | int | `1` | Number of replicas when installing Falco using a deployment. Change it if you really know what you are doing. For more info check the section on Plugins in the README.md file. |
| controller.kind | string | `"daemonset"` |  |
| controller.labels | object | `{}` | Extra labels to add to the daemonset or deployment |
| customRules | object | `{}` | Third party rules enabled for Falco. More info on the dedicated section in README.md file. |
| driver.ebpf | object | `{"bufSizePreset":4,"dropFailedExit":false,"hostNetwork":false,"leastPrivileged":false,"path":"${HOME}/.falco/falco-bpf.o"}` | Configuration section for ebpf driver. |
| driver.ebpf.bufSizePreset | int | `4` | bufSizePreset determines the size of the shared space between Falco and its drivers. This shared space serves as a temporary storage for syscall events. |
| driver.ebpf.dropFailedExit | bool | `false` | dropFailedExit if set true drops failed system call exit events before pushing them to userspace. |
| driver.ebpf.hostNetwork | bool | `false` | Needed to enable eBPF JIT at runtime for performance reasons. Can be skipped if eBPF JIT is enabled from outside the container |
| driver.ebpf.leastPrivileged | bool | `false` | Constrain Falco with capabilities instead of running a privileged container. Ensure the eBPF driver is enabled (i.e., setting the `driver.kind` option to `ebpf`). Capabilities used: {CAP_SYS_RESOURCE, CAP_SYS_ADMIN, CAP_SYS_PTRACE}. On kernel versions >= 5.8 'CAP_PERFMON' and 'CAP_BPF' could replace 'CAP_SYS_ADMIN' but please pay attention to the 'kernel.perf_event_paranoid' value on your system. Usually 'kernel.perf_event_paranoid>2' means that you cannot use 'CAP_PERFMON' and you should fallback to 'CAP_SYS_ADMIN', but the behavior changes across different distros. Read more on that here: https://falco.org/docs/setup/container/#docker-least-privileged-ebpf-probe |
| driver.ebpf.path | string | `"${HOME}/.falco/falco-bpf.o"` | path where the eBPF probe is located. It comes handy when the probe have been installed in the nodes using tools other than the init container deployed with the chart. |
| driver.enabled | bool | `true` | Set it to false if you want to deploy Falco without the drivers. Always set it to false when using Falco with plugins. |
| driver.gvisor | object | `{"runsc":{"config":"/run/containerd/runsc/config.toml","path":"/home/containerd/usr/local/sbin","root":"/run/containerd/runsc"}}` | Gvisor configuration. Based on your system you need to set the appropriate values. Please, remember to add pod tolerations and affinities in order to schedule the Falco pods in the gVisor enabled nodes. |
| driver.gvisor.runsc | object | `{"config":"/run/containerd/runsc/config.toml","path":"/home/containerd/usr/local/sbin","root":"/run/containerd/runsc"}` | Runsc container runtime configuration. Falco needs to interact with it in order to intercept the activity of the sandboxed pods. |
| driver.gvisor.runsc.config | string | `"/run/containerd/runsc/config.toml"` | Absolute path of the `runsc` configuration file, used by Falco to set its configuration and make aware `gVisor` of its presence. |
| driver.gvisor.runsc.path | string | `"/home/containerd/usr/local/sbin"` | Absolute path of the `runsc` binary in the k8s nodes. |
| driver.gvisor.runsc.root | string | `"/run/containerd/runsc"` | Absolute path of the root directory of the `runsc` container runtime. It is of vital importance for Falco since `runsc` stores there the information of the workloads handled by it; |
| driver.kind | string | `"auto"` | kind tells Falco which driver to use. Available options: kmod (kernel driver), ebpf (eBPF probe), modern_ebpf (modern eBPF probe). |
| driver.kmod | object | `{"bufSizePreset":4,"dropFailedExit":false}` | kmod holds the configuration for the kernel module. |
| driver.kmod.bufSizePreset | int | `4` | bufSizePreset determines the size of the shared space between Falco and its drivers. This shared space serves as a temporary storage for syscall events. |
| driver.kmod.dropFailedExit | bool | `false` | dropFailedExit if set true drops failed system call exit events before pushing them to userspace. |
| driver.loader | object | `{"enabled":true,"initContainer":{"args":[],"env":[],"image":{"pullPolicy":"IfNotPresent","registry":"docker.io","repository":"falcosecurity/falco-driver-loader","tag":""},"resources":{},"securityContext":{}}}` | Configuration for the Falco init container. |
| driver.loader.enabled | bool | `true` | Enable/disable the init container. |
| driver.loader.initContainer.args | list | `[]` | Arguments to pass to the Falco driver loader init container. |
| driver.loader.initContainer.env | list | `[]` | Extra environment variables that will be pass onto Falco driver loader init container. |
| driver.loader.initContainer.image.pullPolicy | string | `"IfNotPresent"` | The image pull policy. |
| driver.loader.initContainer.image.registry | string | `"docker.io"` | The image registry to pull from. |
| driver.loader.initContainer.image.repository | string | `"falcosecurity/falco-driver-loader"` | The image repository to pull from. |
| driver.loader.initContainer.resources | object | `{}` | Resources requests and limits for the Falco driver loader init container. |
| driver.loader.initContainer.securityContext | object | `{}` | Security context for the Falco driver loader init container. Overrides the default security context. If driver.kind == "module" you must at least set `privileged: true`. |
| driver.modernEbpf.bufSizePreset | int | `4` | bufSizePreset determines the size of the shared space between Falco and its drivers. This shared space serves as a temporary storage for syscall events. |
| driver.modernEbpf.cpusForEachBuffer | int | `2` | cpusForEachBuffer is the index that controls how many CPUs to assign to a single syscall buffer. |
| driver.modernEbpf.dropFailedExit | bool | `false` | dropFailedExit if set true drops failed system call exit events before pushing them to userspace. |
| driver.modernEbpf.leastPrivileged | bool | `false` | Constrain Falco with capabilities instead of running a privileged container. Ensure the modern bpf driver is enabled (i.e., setting the `driver.kind` option to `modern-bpf`). Capabilities used: {CAP_SYS_RESOURCE, CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE}. Read more on that here: https://falco.org/docs/setup/container/#docker-least-privileged-ebpf-probe |
| extra.args | list | `[]` | Extra command-line arguments. |
| extra.env | list | `[]` | Extra environment variables that will be pass onto Falco containers. |
| extra.initContainers | list | `[]` | Additional initContainers for Falco pods. |
| falco.append_output | list | `[]` |  |
| falco.base_syscalls | object | `{"custom_set":[],"repair":false}` | - [Suggestions]  NOTE: setting `base_syscalls.repair: true` automates the following suggestions for you.  These suggestions are subject to change as Falco and its state engine evolve.  For execve* events: Some Falco fields for an execve* syscall are retrieved from the associated `clone`, `clone3`, `fork`, `vfork` syscalls when spawning a new process. The `close` syscall is used to purge file descriptors from Falco's internal thread / process cache table and is necessary for rules relating to file descriptors (e.g. open, openat, openat2, socket, connect, accept, accept4 ... and many more)  Consider enabling the following syscalls in `base_syscalls.custom_set` for process rules: [clone, clone3, fork, vfork, execve, execveat, close]  For networking related events: While you can log `connect` or `accept*` syscalls without the socket syscall, the log will not contain the ip tuples. Additionally, for `listen` and `accept*` syscalls, the `bind` syscall is also necessary.  We recommend the following as the minimum set for networking-related rules: [clone, clone3, fork, vfork, execve, execveat, close, socket, bind, getsockopt]  Lastly, for tracking the correct `uid`, `gid` or `sid`, `pgid` of a process when the running process opens a file or makes a network connection, consider adding the following to the above recommended syscall sets: ... setresuid, setsid, setuid, setgid, setpgid, setresgid, setsid, capset, chdir, chroot, fchdir ... |
| falco.buffered_outputs | bool | `false` | Enabling buffering for the output queue can offer performance optimization, efficient resource usage, and smoother data flow, resulting in a more reliable output mechanism. By default, buffering is disabled (false). |
| falco.config_files[0] | string | `"/etc/falco/config.d"` |  |
| falco.container_engines.bpm.enabled | bool | `false` |  |
| falco.container_engines.cri.disable_async | bool | `false` |  |
| falco.container_engines.cri.enabled | bool | `false` |  |
| falco.container_engines.cri.sockets[0] | string | `"/run/containerd/containerd.sock"` |  |
| falco.container_engines.cri.sockets[1] | string | `"/run/crio/crio.sock"` |  |
| falco.container_engines.cri.sockets[2] | string | `"/run/k3s/containerd/containerd.sock"` |  |
| falco.container_engines.docker.enabled | bool | `false` |  |
| falco.container_engines.libvirt_lxc.enabled | bool | `false` |  |
| falco.container_engines.lxc.enabled | bool | `false` |  |
| falco.container_engines.podman.enabled | bool | `false` |  |
| falco.falco_libs.thread_table_size | int | `262144` |  |
| falco.file_output | object | `{"enabled":false,"filename":"./events.txt","keep_alive":false}` | When appending Falco alerts to a file, each new alert will be added to a new line. It's important to note that Falco does not perform log rotation for this file. If the `keep_alive` option is set to `true`, the file will be opened once and continuously written to, else the file will be reopened for each output message. Furthermore, the file will be closed and reopened if Falco receives the SIGUSR1 signal. |
| falco.grpc | object | `{"bind_address":"unix:///run/falco/falco.sock","enabled":false,"threadiness":0}` | gRPC server using a local unix socket |
| falco.grpc.threadiness | int | `0` | When the `threadiness` value is set to 0, Falco will automatically determine the appropriate number of threads based on the number of online cores in the system. |
| falco.grpc_output | object | `{"enabled":false}` | Use gRPC as an output service.  gRPC is a modern and high-performance framework for remote procedure calls (RPC). It utilizes protocol buffers for efficient data serialization. The gRPC output in Falco provides a modern and efficient way to integrate with other systems. By default the setting is turned off. Enabling this option stores output events in memory until they are consumed by a gRPC client. Ensure that you have a consumer for the output events or leave it disabled. |
| falco.http_output | object | `{"ca_bundle":"","ca_cert":"","ca_path":"/etc/falco/certs/","client_cert":"/etc/falco/certs/client/client.crt","client_key":"/etc/falco/certs/client/client.key","compress_uploads":false,"echo":false,"enabled":false,"insecure":false,"keep_alive":false,"mtls":false,"url":"","user_agent":"falcosecurity/falco"}` | Send logs to an HTTP endpoint or webhook. |
| falco.http_output.ca_bundle | string | `""` | Path to a specific file that will be used as the CA certificate store. |
| falco.http_output.ca_cert | string | `""` | Path to the CA certificate that can verify the remote server. |
| falco.http_output.ca_path | string | `"/etc/falco/certs/"` | Path to a folder that will be used as the CA certificate store. CA certificate need to be stored as indivitual PEM files in this directory. |
| falco.http_output.client_cert | string | `"/etc/falco/certs/client/client.crt"` | Path to the client cert. |
| falco.http_output.client_key | string | `"/etc/falco/certs/client/client.key"` | Path to the client key. |
| falco.http_output.compress_uploads | bool | `false` | compress_uploads whether to compress data sent to http endpoint. |
| falco.http_output.echo | bool | `false` | Whether to echo server answers to stdout |
| falco.http_output.insecure | bool | `false` | Tell Falco to not verify the remote server. |
| falco.http_output.keep_alive | bool | `false` | keep_alive whether to keep alive the connection. |
| falco.http_output.mtls | bool | `false` | Tell Falco to use mTLS |
| falco.json_include_message_property | bool | `false` |  |
| falco.json_include_output_property | bool | `true` | When using JSON output in Falco, you have the option to include the "output" property itself in the generated JSON output. The "output" property provides additional information about the purpose of the rule. To reduce the logging volume, it is recommended to turn it off if it's not necessary for your use case. |
| falco.json_include_tags_property | bool | `true` | When using JSON output in Falco, you have the option to include the "tags" field of the rules in the generated JSON output. The "tags" field provides additional metadata associated with the rule. To reduce the logging volume, if the tags associated with the rule are not needed for your use case or can be added at a later stage, it is recommended to turn it off. |
| falco.json_output | bool | `false` | When enabled, Falco will output alert messages and rules file loading/validation results in JSON format, making it easier for downstream programs to process and consume the data. By default, this option is disabled. |
| falco.libs_logger | object | `{"enabled":false,"severity":"debug"}` | The `libs_logger` setting in Falco determines the minimum log level to include in the logs related to the functioning of the software of the underlying `libs` library, which Falco utilizes. This setting is independent of the `priority` field of rules and the `log_level` setting that controls Falco's operational logs. It allows you to specify the desired log level for the `libs` library specifically, providing more granular control over the logging behavior of the underlying components used by Falco. Only logs of a certain severity level or higher will be emitted. Supported levels: "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug". It is not recommended for production use. |
| falco.load_plugins | list | `[]` | Add here all plugins and their configuration. Please consult the plugins documentation for more info. Remember to add the plugins name in "load_plugins: []" in order to load them in Falco. |
| falco.log_level | string | `"info"` | The `log_level` setting determines the minimum log level to include in Falco's logs related to the functioning of the software. This setting is separate from the `priority` field of rules and specifically controls the log level of Falco's operational logging. By specifying a log level, you can control the verbosity of Falco's operational logs. Only logs of a certain severity level or higher will be emitted. Supported levels: "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug". |
| falco.log_stderr | bool | `true` | Send information logs to stderr. Note these are *not* security notification logs! These are just Falco lifecycle (and possibly error) logs. |
| falco.log_syslog | bool | `true` | Send information logs to syslog. Note these are *not* security notification logs! These are just Falco lifecycle (and possibly error) logs. |
| falco.metrics | object | `{"convert_memory_to_mb":true,"enabled":false,"include_empty_values":false,"interval":"1h","kernel_event_counters_enabled":true,"kernel_event_counters_per_cpu_enabled":false,"libbpf_stats_enabled":true,"output_rule":true,"resource_utilization_enabled":true,"rules_counters_enabled":true,"state_counters_enabled":true}` | - [Usage]  `enabled`: Disabled by default.  `interval`: The stats interval in Falco follows the time duration definitions used by Prometheus. https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations  Time durations are specified as a number, followed immediately by one of the following units:  ms - millisecond s - second m - minute h - hour d - day - assuming a day has always 24h w - week - assuming a week has always 7d y - year - assuming a year has always 365d  Example of a valid time duration: 1h30m20s10ms  A minimum interval of 100ms is enforced for metric collection. However, for production environments, we recommend selecting one of the following intervals for optimal monitoring:  15m 30m 1h 4h 6h  `output_rule`: To enable seamless metrics and performance monitoring, we recommend emitting metrics as the rule "Falco internal: metrics snapshot". This option is particularly useful when Falco logs are preserved in a data lake. Please note that to use this option, the Falco rules config `priority` must be set to `info` at a minimum.  `output_file`: Append stats to a `jsonl` file. Use with caution in production as Falco does not automatically rotate the file.  `resource_utilization_enabled`: Emit CPU and memory usage metrics. CPU usage is reported as a percentage of one CPU and can be normalized to the total number of CPUs to determine overall usage. Memory metrics are provided in raw units (`kb` for `RSS`, `PSS` and `VSZ` or `bytes` for `container_memory_used`) and can be uniformly converted to megabytes (MB) using the `convert_memory_to_mb` functionality. In environments such as Kubernetes when deployed as daemonset, it is crucial to track Falco's container memory usage. To customize the path of the memory metric file, you can create an environment variable named `FALCO_CGROUP_MEM_PATH` and set it to the desired file path. By default, Falco uses the file `/sys/fs/cgroup/memory/memory.usage_in_bytes` to monitor container memory usage, which aligns with Kubernetes' `container_memory_working_set_bytes` metric. Finally, we emit the overall host CPU and memory usages, along with the total number of processes and open file descriptors (fds) on the host, obtained from the proc file system unrelated to Falco's monitoring. These metrics help assess Falco's usage in relation to the server's workload intensity.  `rules_counters_enabled`: Emit counts for each rule.  `resource_utilization_enabled`: Emit CPU and memory usage metrics. CPU usage is reported as a percentage of one CPU and can be normalized to the total number of CPUs to determine overall usage. Memory metrics are provided in raw units (`kb` for `RSS`, `PSS` and `VSZ` or `bytes` for `container_memory_used`) and can be uniformly converted to megabytes (MB) using the `convert_memory_to_mb` functionality. In environments such as Kubernetes when deployed as daemonset, it is crucial to track Falco's container memory usage. To customize the path of the memory metric file, you can create an environment variable named `FALCO_CGROUP_MEM_PATH` and set it to the desired file path. By default, Falco uses the file `/sys/fs/cgroup/memory/memory.usage_in_bytes` to monitor container memory usage, which aligns with Kubernetes' `container_memory_working_set_bytes` metric. Finally, we emit the overall host CPU and memory usages, along with the total number of processes and open file descriptors (fds) on the host, obtained from the proc file system unrelated to Falco's monitoring. These metrics help assess Falco's usage in relation to the server's workload intensity.  `state_counters_enabled`: Emit counters related to Falco's state engine, including added, removed threads or file descriptors (fds), and failed lookup, store, or retrieve actions in relation to Falco's underlying process cache table (threadtable). We also log the number of currently cached containers if applicable.  `kernel_event_counters_enabled`: Emit kernel side event and drop counters, as an alternative to `syscall_event_drops`, but with some differences. These counters reflect monotonic values since Falco's start and are exported at a constant stats interval.  `kernel_event_counters_per_cpu_enabled`: Detailed kernel event and drop counters per CPU. Typically used when debugging and not in production.  `libbpf_stats_enabled`: Exposes statistics similar to `bpftool prog show`, providing information such as the number of invocations of each BPF program attached by Falco and the time spent in each program measured in nanoseconds. To enable this feature, the kernel must be >= 5.1, and the kernel configuration `/proc/sys/kernel/bpf_stats_enabled` must be set. This option, or an equivalent statistics feature, is not available for non `*bpf*` drivers. Additionally, please be aware that the current implementation of `libbpf` does not support granularity of statistics at the bpf tail call level.  `include_empty_values`: When the option is set to true, fields with an empty numeric value will be included in the output. However, this rule does not apply to high-level fields such as `n_evts` or `n_drops`; they will always be included in the output even if their value is empty. This option can be beneficial for exploring the data schema and ensuring that fields with empty values are included in the output. todo: prometheus export option todo: syscall_counters_enabled option |
| falco.output_timeout | int | `2000` | The `output_timeout` parameter specifies the duration, in milliseconds, to wait before considering the deadline exceeded. By default, the timeout is set to 2000ms (2 seconds), meaning that the consumer of Falco outputs can block the Falco output channel for up to 2 seconds without triggering a timeout error.  Falco actively monitors the performance of output channels. With this setting the timeout error can be logged, but please note that this requires setting Falco's operational logs `log_level` to a minimum of `notice`.  It's important to note that Falco outputs will not be discarded from the output queue. This means that if an output channel becomes blocked indefinitely, it indicates a potential issue that needs to be addressed by the user. |
| falco.outputs_queue | object | `{"capacity":0}` | Falco utilizes tbb::concurrent_bounded_queue for handling outputs, and this parameter allows you to customize the queue capacity. Please refer to the official documentation: https://uxlfoundation.github.io/oneTBB/main/tbb_userguide/Concurrent_Queue_Classes.html. On a healthy system with optimized Falco rules, the queue should not fill up. If it does, it is most likely happening due to the entire event flow being too slow, indicating that the server is under heavy load.  `capacity`: the maximum number of items allowed in the queue is determined by this value. Setting the value to 0 (which is the default) is equivalent to keeping the queue unbounded. In other words, when this configuration is set to 0, the number of allowed items is effectively set to the largest possible long value, disabling this setting.  In the case of an unbounded queue, if the available memory on the system is consumed, the Falco process would be OOM killed. When using this option and setting the capacity, the current event would be dropped, and the event loop would continue. This behavior mirrors kernel-side event drops when the buffer between kernel space and user space is full. |
| falco.plugins | list | `[{"init_config":null,"library_path":"libk8saudit.so","name":"k8saudit","open_params":"http://:9765/k8s-audit"},{"library_path":"libcloudtrail.so","name":"cloudtrail"},{"init_config":"","library_path":"libjson.so","name":"json"}]` | Customize subsettings for each enabled plugin. These settings will only be applied when the corresponding plugin is enabled using the `load_plugins` option. |
| falco.priority | string | `"debug"` | Any rule with a priority level more severe than or equal to the specified minimum level will be loaded and run by Falco. This allows you to filter and control the rules based on their severity, ensuring that only rules of a certain priority or higher are active and evaluated by Falco. Supported levels: "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug" |
| falco.program_output | object | `{"enabled":false,"keep_alive":false,"program":"jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX"}` | Redirect the output to another program or command.  Possible additional things you might want to do with program output:   - send to a slack webhook:         program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX"   - logging (alternate method than syslog):         program: logger -t falco-test   - send over a network connection:         program: nc host.example.com 80 If `keep_alive` is set to `true`, the program will be started once and continuously written to, with each output message on its own line. If `keep_alive` is set to `false`, the program will be re-spawned for each output message. Furthermore, the program will be re-spawned if Falco receives the SIGUSR1 signal. |
| falco.rule_matching | string | `"first"` | - [Examples]  Only enable two rules:  rules:   - disable:       rule: "*"   - enable:       rule: Netcat Remote Code Execution in Container   - enable:       rule: Delete or rename shell history  Disable all rules with a specific tag:  rules:   - disable:       tag: network  [Incubating] `rule_matching`  - Falco has to be performant when evaluating rules against events. To quickly understand which rules could trigger on a specific event, Falco maintains buckets of rules sharing the same event type in a map. Then, the lookup in each bucket is performed through linear search. The `rule_matching` configuration key's values are:  - "first": when evaluating conditions of rules in a bucket, Falco will stop    to evaluate rules if it finds a matching rules. Since rules are stored    in buckets in the order they are defined in the rules files, this option    could prevent other rules to trigger even if their condition is met, causing    a shadowing problem.  - "all": with this value Falco will continue evaluating all the rules    stored in the bucket, so that multiple rules could be triggered upon one    event. |
| falco.rules_files | list | `["/etc/falco/falco_rules.yaml","/etc/falco/falco_rules.local.yaml","/etc/falco/rules.d"]` | The location of the rules files that will be consumed by Falco. |
| falco.stdout_output | object | `{"enabled":true}` | Redirect logs to standard output. |
| falco.syscall_event_drops | object | `{"actions":["log","alert"],"max_burst":1,"rate":0.03333,"simulate_drops":false,"threshold":0.1}` | For debugging/testing it is possible to simulate the drops using the `simulate_drops: true`. In this case the threshold does not apply. |
| falco.syscall_event_drops.actions | list | `["log","alert"]` | Actions to be taken when system calls were dropped from the circular buffer. |
| falco.syscall_event_drops.max_burst | int | `1` | Max burst of messages emitted. |
| falco.syscall_event_drops.rate | float | `0.03333` | Rate at which log/alert messages are emitted. |
| falco.syscall_event_drops.simulate_drops | bool | `false` | Flag to enable drops for debug purposes. |
| falco.syscall_event_drops.threshold | float | `0.1` | The messages are emitted when the percentage of dropped system calls with respect the number of events in the last second is greater than the given threshold (a double in the range [0, 1]). |
| falco.syscall_event_timeouts | object | `{"max_consecutives":1000}` | Generates Falco operational logs when `log_level=notice` at minimum  Falco utilizes a shared buffer between the kernel and userspace to receive events, such as system call information, in userspace. However, there may be cases where timeouts occur in the underlying libraries due to issues in reading events or the need to skip a particular event. While it is uncommon for Falco to experience consecutive event timeouts, it has the capability to detect such situations. You can configure the maximum number of consecutive timeouts without an event after which Falco will generate an alert, but please note that this requires setting Falco's operational logs `log_level` to a minimum of `notice`. The default value is set to 1000 consecutive timeouts without receiving any events. The mapping of this value to a time interval depends on the CPU frequency. |
| falco.syslog_output | object | `{"enabled":true}` | Send logs to syslog. |
| falco.time_format_iso_8601 | bool | `false` | When enabled, Falco will display log and output messages with times in the ISO 8601 format. By default, times are shown in the local time zone determined by the /etc/localtime configuration. |
| falco.watch_config_files | bool | `true` | Watch config file and rules files for modification. When a file is modified, Falco will propagate new config, by reloading itself. |
| falco.webserver | object | `{"enabled":true,"k8s_healthz_endpoint":"/healthz","listen_port":8765,"prometheus_metrics_enabled":false,"ssl_certificate":"/etc/falco/falco.pem","ssl_enabled":false,"threadiness":0}` | Falco supports an embedded webserver that runs within the Falco process, providing a lightweight and efficient way to expose web-based functionalities without the need for an external web server. The following endpoints are exposed: - /healthz: designed to be used for checking the health and availability of   the Falco application (the name of the endpoint is configurable). - /versions: responds with a JSON object containing the version numbers of the   internal Falco components (similar output as `falco --version -o   json_output=true`).  Please note that the /versions endpoint is particularly useful for other Falco services, such as `falcoctl`, to retrieve information about a running Falco instance. If you plan to use `falcoctl` locally or with Kubernetes, make sure the Falco webserver is enabled.  The behavior of the webserver can be controlled with the following options, which are enabled by default:  The `ssl_certificate` option specifies a combined SSL certificate and corresponding key that are contained in a single file. You can generate a key/cert as follows:  $ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem $ cat certificate.pem key.pem > falco.pem $ sudo cp falco.pem /etc/falco/falco.pem |
| falcoctl.artifact.follow | object | `{"args":["--log-format=json"],"enabled":true,"env":[],"mounts":{"volumeMounts":[]},"resources":{},"securityContext":{}}` | Runs "falcoctl artifact follow" command as a sidecar container. It is used to automatically check for updates given a list of artifacts. If an update is found it downloads and installs it in a shared folder (emptyDir) that is accessible by Falco. Rulesfiles are automatically detected and loaded by Falco once they are installed in the correct folder by falcoctl. To prevent new versions of artifacts from breaking Falco, the tool checks if it is compatible with the running version of Falco before installing it. |
| falcoctl.artifact.follow.args | list | `["--log-format=json"]` | Arguments to pass to the falcoctl-artifact-follow sidecar container. |
| falcoctl.artifact.follow.env | list | `[]` | Extra environment variables that will be pass onto falcoctl-artifact-follow sidecar container. |
| falcoctl.artifact.follow.mounts | object | `{"volumeMounts":[]}` | A list of volume mounts you want to add to the falcoctl-artifact-follow sidecar container. |
| falcoctl.artifact.follow.resources | object | `{}` | Resources requests and limits for the falcoctl-artifact-follow sidecar container. |
| falcoctl.artifact.follow.securityContext | object | `{}` | Security context for the falcoctl-artifact-follow sidecar container. |
| falcoctl.artifact.install | object | `{"args":["--log-format=json"],"enabled":true,"env":[],"mounts":{"volumeMounts":[]},"resources":{},"securityContext":{}}` | Runs "falcoctl artifact install" command as an init container. It is used to install artfacts before Falco starts. It provides them to Falco by using an emptyDir volume. |
| falcoctl.artifact.install.args | list | `["--log-format=json"]` | Arguments to pass to the falcoctl-artifact-install init container. |
| falcoctl.artifact.install.env | list | `[]` | Extra environment variables that will be pass onto falcoctl-artifact-install init container. |
| falcoctl.artifact.install.mounts | object | `{"volumeMounts":[]}` | A list of volume mounts you want to add to the falcoctl-artifact-install init container. |
| falcoctl.artifact.install.resources | object | `{}` | Resources requests and limits for the falcoctl-artifact-install init container. |
| falcoctl.artifact.install.securityContext | object | `{}` | Security context for the falcoctl init container. |
| falcoctl.config | object | `{"artifact":{"allowedTypes":["rulesfile","plugin"],"follow":{"every":"6h","falcoversions":"http://localhost:8765/versions","pluginsDir":"/plugins","refs":["falco-rules:3"],"rulesfilesDir":"/rulesfiles"},"install":{"pluginsDir":"/plugins","refs":["falco-rules:3"],"resolveDeps":true,"rulesfilesDir":"/rulesfiles"}},"indexes":[{"name":"falcosecurity","url":"https://falcosecurity.github.io/falcoctl/index.yaml"}]}` | Configuration file of the falcoctl tool. It is saved in a configmap and mounted on the falcotl containers. |
| falcoctl.config.artifact | object | `{"allowedTypes":["rulesfile","plugin"],"follow":{"every":"6h","falcoversions":"http://localhost:8765/versions","pluginsDir":"/plugins","refs":["falco-rules:3"],"rulesfilesDir":"/rulesfiles"},"install":{"pluginsDir":"/plugins","refs":["falco-rules:3"],"resolveDeps":true,"rulesfilesDir":"/rulesfiles"}}` | Configuration used by the artifact commands. |
| falcoctl.config.artifact.allowedTypes | list | `["rulesfile","plugin"]` | List of artifact types that falcoctl will handle. If the configured refs resolves to an artifact whose type is not contained in the list it will refuse to downloade and install that artifact. |
| falcoctl.config.artifact.follow.every | string | `"6h"` | How often the tool checks for new versions of the followed artifacts. |
| falcoctl.config.artifact.follow.falcoversions | string | `"http://localhost:8765/versions"` | HTTP endpoint that serves the api versions of the Falco instance. It is used to check if the new versions are compatible with the running Falco instance. |
| falcoctl.config.artifact.follow.pluginsDir | string | `"/plugins"` | See the fields of the artifact.install section. |
| falcoctl.config.artifact.follow.refs | list | `["falco-rules:3"]` | List of artifacts to be followed by the falcoctl sidecar container. |
| falcoctl.config.artifact.follow.rulesfilesDir | string | `"/rulesfiles"` | See the fields of the artifact.install section. |
| falcoctl.config.artifact.install.pluginsDir | string | `"/plugins"` | Same as the one above but for the artifacts. |
| falcoctl.config.artifact.install.refs | list | `["falco-rules:3"]` | List of artifacts to be installed by the falcoctl init container. |
| falcoctl.config.artifact.install.resolveDeps | bool | `true` | Resolve the dependencies for artifacts. |
| falcoctl.config.artifact.install.rulesfilesDir | string | `"/rulesfiles"` | Directory where the rulesfiles are saved. The path is relative to the container, which in this case is an emptyDir mounted also by the Falco pod. |
| falcoctl.config.indexes | list | `[{"name":"falcosecurity","url":"https://falcosecurity.github.io/falcoctl/index.yaml"}]` | List of indexes that falcoctl downloads and uses to locate and download artiafcts. For more info see: https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md#index-file-overview |
| falcoctl.image.pullPolicy | string | `"IfNotPresent"` | The image pull policy. |
| falcoctl.image.registry | string | `"docker.io"` | The image registry to pull from. |
| falcoctl.image.repository | string | `"falcosecurity/falcoctl"` | The image repository to pull from. |
| falcoctl.image.tag | string | `"0.11.0"` | The image tag to pull. |
| falcosidekick | object | `{"enabled":false,"fullfqdn":false,"listenPort":""}` | For configuration values, see https://github.com/falcosecurity/charts/blob/master/charts/falcosidekick/values.yaml |
| falcosidekick.enabled | bool | `false` | Enable falcosidekick deployment. |
| falcosidekick.fullfqdn | bool | `false` | Enable usage of full FQDN of falcosidekick service (useful when a Proxy is used). |
| falcosidekick.listenPort | string | `""` | Listen port. Default value: 2801 |
| falcotalon | object | `{"enabled":false}` | For configuration values, see https://github.com/falcosecurity/charts/blob/master/charts/falco-talon/values.yaml |
| falcotalon.enabled | bool | `false` | Enable falcotalon deployment. |
| fullnameOverride | string | `""` | Same as nameOverride but for the fullname. |
| grafana | object | `{"dashboards":{"configMaps":{"falco":{"folder":"","name":"falco-grafana-dashboard","namespace":""}},"enabled":false}}` | grafana contains the configuration related to grafana. |
| grafana.dashboards | object | `{"configMaps":{"falco":{"folder":"","name":"falco-grafana-dashboard","namespace":""}},"enabled":false}` | dashboards contains configuration for grafana dashboards. |
| grafana.dashboards.configMaps | object | `{"falco":{"folder":"","name":"falco-grafana-dashboard","namespace":""}}` | configmaps to be deployed that contain a grafana dashboard. |
| grafana.dashboards.configMaps.falco | object | `{"folder":"","name":"falco-grafana-dashboard","namespace":""}` | falco contains the configuration for falco's dashboard. |
| grafana.dashboards.configMaps.falco.folder | string | `""` | folder where the dashboard is stored by grafana. |
| grafana.dashboards.configMaps.falco.name | string | `"falco-grafana-dashboard"` | name specifies the name for the configmap. |
| grafana.dashboards.configMaps.falco.namespace | string | `""` | namespace specifies the namespace for the configmap. |
| grafana.dashboards.enabled | bool | `false` | enabled specifies whether the dashboards should be deployed. |
| healthChecks | object | `{"livenessProbe":{"initialDelaySeconds":60,"periodSeconds":15,"timeoutSeconds":5},"readinessProbe":{"initialDelaySeconds":30,"periodSeconds":15,"timeoutSeconds":5}}` | Parameters used |
| healthChecks.livenessProbe.initialDelaySeconds | int | `60` | Tells the kubelet that it should wait X seconds before performing the first probe. |
| healthChecks.livenessProbe.periodSeconds | int | `15` | Specifies that the kubelet should perform the check every x seconds. |
| healthChecks.livenessProbe.timeoutSeconds | int | `5` | Number of seconds after which the probe times out. |
| healthChecks.readinessProbe.initialDelaySeconds | int | `30` | Tells the kubelet that it should wait X seconds before performing the first probe. |
| healthChecks.readinessProbe.periodSeconds | int | `15` | Specifies that the kubelet should perform the check every x seconds. |
| healthChecks.readinessProbe.timeoutSeconds | int | `5` | Number of seconds after which the probe times out. |
| image.pullPolicy | string | `"IfNotPresent"` | The image pull policy. |
| image.registry | string | `"docker.io"` | The image registry to pull from. |
| image.repository | string | `"falcosecurity/falco"` | The image repository to pull from |
| image.tag | string | `""` | The image tag to pull. Overrides the image tag whose default is the chart appVersion. |
| imagePullSecrets | list | `[]` | Secrets containing credentials when pulling from private/secure registries. |
| metrics | object | `{"convertMemoryToMB":true,"enabled":false,"includeEmptyValues":false,"interval":"1h","kernelEventCountersEnabled":true,"kernelEventCountersPerCPUEnabled":false,"libbpfStatsEnabled":true,"outputRule":false,"resourceUtilizationEnabled":true,"rulesCountersEnabled":true,"service":{"annotations":{},"create":true,"labels":{},"ports":{"metrics":{"port":8765,"protocol":"TCP","targetPort":8765}},"type":"ClusterIP"},"stateCountersEnabled":true}` | metrics configures Falco to enable and expose the metrics. |
| metrics.convertMemoryToMB | bool | `true` | convertMemoryToMB specifies whether the memory should be converted to mb. |
| metrics.enabled | bool | `false` | enabled specifies whether the metrics should be enabled. |
| metrics.includeEmptyValues | bool | `false` | includeEmptyValues specifies whether the empty values should be included in the metrics. |
| metrics.interval | string | `"1h"` | interval is stats interval in Falco follows the time duration definitions used by Prometheus. https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations Time durations are specified as a number, followed immediately by one of the following units: ms - millisecond s - second m - minute h - hour d - day - assuming a day has always 24h w - week - assuming a week has always 7d y - year - assuming a year has always 365d Example of a valid time duration: 1h30m20s10ms A minimum interval of 100ms is enforced for metric collection. However, for production environments, we recommend selecting one of the following intervals for optimal monitoring: 15m 30m 1h 4h 6h |
| metrics.kernelEventCountersPerCPUEnabled | bool | `false` | kernelEventCountersPerCPUEnabled specifies whether the event counters per cpu should be enabled. |
| metrics.libbpfStatsEnabled | bool | `true` | libbpfStatsEnabled exposes statistics similar to `bpftool prog show`, providing information such as the number of invocations of each BPF program attached by Falco and the time spent in each program measured in nanoseconds. To enable this feature, the kernel must be >= 5.1, and the kernel configuration `/proc/sys/kernel/bpf_stats_enabled` must be set. This option, or an equivalent statistics feature, is not available for non `*bpf*` drivers. Additionally, please be aware that the current implementation of `libbpf` does not support granularity of statistics at the bpf tail call level. |
| metrics.outputRule | bool | `false` | outputRule enables seamless metrics and performance monitoring, we recommend emitting metrics as the rule "Falco internal: metrics snapshot". This option is particularly useful when Falco logs are preserved in a data lake. Please note that to use this option, the Falco rules config `priority` must be set to `info` at a minimum. |
| metrics.resourceUtilizationEnabled | bool | `true` | resourceUtilizationEnabled`: Emit CPU and memory usage metrics. CPU usage is reported as a percentage of one CPU and can be normalized to the total number of CPUs to determine overall usage. Memory metrics are provided in raw units (`kb` for `RSS`, `PSS` and `VSZ` or `bytes` for `container_memory_used`) and can be uniformly converted to megabytes (MB) using the `convert_memory_to_mb` functionality. In environments such as Kubernetes when deployed as daemonset, it is crucial to track Falco's container memory usage. To customize the path of the memory metric file, you can create an environment variable named `FALCO_CGROUP_MEM_PATH` and set it to the desired file path. By default, Falco uses the file `/sys/fs/cgroup/memory/memory.usage_in_bytes` to monitor container memory usage, which aligns with Kubernetes' `container_memory_working_set_bytes` metric. Finally, we emit the overall host CPU and memory usages, along with the total number of processes and open file descriptors (fds) on the host, obtained from the proc file system unrelated to Falco's monitoring. These metrics help assess Falco's usage in relation to the server's workload intensity. |
| metrics.rulesCountersEnabled | bool | `true` | rulesCountersEnabled specifies whether the counts for each rule should be emitted. |
| metrics.service | object | `{"annotations":{},"create":true,"labels":{},"ports":{"metrics":{"port":8765,"protocol":"TCP","targetPort":8765}},"type":"ClusterIP"}` | service exposes the metrics service to be accessed from within the cluster. ref: https://kubernetes.io/docs/concepts/services-networking/service/ |
| metrics.service.annotations | object | `{}` | annotations to add to the service. |
| metrics.service.create | bool | `true` | create specifies whether a service should be created. |
| metrics.service.labels | object | `{}` | labels to add to the service. |
| metrics.service.ports | object | `{"metrics":{"port":8765,"protocol":"TCP","targetPort":8765}}` | ports denotes all the ports on which the Service will listen. |
| metrics.service.ports.metrics | object | `{"port":8765,"protocol":"TCP","targetPort":8765}` | metrics denotes a listening service named "metrics". |
| metrics.service.ports.metrics.port | int | `8765` | port is the port on which the Service will listen. |
| metrics.service.ports.metrics.protocol | string | `"TCP"` | protocol specifies the network protocol that the Service should use for the associated port. |
| metrics.service.ports.metrics.targetPort | int | `8765` | targetPort is the port on which the Pod is listening. |
| metrics.service.type | string | `"ClusterIP"` | type denotes the service type. Setting it to "ClusterIP" we ensure that are accessible from within the cluster. |
| mounts.volumeMounts | list | `[]` | A list of volumes you want to add to the Falco pods. |
| mounts.volumes | list | `[]` | A list of volumes you want to add to the Falco pods. |
| nameOverride | string | `""` | Put here the new name if you want to override the release name used for Falco components. |
| namespaceOverride | string | `""` | Override the deployment namespace |
| nodeSelector | object | `{}` | Selectors used to deploy Falco on a given node/nodes. |
| podAnnotations | object | `{}` | Add additional pod annotations |
| podLabels | object | `{}` | Add additional pod labels |
| podPriorityClassName | string | `nil` | Set pod priorityClassName |
| podSecurityContext | object | `{}` | Set securityContext for the pods These security settings are overriden by the ones specified for the specific containers when there is overlap. |
| rbac.create | bool | `true` |  |
| resources.limits | object | `{"cpu":"1000m","memory":"1024Mi"}` | Maximum amount of resources that Falco container could get. If you are enabling more than one source in falco, than consider to increase the cpu limits. |
| resources.requests | object | `{"cpu":"100m","memory":"512Mi"}` | Although resources needed are subjective on the actual workload we provide a sane defaults ones. If you have more questions or concerns, please refer to #falco slack channel for more info about it. |
| scc.create | bool | `true` | Create OpenShift's Security Context Constraint. |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account. |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created. |
| serviceAccount.imagePullSecrets | list | `[]` | Secrets containing credentials when pulling from private/secure registries. |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| serviceMonitor | object | `{"create":false,"endpointPort":"metrics","interval":"15s","labels":{},"path":"/metrics","relabelings":[],"scheme":"http","scrapeTimeout":"10s","selector":{},"targetLabels":[],"tlsConfig":{}}` | serviceMonitor holds the configuration for the ServiceMonitor CRD. A ServiceMonitor is a custom resource definition (CRD) used to configure how Prometheus should discover and scrape metrics from the Falco service. |
| serviceMonitor.create | bool | `false` | create specifies whether a ServiceMonitor CRD should be created for a prometheus operator. https://github.com/coreos/prometheus-operator Enable it only if the ServiceMonitor CRD is installed in your cluster. |
| serviceMonitor.endpointPort | string | `"metrics"` | endpointPort is the port in the Falco service that exposes the metrics service. Change the value if you deploy a custom service for Falco's metrics. |
| serviceMonitor.interval | string | `"15s"` | interval specifies the time interval at which Prometheus should scrape metrics from the service. |
| serviceMonitor.labels | object | `{}` | labels set of labels to be applied to the ServiceMonitor resource. If your Prometheus deployment is configured to use serviceMonitorSelector, then add the right label here in order for the ServiceMonitor to be selected for target discovery. |
| serviceMonitor.path | string | `"/metrics"` | path at which the metrics are exposed by Falco. |
| serviceMonitor.relabelings | list | `[]` | relabelings configures the relabeling rules to apply the target’s metadata labels. |
| serviceMonitor.scheme | string | `"http"` | scheme specifies network protocol used by the metrics endpoint. In this case HTTP. |
| serviceMonitor.scrapeTimeout | string | `"10s"` | scrapeTimeout determines the maximum time Prometheus should wait for a target to respond to a scrape request. If the target does not respond within the specified timeout, Prometheus considers the scrape as failed for that target. |
| serviceMonitor.selector | object | `{}` | selector set of labels that should match the labels on the Service targeted by the current serviceMonitor. |
| serviceMonitor.targetLabels | list | `[]` | targetLabels defines the labels which are transferred from the associated Kubernetes service object onto the ingested metrics. |
| serviceMonitor.tlsConfig | object | `{}` | tlsConfig specifies TLS (Transport Layer Security) configuration for secure communication when scraping metrics from a service. It allows you to define the details of the TLS connection, such as CA certificate, client certificate, and client key. Currently, the k8s-metacollector does not support TLS configuration for the metrics endpoint. |
| services | string | `nil` | Network services configuration (scenario requirement) Add here your services to be deployed together with Falco. |
| tolerations | list | `[{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"}]` | Tolerations to allow Falco to run on Kubernetes masters. |
| tty | bool | `false` | Attach the Falco process to a tty inside the container. Needed to flush Falco logs as soon as they are emitted. Set it to "true" when you need the Falco logs to be immediately displayed. |
