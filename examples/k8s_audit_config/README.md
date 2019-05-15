# Introduction

This page describes how to get K8s Audit Logging working with Falco for either K8s 1.11, using static audit policies/sinks, or 1.13, with dynamic audit policies/sinks using AuditSink objects.

## K8s 1.11 Instructions

The main steps are:

1. Deploy Falco to your K8s cluster
1. Define your audit policy and webhook configuration
1. Restart the API Server to enable Audit Logging
1. Observe K8s audit events at falco

### Deploy Falco to your K8s cluster

Follow the [K8s Using Daemonset](../../integrations/k8s-using-daemonset/README.md) instructions to create a falco service account, service, configmap, and daemonset.

### Define your audit policy and webhook configuration

The files in this directory can be used to configure k8s audit logging. The relevant files are:

* [audit-policy.yaml](./audit-policy.yaml): The k8s audit log configuration we used to create the rules in [k8s_audit_rules.yaml](../../rules/k8s_audit_rules.yaml).
* [webhook-config.yaml.in](./webhook-config.yaml.in): A (templated) webhook configuration that sends audit events to an ip associated with the falco service, port 8765. It is templated in that the *actual* ip is defined in an environment variable `FALCO_SERVICE_CLUSTERIP`, which can be plugged in using a program like `envsubst`.

Run the following to fill in the template file with the ClusterIP ip address you created with the `falco-service` service above. Although services like `falco-service.default.svc.cluster.local` can not be resolved from the kube-apiserver container within the minikube vm (they're run as pods but not *really* a part of the cluster), the ClusterIPs associated with those services are routable.

```
FALCO_SERVICE_CLUSTERIP=$(kubectl get service falco-service -o=jsonpath={.spec.clusterIP}) envsubst < webhook-config.yaml.in > webhook-config.yaml
```

### Restart the API Server to enable Audit Logging

A script [enable-k8s-audit.sh](./enable-k8s-audit.sh) performs the necessary steps of enabling audit log support for the apiserver, including copying the audit policy/webhook files to the apiserver machine, modifying the apiserver command line to add `--audit-log-path`, `--audit-policy-file`, etc. arguments, etc. (For minikube, ideally you'd be able to pass all these options directly on the `minikube start` command line, but manual patching is necessary. See [this issue](https://github.com/kubernetes/minikube/issues/2741) for more details.)

It is run as `bash ./enable-k8s-audit.sh <variant> static`. `<variant>` can be one of the following:

* "minikube"
* "kops"

When running with variant="kops", you must either modify the script to specify the kops apiserver hostname or set it via the environment: `APISERVER_HOST=api.my-kops-cluster.com bash ./enable-k8s-audit.sh kops`

Its output looks like this:

```
$ bash enable-k8s-audit.sh minikube static
***Copying apiserver config patch script to apiserver...
apiserver-config.patch.sh                                                                   100% 1190     1.2MB/s   00:00
***Copying audit policy/webhook files to apiserver...
audit-policy.yaml                                                                           100% 2519     1.2MB/s   00:00
webhook-config.yaml                                                                         100%  248   362.0KB/s   00:00
***Modifying k8s apiserver config (will result in apiserver restarting)...
***Done!
$
```
### Observe K8s audit events at falco

K8s audit events will then be routed to the falco daemonset within the cluster, which you can observe via `kubectl logs -f $(kubectl get pods -l app=falco-example -o jsonpath={.items[0].metadata.name})`.

## K8s 1.13 Instructions

The main steps are:

1. Deploy Falco to your K8s cluster
1. Restart the API Server to enable Audit Logging
1. Deploy the AuditSink object for your audit policy and webhook configuration
1. Observe K8s audit events at falco

### Deploy Falco to your K8s cluster

Follow the [K8s Using Daemonset](../../integrations/k8s-using-daemonset/README.md) instructions to create a falco service account, service, configmap, and daemonset.

### Restart the API Server to enable Audit Logging

A script [enable-k8s-audit.sh](./enable-k8s-audit.sh) performs the necessary steps of enabling dynamic audit support for the apiserver by modifying the apiserver command line to add `--audit-dynamic-configuration`, `--feature-gates=DynamicAuditing=true`, etc. arguments, etc. (For minikube, ideally you'd be able to pass all these options directly on the `minikube start` command line, but manual patching is necessary. See [this issue](https://github.com/kubernetes/minikube/issues/2741) for more details.)

It is run as `bash ./enable-k8s-audit.sh <variant> dynamic`. `<variant>` can be one of the following:

* "minikube"
* "kops"

When running with variant="kops", you must either modify the script to specify the kops apiserver hostname or set it via the environment: `APISERVER_HOST=api.my-kops-cluster.com bash ./enable-k8s-audit.sh kops`

Its output looks like this:

```
$ bash enable-k8s-audit.sh minikube dynamic
***Copying apiserver config patch script to apiserver...
apiserver-config.patch.sh                                                                   100% 1190     1.2MB/s   00:00
***Modifying k8s apiserver config (will result in apiserver restarting)...
***Done!
$
```

### Deploy AuditSink objects

[audit-sink.yaml.in](./audit-sink.yaml.in), in this directory, is a template audit sink configuration that defines the dynamic audit policy and webhook to route k8s audit events to Falco.

Run the following to fill in the template file with the ClusterIP ip address you created with the `falco-service` service above. Although services like `falco-service.default.svc.cluster.local` can not be resolved from the kube-apiserver container within the minikube vm (they're run as pods but not *really* a part of the cluster), the ClusterIPs associated with those services are routable.

```
FALCO_SERVICE_CLUSTERIP=$(kubectl get service falco-service -o=jsonpath={.spec.clusterIP}) envsubst < audit-sink.yaml.in > audit-sink.yaml
```

### Observe K8s audit events at falco

K8s audit events will then be routed to the falco daemonset within the cluster, which you can observe via `kubectl logs -f $(kubectl get pods -l app=falco-example -o jsonpath={.items[0].metadata.name})`.

## K8s 1.13 + Local Log File Instructions

If you want to use a mix of AuditSink for remote audit events as well as a local audit log file, you can run enable-k8s-audit.sh with the "dynamic-log" argument e.g. `bash ./enable-k8s-audit.sh <variant> dynamic+log`. This will enable dynamic audit logs as well as a static audit log to a local file. Its output looks like this:

```
***Copying apiserver config patch script to apiserver...
apiserver-config.patch.sh                                                                          100% 2211   662.9KB/s   00:00
***Copying audit policy file to apiserver...
audit-policy.yaml                                                                                  100% 2519   847.7KB/s   00:00
***Modifying k8s apiserver config (will result in apiserver restarting)...
***Done!
```

The audit log will be available on the apiserver host at `/var/lib/k8s_audit/audit.log`.
