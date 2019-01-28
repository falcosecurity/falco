# Introduction

The files in this directory can be used to configure k8s audit logging. The relevant files are:

* [audit-policy.yaml](./audit-policy.yaml): The k8s audit log configuration we used to create the rules in [k8s_audit_rules.yaml](../../rules/k8s_audit_rules.yaml). You may find it useful as a reference when creating your own K8s Audit Log configuration.
* [webhook-config.yaml.in](./webhook-config.yaml.in): A (templated) webhook configuration that sends audit events to an ip associated with the falco service, port 8765. It is templated in that the *actual* ip is defined in an environment variable `FALCO_SERVICE_CLUSTERIP`, which can be plugged in using a program like `envsubst`. You may find it useful as a starting point when deciding how to route audit events to the embedded webserver within falco.

These files are only needed when using Minikube, which doesn't currently
have the ability to provide an audit config/webhook config directly
from the minikube commandline. See [this issue](https://github.com/kubernetes/minikube/issues/2741) for more details.

* [apiserver-config.patch.sh](./apiserver-config.patch.sh): A script that changes the configuration file `/etc/kubernetes/manifests/kube-apiserver.yaml` to add necessary config options and mounts for the kube-apiserver container that runs within the minikube vm.

A way to use these files with minikube to run falco and enable audit logging would be the following:

#### Start Minikube with Audit Logging Enabled

Run the following to start minikube with Audit Logging Enabled:

```
minikube start --kubernetes-version v1.11.0 --mount --mount-string $PWD:/tmp/k8s_audit_config --feature-gates AdvancedAuditing=true
```

#### Create a Falco DaemonSet and Supporting Accounts/Services

Follow the [K8s Using Daemonset](../../integrations/k8s-using-daemonset/README.md) instructions to create a falco service account, service, configmap, and daemonset.

#### Configure Audit Logging with a Policy and Webhook

Run the following commands to fill in the template file with the ClusterIP ip address you created with the `falco-service` service above, and configure audit logging to use a policy and webhook that directs the right events to the falco daemonset. Although services like `falco-service.default.svc.cluster.local` can not be resolved from the kube-apiserver container within the minikube vm (they're run as pods but not *really* a part of the cluster), the ClusterIPs associated with those services are routable.

```
FALCO_SERVICE_CLUSTERIP=$(kubectl get service falco-service -o=jsonpath={.spec.clusterIP}) envsubst < webhook-config.yaml.in > webhook-config.yaml
minikube ssh sudo bash /tmp/k8s_audit_config/apiserver-config.patch.sh
```

K8s audit events will then be routed to the falco daemonset within the cluster, which you can observe via `kubectl logs -f $(kubectl get pods -l app=falco-example -o jsonpath={.items[0].metadata.name})`.

