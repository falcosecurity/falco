# Introduction

The files in this directory can be used to configure k8s audit logging. The relevant files are:

* [audit-policy.yaml](./audit-policy.yaml): The k8s audit log configuration we used to create the rules in [k8s_audit_rules.yaml](../../rules/k8s_audit_rules.yaml). You may find it useful as a reference when creating your own K8s Audit Log configuration.
* [webhook-config.yaml](./webhook-config.yaml): A webhook configuration that sends audit events to localhost, port 8765. You may find it useful as a starting point when deciding how to route audit events to the embedded webserver within falco.

This file is only needed when using Minikube, which doesn't currently
have the ability to provide an audit config/webhook config directly
from the minikube commandline. See [this issue](https://github.com/kubernetes/minikube/issues/2741) for more details.

* [apiserver-config.patch.sh](./apiserver-config.patch.sh): A script that changes the configuration file `/etc/kubernetes/manifests/kube-apiserver.yaml` to add necessary config options and mounts for the kube-apiserver container that runs within the minikube vm.

A way to use these files with minikube to enable audit logging would be to run the following commands, from this directory:

```
minikube start --kubernetes-version v1.11.0 --mount --mount-string $PWD:/tmp/k8s_audit_config --feature-gates AdvancedAuditing=true
ssh -i $(minikube ssh-key) docker@$(minikube ip) sudo bash /tmp/k8s_audit_config/apiserver-config.patch.sh
ssh -i $(minikube ssh-key) -R 8765:localhost:8765 docker@$(minikube ip)
```

K8s audit events will then be sent to localhost on the host (not minikube vm) machine, port 8765.

