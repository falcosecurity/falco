# Example Helm Chart for Sysdig Falco

## Usage

### Install

```
$ helm install . -n falco
NAME:   falco
LAST DEPLOYED: Fri Mar  8 09:56:03 2019
NAMESPACE: default
STATUS: DEPLOYED

RESOURCES:
==> v1beta1/ClusterRoleBinding
NAME   AGE
falco  0s

==> v1/Service
NAME   TYPE       CLUSTER-IP    EXTERNAL-IP  PORT(S)   AGE
falco  ClusterIP  10.97.17.101  <none>       8765/TCP  0s

==> v1beta1/DaemonSet
NAME   DESIRED  CURRENT  READY  UP-TO-DATE  AVAILABLE  NODE SELECTOR  AGE
falco  2        2        0      2           0          <none>         0s

==> v1/Pod(related)
NAME         READY  STATUS             RESTARTS  AGE
falco-8hws4  0/1    ContainerCreating  0         0s
falco-bmfqw  0/1    ContainerCreating  0         0s

==> v1/ConfigMap
NAME   DATA  AGE
falco  4     1s

==> v1/ServiceAccount
NAME   SECRETS  AGE
falco  1        1s

==> v1beta1/ClusterRole
NAME   AGE
falco  0s
```

Also you can specify namespace with `--namespace` option.


For more details about config, refer to [docs](../k8s-using-daemonset/README.md).

### Uninstall

```
$ helm del --purge falco
```
