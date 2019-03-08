# Example Helm Chart for Sysdig Falco

## Install

To install the chart with the release name my-release run:

```
$ helm install --name my-release stable/falco
```
After a few seconds, Falco should be running.

## Uninstall

To uninstall/delete the my-release deployment:

```
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Details

refer to [docs](https://github.com/helm/charts/tree/master/stable/sysdig)
