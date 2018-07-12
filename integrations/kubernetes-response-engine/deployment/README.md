# Kubernetes Manifests for Kubernetes Response Engine

In this directory are the manifests for creating required infrastructure in the
Kubernetes cluster

## Deploy

For deploying NATS, Falco + Falco-NATS output and Kubeless just run default Makefile target:

```
make
```

## Clean

You can clean your cluster with:

```
make clean
```
