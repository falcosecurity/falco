# NATS output for Sysdig Falco

As Falco does not support a NATS output natively, we have created this small
golang utility wich reads Falco alerts from a named pipe and sends them to a
NATS server.

This utility is designed to being run in a sidecar container in the same
Pod as Falco.

## Configuration

You have a [complete Kubernetes manifest available](https://github.com/draios/falco/tree/kubernetes-response-engine/deployment/falco-daemonset.yaml) for future reading.

Take a look at sidecar container and to the initContainers directive which
craetes the shared pipe between containers.

### Container image

You have this adapter available as a container image. Its name is *sysdig/falco-nats*.

### Parameters Reference

* -s: Specifies the NATS server URL where message will be published.  By default
    is: *nats://nats.nats-io.svc.cluster.local:4222*

* -f: Specifies the named pipe path where Falco publishes its alerts. By default
    is: */var/run/falco/nats*
