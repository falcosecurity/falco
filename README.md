<p align="center"><img src="https://raw.githubusercontent.com/falcosecurity/community/master/logo/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

<hr>

[![Build Status](https://img.shields.io/circleci/build/github/falcosecurity/falco/master?style=for-the-badge)](https://circleci.com/gh/falcosecurity/falco) [![CII Best Practices Summary](https://img.shields.io/cii/summary/2317?label=CCI%20Best%20Practices&style=for-the-badge)](https://bestpractices.coreinfrastructure.org/projects/2317) [![GitHub](https://img.shields.io/github/license/falcosecurity/falco?style=for-the-badge)](COPYING)

Want to talk? Join us on the [#falco](https://kubernetes.slack.com/archives/CMWH3EH32) channel in the [Kubernetes Slack](https://slack.k8s.io).

### Latest releases

Read the [change log](CHANGELOG.md).

|        | development                                                                                                                 | stable                                                                                                              |
|--------|-----------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| rpm    | [![rpm-dev](https://img.shields.io/bintray/v/falcosecurity/rpm-dev/falco?label=Falco&color=%2300aec7&style=flat-square)][1] | [![rpm](https://img.shields.io/bintray/v/falcosecurity/rpm/falco?label=Falco&color=%23005763&style=flat-square)][2] |
| deb    | [![deb-dev](https://img.shields.io/bintray/v/falcosecurity/deb-dev/falco?label=Falco&color=%2300aec7&style=flat-square)][3] | [![deb](https://img.shields.io/bintray/v/falcosecurity/deb/falco?label=Falco&color=%23005763&style=flat-square)][4] |
| binary | [![bin-dev](https://img.shields.io/bintray/v/falcosecurity/bin-dev/falco?label=Falco&color=%2300aec7&style=flat-square)][5] | [![bin](https://img.shields.io/bintray/v/falcosecurity/bin/falco?label=Falco&color=%23005763&style=flat-square)][6] |

---

The Falco Project, originally created by [Sysdig](https://sysdig.com), is an incubating [CNCF](https://cncf.io) open source cloud native runtime security tool.
Falco makes it easy to consume kernel events, and enrich those events with information from Kubernetes and the rest of the cloud native stack.
Falco has a rich rule set of security rules specifically built for Kubernetes, Linux, and cloud-native.
If a rule is violated in a system, Falco will send an alert notifying the user of the violation and its severity.

### Installing Falco

If you would like to run Falco in **production** please adhere to the [official installation guide](https://falco.org/docs/installation/).

##### Kubernetes

| Tool     | Link                                                                                       | Note                                                               |
|----------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| Helm     | [Chart Repository](https://github.com/falcosecurity/charts/tree/master/falco#introduction) | The Falco community offers regular helm chart releases.            |
| Minikube | [Tutorial](https://falco.org/docs/third-party/#minikube)                                   | The Falco driver has been baked into minikube for easy deployment. |
| Kind     | [Tutorial](https://falco.org/docs/third-party/#kind)                                       | Running Falco with kind requires a driver on the host system.      |
| GKE      | [Tutorial](https://falco.org/docs/third-party/#gke)                                        | We suggest using the eBPF driver for running Falco on GKE.         |

### Developing

Falco is designed to be extensible such that it can be built into cloud-native applications and infrastructure.

Falco has a [gRPC](https://falco.org/docs/grpc/) endpoint and an API defined in [protobuf](https://github.com/falcosecurity/falco/blob/master/userspace/falco/outputs.proto).
The Falco Project supports various SDKs for this endpoint.

##### SDKs

| Language | Repository                                              |
|----------|---------------------------------------------------------|
| Go       | [client-go](https://github.com/falcosecurity/client-go) |
| Rust     | [client-rs](https://github.com/falcosecurity/client-rs) |
| Python   | [client-py](https://github.com/falcosecurity/client-py) |


### What can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls.
Falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process.
For example, Falco can easily detect incidents including but not limited to:

- A shell is running inside a container or pod in Kubernetes.
- A container is running in privileged mode, or is mounting a sensitive path, such as `/proc`, from the host.
- A server process is spawning a child process of an unexpected type.
- Unexpected read of a sensitive file, such as `/etc/shadow`.
- A non-device file is written to `/dev`.
- A standard system binary, such as `ls`, is making an outbound network connection.
- A privileged pod is started in a Kubernetes cluster.

### Documentation

The [Official Documentation](https://falco.org/docs/) is the best resource to learn about Falco.

### Join the Community

To get involved with The Falco Project please visit [the community repository](https://github.com/falcosecurity/community) to find more.

How to reach out?

 - Join the #falco channel on the [Kubernetes Slack](https://slack.k8s.io)
 - [Join the Falco mailing list](https://lists.cncf.io/g/cncf-falco-dev)
 - [Read the Falco documentation](https://falco.org/docs/)


### Contributing

See the [CONTRIBUTING.md](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md).

### Security Audit

A third party security audit was performed by Cure53, you can see the full report [here](./audits/SECURITY_AUDIT_2019_07.pdf).

### Reporting security vulnerabilities

Please report security vulnerabilities following the community process documented [here](https://github.com/falcosecurity/.github/blob/master/SECURITY.md).

### License Terms

Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.


[1]: https://dl.bintray.com/falcosecurity/rpm-dev
[2]: https://dl.bintray.com/falcosecurity/rpm
[3]: https://dl.bintray.com/falcosecurity/deb-dev/stable
[4]: https://dl.bintray.com/falcosecurity/deb/stable
[5]: https://dl.bintray.com/falcosecurity/bin-dev/x86_64
[6]: https://dl.bintray.com/falcosecurity/bin/x86_64
