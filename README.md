<p align="center"><img src="https://raw.githubusercontent.com/falcosecurity/community/master/logo/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

<hr>

[![Build Status](https://img.shields.io/circleci/build/github/falcosecurity/falco/master?style=for-the-badge)](https://circleci.com/gh/falcosecurity/falco) [![CII Best Practices Summary](https://img.shields.io/cii/summary/2317?label=CCI%20Best%20Practices&style=for-the-badge)](https://bestpractices.coreinfrastructure.org/projects/2317) [![GitHub](https://img.shields.io/github/license/falcosecurity/falco?style=for-the-badge)](COPYING) [![Latest](https://img.shields.io/github/v/release/falcosecurity/falco?style=for-the-badge)](https://github.com/falcosecurity/falco/releases/latest) ![Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64-blueviolet?style=for-the-badge)

Want to talk? Join us on the [#falco](https://kubernetes.slack.com/messages/falco) channel in the [Kubernetes Slack](https://slack.k8s.io).

## Latest releases

Read the [change log](CHANGELOG.md).

<!-- 
Badges in the following table are constructed by using the
https://img.shields.io/badge/dynamic/xml endpoint.

Parameters are configured for fetching packages from S3 before 
(filtered by prefix, sorted in ascending order) and for picking 
the latest package by using an XPath selector after.

- Common query parameters:

color=#300aec7
style=flat-square
label=Falco

- DEB packages parameters:

url=https://falco-distribution.s3-eu-west-1.amazonaws.com/?prefix=packages/deb/stable/falco-
query=substring-before(substring-after((/*[name()='ListBucketResult']/*[name()='Contents'])[last()]/*[name()='Key'],"falco-"),".asc")

- RPM packages parameters:

url=https://falco-distribution.s3-eu-west-1.amazonaws.com/?prefix=packages/rpm/falco-
query=substring-before(substring-after((/*[name()='ListBucketResult']/*[name()='Contents'])[last()]/*[name()='Key'],"falco-"),".asc")

- BIN packages parameters:

url=https://falco-distribution.s3-eu-west-1.amazonaws.com/?prefix=packages/bin/x86_64/falco-
query=substring-after((/*[name()='ListBucketResult']/*[name()='Contents'])[last()]/*[name()='Key'], "falco-")

Notes:
 - if more than 1000 items are present under as S3 prefix, 
   the actual latest package will be not picked;
   see https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
 - for `-dev` packages, the S3 prefix is modified accordingly
 - finally, all parameters are URL encoded and appended to the badge endpoint

-->

|              | development                                                                                                                                                                                                                                                                                                                                                                                                                                                                | stable                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| rpm-x86_64          | [![rpm-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Frpm-dev%2Ffalco-%26delimiter=aarch64)][1]          | [![rpm](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Frpm%2Ffalco-%26delimiter=aarch64)][2]          |
| deb-x86_64          | [![deb-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fdeb-dev%2Fstable%2Ffalco-%26delimiter=aarch64)][3] | [![deb](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fdeb%2Fstable%2Ffalco-%26delimiter=aarch64)][4] |
| binary-x86_64       | [![bin-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%20%22falco-%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fbin-dev%2Fx86_64%2Ffalco-)][5]                                                     | [![bin](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%20%22falco-%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fbin%2Fx86_64%2Ffalco-)][6]                                                     |
| rpm-aarch64    | [![rpm-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Frpm-dev%2Ffalco-%26delimiter=x86_64)][1]           | [![rpm](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Frpm%2Ffalco-%26delimiter=x86_64)][2]           |
| deb-aarch64    | [![deb-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fdeb-dev%2Fstable%2Ffalco-%26delimiter=x86_64)][3]  | [![deb](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-before%28substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%22falco-%22%29%2C%22.asc%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fdeb%2Fstable%2Ffalco-%26delimiter=x86_64)][4]  |
| binary-aarch64 | [![bin-dev](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%20%22falco-%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fbin-dev%2Faarch64%2Ffalco-)][7]                                                    | [![bin](https://img.shields.io/badge/dynamic/xml?color=%2300aec7&style=flat-square&label=Falco&query=substring-after%28%28%2F%2A%5Bname%28%29%3D%27ListBucketResult%27%5D%2F%2A%5Bname%28%29%3D%27Contents%27%5D%29%5Blast%28%29%5D%2F%2A%5Bname%28%29%3D%27Key%27%5D%2C%20%22falco-%22%29&url=https%3A%2F%2Ffalco-distribution.s3-eu-west-1.amazonaws.com%2F%3Fprefix%3Dpackages%2Fbin%2Faarch64%2Ffalco-)][8]                                                    |

---

The Falco Project, originally created by [Sysdig](https://sysdig.com), is an incubating [CNCF](https://cncf.io) open source cloud native runtime security tool.
Falco makes it easy to consume kernel events, and enrich those events with information from Kubernetes and the rest of the cloud native stack. 
Falco can also be extended to other data sources by using plugins.
Falco has a rich set of security rules specifically built for Kubernetes, Linux, and cloud-native.
If a rule is violated in a system, Falco will send an alert notifying the user of the violation and its severity.

## What can Falco detect?

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

The Falco rules inventory [document](rules-inventory/rules_mitre_overview.md) provides additional details around the default rules Falco ships with.

## Installing Falco

If you would like to run Falco in **production** please adhere to the [official installation guide](https://falco.org/docs/getting-started/installation/).

### Kubernetes

| Tool     | Link                                                                                       | Note                                                               |
|----------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| Helm     | [Chart Repository](https://github.com/falcosecurity/charts/tree/master/falco#introduction) | The Falco community offers regular helm chart releases.            |
| Minikube | [Tutorial](https://falco.org/docs/getting-started/third-party/#minikube)                                   | The Falco driver has been baked into minikube for easy deployment. |
| Kind     | [Tutorial](https://falco.org/docs/getting-started/third-party/#kind)                                       | Running Falco with kind requires a driver on the host system.      |
| GKE      | [Tutorial](https://falco.org/docs/getting-started/third-party/#gke)                                        | We suggest using the eBPF driver for running Falco on GKE.         |

## Developing

Falco is designed to be extensible such that it can be built into cloud-native applications and infrastructure.

Falco has a [gRPC](https://falco.org/docs/grpc/) endpoint and an API defined in [protobuf](https://github.com/falcosecurity/falco/blob/master/userspace/falco/outputs.proto).
The Falco Project supports various SDKs for this endpoint.

### SDKs

| Language | Repository                                              |
|----------|---------------------------------------------------------|
| Go       | [client-go](https://github.com/falcosecurity/client-go) |

## Plugins

Falco comes with a [plugin framework](https://falco.org/docs/plugins/) that extends it to potentially any cloud detection scenario. Plugins are shared libraries that conform to a documented API and allow for:

- Adding new event sources that can be used in rules;
- Adding the ability to define new fields and extract information from events.

The Falco Project maintains [various plugins](https://github.com/falcosecurity/plugins) and provides SDKs for plugin development.


### SDKs

| Language | Repository                                                                    |
|----------|-------------------------------------------------------------------------------|
| Go       | [falcosecurity/plugin-sdk-go](https://github.com/falcosecurity/plugin-sdk-go) |


## Documentation

The [Official Documentation](https://falco.org/docs/) is the best resource to learn about Falco.

## Join the Community

To get involved with The Falco Project please visit [the community repository](https://github.com/falcosecurity/community) to find more.

How to reach out?

 - Join the [#falco](https://kubernetes.slack.com/messages/falco) channel on the [Kubernetes Slack](https://slack.k8s.io)
 - [Join the Falco mailing list](https://lists.cncf.io/g/cncf-falco-dev)
 - [Read the Falco documentation](https://falco.org/docs/)

## How to contribute

See the [contributing guide](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) and the [code of conduct](https://github.com/falcosecurity/evolution/CODE_OF_CONDUCT.md).
 
## Security Audit

A third party security audit was performed by Cure53, you can see the full report [here](./audits/SECURITY_AUDIT_2019_07.pdf).

## Reporting security vulnerabilities

Please report security vulnerabilities following the community process documented [here](https://github.com/falcosecurity/.github/blob/main/SECURITY.md).

## License

Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.

## Project Evolution

The [falcosecurity/evolution](https://github.com/falcosecurity/evolution) repository is the official space for the community to work together, discuss ideas, and document processes. It is also a place to make decisions. Check it out to find more helpful resources.

## Resources

 - [Governance](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md)
 - [Code Of Conduct](https://github.com/falcosecurity/evolution/blob/main/CODE_OF_CONDUCT.md)
 - [Maintainers Guidelines](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS_GUIDELINES.md)
 - [Maintainers List](https://github.com/falcosecurity/evolution/blob/main/MAINTAINERS.md)
 - [Repositories Guidelines](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md)
 - [Repositories List](https://github.com/falcosecurity/evolution/blob/main/README.md#repositories)
 - [Adopters List](https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md)


[1]: https://download.falco.org/?prefix=packages/rpm-dev/
[2]: https://download.falco.org/?prefix=packages/rpm/
[3]: https://download.falco.org/?prefix=packages/deb-dev/stable/
[4]: https://download.falco.org/?prefix=packages/deb/stable/
[5]: https://download.falco.org/?prefix=packages/bin-dev/x86_64/
[6]: https://download.falco.org/?prefix=packages/bin/x86_64/
[7]: https://download.falco.org/?prefix=packages/bin-dev/aarch64/
[8]: https://download.falco.org/?prefix=packages/bin/aarch64/
