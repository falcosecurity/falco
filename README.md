<p align="center"><img src="https://raw.githubusercontent.com/falcosecurity/community/master/logo/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

<hr>

# The Falco Project

#### Latest release

**v0.21.0**
Read the [change log](CHANGELOG.md)

[![Build Status](https://img.shields.io/circleci/build/github/falcosecurity/falco/master?style=for-the-badge)](https://circleci.com/gh/falcosecurity/falco) [![CII Best Practices Summary](https://img.shields.io/cii/summary/2317?label=CCI%20Best%20Practices&style=for-the-badge)](https://bestpractices.coreinfrastructure.org/projects/2317) [![GitHub](https://img.shields.io/github/license/falcosecurity/falco?style=for-the-badge)](COPYING)

---

Falco is a behavioral activity monitor designed to detect anomalous activity in your applications. Falco audits a system at the most fundamental level, the kernel. Falco then enriches this data with other input streams such as container runtime metrics, and Kubernetes metrics. Falco lets you continuously monitor and detect container, application, host, and network activity—all in one place—from one source of data, with one set of rules.

Falco is hosted by the Cloud Native Computing Foundation (CNCF) as a sandbox level project. If you are an organization that wants to help shape the evolution of technologies that are container-packaged, dynamically-scheduled and microservices-oriented, consider joining the CNCF. For details read the [Falco CNCF project proposal](https://github.com/cncf/toc/tree/master/proposals/falco.adoc).

#### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls. Falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. For example, Falco can easily detect incidents including but not limited to:

- A shell is running inside a container.
- A container is running in privileged mode, or is mounting a sensitive path, such as `/proc`, from the host.
- A server process is spawning a child process of an unexpected type.
- Unexpected read of a sensitive file, such as `/etc/shadow`.
- A non-device file is written to `/dev`.
- A standard system binary, such as `ls`, is making an outbound network connection.


### Installing Falco

You can find the latest release downloads on the official [release archive](https://bintray.com/falcosecurity)

Furthermore the comprehensive [installation guide](https://falco.org/docs/installation/) for Falco is available in the documentation website.

#### How do you compare Falco with other security tools?

One of the questions we often get when we talk about Falco is “How does Falco differ from other Linux security tools such as SELinux, AppArmor, Auditd, etc.?”. We wrote a [blog post](https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/) comparing Falco with other tools.


Documentation
---

See [Falco Documentation](https://falco.org/docs/) to quickly get started using Falco.

Join the Community
---

To get involved with The Falco Project please visit [the community repository](https://github.com/falcosecurity/community) to find more.

License Terms
---

Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.

Contributing
---

See the [CONTRIBUTING.md](./CONTRIBUTING.md).

Security
---

### Security Audit

A third party security audit was performed by Cure53, you can see the full report [here](./audits/SECURITY_AUDIT_2019_07.pdf).

### Reporting security vulnerabilities
Please report security vulnerabilities following the community process documented [here](https://github.com/falcosecurity/.github/blob/master/SECURITY.md).

Versions
---

|        | development                                                                                                            | stable                                                                                                         |
|--------|------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| rpm    | ![rpm-dev](https://img.shields.io/bintray/v/falcosecurity/rpm-dev/falco?label=Falco&color=%2300aec7&style=flat-square) | ![rpm](https://img.shields.io/bintray/v/falcosecurity/rpm/falco?label=Falco&color=%23005763&style=flat-square) |
| deb    | ![deb-dev](https://img.shields.io/bintray/v/falcosecurity/deb-dev/falco?label=Falco&color=%2300aec7&style=flat-square) | ![deb](https://img.shields.io/bintray/v/falcosecurity/deb/falco?label=Falco&color=%23005763&style=flat-square) |
| binary | ![bin-dev](https://img.shields.io/bintray/v/falcosecurity/bin-dev/falco?label=Falco&color=%2300aec7&style=flat-square) | ![bin](https://img.shields.io/bintray/v/falcosecurity/bin/falco?label=Falco&color=%23005763&style=flat-square) |
