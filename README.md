<p><img align="right" src="https://github.com/falcosecurity/falco-website/raw/master/themes/falco-fresh/static/images/favicon.png" width="64px"/></p>
<p></p>

# Falco

#### Latest release

**v0.16.0**
Read the [change log](https://github.com/falcosecurity/falco/blob/dev/CHANGELOG.md)

Dev Branch: [![Build Status](https://travis-ci.com/falcosecurity/falco.svg?branch=dev)](https://travis-ci.com/falcosecurity/falco)<br />
Master Branch: [![Build Status](https://travis-ci.com/falcosecurity/falco.svg?branch=master)](https://travis-ci.com/falcosecurity/falco)<br />
CII Best Practices: [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2317/badge)](https://bestpractices.coreinfrastructure.org/projects/2317)

---

Falco is a behavioral activity monitor designed to detect anomalous activity in your applications. Powered by [sysdig’s](https://github.com/draios/sysdig) system call capture infrastructure, Falco lets you continuously monitor and detect container, application, host, and network activity—all in one place—from one source of data, with one set of rules.

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

A comprehensive [installation guide](https://falco.org/docs/installation/) for Falco is available in the documentation website.

#### How do you compare Falco with other security tools?

One of the questions we often get when we talk about Falco is “How does Falco differ from other Linux security tools such as SELinux, AppArmor, Auditd, etc.?”. We wrote a [blog post](https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/) comparing Falco with other tools.


Documentation
---
See [Falco Documentation](https://falco.org/docs/) to quickly get started using Falco.

Join the Community
---
* [Website](https://falco.org) for Falco.
* We are working on a blog for the Falco project. In the meantime you can find [Falco](https://sysdig.com/blog/tag/falco/) posts over on the Sysdig blog.
* Join our [Public Slack](https://slack.sysdig.com) channel for open source Sysdig and Falco announcements and discussions.

License Terms
---
Falco is licensed to you under the [Apache 2.0](./COPYING) open source license.

Contributing
---
See the [CONTRIBUTING.md](./CONTRIBUTING.md).
