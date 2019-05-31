# Falco

#### Latest release

**v0.15.0**
Read the [change log](https://github.com/falcosecurity/falco/blob/dev/CHANGELOG.md)

Dev Branch: [![Build Status](https://travis-ci.com/falcosecurity/falco.svg?branch=dev)](https://travis-ci.com/falcosecurity/falco)<br />
Master Branch: [![Build Status](https://travis-ci.com/falcosecurity/falco.svg?branch=master)](https://travis-ci.com/falcosecurity/falco)<br />
CII Best Practices: [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2317/badge)](https://bestpractices.coreinfrastructure.org/projects/2317)


## Overview
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

Contributor License Agreements
---
### Background
We are formalizing the way that we accept contributions of code from the contributing community. We must now ask that contributions to falco be provided subject to the terms and conditions of a [Contributor License Agreement (CLA)](./cla). The CLA comes in two forms, applicable to contributions by individuals, or by legal entities such as corporations and their employees. We recognize that entering into a CLA with us involves real consideration on your part, and we’ve tried to make this process as clear and simple as possible.

We’ve modeled our CLA off of industry standards, such as [the CLA used by Kubernetes](https://github.com/kubernetes/kubernetes/blob/master/CONTRIBUTING.md). Note that this agreement is not a transfer of copyright ownership, this simply is a license agreement for contributions, intended to clarify the intellectual property license granted with contributions from any person or entity. It is for your protection as a contributor as well as the protection of falco; it does not change your rights to use your own contributions for any other purpose.

For some background on why contributor license agreements are necessary, you can read FAQs from many other open source projects:

- [Django’s excellent CLA FAQ](https://www.djangoproject.com/foundation/cla/faq/)
- [A well-written chapter from Karl Fogel’s Producing Open Source Software on CLAs](http://producingoss.com/en/copyright-assignment.html)
- [The Wikipedia article on CLAs](http://en.wikipedia.org/wiki/Contributor_license_agreement)

As always, we are grateful for your past and present contributions to falco.

### What do I need to do in order to contribute code?

At first, you need to make the changes based on the dev branch not the master branch.

**Individual contributions**: Individuals who wish to make contributions must review the [Individual Contributor License Agreement](./cla/falco_contributor_agreement.txt) and indicate agreement by adding the following line to every GIT commit message:

```
falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
```

Use your real name; pseudonyms or anonymous contributions are not allowed.

**Corporate contributions**: Employees of corporations, members of LLCs or LLPs, or others acting on behalf of a contributing entity, must review the [Corporate Contributor License Agreement](./cla/falco_corp_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message:

```
falco-CLA-1.0-contributing-entity: Full Legal Name of Entity
falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.

**Government contributions**: Employees or officers of the United States Government, must review the [Government Contributor License Agreement](https://github.com/falcosecurity/falco/blob/dev/cla/falco_govt_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message:

```
falco-CLA-1.0-contributing-govt-entity: Full Legal Name of Entity
falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
This file is a work of authorship of an employee or officer of the United States Government and is not subject to copyright in the United States under 17 USC 105.
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.
