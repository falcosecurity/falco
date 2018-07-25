# Sysdig Falco

#### Latest release

**v0.11.0**
Read the [change log](https://github.com/draios/falco/blob/dev/CHANGELOG.md)

Dev Branch: [![Build Status](https://travis-ci.org/draios/falco.svg?branch=dev)](https://travis-ci.org/draios/falco)<br />
Master Branch: [![Build Status](https://travis-ci.org/draios/falco.svg?branch=master)](https://travis-ci.org/draios/falco)

## Overview
Sysdig Falco is a behavioral activity monitor designed to detect anomalous activity in your applications. Powered by sysdig’s system call capture infrastructure, falco lets you continuously monitor and detect container, application, host, and network activity... all in one place, from one source of data, with one set of rules.

#### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls. Thanks to Sysdig's core decoding and state tracking functionality, falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. For example, you can easily detect things like:

- A shell is run inside a container
- A container is running in privileged mode, or is mounting a sensitive path like `/proc` from the host.
- A server process spawns a child process of an unexpected type
- Unexpected read of a sensitive file (like `/etc/shadow`)
- A non-device file is written to `/dev`
- A standard system binary (like `ls`) makes an outbound network connection

#### How Falco Compares to Other Security Tools like SELinux, Auditd, etc.

One of the questions we often get when we talk about Sysdig Falco is “How does it compare to other tools like SELinux, AppArmor, Auditd, etc. that also have security policies?”. We wrote a [blog post](https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/) comparing Falco to other tools.


Documentation
---
[Visit the wiki](https://github.com/draios/falco/wiki) for full documentation on falco.

Join the Community
---
* Follow us on [Twitter](https://twitter.com/sysdig) for general falco and sysdig news.
* This is our [blog](https://sysdig.com/blog/), where you can find the latest [falco](https://sysdig.com/blog/tag/falco/) posts.
* Join our [Public Slack](https://slack.sysdig.com) channel for sysdig and falco announcements and discussions.

License Terms
---
Falco is licensed to you under the [GPL 2.0](./COPYING) open source license.

In addition, as a special exception, the copyright holders give permission to link the code of portions of this program with the OpenSSL library under certain conditions as described in each individual source file, and distribute linked combinations including the two.

You must obey the GNU General Public License in all respects for all of the code used other than OpenSSL.  If you modify file(s) with this exception, you may extend this exception to your version of the file(s), but you are not obligated to do so.  If you do not wish to do so, delete this exception statement from your version.

Contributor License Agreements
---
### Background
 As we did for sysdig, we are formalizing the way that we accept contributions of code from the contributing community. We must now ask that contributions to falco be provided subject to the terms and conditions of a [Contributor License Agreement (CLA)](./cla). The CLA comes in two forms, applicable to contributions by individuals, or by legal entities such as corporations and their employees. We recognize that entering into a CLA with us involves real consideration on your part, and we’ve tried to make this process as clear and simple as possible.

 We’ve modeled our CLA off of industry standards, such as [the CLA used by Kubernetes](https://github.com/kubernetes/kubernetes/blob/master/CONTRIBUTING.md). Note that this agreement is not a transfer of copyright ownership, this simply is a license agreement for contributions, intended to clarify the intellectual property license granted with contributions from any person or entity. It is for your protection as a contributor as well as the protection of falco; it does not change your rights to use your own contributions for any other purpose.

 For some background on why contributor license agreements are necessary, you can read FAQs from many other open source projects:

- [Django’s excellent CLA FAQ](https://www.djangoproject.com/foundation/cla/faq/)
- [A well-written chapter from Karl Fogel’s Producing Open Source Software on CLAs](http://producingoss.com/en/copyright-assignment.html)
- [The Wikipedia article on CLAs](http://en.wikipedia.org/wiki/Contributor_license_agreement)

As always, we are grateful for your past and present contributions to falco.

### What do I need to do in order to contribute code?

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

**Government contributions**: Employees or officers of the United States Government, must review the [Government Contributor License Agreement](https://github.com/draios/falco/blob/dev/cla/falco_govt_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message:

```
falco-CLA-1.0-contributing-govt-entity: Full Legal Name of Entity
falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
This file is a work of authorship of an employee or officer of the United States Government and is not subject to copyright in the United States under 17 USC 105.
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.
