# Sysdig Falco

####Latest release

**v0.1.0**
Read the [change log](https://github.com/draios/falco/blob/dev/CHANGELOG.md)

Dev Branch: [![Build Status](https://travis-ci.org/draios/falco.svg?branch=dev)](https://travis-ci.org/draios/falco)<br />
Master Branch: [![Build Status](https://travis-ci.org/draios/falco.svg?branch=master)](https://travis-ci.org/draios/falco)

## Overview
Sysdig Falco is a behavioral activity monitor designed to detect anomalous activity in your applications. Powered by sysdig’s system call capture infrastructure, falco lets you continuously monitor and detect container, application, host, and network activity... all in one place, from one source of data, with one set of rules.

#### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls. Thanks to Sysdig's core decoding and state tracking functionality, falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. For example, you can easily detect things like:

- A shell is run inside a container
- A server process spawns a child process of an unexpected type
- Unexpected read of a sensitive file (like `/etc/shadow`)
- A non-device file is written to `/dev`
- A standard system binary (like `ls`) makes an outbound network connection

This is the initial falco release. Note that much of falco's code comes from
[sysdig](https://github.com/draios/sysdig), so overall stability is very good
for an early release. On the other hand performance is still a work in
progress. On busy hosts and/or with large rule sets, you may see the current
version of falco using high CPU. Expect big improvements in coming releases.

Documentation
---
[Visit the wiki] (https://github.com/draios/falco/wiki) for full documentation on falco.

Join the Community
---
* Contact the [official mailing list] (https://groups.google.com/forum/#!forum/falco) for support and to talk with other users.
* Follow us on [Twitter] (https://twitter.com/sysdig) for general falco and sysdig news.
* This is our [blog] (https://sysdig.com/blog/), where you can find the latest [falco](https://sysdig.com/blog/tag/falco/) posts.
* Join our [Public Slack](https://sysdig.slack.com) channel for sysdig and falco announcements and discussions.

License Terms
---
Falco is licensed to you under the [GPL 2.0](./COPYING) open source license.

Contributor License Agreements
---
###Background
 As we did for sysdig, we are formalizing the way that we accept contributions of code from the contributing community. We must now ask that contributions to falco be provided subject to the terms and conditions of a [Contributor License Agreement (CLA)](./cla). The CLA comes in two forms, applicable to contributions by individuals, or by legal entities such as corporations and their employees. We recognize that entering into a CLA with us involves real consideration on your part, and we’ve tried to make this process as clear and simple as possible.

 We’ve modeled our CLA off of industry standards, such as [the CLA used by Kubernetes](https://github.com/kubernetes/kubernetes/blob/master/CONTRIBUTING.md). Note that this agreement is not a transfer of copyright ownership, this simply is a license agreement for contributions, intended to clarify the intellectual property license granted with contributions from any person or entity. It is for your protection as a contributor as well as the protection of falco; it does not change your rights to use your own contributions for any other purpose.

 For some background on why contributor license agreements are necessary, you can read FAQs from many other open source projects:

- [Django’s excellent CLA FAQ](https://www.djangoproject.com/foundation/cla/faq/)
- [A well-written chapter from Karl Fogel’s Producing Open Source Software on CLAs](http://producingoss.com/en/copyright-assignment.html)
- [The Wikipedia article on CLAs](http://en.wikipedia.org/wiki/Contributor_license_agreement)

As always, we are grateful for your past and present contributions to falco.

###What do I need to do in order to contribute code?

**Individual contributions**: Individuals who wish to make contributions must review the [Individual Contributor License Agreement](./cla/falco_contributor_agreement.txt) and indicate agreement by adding the following line to every GIT commit message:

falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name; pseudonyms or anonymous contributions are not allowed.

**Corporate contributions**: Employees of corporations, members of LLCs or LLPs, or others acting on behalf of a contributing entity, must review the [Corporate Contributor License Agreement](./cla/falco_corp_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message:

```
 falco-CLA-1.0-contributing-entity: Full Legal Name of Entity
 falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.
