sysdig
======

[![Build Status](https://travis-ci.com/draios/sysdig.png?branch=master)](https://travis-ci.com/draios/sysdig)

# Welcome to **sysdig**!

**Sysdig** is a universal system visibility tool with native support for containers:  
`~$ sysdig`

**Csysdig** is a simple, intuitive, and fully customizable curses UI for sysdig:  
`~$ csysdig`
  
What does sysdig do and why should I use it?
---
**Sysdig is a simple tool for deep system visibility, with native support for containers.**

We built sysdig to give you _easy access_ to the actual behavior of your Linux systems and containers. Honestly, the best way to understand sysdig is to [try it](https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux) - its super easy! Or here's a quick video introduction to csysdig, the simple, intuitive, and fully customizable curses-based UI for sysdig: https://www.youtube.com/watch?v=UJ4wVrbP-Q8

Far too often, system-level monitoring and troubleshooting still involves logging into a machine with SSH and using a plethora of dated tools with very inconsistent interfaces. And many of these classic Linux tools breakdown completely in containerized environments. Sysdig unites your Linux toolkit into a single, consistent, easy-to-use interface. And sysdig's unique architecture allows deep inspection into containers, right out of the box, without having to instrument the containers themselves in any way.

Sysdig instruments your physical and virtual machines at the OS level by installing into the Linux kernel and capturing system calls and other OS events. Sysdig also makes it possible to create trace files for system activity, similarly to what you can do for networks with tools like tcpdump and Wireshark. This way, problems can be analyzed at a later time, without losing important information. Rich system state is stored in the trace files, so that the captured activity can be put into full context.

Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce.

Documentation / Support
---
[Visit the wiki](https://github.com/draios/sysdig/wiki) for full documentation on sysdig and its APIs.  

For support using sysdig, please contact [the official mailing list](https://groups.google.com/forum/#!forum/sysdig).  

Join the Community
---
* Contact the [official mailing list](https://groups.google.com/forum/#!forum/sysdig) for support and to talk with other users
* Follow us on [Twitter](https://twitter.com/sysdig)
* This is our [blog](https://sysdig.com/blog/). There are many like it, but this one is ours.
* Join our [Public Slack](https://slack.sysdig.com) channel for sysdig announcements and discussions.

License Terms
---
The sysdig userspace programs and supporting code are licensed to you under the [Apache 2.0](./COPYING) open source license.

The sysdig kernel module, which is in the `driver` subdirectory, is licensed to you under both the [MIT](https://github.com/draios/sysdig/blob/dev/driver/MIT.txt) and [GPLv2](https://github.com/draios/sysdig/blob/dev/driver/GPL2.txt) open source licenses.

Contributor License Agreements
---
### Background
As sysdig matures and gains wider acceptance, we are formalizing the way that we accept contributions of code from the contributing community. We must now ask that contributions to sysdig be provided subject to the terms and conditions of a [Contributor License Agreement (CLA)](https://github.com/draios/sysdig/tree/dev/cla). The CLA comes in two forms, applicable to contributions by individuals, or by legal entities such as corporations and their employees. We recognize that entering into a CLA with us involves real consideration on your part, and we’ve tried to make this process as clear and simple as possible.
 
We’ve modeled our CLA off of industry standards, such as [the CLA used by Kubernetes](https://github.com/kubernetes/kubernetes/blob/master/CONTRIBUTING.md). Note that this agreement is not a transfer of copyright ownership, this simply is a license agreement for contributions, intended to clarify the intellectual property license granted with contributions from any person or entity. It is for your protection as a contributor as well as the protection of sysdig; it does not change your rights to use your own contributions for any other purpose.

For some background on why contributor license agreements are necessary, you can read FAQs from many other open source projects:
- [Django’s excellent CLA FAQ](https://www.djangoproject.com/foundation/cla/faq/)
- [A well-written chapter from Karl Fogel’s Producing Open Source Software on CLAs](http://producingoss.com/en/copyright-assignment.html)
- [The Wikipedia article on CLAs](http://en.wikipedia.org/wiki/Contributor_license_agreement)

As always, we are grateful for your past and present contributions to sysdig.

### What do I need to do in order to contribute code?
**Individual contributions**: Individuals who wish to make contributions must review the [Individual Contributor License Agreement](https://github.com/draios/sysdig/blob/dev/cla/sysdig_contributor_agreement.txt) and indicate agreement by adding the following line to every GIT commit message: 
 
```
sysdig-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>
```

Use your real name; pseudonyms or anonymous contributions are not allowed.

**Corporate contributions**: Employees of corporations, members of LLCs or LLPs, or others acting on behalf of a contributing entity, must review the [Corporate Contributor License Agreement](https://github.com/draios/sysdig/blob/dev/cla/sysdig_corp_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message: 
 
```
sysdig-CLA-1.0-contributing-entity: Full Legal Name of Entity  
sysdig-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>  
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.

**Government contributions**: Employees or officers of the United States Government, must review the [Corporate Contributor License Agreement](https://github.com/draios/sysdig/blob/dev/cla/sysdig_corp_contributor_agreement.txt), must be an authorized representative of the contributing entity, and indicate agreement to it on behalf of the contributing entity by adding the following lines to every GIT commit message: 
 
```
sysdig-CLA-1.0-contributing-govt-entity: Full Legal Name of Entity
sysdig-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>  
This file is a work of authorship of an employee or officer of the United States Government and is not subject to copyright in the United States under 17 USC 105.
```

Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.

Commercial Support
---
Interested in a fully supported, fully distributed version of sysdig? Check out [Sysdig Monitor](https://sysdig.com/products/monitor/)!

Open source sysdig is proudly supported by [Sysdig Inc](https://sysdig.com/company/).  

Interested in what we're doing? [Sysdig is hiring](https://sysdig.com/jobs/).
