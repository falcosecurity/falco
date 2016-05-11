# Sysdig Falco
### *Host Activity Monitoring using Sysdig Event Filtering*

**Table of Contents**

- [Overview](#overview)
- [Rules](#rules)
- [Configuration](#configuration)
- [Installation](#installation)
- [Running Falco](#running-falco)


## Overview
Sysdig Falco is a behavioral activity monitor designed to secure your applications. Powered by Sysdig’s universal system level visibility, write simple and powerful rules, and then output warnings in the format you need. Continuously monitor and detect container, application, host, and network activity... all in one place, from one source of data, with one set of rules.


#### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls. Thanks to Sysdig's core decoding and state tracking functionality, Falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. For example, you can easily detect things like:
- A shell is run inside a container
- A server process spawns a child process of an unexpected type
- Unexpected read of a sensitive file (like `/etc/passwd`)
- A non-device file is written to `/dev`
- A standard system binary (like `ls`) makes an outbound network connection

#### How you use it

Falco is deployed as a long-running daemon. You can install it as a debian/rpm
package on a regular host or container host, or you can deploy it as a
container.

Falco is configured via a rules file defining the behaviors and events to
watch for, and a general configuration file. Rules are expressed in a
high-level, human-readable language. We've provided a sample rule file
`./rules/falco_rules.yaml` as a starting point - you can (and will likely
want!) to adapt it to your environment.

When developing rules, one helpful feature is Falco's ability to read trace
files saved by sysdig. This allows you to "record" the offending behavior
once, and replay it with Falco as many times as needed while tweaking your
rules.

Once deployed, Falco uses the Sysdig kernel module and userspace libraries to
watch for any events matching one of the conditions defined in the rule
file. If a matching event occurs, a notification is written to the the
configured output(s).


## Rules

_Call for contributions: If you come up with additional rules which you'd like to see in the core repository - PR welcome!_

A Falco rules file is comprised of two kinds of elements: rules and macro definitions. Macros are simply definitions that can be re-used inside rules and other macros, providing a way to factor out and name common patterns.

#### Conditions

The key part of a rule is the _condition_ field. A condition is simply a boolean predicate on sysdig events.
Conditions are expressed using the Sysdig [filter syntax](http://www.sysdig.org/wiki/sysdig-user-guide/#filtering). Any Sysdig filter is a valid Falco condition (with the caveat of certain excluded system calls, discussed below). In addition, Falco expressions can contain _macro_ terms, which are not present in Sysdig syntax.

Here's an example of a condition that alerts whenever a bash shell is run inside a container:

`container.id != host and proc.name = bash`

The first clause checks that the event happened in a container (sysdig events have a `container` field that is equal to "host" if the event happened on a regular host). The second clause checks that the process name is `bash`. Note that this condition does not even include a clause with system call! It only uses event metadata. As such, if a bash shell does start up in a container, Falco will output events for every syscall that is done by that shell.

_Tip: If you're new to sysdig and unsure what fields are available, run `sysdig -l` to see the list of supported fields._

#### Rules

Along with a condition, each rule includes an _output_ and a _priority_. The output format specifies the message that should be output if a matching event occurs, and follows the Sysdig [output format syntax](http://www.sysdig.org/wiki/sysdig-user-guide/#output-formatting). The priority is a case-insensitive representation of severity and should be one of "emergency", "alert", "critical", "error", "warning", "notice", "informational", or "debug".

A complete rule using the above condition might be:

```yaml
- condition: container.id != host and proc.name = bash
  output: "shell in a container (%user.name %container.id %proc.name %evt.dir %evt.type %evt.args %fd.name)"
  priority: WARNING
```

#### Macros
As noted above, macros provide a way to define common sub-portions of rules in a reusable way. As a very simple example, if we had many rules for events happening in containers, we might to define a `in_container` macro:

```yaml
- macro: in_container
  condition: container.id != host
```

With this macro defined, we can then rewrite the above rule's condition as `in_container and proc.name = bash`.

For many more examples of rules and macros, please take a look at the accompanying [rules file](rules/falco_rules.yaml).


#### Ignored system calls

For performance reasons, some system calls are currently discarded before Falco processing. The current list is:
`clock_getres,clock_gettime,clock_nanosleep,clock_settime,close,epoll_create,epoll_create1,epoll_ctl,epoll_pwait,epoll_wait,eventfd,fcntl,fcntl64,fstat,fstat64,getitimer,gettimeofday,nanosleep,poll,ppoll,pread64,preadv,pselect6,pwrite64,pwritev,read,readv,recv,recvfrom,recvmmsg,recvmsg,select,send,sendfile,sendfile64,sendmmsg,sendmsg,sendto,setitimer,settimeofday,shutdown,socket,splice,switch,tee,timer_create,timer_delete,timerfd_create,timerfd_gettime,timerfd_settime,timer_getoverrun,timer_gettime,timer_settime,wait4,write,writev`


## Configuration

General configuration is done via a separate yaml file. The
[config file](falco.yaml) in this repo has comments describing the various
configuration options.


## Installation
#### Scripted install

To install Falco automatically in one step, simply run the following command as root or with sudo:

`curl -s https://s3.amazonaws.com/download.draios.com/stable/install-falco | sudo bash`

#### Package install

##### RHEL

- Trust the Draios GPG key and configure the yum repository
```
rpm --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public
curl -s -o /etc/yum.repos.d/draios.repo http://download.draios.com/stable/rpm/draios.repo
```
- Install the EPEL repository

Note: The following command is required only if DKMS is not available in the distribution. You can verify if DKMS is available with yum list dkms

`rpm -i http://mirror.us.leaseweb.net/epel/6/i386/epel-release-6-8.noarch.rpm`

- Install kernel headers

Warning: The following command might not work with any kernel. Make sure to customize the name of the package properly

`yum -y install kernel-devel-$(uname -r)`

- Install Falco

`yum -y install falco`


To uninstall, just do `yum erase falco`.

##### Debian

- Trust the Draios GPG key, configure the apt repository, and update the package list

```
curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -
curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/stable/deb/draios.list
apt-get update
```

- Install kernel headers

Warning: The following command might not work with any kernel. Make sure to customize the name of the package properly

`apt-get -y install linux-headers-$(uname -r)`

- Install Falco

`apt-get -y install falco`

To uninstall, just do `apt-get remove falco`.


##### Container install (general)

If you have full control of your host operating system, then installing Falco using the normal installation method is the recommended best practice. This method allows full visibility into all containers on the host OS. No changes to the standard automatic/manual installation procedures are required.

However, Falco can also run inside a Docker container. To guarantee a smooth deployment, the kernel headers must be installed in the host operating system, before running Falco.

This can usually be done on Debian-like distributions with:
`apt-get -y install linux-headers-$(uname -r)`

Or, on RHEL-like distributions:
`yum -y install kernel-devel-$(uname -r)`

Falco can then be run with:

```
docker pull sysdig/falco
docker run -i -t --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro sysdig/falco
```

##### Container install (CoreOS)

The recommended way to run Falco on CoreOS is inside of its own Docker container using the install commands in the paragraph above. This method allows full visibility into all containers on the host OS.

This method is automatically updated, includes some nice features such as automatic setup and bash completion, and is a generic approach that can be used on other distributions outside CoreOS as well.

However, some users may prefer to run Falco in the CoreOS toolbox. While not the recommended method, this can be achieved by installing Falco inside the toolbox using the normal installation method, and then manually running the sysdig-probe-loader script:

```
toolbox --bind=/dev --bind=/var/run/docker.sock
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-falco | bash
sysdig-probe-loader
```



## Running Falco

Falco is intended to be run as a service. But for experimentation and designing/testing rulesets, you will likely want to run it manually from the command-line.

#### Running Falco as a service (after installing package)

`service falco start`

#### Running Falco in a container

`docker run -i -t --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro sysdig/falco`

#### Running Falco manually

Do `falco --help` to see the command-line options available when running manually.


## Building and running Falco locally from source
Building Falco requires having `cmake` and `g++` installed.


#### Building Falco
Clone this repo in a directory that also contains the sysdig source repo. The result should be something like:

```
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ pwd
/sysdig
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ ls -l
total 20
drwxr-xr-x  1 vagrant vagrant  238 Feb 21 21:44 falco
drwxr-xr-x  1 vagrant vagrant  646 Feb 21 17:41 sysdig
```

create a build dir, then setup cmake and run make from that dir:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

as a result, you should have a falco executable in `build/userspace/falco/falco`.

#### Load latest sysdig kernel module

If you have a binary version of sysdig installed, an older sysdig kernel module may already be loaded. To ensure you are using the latest version, you should unload any existing sysdig kernel module and load the locally built version.

Unload any existing kernel module via:

`$ rmmod sysdig_probe`

To load the locally built version, assuming you are in the `build` dir, use:

`$ insmod driver/sysdig-probe.ko`

#### Running Falco

Assuming you are in the `build` dir, you can run Falco as:

`$ sudo ./userspace/falco/falco -c ../falco.yaml -r ../rules/falco_rules.yaml`

Or instead you can try using some of the simpler rules files in `rules`. Or to get started, try creating a file with this:

Create a file with some [Falco rules](Rule-syntax-and-design). For example:
```
write: (syscall.type=write and fd.typechar=f) or syscall.type=mkdir or syscall.type=creat or syscall.type=rename
interactive: proc.pname = bash or proc.pname = sshd
write and interactive and fd.name contains sysdig
write and interactive and fd.name contains .txt
```

And you will see an output event for any interactive process that touches a file with "sysdig" or ".txt" in its name!

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

   falco-CLA-1.0-contributing-entity: Full Legal Name of Entity
   falco-CLA-1.0-signed-off-by: Joe Smith <joe.smith@email.com>

   Use a real name of a natural person who is an authorized representative of the contributing entity; pseudonyms or anonymous contributions are not allowed.
