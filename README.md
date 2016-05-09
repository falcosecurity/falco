# Sysdig Falco
### *Host Activity Monitoring using Sysdig Event Filtering*

## Overview
Sysdig Falco is a behavioral activity monitor designed to secure your applications. Powered by Sysdig’s universal system level visibility, write simple and powerful rules, and then output warnings in the format you need. Continuously monitor and detect container, application, host, and network activity... all in one place, from one source of data, with one set of rules.


### What kind of behaviors can Falco detect?

Falco can detect and alert on any behavior that involves making Linux system calls.  Thanks to Sysdig's core decoding and state tracking functionality, Falco alerts can be triggered by the use of specific system calls, their arguments, and by properties of the calling process. Rules are expressed in a high-level, human-readable language. For example, you can easily detect things like:
- A shell is run inside a container
- A server process spawns a child process of an unexpected type
- Unexpected read of a sensitive file (like `/etc/passwd`)
- A non-device file is written to `/dev`
- A standard system binary (like `ls`) makes an outbound network connection


## Installing Falco
### Scripted install

To install Falco automatically in one step, simply run the following command as root or with sudo:

`curl -s https://s3.amazonaws.com/download.draios.com/stable/install-falco | sudo bash`

### Package install

#### RHEL

- Trust the Draios GPG key, configure the yum repository
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

#### Debian

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


Instructions for installing via .deb, .rpm, or docker. To be filled in pre-release.

For now, local compilation and installation is the way to install (see "Building Falco" below).

#### Container install (general)

If you have full control of your host operating system, then installing Falco using the normal installation method is the recommended best practice. This method allows full visibility into all containers on the host OS. No changes to the standard automatic/manual installation procedures are required.

However, Falco can also run inside a Docker container. To guarantee a smooth deployment, the kernel headers must be installed in the host operating system, before running Falco.

This can usually be done on Debian-like distributions with:
`apt-get -y install linux-headers-$(uname -r)`

Or, on RHEL-like distributions:
`yum -y install kernel-devel-$(uname -r)`

Falco can then be run with:

```
docker pull sysdig/falco
docker run -i -t --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro sysdig/falco falco
```

#### Container install (CoreOS)

The recommended way to run Falco on CoreOS is inside of its own Docker container using the install commands in the paragraph above. This method allows full visibility into all containers on the host OS.

This method is automatically updated, includes some nice features such as automatic setup and bash completion, and is a generic approach that can be used on other distributions outside CoreOS as well.

However, some users may prefer to run Falco in the CoreOS toolbox. While not the recommended method, this can be achieved by installing Falco inside the toolbox using the normal installation method, and then manually running the sysdig-probe-loader script:

```
toolbox --bind=/dev --bind=/var/run/docker.sock
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-falco | bash
sysdig-probe-loader
```

## Configuring Falco

Falco is primarily configured via two files: a configuration file (such as the `falco.yaml` in this repository) and a rules file (such as the `falco_rules.conf` file in `rules/`). These two files are written to `/etc` after you install the Falco package.

### Rules file

The rules file is where you define the events and actions that you want to be notified on. We've provided a sample rule file `./rules/falco_rules.conf` as a starting point, but you'll want to familiarize yourself with the contents, and most likely, to adapt it to your environment. 

_Call for contributions: If you come up with additional rules which you think should be part of this core set - PR welcome! And likewise if you have an entirely separate ruleset that may not belong in the core rule set._

A Falco rules file is comprised of two kinds of elements: rules and macro definitions. 

Here's an example of a rule that alerts whenever a bash shell is run inside a container:

`container.id != host and proc.name = bash | WARNING Bash run in a container (%user.name %proc.name %evt.dir %evt.type %evt.args %fd.name)`

The part to the left of the pipe (`|`) is the _condition_. It is expressed using the Sysdig [filter syntax](http://www.sysdig.org/wiki/sysdig-user-guide/#filtering). Any Sysdig filter expression is a valid Falco expression (with the caveat of certain excluded system calls, discussed below). In addition, Falco expressions can contain _macro_ terms, which are not present in Sysdig syntax.

The part to the right of the pipe is the _output_. It is composed of a priority level and an output format. The priority level is case-insensitive and should be one of "emergency", "alert", "critical", "error", "warning", "notice", "informational", or "debug". The output format specifies the message that should be output if a matching event occurs, and follows the Sysdig [output format syntax](http://www.sysdig.org/wiki/sysdig-user-guide/#output-formatting).

Macro definitions provide a way to define common sub-portions of rules in a reusable way. The syntax for a macro is:

`macro_name: macro_definition`

where `macro_name` is a string, and `macro_definition` is any valid Falco condition. 

(_insert example here_).



#### Ignored system calls

For performance reasons, some system calls are currently discarded before Falco processing. The current list is: 
`clock_getres,clock_gettime,clock_nanosleep,clock_settime,close,epoll_create,epoll_create1,epoll_ctl,epoll_pwait,epoll_wait,eventfd,fcntl,fcntl64,fstat,fstat64,getitimer,gettimeofday,nanosleep,poll,ppoll,pread64,preadv,pselect6,pwrite64,pwritev,read,readv,recv,recvfrom,recvmmsg,recvmsg,select,send,sendfile,sendfile64,sendmmsg,sendmsg,sendto,setitimer,settimeofday,shutdown,socket,splice,switch,tee,timer_create,timer_delete,timerfd_create,timerfd_gettime,timerfd_settime,timer_getoverrun,timer_gettime,timer_settime,wait4,write,writev,`




### Configuration file
Falco is configured via a yaml file. The sample config `falco.yaml` in this repo has comments describing the various options.


## Running Falco

Falco is intended to be run as a service. But for experimentation and designing/testing rulesets, you will likely want to run it manually from the command-line.

### Running Falco as a service
Instructions for Centos and Ubuntu.

### Running Falco manually

`falco --help`



## Building and running Falco locally from source
Building Falco requires having `cmake` and `g++` installed.


### Building Falco
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

### Load latest sysdig kernel module

If you have a binary version of sysdig installed, an older sysdig kernel module may already be loaded. To ensure you are using the latest version, you should unload any existing sysdig kernel module and load the locally built version.

Unload any existing kernel module via:

`$ rmmod sysdig_probe`

To load the locally built version, assuming you are in the `build` dir, use:

`$ insmod driver/sysdig-probe.ko`

### Running Falco

Assuming you are in the `build` dir, you can run Falco as:

`$ sudo ./userspace/falco/falco -c ../falco.yaml -r ../rules/falco_rules.conf`

Or instead you can try using some of the simpler rules files in `rules`. Or to get started, try creating a file with this:

Create a file with some [Falco rules](Rule-syntax-and-design). For example:
```
write: (syscall.type=write and fd.typechar=f) or syscall.type=mkdir or syscall.type=creat or syscall.type=rename
interactive: proc.pname = bash or proc.pname = sshd
write and interactive and fd.name contains sysdig
write and interactive and fd.name contains .txt
```

And you will see an output event for any interactive process that touches a file with "sysdig" or ".txt" in its name!











