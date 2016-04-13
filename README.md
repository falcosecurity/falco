# Digwatch: Host Activity Monitoring with Sysdig Filters

## Overview
Brief description of what, why, how, and pointer to website.

### What kind of events can digwatch detect?



## Installing Digwatch
Installation instructions.

## Configuring Digwatch

Digwatch is primarily configured via two files: a configuration file (such as the `digwatch.yaml` in this repository) and a rules file (such as the `digwatch_rules.conf` file in `rules/`). These two files are written to `/etc` after you install the Digwatch package.

### Rules file
Explain the rules file syntax

### Configuration file
Explain the config file contents and syntax


## Running Digwatch

Digwatch is intended to be run as a service. But for experimentation and designing/testing rulesets, you will likely want to run it manually from the command-line.

### Running Digwatch as a service
Instructions for Centos and Ubuntu.

### Running Digwatch manually


## Building Digwatch

### Building
Clone this repo in a directory that also contains the sysdig source repo. The result should be something like:

```
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ pwd
/sysdig
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ ls -l
total 20
drwxr-xr-x  1 vagrant vagrant  238 Feb 21 21:44 digwatch
drwxr-xr-x  1 vagrant vagrant  646 Feb 21 17:41 sysdig
```

create a build dir, then setup cmake and run make from that dir:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

as a result, you should have a digwatch executable in `build/userspace/digwatch/digwatch`.


### Running locally-built sysdig

Assuming you are in the `build` dir, you can run digwatch as:

`$ sudo ./userspace/digwatch/digwatch -c ../digwatch.yaml -r ../rules/digwatch_rules.conf`

Or instead you can try using some of the simpler rules files in `rules`. Or to get started, try creating a file with this:

Create a file with some [digwatch rules](Rule-syntax-and-design). For example:
```
write: (syscall.type=write and fd.typechar=f) or syscall.type=mkdir or syscall.type=creat or syscall.type=rename
interactive: proc.pname = bash or proc.pname = sshd
write and interactive and fd.name contains sysdig
write and interactive and fd.name contains .txt
```

And you will see an output event for any interactive process that touches a file with "sysdig" or ".txt" in its name!











