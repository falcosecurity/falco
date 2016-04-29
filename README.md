# Sysdig Falco
### *Host Activity Monitoring using Sysdig Event Filtering*

## Overview
Brief description of what, why, how, and pointer to website.

### What kind of events can Falco detect?



## Installing Falco
Instructions for installing via .deb, .rpm, or docker. To be filled in pre-release.

For now, local compilation and installation is the way to install (see "Building Falco" below).

## Configuring Falco

Digwatch is primarily configured via two files: a configuration file (such as the `falco.yaml` in this repository) and a rules file (such as the `falco_rules.conf` file in `rules/`). These two files are written to `/etc` after you install the Falco package.

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








### Configuration file
Falco is configured via a yaml file. The sample config `falco.yaml` in this repo has comments describing the various options.

## Running Falco

Falco is intended to be run as a service. But for experimentation and designing/testing rulesets, you will likely want to run it manually from the command-line.

### Running Falco as a service
Instructions for Centos and Ubuntu.

### Running Falco manually

`falco --help`



## Building Falco
Building Falco requires having `cmake` and `g++` installed.


### Building
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


### Running locally-built Falco

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











