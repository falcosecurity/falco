# Falco Scope

As a project we would like to support the following artifacts.

Everything else will be moved to [contrib](https://github.com/falcosecurity/contrib).

As a project we will build, change, rename, and move files, documents, scripts, configurations according to this new state of the world.

Inspired from [#1114](https://github.com/falcosecurity/falco/issues/1114) and many of the weekly community calls.

## Terms

**falco** 

*Standalone Falco binary*

**driver**

*System call provider from the Linux kernel. Either (`bpf`, `module`, or `ptrace`)*

**falco-driver-loader-script**


*The bash script found [here](https://github.com/falcosecurity/falco/blob/master/scripts/falco-driver-loader) that tries to compile else download the kernel module.*

**package**

*An installable artifact that is operating system specific. All packages MUST be hosted on bintray for X86_64.*

**image**

*OCI compliant container image hosted on dockerhub with tags for every release.*
 

# Packages

Official packages for X86_64 only. All package names should contain a version which is not specified below.

The following convention MUST be used for all packages.

_If a package installs Falco as a daemon (systemd, init) it MUST contain `daemon`._

_If a package installs the Falco kernel module it MUST contain `module`._

_If a package installs the Falco BPF probe it MUST contain `bpf`._

_If a package installs the Falco kernel module it MUST contain `module`._

---

### .deb

 Falco running in debian like systems that will default to the kernel module.

- falco-x86.deb
     - `falco` only (default depends on `falco-module`)
 - falco-daemon-x86.deb
     - `falco` and script to configure as daemon (default depends on `falco-module`)
 - falco-module-x86.deb
     - `module` only
 - falco-bpf-x86.deb
     - `bpf` only
 - falco-ptrace-x86.deb
     - `ptrace` only

### .rpm

 Falco running in rpm like systems that will default to the kernel module.

- falco-x86.deb
     - `falco` only (default depends on `falco-module`)
 - falco-daemon-x86.deb
     - `falco` and script to configure as daemon (default depends on `falco-module`)
 - falco-module-x86.deb
     - `module` only
 - falco-bpf-x86.deb
     - `bpf` only
 - falco-ptrace-x86.deb
     - `ptrace` only


### .tar.gz

 - falco-src-x86.tar.gz
     - No binaries
     - `INSTALL` file
 - falco-driver-src-x86.tar.gz
     - `falco` and `/driver` with `Makefile`
     - `INSTALL` file
 - falco-driver-download-x86.tar.gz
     - `falco` and `falco-driver-loader` download only
 - falco-driver-full-x86.tar.gz
     - `falco` and `falco-driver-loader` download else compile


# Images

The following convention MUST be used for all container images.

_If a container image requires `--privileged` the name MUST have the `priviliged-` prefix._

_If a container image is for development purproses it MUST have the `dev-` prefix._ 

_If a container image is used to install something, then exit it MUST have the `-install` suffix.*_

---

 - falcosecurity/falco:TAG
     - Runs `falco` userspace only
 - falcosecurity/privileged-driver-install:TAG
     - Runs `falco-driver-loader` and exit
 - falcosecurity/priviliged-driver-install-falco 
     - first runs `privileged-driver-install` then runs `falco`
 - falcosecurity/priviliged-host-systemd-driver-falco:TAG
     - Detects arch and runs new bash script:
         - Installs Falco with packages (deb, rpm, src)
         - Configures with systemd and Unix Domain Socket [#858](https://github.com/falcosecurity/falco/issues/858)
 - falcosecurity/dev-tester:TAG 
     - Runs the falco test suite
 - falcosecurity/dev-builder:TAG
     -  Contains falco tool chain


# Falco Project Evolution

We will modeling a loosely defined adoption of the Kubernetes and CNCF incubator efforts.

The criteria will remain loose, and tighten as needed at the discretion of the Falco open source community.

### contrib

Sandbox level

This new [contrib](https://github.com/falcosecurity/contrib) repository will be equivalent to the `Falco Sandbox` and serves as a place for the community to `test-drive` ideas/projects/code.

### repository

Incubating level projects such as [falco-exporter](https://github.com/falco-exporter) can be promoted from `contrib` to their own repository. 

This is done as needed, and can best be measured by the need to cut a release and use the github release features. Again, this is at the discretion of the Falco open source community.

### Official support

As the need for a project grows, it can ultimately achieve the highest and most coveted status. Offical support.

These artifacts will be ammended to the ones listed above, and will become a part of the official Falco release process.

# Action

For each item, ask if this already exists. If so we need to rename, and update it to match this new convention.

    
### Action Items

Here are SOME of the items that would need to be done for example:

 - Rename `stable` image to `privileged-driver-install-falco`
 - Rename `bin` package to `falco-driver-full-x86.tar.gz`
 - Rename `slim` image to `falco`
 - Documentation in all packages with `INSTALL` file.
 - Move everything else to contrib
     - Move [/integrations](https://github.com/falcosecurity/falco/tree/master/integrations) to contrib
     - Move [/examples](https://github.com/falcosecurity/falco/tree/master/examples) to contrib
     - Old docker files
     - Old documentation

### Documentation

Update documentation in [falco-website#184](https://github.com/falcosecurity/falco-website/pull/184)

### Adjusting projects

 - Helm chart documentation to be moved to `contrib`
 - YAML manifest documentation to be moved to `contrib`
 - Minkube, Kind, Puppet, Ansible, etc documentation to be moved to `contrib`

#### Note:

This could break the current helm chart, and maybe other dependencies.

We owe existing users of the Falco project some courtesy if we will break their usage of how Falco has traditionally been advertised. 

Some things we owe the community.

 - Announcement on Falco mailing list
 - Issues/Pull Request to Helm chart
     - Note: At the very least open an issue and document how to make the existing helm chart work with the new changes if needed. [Nova Volunteers]
     - We should at least open a PR and update the helm chart with these new expectations if needed. [Nova Volunteers]
     - We should revisit the helm chart OWNERS
 - Twitter
 - Documentation
