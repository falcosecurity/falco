# Falco Artifacts Scope - Part 2

The **Falco Artifact Scope** proposal is divided in two parts:
1. the [Part 1](./20200506-artifacts-scope-part-1.md): to “capture” the state of recent changes
2. the Part 2 - *this document*: the intended state moving forward

## Summary 

See [Part 1](./20200506-artifacts-scope-part-1.md).

## Terms

See [Part 1](./20200506-artifacts-scope-part-1.md).

## Packages

Official packages for x86 64bits only.

The following convention MUST be used for all packages.

_All package names MUST contain a version._

_If a package installs the Falco kernel module it MUST contain `module`._

_If a package installs the Falco BPF probe it MUST contain `bpf`._

_In general, if a package install a Falco driver it MUST contain the driver name._


### .deb

 Falco running in debian like systems that will default to the kernel module.

- falco-*x.y.z*-x86.deb
     - `falco` only (default depends on `falco-module`)
 - falco-*x.y.z*-module-x86.deb
     - `module` only
 - falco-*x.y.z*-bpf-x86.deb
     - `bpf` only
 - falco-*x.y.z*-ptrace-x86.deb
     - `ptrace` only

N.B.:

### .rpm

 Falco running in rpm like systems that will default to the kernel module.

- falco-*x.y.z*-x86.deb
     - `falco` only (default depends on `falco-module`)
- falco-*x.y.z*-module-x86.deb
    - `module` only
- falco-*x.y.z*-bpf-x86.deb
    - `bpf` only
- falco-*x.y.z*-ptrace-x86.deb
    - `ptrace` only


### .tar.gz

- falco-bin-x86.tar.gz
    - `falco` binary, `falco-loader-script`, and related dependecies
    - `INSTALL` file
    - `Makefile` file
- falco-src-x86.tar.gz
    - No binaries
    - `INSTALL` file
- falco-module-src-x86.tar.gz
    - `module` sources with `Makefile`
    - `INSTALL` file
- falco-bpf-src-x86.tar.gz
    - `bpf` sources with `Makefile`
    - `INSTALL` file
- falco-ptrace-src-x86.tar.gz
    - `ptrace` sources with `Makefile`
    - `INSTALL` file

## Images

The following convention MUST be used for all container images.

*TODO* image name conventions

 - falcosecurity/falco:TAG
     - Runs `falco` userspace only
 - falcosecurity/falco-driver-loader:TAG
     - Runs `falco-driver-loader` and exit
 - falcosecurity/*TBD**
     - First runs `falco-driver-loader` then runs `falco`
 - falcosecurity/tester:TAG 
     - Runs the Falco integration test suite
 - falcosecurity/builder:TAG
     - Contains falco tool chain

The image usage MUST be documented in the Dockerfile and in the [website](https://falco.org/docs/).
If an image does not take any action by default, a command usage MUST printed out.

## Official support

These artifacts will be amended to the ones listed above, and will become a part of the official Falco release process.

## Action

For each item, ask if this already exists. If so we need to rename, and update it to match this new convention. If does not exist, add it.

    
### Action Items

Here are SOME of the items that would need to be done for example:

 - Rename package accordingly 
 - Rename docker images accordingly 
 - Documentation in all packages with `INSTALL` file
 - Add `Makefile` where needed
 - Implement missing packages

### Documentation

Update documentation in [falco-website](https://github.com/falcosecurity/falco-website/)

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