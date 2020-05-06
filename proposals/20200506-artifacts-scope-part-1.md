# Falco Artifacts Scope - Part 1

The **Falco Artifact Scope** proposal is divided in two parts:
1. the Part 1 - *this document*: the State of Art of Falco artifacts
2. the [Part 2](./20200506-artifacts-scope-part-2.md): the intended state moving forward

## Summary 

As a project we would like to support the following artifacts.

Everything else will be moved to [contrib](https://github.com/falcosecurity/contrib).

As a project we will build, change, rename, and move files, documents, scripts, configurations according to the new state of the art described into [Part 2](./20200506-artifacts-scope-part-2.md).

Inspired by many previous issues and many of the weekly community calls.

## Terms

**falco** 

*The Falco binary*

**driver**

*System call provider from the Linux kernel. Either (`bpf`, `module`, or `ptrace`)*

**falco-driver-loader**

*The bash script found [here](https://github.com/falcosecurity/falco/blob/master/scripts/falco-driver-loader) that tries to compile else download the driver (kernel module or eBPF probe).*

**package**

*An installable artifact that is operating system specific. All packages MUST be hosted on bintray.*

**image**

*OCI compliant container image hosted on dockerhub with tags for every release and the current master branch.*
 

# Packages

List of currently official packages (for x86 64bits only):

- `falco-x.y.z-x86_64.deb` for debian like systems, it installs the kernel module by default
- `falco-x.y.z-x86_64.rpm` for rpm like systems, it installs the kernel module by default
- `falco-x.y.z-x86_64.tar.gz` for binary installation, it contains `falco` binary, `falco-driver-loader` script, drivers source, and related dependencies


# Images

List of currently official container images (for X86 64bits only):

| Name | Directory | Description |
|---|---|---|
| [falcosecurity/falco:latest](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:master](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/stable | Falco (DEB built from git tag or from the master) with all the building toolchain. | 
| [falcosecurity/falco:latest-slim](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:_tag_-slim](https://hub.docker.com/repository/docker/falcosecurity/falco),[falcosecurity/falco:master-slim](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/slim | Falco (DEB build from git tag or from the master) without the building toolchain. | 
| [falcosecurity/falco-driver-loader:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader), [falcosecurity/falco-driver-loader:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader), [falcosecurity/falco-driver-loader:master](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader) | docker/falco-driver-loader | `falco-driver-loader` as entrypoint with the building toolchain. | 
| [falcosecurity/falco-builder:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-builder) | docker/builder | The complete build tool chain for compiling Falco from source. See [the documentation](https://falco.org/docs/source/) for more details on building from source. Used to build Falco (CI). | 
| [falcosecurity/falco-tester:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-tester) | docker/tester | Container image for running the Falco test suite. Used to run Falco integration tests (CI). | 
| _to not be published_ | docker/local | Built on-the-fly and used by falco-tester. |

**Note**: `falco-builder`, `falco-tester` (and the `docker/local` image which it's built on the fly by the `falco-tester` one) are not integrated into the release process because they are development and CI tools that need to be manually pushed only when updated.


# Falco Project Evolution

We will modeling a loosely defined adoption of the Kubernetes and CNCF incubator efforts.

The criteria will remain loose, and tighten as needed at the discretion of the Falco open source community.

### contrib

"_Sandbox level_"

This new [contrib](https://github.com/falcosecurity/contrib) repository will be equivalent to the `Falco Sandbox` and serves as a place for the community to `test-drive` ideas/projects/code.

### repository

"_Incubating level_" projects such as [falco-exporter](https://github.com/falco-exporter) can be promoted from `contrib` to their own repository. 

This is done as needed, and can best be measured by the need to cut a release and use the GitHub release features. Again, this is at the discretion of the Falco open source community.

### official support

As the need for a project grows, it can ultimately achieve the highest and most coveted status within The Falco Project. "_Offical support_."

The artifacts listed above are part of the official Falco release process. These artifact will be refined and amended by the [Part 2](./20200506-artifacts-scope-part-2.md).

# Action

The *Part 1* is mainly intended as a cleanup process.
For each item not listed above, ask if it needs to be moved or deleted.
After the cleanup process, all items will match the *Part 1* of this proposal.

    
### Action Items

Here are SOME of the items that would need to be done, for example:

 - Remove `minimal` from `falco` repository (it's almost similar to `slim`, we don't need two images for the same purpose)
 - Rename `driverloader` image to `falco-driver-loader` (since it has not been release yet, we can rename it without breaking things)
 - Move everything else to contrib
     - Move [/integrations](https://github.com/falcosecurity/falco/tree/master/integrations) to contrib
     - Move [/examples](https://github.com/falcosecurity/falco/tree/master/examples) to contrib
     - Old documentation

### Documentation

Update documentation in [falco-website#184](https://github.com/falcosecurity/falco-website/pull/184).

### Adjusting projects

 - YAML manifest documentation to be moved to `contrib`
 - Minkube, Kind, Puppet, Ansible, etc documentation to be moved to `contrib`
