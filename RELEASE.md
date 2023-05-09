# Falco Release Process


## Overview

This document provides the process to create a new Falco release. In addition, it provides information about the versioning of the Falco components. At a high level each Falco release consists of the following main components:

- Falco binary (userspace)
- Falco kernel driver object files (kernel space)
    - Option 1: Kernel module (`.ko` files)
    - Option 2: eBPF (`.o` files)
- Falco config and primary rules `.yaml` files (userspace)
- Falco plugins (userspace - optional)

One nice trait about releasing separate artifacts for userspace and kernel space is that Falco is amenable to supporting a large array of environments, that is, multiple kernel versions, distros and architectures (see `libs` [driver - kernel version support matrix](https://github.com/falcosecurity/libs#drivers-officially-supported-architectures)). The Falco project manages the release of both the Falco userspace binary and pre-compiled Falco kernel drivers for the most popular kernel versions and distros. The build and publish process is managed by the [test-infra](https://github.com/falcosecurity/test-infra) repo. The Falco userspace executable includes bundled dependencies, so that it can be run from anywhere.

The Falco project also publishes all sources for each component. In fact, sources are included in the Falco release in the same way as some plugins (k8saudit and cloudtrail) as well as the rules that are shipped together with Falco. This empowers the end user to audit the integrity of the project as well as build kernel drivers for custom kernels or not officially supported kernels / distros (see [driverkit](https://github.com/falcosecurity/driverkit) for more information). While the Falco project is deeply embedded into an ecosystem of supporting [Falco sub-projects](https://github.com/falcosecurity/evolution) that aim to make the deployment of Falco easy, user-friendly, extendible and cloud-native, core Falco is split across two repos, [falco](https://github.com/falcosecurity/falco) (this repo) and [libs](https://github.com/falcosecurity/libs). The `libs` repo contains >90% of Falco's core features and is the home of each of the kernel drivers and engines. More details are provided in the [Falco Components Versioning](#falco-components-versioning) section.

Finally, the release process follows a transparent process described in more detail in the following sections and the official [Falco docs](https://falco.org/) contain rich information around building, installing and using Falco.


### Falco Binaries, Rules and Sources Artifacts - Quick Links

The Falco project publishes all sources and the Falco userspace binaries as GitHub releases.

- [Falco Releases](https://github.com/falcosecurity/falco/releases)
    - `tgz`, `rpm` and `deb` Falco binary packages (contains sources, including driver sources, Falco rules as well as k8saudit and cloudtrail plugins)
    - `tgz`, `zip` source code
- [Libs Releases](https://github.com/falcosecurity/libs/releases)
    - `tgz`, `zip` source code
- [Driver Releases](https://github.com/falcosecurity/libs/releases), marked with `+driver` [build metadata](https://semver.org/). 
    - `tgz`, `zip` source code
- [Falco Rules Releases](https://github.com/falcosecurity/rules/releases)
    - `tgz`, `zip` source code, each ruleset is tagged separately in a mono-repo fashion, see the [rules release guidelines](https://github.com/falcosecurity/rules/blob/main/RELEASE.md)


Alternatively Falco binaries or plugins can be downloaded from the Falco Artifacts repo.

- [Falco Artifacts Repo Packages Root](https://download.falco.org/?prefix=packages/)
- [Falco Artifacts Repo Plugins Root](https://download.falco.org/?prefix=plugins/)


### Falco Drivers Artifacts Repo - Quick Links


The Falco project publishes all drivers for each release for all popular kernel versions / distros and `x86_64` and `aarch64` architectures to the Falco project managed Artifacts repo. The Artifacts repo follows standard directory level conventions. The respective driver object file is prefixed by distro and named / versioned by kernel release - `$(uname -r)`. Pre-compiled drivers are released with a [best effort](https://github.com/falcosecurity/falco/blob/master/proposals/20200818-artifacts-storage.md#notice) notice. This is because gcc (`kmod`) and clang (`bpf`) compilers or for example the eBPF verifier are not perfect. More details around driver versioning and driver compatibility are provided in the [Falco Components Versioning](#falco-components-versioning) section. Short preview: If you use the standard Falco setup leveraging driver-loader, [driver-loader script](https://github.com/falcosecurity/falco/blob/master/scripts/falco-driver-loader) will fetch the kernel space artifact (object file) corresponding to the default `DRIVER_VERSION` Falco was shipped with.

- [Falco Artifacts Repo Drivers Root](https://download.falco.org/?prefix=driver/)
    - Option 1: Kernel module (`.ko` files) - all under same driver version directory
    - Option 2: eBPF (`.o` files) - all under same driver version directory


### Timeline

Falco releases are due to happen 3 times per year. Our current schedule sees a new release by the end of January, May, and September each year. Hotfix releases can happen whenever it's needed.

Changes and new features are grouped in [milestones](https://github.com/falcosecurity/falco/milestones), the milestone with the next version represents what is going to be released.


### Procedures

The release process is mostly automated requiring only a few manual steps to initiate and complete it.

Moreover, we need to assign owners for each release (usually we pair a new person with an experienced one). Assignees and the due date are proposed during the [weekly community call](https://github.com/falcosecurity/community).

At a high level each Falco release needs to follow a pre-determined sequencing of releases and build order:

- [1 - 3] `libs` (+ `driver`) and `plugins` components releases
- [4] Falco driver pre-compiled object files push to Falco's Artifacts repo
- [5] Falco userspace binary release

Finally, on the proposed due date the assignees for the upcoming release proceed with the processes described below.  

## Pre-Release Checklist

Prior to cutting a release the following preparatory steps should take 5 minutes using the GitHub UI.

### 1. Release notes
- Find the previous release date (`YYYY-MM-DD`) by looking at the [Falco releases](https://github.com/falcosecurity/falco/releases)
- Check the release note block of every PR matching the `is:pr is:merged closed:>YYYY-MM-DD` [filter](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+closed%3A%3EYYYY-MM-DD)
    - Ensure the release note block follows the [commit convention](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md#commit-convention), otherwise fix its content
    - If the PR has no milestone, assign it to the milestone currently undergoing release
- Check issues without a milestone (using `is:pr is:merged no:milestone closed:>YYYY-MM-DD` [filter](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+no%3Amilestone+closed%3A%3EYYYY-MM-DD) ) and add them to the milestone currently undergoing release
- Double-check that there are no more merged PRs without the target milestone assigned with the `is:pr is:merged no:milestone closed:>YYYY-MM-DD` [filter](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Amerged+no%3Amilestone+closed%3A%3EYYYY-MM-DD), if any, update those missing

### 2. Milestones

- Move the [tasks not completed](https://github.com/falcosecurity/falco/pulls?q=is%3Apr+is%3Aopen) to a new minor milestone


### 3. Release branch

Assuming we are releasing a non-patch version (like: Falco 0.34.0), a new release branch needs to be created.  
Its naming will be `release/M.m.x`; for example: `release/0.34.x`.  
The same branch will then be used for any eventual cherry pick for patch releases.  

For patch releases, instead, the `release/M.m.x` branch should already be in place; no more steps are needed.  
Double check that any PR that should be part of the tag has been cherry-picked from master!

### 4. Release PR

The release PR is meant to be made against the respective `release/M.m.x` branch, **then cherry-picked on master**.  

- Double-check if any hard-coded version number is present in the code, it should be not present anywhere:
    - If any, manually correct it then open an issue to automate version number bumping later
    - Versions table in the `README.md` updates itself automatically
- Generate the change log using [rn2md](https://github.com/leodido/rn2md):
    - Execute `rn2md -o falcosecurity -m <version> -r falco`
    - In case `rn2md` emits error try to generate an GitHub OAuth access token and provide it with the `-t` flag
- Add the latest changes on top the previous `CHANGELOG.md`
- Submit a PR with the above modifications
- Await PR approval
- Close the completed milestone as soon as the PR is merged into the release branch
- Cherry pick the PR on master too

## Publishing Pre-Releases (RCs and tagged development versions)

Core maintainers and/or the release manager can decide to publish pre-releases at any time before the final release
is live for development and testing purposes.

The prerelease tag must be formatted as `M.m.p-r`where `r` is the prerelease version information (e.g. `0.35.0-rc1`.)

To do so:

- [Draft a new release](https://github.com/falcosecurity/falco/releases/new)
- Use `M.m.p-r` both as tag version and release title.
- Check the "Set as a pre-release" checkbox and make sure "Set as the latest release" is unchecked
- It is recommended to add a brief description so that other contributors will understand the reason why the prerelease is published
- Publish the prerelease!
- The release pipeline will start automatically. Packages will be uploaded to the `-dev` bucket and container images will be tagged with the specified tag.

In order to check the status of the release pipeline click on the [GitHub Actions tab](https://github.com/falcosecurity/falco/actions?query=event%3Arelease) in the Falco repository and filter by release.

## Release

Assume `M.m.p` is the new version.

### 1. Create the release with GitHub

- [Draft a new release](https://github.com/falcosecurity/falco/releases/new)
- Use `M.m.p` both as tag version and release title
- Use the following template to fill the release description:
    ```
    <!-- Substitute M.m.p with the current release version -->

    | Packages | Download                                                                                                                                               |
    | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
    | rpm-x86_64      | [![rpm](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/rpm/falco-M.m.p-x86_64.rpm)        |
    | deb-x86_64      | [![deb](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/deb/stable/falco-M.m.p-x86_64.deb) |
    | tgz-x86_64      | [![tgz](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/bin/x86_64/falco-M.m.p-x86_64.tar.gz) |
    | rpm-aarch64      | [![rpm](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/rpm/falco-M.m.p-aarch64.rpm)        |
    | deb-aarch64      | [![deb](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/deb/stable/falco-M.m.p-aarch64.deb) |
    | tgz-aarch64      | [![tgz](https://img.shields.io/badge/Falco-M.m.p-%2300aec7?style=flat-square)](https://download.falco.org/packages/bin/aarch64/falco-M.m.p-aarch64.tar.gz) |

    | Images                                                                      |
    | --------------------------------------------------------------------------- |
    | `docker pull docker.io/falcosecurity/falco:M.m.p`                           |
    | `docker pull public.ecr.aws/falcosecurity/falco:M.m.p`                      |
    | `docker pull docker.io/falcosecurity/falco-driver-loader:M.m.p`             |
    | `docker pull docker.io/falcosecurity/falco-no-driver:M.m.p`                 |

    <changelog>

    <!-- Substitute <changelog> with the one generated by [rn2md](https://github.com/leodido/rn2md) -->

    ### Statistics

    | Merged PRs      | Number |
    | --------------- | ------ |
    | Not user-facing | x      |
    | Release note    | x      |
    | Total           | x      |

    <!-- Calculate stats and fill the above table -->

    #### Release Manager <github handle>

    <!-- Substitute GitHub handle with the release manager's one -->
    ```

- Finally, publish the release!
- The release pipeline will start automatically upon publication and all packages and container images will be uploaded to the stable repositories.

In order to check the status of the release pipeline click on the [GitHub Actions tab](https://github.com/falcosecurity/falco/actions?query=event%3Arelease) in the Falco repository and filter by release.

### 2. Update the meeting notes

For each release we archive the meeting notes in git for historical purposes.

 - The notes from the Falco meetings can be [found here](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg).
    - Note: There may be other notes from working groups that can optionally be added as well as needed.
 - Add the entire content of the document to a new file in [github.com/falcosecurity/community/tree/master/meeting-notes](https://github.com/falcosecurity/community/tree/master/meeting-notes) as a new file labeled `release-M.m.p.md`
 - Open up a pull request with the new change.


## Post-Release tasks

Announce the new release to the world!

- Publish a blog on [Falco website](https://github.com/falcosecurity/falco-website) ([example](https://github.com/falcosecurity/falco-website/blob/master/content/en/blog/falco-0-28-1.md))
- Send an announcement to cncf-falco-dev@lists.cncf.io (plain text, please)
- Let folks in the slack #falco channel know about a new release came out
- IFF the on going release introduces a **new minor version**, [archive a snapshot of the Falco website](https://github.com/falcosecurity/falco-website/blob/master/release.md#documentation-versioning)


## Falco Components Versioning

This section provides more details around the versioning of all components that make up core Falco. It can also be a useful guide for the uninitiated to be more informed about Falco's source. Because the `libs` repo contains >90% of Falco's core features and is the home of each of the kernel drivers and engines, the [libs release doc](https://github.com/falcosecurity/libs/blob/master/release.md) is an excellent additional resource. In addition, the [plugins release doc](https://github.com/falcosecurity/plugins/blob/master/release.md) provides similar details around Falco's plugins. `SHA256` checksums are provided throughout Falco's source code to empower the end user to perform integrity checks. All Falco releases also contain the sources as part of the packages.


### Falco repo (this repo)
- Falco version is a git tag (`x.y.z`), see [Procedures](#procedures) section. Note that the Falco version is a sem-ver-like schema, but not fully compatible with sem-ver.
- [FALCO_ENGINE_VERSION](https://github.com/falcosecurity/falco/blob/master/userspace/engine/falco_engine_version.h) is not sem-ver and must be bumped either when a backward incompatible change has been introduced to the rules files syntax or `falco --list -N | sha256sum` has changed. Breaking changes introduced in the Falco engine are not necessarily tied to the drivers or libs versions. The primary idea behind the hash is that when new filter / display fields (see currently supported [Falco fields](https://falco.org/docs/rules/supported-fields/)) are introduced a version bump indicates that this field was not available in previous engine versions. See the [rules release guidelines](https://github.com/falcosecurity/rules/blob/main/RELEASE.md#versioning-a-ruleset) to understand how this affects the versioning of Falco rules.
- During development and release preparation, libs and driver reference commits are often bumped in Falco's cmake setup ([falcosecurity-libs cmake](https://github.com/falcosecurity/falco/blob/master/cmake/modules/falcosecurity-libs.cmake#L30) and [driver cmake](https://github.com/falcosecurity/falco/blob/master/cmake/modules/driver.cmake#L29)) in order to merge new Falco features. In practice they are mostly bumped at the same time referencing the same `libs` commit. However, for the official Falco build `FALCOSECURITY_LIBS_VERSION` flag that references the stable Libs version is used (read below).
- Similarly, Falco plugins versions are bumped in Falco's cmake setup ([plugins cmake](https://github.com/falcosecurity/falco/blob/master/cmake/modules/plugins.cmake)) and those versions are the ones used for the Falco release.
- At release time Plugin, Libs and Driver versions are compatible with Falco.
- If you use the standard Falco setup leveraging driver-loader, [driver-loader script](https://github.com/falcosecurity/falco/blob/master/scripts/falco-driver-loader) will fetch the kernel space artifact (object file) corresponding to the default `DRIVER_VERSION` Falco was shipped with (read more below under Libs).


```
Falco version: x.y.z (sem-ver like)
Libs version:  x.y.z (sem-ver like)
Plugin API:    x.y.z (sem-ver like)
Engine:        x
Driver:
  API version:    x.y.z (sem-ver)
  Schema version: x.y.z (sem-ver)
  Default driver: x.y.z+driver (sem-ver like, indirectly encodes compatibility range in addition to default version Falco is shipped with)
```


### Libs repo
- Libs version is a git tag (`x.y.z`) and when building Falco the libs version is set via the `FALCOSECURITY_LIBS_VERSION` flag (see above).
- Driver version itself is not directly tied to the Falco binary as opposed to the libs version being part of the source code used to compile Falco's userspace binary. This is because of the strict separation between userspace and kernel space artifacts, so things become a bit more interesting here. This is why the concept of a `Default driver` has been introduced to still implicitly declare the compatible driver versions. For example, if the default driver version is `2.0.0+driver`, Falco works with all driver versions >= 2.0.0 and < 3.0.0. This is a consequence of how the driver version is constructed starting from the `Driver API version` and `Driver Schema version`. Driver API and Schema versions are explained in the respective [libs driver doc](https://github.com/falcosecurity/libs/blob/master/driver/README.VERSION.md) -> Falco's `driver-loader` will always fetch the default driver, therefore a Falco release is always "shipped" with the driver version corresponding to the default driver.
- See [libs release doc](https://github.com/falcosecurity/libs/blob/master/release.md) for more information.

### Plugins repo

- Plugins version is a git tag (`x.y.z`)
- See [plugins release doc](https://github.com/falcosecurity/plugins/blob/master/release.md) for more information.

### Rules repo
- Rulesets are versioned individually through git tags
- See [rules release doc](https://github.com/falcosecurity/rules/blob/main/RELEASE.md) for more information.
- See [plugins release doc](https://github.com/falcosecurity/plugins/blob/master/release.md) for more information about plugins rulesets.
