# Artifacts distribution

This proposal aims to define guidelines for the official distribution of artifacts published by Falcosecurity. 

Therefore, to create a unified management of the distribution of artifacts, this document supersedes (for the parts concerning the distributions of artifacts) proposals [Falco Artifacts Scope - Part 1](https://github.com/falcosecurity/falco/blob/master/proposals/20200506-artifacts-scope-part-1.md), [Falco Artifacts Scope - Part 2](https://github.com/falcosecurity/falco/blob/master/proposals/20200506-artifacts-scope-part-2.md), and [Falco Drivers Storage S3](https://github.com/falcosecurity/falco/blob/master/proposals/20201025-drivers-storage-s3.md) and also extends and generalizes the proposal [Falco Rules and Plugin distribution](https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md) for [falcoctl](https://github.com/falcosecurity/falcoctl).

## Goals

- Allow users to consume artifacts in a consistent way
- Define official artifacts
- Unify distribution mechanism, infrastructure and tooling
- Provide generic guidelines applicable to any artifact to be distributed

## Non-Goals

- Infra/CI implementation details
- Supply chain security topics

## Proposal

With officially supported artifacts, we mean that set of artifacts published 
by Falcosecurity as part of Falco or its ecosystem.

At the time of writing, the Falcosecurity organization distributes several kinds of artifacts in the form of files or container images. They include:
- Installation packages
- Helm charts
- Drivers (eg, kmod, eBPF)
- Rule files
- Plugins
- Other kinds may be added in the future.

Features shipped with **official artifacts are intended for general availability(GA)**, unless otherwise specified (eg. if experimental or non-production ready features are present, they must be indicated in the release notes). 

The same artifacts can be distributed via multiple distribution channels, and each channel can be mirrored. **The [falco.org](https://falco.org/) website must list all official distribution channels and mirrors**. Any distribution channel not listed on our official website must not be considered part of the official distribution. However, maintainers can still use other channels for experimentation or incubating projects eventually.

### Distribution channels

#### HTTP Distribution

Distributing artifacts as plain files via HTTP is mostly intended for **humans, simple and legacy clients** (e.g., a shell script that downloads a file). 

The allowed publishing channels are:
- **[download.falco.org](https://download.falco.org/)** where most of the file artifacts lives
- **endpoints made available by GitHub** for the Falcosecurity organization (e.g., release download URL, GitHub pages, etc.).

Typically, all official artifacts that can be shipped as plain files should be published at [download.falco.org](https://download.falco.org/) and available for download. 

Using the GitHub platform is allowed as an alternative assuming that artifacts are published under the Falcosecurity organization and the GitHub platform usage limitations are being respected (a notable example is publishing a [Helm chart index file using GitHub pages](https://falcosecurity.github.io/charts/)).

It is allowed to publish other non-official artifacts (for example, [development builds](https://download.falco.org/?prefix=packages/bin-dev/)), taking that those are correctly denoted.

Introducing other HTTP channels is discouraged. Providing mirrors is discouraged unless required for technical reasons.

#### OCI Distribution

Some artifacts are in the form of Open Container Initiative (OCI) images and require OCI registries to be distributed. Nevertheless, since the [OCI Distribution Spec](https://specs.opencontainers.org/distribution-spec/?v=v1.0.0) allows any content, even regular files can be stored in OCI registries and distributed likewise. Notably, the [Helm project in early 2022 started storing charts in OCI](https://helm.sh/blog/storing-charts-in-oci/) registries. One our tool [falcoctl did the same](https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md) later.

Distributing artifacts via OCI registries is intended for all compatible consumers (i.e., [falcoctl](https://github.com/falcosecurity/falcoctl)). It is **allowed and encouraged for any artifacts**. All official artifacts should be published so.

The allowed publishing channels are:


| Registry | Name | Account URL |
| -------- | -------- | -------- |
| `docker.io`    | Docker Hub     | https://hub.docker.com/u/falcosecurity |
| `ghcr.io`    | Github Packages Container registry     | https://github.com/orgs/falcosecurity/packages |


Both channels are equivalent and may publish the same artifacts. However, for historical reasons and to avoid confusion, the **`docker.io` registry should only be used for container images** and not for other kinds of artifacts (e.g., plugins, rules, etc.).


Mirrors are allowed and encouraged if they facilitate artifacts consumption by our users. This proposal recommends to enable mirrors on the major public OCI registry, such as [Amazon ECR](https://gallery.ecr.aws/) (which is already implentend in our infra at the time of writing).


Official **channels and mirrors must be listed at [falco.org](https://falco.org/)**. 

It is allowed to publish other non-official artifacts, even using image tags, taking that those are correctly denoted.


#### Other channels

At the time of writing, no other distribution channels are present or needed. However, in case a new kind of artifact will require a particular distribution mechanism (for example, in case an existing package manager system need to consume the artifact using its protocol), the rule of thumb is first to use the available GitHub features for the Falcosecurity organization, if possible. Users will quickly recognize the association between the artifact and the publisher (i.e., falcosecurity), and for that reason is usually preferable.

In all other cases, introducing a new distribution channel must require extensive discussion among maintainers. Nevertheless, **introducing too many distribution channels is discouraged** because it disperses the effort and can mislead users. 


### Publishing

#### Source repository

Artifacts must always be built starting from the originating source code and thru an auditable and reproducible process that runs on our infra. It's recommended that the naming and versioning of the published artifact consistently match the originating repository's naming and versioning. For example, the package `falco-0.33.0-x86_64.tar.gz` must match the source code of the git tag [0.33.0](https://github.com/falcosecurity/falco/tree/0.33.0) of the [falco](https://github.com/falcosecurity/falco) repository.

It's recommended that **each repository publish only one kind of artifact** associated with it. 

Exceptions are allowed for:
 - mono repos (notably [charts](https://github.com/falcosecurity/charts) and [plugins](https://github.com/falcosecurity/plugins)), 
 - or whenever technical constraints impose a different approach (notably, our Driver Build Grid lives on [test-infra](https://github.com/falcosecurity/test-infra), but the source code is in [libs](https://github.com/falcosecurity/libs)).

Exceptions should be documented to avoid the users and contributors might be confused.

#### Namespacing

As a general rule, to avoid name clashing among different projects under the Falcosecurity organization, all **published artifacts should reflect the originating repository name** in their publishing URL. For example, all artifacts generated by the [falcosecurity/plugins](https://github.com/falcosecurity/plugins) repository should have `falcosecurity/plugins` as the URL's base path.

Exceptions are allowed for:
- legacy and already published artifacts (to avoid disruption);
- justified technical reasons.

#### Versioning

All published artifacts must be labeled with version numbers following the **[Semantic Versioning 2 specification](https://semver.org/)**.

For the [HTTP Distribution](#http-distribution), the version number must be reflected in the file name (including build metadata like the targeted arch and platform).

For the [OCI Distribution](#oci-distribution), the version number must be reflected in the image tag (build metadata may be avoided if included in the manifest).

### Tooling

Tooling is essential to deliver a consistent and straightforward UX to our users since the limited set of distribution channels is acceptable to provide just one (or a limited set of) tool(s) capable of working with various artifacts published by the Falcosecurity organization.

In this regard, this proposal follows up the [Falco Rules and Plugin distribution](https://github.com/falcosecurity/falcoctl/blob/main/proposals/20220916-rules-and-plugin-distribution.md) proposal and recommends to use of **[falcoctl](https://github.com/falcosecurity/falcoctl) as the tool to managing artifacts specifically intended for Falco**. The tool's design should consider that other kinds of artifacts may be added in the future.

Likewise, relying on existing **third-party tools for generic or well-known kinds of artifacts** (for example, Helm charts) is recommended.

### Ecosystem

Compatibility with other tools on the broader cloud native ecosystem should be considered when dealing with artifacts and their distribution.

It is also recommended to use third-party solutions and projects that facilitate our users' discovery of published artifacts (for example, https://artifacthub.io/).


## Action items

The following subsections indicate major action items to be executed in order to transition from the current to the desiderate state of the art, as noted in this proposal.

### Move [Falco rules](https://github.com/falcosecurity/falco/tree/master/rules) to their own repo

Falco rules files (i.e., the ruleset for the data source syscall) are currently only distributed in bundles with Falco. However, now falcoctl can manage rules artifacts so that we can ship them separately.

The benefits of having rules living in their repository are:
  - dedicated versioning
  - rules release will not be tied anymore to a Falco release (e.g., no need to wait for the scheduled Falco release to publish a new rule aiming to detect the latest published CVE)
  - consistent installation/update mechanism with other rulesets (plugins rules are already published in their repository and can be consumed by falcoctl)

Note that this change will not introduce a breaking change: Falco will continue shipping the default ruleset by including the published ruleset package.

### Make `falcoctl` official

Considering the centrality of falcoctl for managing official artifacts for Falco, the falcoctl project must be promoted to "Official" status, and its repository assumed to be [core](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md#core-repositories).

### Deprecate `falco-driver-loader`

At the time of writing, `falco-driver-loader` is a shell script shipped in a bundle with Falco that has the responsibility of installing a driver by either downloading it from our distribution channels or trying to build it on-the-fly.

Our experience showed all the limitations of this approach, and it's now clear that such as script is hard to maintain. Furthermore, its responsibility overlaps with our aim to use `falcoctl` as the tool for managing artifacts.

Thus, this proposal mandates to deprecate of `falco-driver-loader` in favor of `falcoctl.`

However, to avoid user disruption and breaking legacy use case, it's recommended to provide still a faced script that exposes the same command line usage of `falco-driver-loader` but forward its execution to the new tool `falcoctl`.

This implicitly requires that `falcoctl` be shipped in a bundle with Falco.

### Update the documentation

This proposal mandates making use of official documentation (i.e., falco.org) to state official items, such as artifacts, distribution channels, and mirrors.

For that reason, it becomes imperative to update the documentation periodically concerning the list of officially supported distribution channels and mirrors.

### Usage of GitHub Packages

Since GitHub is the primary platform where the Falcosecurity organization hosts its code and infrastructure, its provided features should be preferred whenever possible.

This proposal recommends using the GitHub Packages feature when the need to distribute a new kind of artifact arises. Such as convention should be adopted among all repositories of the organization.
