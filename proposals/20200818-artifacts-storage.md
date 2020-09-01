# Falco Artifacts Storage

This document reflects the way we store the Falco artifacts.

## Terms & Definitions

- [Falco artifacts](./20200506-artifacts-scope-part-1.md)
- Bintray: artifacts distribution platform

## Packages

The Falco packages are **automatically** built and sent to [bintray](https://bintray.com/falcosecurity) in the following cases:

- a pull request gets merged into the master branch (**Falco development releases**)
- a new Falco release (git tag) happens on the master branch (**Falco stable releases**)

The only prerequisite is that the specific Falco source code builds successfully and that the tests pass.

As per [Falco Artifacts Scope (#1)](./20200506-artifacts-scope-part-1.md) proposal we provide three kind of Falco packages:

- DEB
- RPM
- Tarball

Thus, we have three repositories for the Falco stable releases:

- https://bintray.com/falcosecurity/deb
- https://bintray.com/falcosecurity/rpm
- https://bintray.com/falcosecurity/bin

And three repositories for the Falco development releases:

- https://bintray.com/falcosecurity/deb-dev
- https://bintray.com/falcosecurity/rpm-dev
- https://bintray.com/falcosecurity/bin-dev

## Drivers

The process of publishing a set of prebuilt Falco drivers is implemented by the **Drivers Build Grid (DBG)** in the [test-infra](https://github.com/falcosecurity/test-infra/tree/master/driverkit) repository (`driverkit` directory).

This process is driven by the configuration files (YAML) present in the `driverkit/config` directory in the [test-infra](https://github.com/falcosecurity/test-infra/tree/master/driverkit) repository.

Each of these files represents a prebuilt driver (eventually two: kernel module and eBPF probe, when possible) that will be published on [bintray](https://bintray.com/falcosecurity) if it builds correctly.

Every time the `driverkit/config` directory on the master branch has some changes from the previous commit the CI system, which you can find defined in the [.circleci/config.yml](https://github.com/falcosecurity/test-infra/blob/master/.circleci/config.yml) file, takes care of building and publishing all the drivers.

The driver versions we ship prebuilt drivers for are:

- the driver version associated with the last stable Falco version ([see here](https://github.com/falcosecurity/falco/blob/c4b7f17271d1a4ca533b2e672ecaaea5289ccdc5/cmake/modules/sysdig.cmake#L29))
- the driver version associated with the current development Falco version - ie., the one on [master](https://github.com/falcosecurity/falco/blob/master/cmake/modules/sysdig.cmake#L30)

The prebuilt drivers get published into [this](https://bintray.com/falcosecurity/driver) generic artifacts repository.

You can also visualize the full list of prebuilt drivers by driver version visiting this [URL](https://dl.bintray.com/falcosecurity/driver).

### Notice

The generation of new prebuilt drivers takes usually place with a frequency of 1-2 weeks.

Thus, it can happen the list of available prebuilt drivers does not yet contain the driver version currently on Falco master.

Nevertheless, this process is an open, auditable, and transparent one.

So, by sending a pull-request towards [test-infra](https://github.com/falcosecurity/test-infra) repository containing the configuration YAML files you can help the Falco community stay on track.

Some pull-requests you can look at to create your own are:

- https://github.com/falcosecurity/test-infra/pull/165
- https://github.com/falcosecurity/test-infra/pull/163
- https://github.com/falcosecurity/test-infra/pull/162

While, the documentation of the YAML configuration files can be found [here](https://github.com/falcosecurity/driverkit/blob/master/README.md).

## Container images

As per Falco packages, also the Falco official container images are **automatically** published to the [dockerhub](https://hub.docker.com/r/falcosecurity/falco).

These images are built and published in two cases:

- a pull request gets merged into the master branch (**Falco development releases**)
- a new Falco release (git tag) happens (**Falco stable releases**)

For a detailed explanation of the container images we build and ship look at the following [documentation](https://github.com/falcosecurity/falco/blob/master/docker/README.md).