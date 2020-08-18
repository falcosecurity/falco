# Falco Artifacts Storage

This document reflects the way we store the Falco artifacts.

## Terms & Definitions

- [Falco artifacts](./20200506-artifacts-scope-part-1.md)
- Bintray: artifacts distribution platform

## Packages

The Falco packages are **automatically** sent to [bintray](https://bintray.com/falcosecurity) in the following cases:

- a pull request gets merged into the master branch (**Falco development releases**)
- a new Falco release (git tag) happens (**Falco stable releases**)

The only prerequisite is that the specific Falco source code built successfully and that the tests passed.

As per [Falco artifacts](./20200506-artifacts-scope-part-1.md) document we ship three kind of Falco packages:

- DEB
- RPM
- Tarballs

Thus, we have three repositories for the Falco stable releases:

- https://bintray.com/falcosecurity/deb
- https://bintray.com/falcosecurity/rpm
- https://bintray.com/falcosecurity/bin

And three repositories for the Falco development releases:

- https://bintray.com/falcosecurity/deb-dev
- https://bintray.com/falcosecurity/rpm-dev
- https://bintray.com/falcosecurity/bin-dev

## Drivers

The process of publishing a set of prebuilt Falco drivers is implemented by the **Drivers Build Grid** in the [test-infra](https://github.com/falcosecurity/test-infra/tree/master/driverkit) repository (`driverkit` directory).

It is driven by the configuration files (YAML) present in the `config` directory.
Each of these files represents a prebuilt driver (eventually two: kernel module and eBPF probe) that will be published on [bintray](https://bintray.com/falcosecurity) if it builds correctly.

The driver versions we ship prebuilt drivers for are:

- the current driver version associated with the last stable Falco version ([see here](https://github.com/falcosecurity/falco/blob/c4b7f17271d1a4ca533b2e672ecaaea5289ccdc5/cmake/modules/sysdig.cmake#L29))
- ...

The prebuilt drivers get published into [this](https://bintray.com/falcosecurity/driver) generic artifacts repository.

You can also visualize the full list of prebuilt drivers by driver version visiting this [link](https://dl.bintray.com/falcosecurity/driver).

## Container images

As per Falco packages, also the Falco official container images are **automatically** published to the [dockerhub](https://hub.docker.com/r/falcosecurity/falco).

These images are built and published in two cases:

- a pull request gets merged into the master branch (**Falco development releases**)
- a new Falco release (git tag) happens (**Falco stable releases**)