# Falco Dockerfiles

This directory contains the various ways to package Falco as a container. 

## Currently Supported Containers

### `falcosecurity/falco` Dockerfiles
 - `./dev`: Builds a container image from the `dev` apt repo.
 - `./stable`: Builds a container image from the `stable` apt repo.
 - `./local`: Builds a container image from a locally provided Falco `dpkg` package.

### Build & Testing Dockerfiles
 - `./builder`: `falcosecurity/falco-builder` - The complete build tool chain for compiling Falco from source. See [the documentation](https://falco.org/docs/source/) for more details on building from source.
 - `./tester`: `falcosecurity/falco-tester` - Container image for running the Falco test suite.

## Alpha Release Containers

These Dockerfiles (and resulting container images) are currently in `alpha`. We'd love for you to test these images and [report any feedback](https://github.com/falcosecurity/falco/issues/new/choose).

### Slim and Minimal Dockerfiles
The goal of these container images is to reduce the size of the underlying Falco container. 
 - `./slim-dev`: Like `./dev` above but removes build tools for older kernels.
 - `./slim-stable`: Like `./stable` above but removes build tools for older kernels.
 - `./minimal`: A minimal container image (~20mb), containing only the files required to run Falco.

