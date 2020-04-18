# Falco Dockerfiles

This directory contains the various ways to package Falco as a container. 

## Currently Supported Images

| Name | Directory | Description |
|---|---|---|
| [falcosecurity/falco:latest](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:master](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/stable | Falco (DEB built from git tag or from the master) with all the building toolchain. | 
| [falcosecurity/falco:latest-slim](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:master-slim](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/slim | Falco (DEB build from git tag or from the master) without the building toolchain. | 
| [falcosecurity/falco:latest-minimal](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:master-minimal](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/minimal | Falco (TGZ built from git tag or from the master) without the building toolchain. | 
| [falcosecurity/falco-event-generator:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-event-generator) | docker/event-generator | Event generator tool to simulate events Falco catches. | 
| [falcosecurity/falco-builder:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-builder) | docker/builder | The complete build tool chain for compiling Falco from source. See [the documentation](https://falco.org/docs/source/) for more details on building from source. Used to build Falco (CI). | 
| [falcosecurity/falco-tester:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-tester) | docker/tester | Container image for running the Falco test suite. Used to run Falco integration tests (CI). | 
| _to not be published_ | docker/local | Built on-the-fly and used by falco-tester. |

> Note: `falco-builder`, `falco-tester` (and the `docker/local` image that it's built on the fly) are not integrated into the release process because they are development and CI tools that need to be manually pushed only when updated.

