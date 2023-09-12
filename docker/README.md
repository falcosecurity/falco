# Falco Dockerfiles

This directory contains various ways to package Falco as a container and related tools.

## Currently Supported Images

| Name | Directory | Description |
|---|---|---|
| [falcosecurity/falco:latest](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco), [falcosecurity/falco:master](https://hub.docker.com/repository/docker/falcosecurity/falco) | docker/falco | Falco (DEB built from git tag or from the master) with all the building toolchain. |
| [falcosecurity/falco-driver-loader:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader), [falcosecurity/falco-driver-loader:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader), [falcosecurity/falco-driver-loader:master](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader) | docker/driver-loader | `falco-driver-loader` as entrypoint with the building toolchain. |
| [falcosecurity/falco-no-driver:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-no-driver), [falcosecurity/falco-no-driver:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco-no-driver),[falcosecurity/falco-no-driver:master](https://hub.docker.com/repository/docker/falcosecurity/falco-no-driver) | docker/no-driver | Falco (TGZ built from git tag or from the master) without the building toolchain. |
| [falcosecurity/falco-driver-loader-legacy:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader-legacy), [falcosecurity/falco-driver-loader-legacy:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco-driver-loader-legacy) | docker/driver-loader-legacy | `falco-driver-loader` as entrypoint with the legacy building toolchain. Recommended for kernels < 4.0 |

## Experimental Images

| Name | Directory | Description |
|---|---|---|
| [falcosecurity/falco-distroless:latest](https://hub.docker.com/repository/docker/falcosecurity/falco-distroless), [falcosecurity/falco-distroless:_tag_](https://hub.docker.com/repository/docker/falcosecurity/falco-distroless),[falcosecurity/falco-distroless:master](https://hub.docker.com/repository/docker/falcosecurity/falco-distroless) | docker/no-driver/Dockerfile.distroless | Falco without the building toolchain built from a distroless base image. This results in a smaller image that has less potentially vulnerable components. |
