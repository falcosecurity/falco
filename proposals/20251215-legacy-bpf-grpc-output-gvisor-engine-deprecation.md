# Legacy eBPF probe, gVisor libscap engine and gRPC output deprecations

## Summary

This proposal aims to formalize motivations and procedures for deprecating the legacy eBPF probe, the gRPC output and
the gVisor libscap engine.

One of the key objectives of Falco is to maintain a seamless user experience, regardless of the system call event source
actually used. This objective imposes strong requirements among all drivers and engines acting as system call source
(i.e.: gVisor libscap engine), feature parity, among each other, above all. Feature parity raises challenges from both
technical and maintainability perspectives, and these challenges are not justified if the driver/engine is no/little
used. For these reasons, this document aims for raising consensus regarding the legacy eBPF probe and gRPC output
deprecation.

Similar arguments could be raised in favor of the gRPC output deprecation: this output requires dependency on the
gRPC framework, that introduces a non-negligible build time overhead and maintainability burden (especially in a C++
codebase), not justified by the little usage of the output.

Upcoming evidences of non-negligible use of the gVisor engine and the gRPC output could be addressed by providing a
separate source plugin in case of gVisor, and a Falco Sidekick output as a replacement of the gRPC output.

## Motivation

### Legacy eBPF probe deprecation

The following matrix details the current minimum kernel version officially supported by each driver, for each
architecture:

|             | Kernel module                                                                                | legacy eBPF probe                                                                           | Modern eBPF probe | Status |
| ----------- |----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------| ----------------- | ------ |
| **x86_64**  | >= 3.10                                                                                        | >= 4.14                                                                                     | >= 5.8            | _STABLE_ |
| **aarch64** | >= [3.16](https://github.com/torvalds/linux/commit/055b1212d141f1f398fca548f8147787c0b6253f) | >= 4.17                                                                                     | >= 5.8            | _STABLE_ |
| **s390x**   | >= 3.10                                                                                        | >= [5.5](https://github.com/torvalds/linux/commit/6ae08ae3dea)                              | >= 5.8            | _EXPERIMENTAL_ |
| **riscv64** | >= [5.0](https://github.com/torvalds/linux/commit/5aeb1b36cedd3a1dfdbfe368629fed52dee34103)  | N/A                                                                                         | N/A               | _EXPERIMENTAL_ |
| **ppc64le** | >= 3.10                                                                                        | >= [5.1](https://github.com/torvalds/linux/commit/ed1cd6deb013a11959d17a94e35ce159197632da) | >= 5.8               | _STABLE_ |

The legacy eBPF probe strives to provide a little more coverage than the modern eBPF one. This increased coverage comes
at cost of flexibility and maintainability. Indeed:
1. it cannot leverage CORE eBPF features - as a result, falcosecurity must maintain a great number of officially
supported eBPF objects, each one built for a specific officially-supported kernel flavor; this increases the
maintainability burden and makes the system less flexible to kernel configurations/structures changes
2. old kernel versions support is difficult to retain - the verifier imposes huge limitations on old kernel versions,
and any tiny change easily result in the verifier rejecting the code
3. it is difficult to keep it up to date with other drivers - some desired features cannot be implemented in any way
using eBPF on old kernel flavors, due to lack of eBPF helpers/program types or verifier limitations (e.g.: there is no
way of implementing a synchronous data harvesting mechanism like the one provided by BPF iterators). As falcosecurity
strives for feature parity among drivers, this imposes a big limitation on the other drivers. Please notice that:
   1. the kernel module is unconstrained on the nature of feature it can support
   2. the modern eBPF probe can easily rely on CORE features to probe for kernel features and use them if available

Besides the above, the legacy eBPF probe provides support for a range of versions that is entirely contained by the
kernel module supported range. Additionally, different distro kernel flavors already back-port features required by the
modern eBPF, enabling its usage on kernel older than `5.8`.

The above considerations, together with the evidence of its little usage, make the legacy eBPF probe a good candidate
for deprecation.

### gVisor libscap engine deprecation

gVisor libscap engine implements a system call event source by leveraging events coming from gVisor itself through gRPC.

There is evidence that this engine is little used. Moreover, gVisor doesn't provide all information required to build
all supported event types, indeed resulting in a system call source not completely equivalent to the ones provided by
drivers. Finally, it requires `falcosecurity/libs` being dependent on protobuf, this latter introducing a non-negligible
build time overhead and maintainability burden.

Deprecating it would allow to streamline system call event sources alignment, maintainability, and reduce build time for
both `falcosecurity/falco` and `falcosecurity/libs`.

### gRPC output deprecation

The gRPC output provides a mechanism through which a gRPC client can subscribe to the Falco alerts stream. This output
leverages a gRPC server embedded into Falco.

As for the legacy eBPF probe and the gVisor libscap engine, there is evidence that this output is little used. Also,
similarly to the gVisor libscap engine, this requires Falco being dependent on the protobuf, and additionally, on the
entire C++ gRPC framework. Finally, the little amount of data that is sent through the gRPC stream, and the
communication model (only involving a one-way communication from the server to the client) doesn't justify the need of
using gRPC.

Deprecating it would allow to reduce the build system, streamline maintainability, and reduce build time for
`falcosecurity/falco`.

## Goals

* Deprecate the legacy eBPF probe, the gVisor libscap engine, and the gRPC output
* Detail a plan to follow during the deprecation period, before completely remove any of the aforementioned components

## Non-goals

* Implement a gVisor source plugin as gVisor libscap engine alternative
* Implement the gRPC output as Falco Sidekick output
* Detail a plan to follow after taking the decision to completely remove any of the aforementioned components

## The plan

This section aims to detail the plan to follow contextually and after the deprecation mark, but before taking any
definitive removal decision about the legacy eBPF probe, the gVisor libscap engine, and the gRPC output (collectively
referred to hereinafter as "the components" or simply "components").

The deprecation of these components introduces user-facing changes that must be addressed as prescribed by the current
deprecation policy for "non-backward compatible user-facing changes" (see
[20231220-features-adoption-and-deprecation.md#deprecation-policy](./20231220-features-adoption-and-deprecation.md#deprecation-policy)).

All components are stable, and considering that deprecations will first be enforced in the stable Falco version `0.43.0`
(ante `1.0.0`), the minimum deprecation period length is 1 release: this means that components cannot be removed before
Falco `0.44.0`.

At high level, the action plan is to inform users, during the deprecation period, about the deprecation: this is
achieved by emitting a deprecation notice if the user try to leverage any of the feature exposed by any component, and
by updating the website in any of the relevant areas.

During the deprecation period, but before taking decision to remove the components, projects belonging to the
`falcosecurity` organization will be updated to not use/rely on any of these. Specifically:
- on `falcosecurity/libs`, any CI job building and testing the legacy eBPF probe will be removed
- on `falcosecurity/kernel-testing`, playbooks will not build and test the legacy eBPF probe anymore
- on `falcosecurity/event-generator`, the internal gRPC alert retriever will be replaced with an HTTP alert retriever,
leveraging the existing HTTP output.

## The non-plan

This proposal does not address any design or implementation aspect of the gVisor engine and gRPC output replacement, nor
formalizes in any way the conditions under which a replacement should be delivered. Upcoming evidences of non-negligible
use of the gVisor engine and the gRPC output may be addressed by providing a separate source plugin in case of gVisor,
and a Falco Sidekick output as a replacement of the gRPC output, but these latter possibilities should be intended as
suggestions, and will not constraint in any way any related future choice.

Finally, this proposal doesn't detail any aspect of the eventual removal.
