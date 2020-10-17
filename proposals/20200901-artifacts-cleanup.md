# Falco Artifacts Cleanup

This document reflects when and how we clean up the Falco artifacts from their storage location.

## Motivation

The [bintray](https://bintray.com/falcosecurity) open-source plan offers 10GB free space for storing artifacts.

They also kindly granted us an additional 5GB of free space.

## Goal

Keep the storage space usage under 15GB by cleaning up the [Falco artifacts](./20200506-artifacts-scope-part-1.md) from the [storage](./20200818-artifacts-storage).

## Status

To be implemented.

## Packages

### Tarballs from Falco master

At the moment of writing this document, this kind of Falco package requires approx. 50MB (maximum detected size) of storage space.

Since, historically, the [bin-dev](https://bintray.com/falcosecurity/bin-dev) repository is the less used one, this document proposes to keep only the last 10 **Falco development releases** it contains.

This means that the [bin-dev](https://bintray.com/falcosecurity/bin-dev) repository will take at maximum 500MB of storage space.

### DEB from Falco master

At the moment of writing this document, this kind of Falco package requires approx. 5.1MB (maximum detected size) of storage space.

Historically, every Falco release is composed by less than 50 merges (upper limit).

So, to theoretically retain all the **Falco development releases** that led to a Falco stable release, this document proposes to keep the last 50 Falco DEB packages.

This means that the [deb-dev](https://bintray.com/falcosecurity/deb-dev) repository will take at maximum 255MB of storage space.

### RPM from Falco master

At the moment of writing this document, this kind of Falco package requires approx. 4.3MB (maximum detected size) of storage space.

For the same exact reasons explained above this document proposes to keep the last 50 Falco RPM packages.

This means that the [rpm-dev](https://bintray.com/falcosecurity/rpm-dev) repository will take at maximum 215MB of storage space.

### Stable releases

This document proposes to retain all the stable releases.

This means that all the Falco packages present in the Falco stable release repositories will be kept.

The [bin](https://bintray.com/falcosecurity/bin) repository contains a Falco tarball package for every release.
This means it grows in space of ~50MB each month.

The [deb](https://bintray.com/falcosecurity/deb) repository contains a Falco DEB package for every release.
This means it grows in space of ~5MB each month.

The [rpm](https://bintray.com/falcosecurity/rpm) repository contains a Falco RPM package for every release.
This means it grows in space of ~4.3MB each month.

### Considerations

Assuming the size of the packages does not surpass the numbers listed in the above sections, the **Falco development releases** will always take less that 1GB of artifacts storage space.

Assuming 12 stable releases at year, at the current size of packages, the **Falco stable releases** will take approx. 720MB of storage space every year.

### Implementation

The Falco CI will have a new CI job - called `cleanup/packages-dev` - responsible for removing the **Falco development releases** depending on the above plan.

This job will be triggered after the `publish/packages-dev` completed successfully.

## Drivers

As explained in the [Artifacts Storage](./20200818-artifacts-storage) proposal, we build the drivers for the **last two driver versions** associated with **latest Falco stable releases**.
Then, we store those drivers into a [generic bintray repository](https://bintray.com/falcosecurity/driver) from which the installation process automatically downloads them, if suitable.

This document proposes to implement a cleanup mechanism that deletes all the other driver versions available.

At the moment of writing, considering only the last two driver versions (**ae104eb**, **85c8895**) associated with the latest Falco stable releases, we ship ~340 eBPF drivers, each accounting for ~3.1MB of storage space, and 1512 kernel modules (~3.1MB size each, too).

Thus, we obtain an estimate of approx. 2.875GB for **each** driver version.

This document proposes to only store the last two driver versions associates with the latest Falco stable releases. And deleting the other ones.

This way, assuming the number of prebuilt drivers does not skyrocket, we can reasonably estimate the storage space used by prebuilt drivers to be around 6GB.

Notice that, in case a Falco stable release will not depend on a new driver version, this means the last two driver versions will, in this case, cover more than the two Falco stable releases.

### Archivation

Since the process of building drivers is time and resource consuming, this document also proposes to move the driver versions in other storage facilities.

The candidate is an AWS S3 bucket responsible for holding the deleted driver version files.

### Implementation

The [test-infra](https://github.com/falcosecurity/test-infra) CI, specifically its part dedicated to run the **Drivers Build Grid** that runs every time it detects changes into the `driverkit` directory of the [test-infra](https://github.com/falcosecurity/test-infra) repository,
will have a new job - called `drivers/cleanup` - responsible for removing all the Falco driver versions except the last two.

This job will be triggered after the `drivers/publish` completed successfully on the master branch.