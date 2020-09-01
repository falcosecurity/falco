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

Which means that all the Falco packages present in the Falco stable release repositories will be kept.


The [bin](https://bintray.com/falcosecurity/bin) repository contains a Falco tarball package for every release.
This means it grows in space of ~50MB each month.

the [deb](https://bintray.com/falcosecurity/deb) repository contains a Falco DEB package for every release.
This means it grows in space of ~5MB each month.

the [rpm](https://bintray.com/falcosecurity/rpm) repository contains a Falco RPM package for every release.
This means it grows in space of ~4.3MB each month.

### Considerations

Assuming the size of the packages does not surpass the numbers listed in the above sections, the **Falco development releases** will always take less that 1GB of artifacts storage space.

Assuming 12 stable releases at year, at the current size of packages, the **Falco stable releases** will take approx. 720MB of storage space every year.

## Drivers


Archive ...



A scheduled job will be added to the continuous integration system of the [test-infra](https://github.com/falcosecurity/test-infra) repository.