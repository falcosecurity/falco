# Falco Automated Probe Builder using Docker

With the arrival of eBPF support to Sysdig, we need to compile another artifact
tied to Linux Kernel. The problem with our existent infrastructure is that this
probe needs to be built with clang + llvm and our builder does not provide this
software.

So the next natural step seems to be using containers for building this module
and uploading it to the s3 bucket.

There are advantages over previous solution, I'm  going to enumerate a few here:

* Build eBPF probe for Falco
* Use a container derived from Falco image, which contains the source code for
  the probe
* Splitted `build-probe-binaries` script in several builders, so we can build
  and test build only a subset of probes
* Is easy to add more builders
* Support of parallel builds
* Separated lifecycle from other Sysdig components

Also there are other known pitfalls:

* Falco image ships a modern compiler, and we can't build 2.6 kernels
* Still relies on some host settings when preparing sources to be compiled in
  container image

There are a several stuff to be improved:

* Prefix HASH and HASH_ORIGIN with BUILDER\_
* Test with GNU/Parallel
* Add a Minikube builder
* Encapsulate builders in Docker images
* Add falco:dev support

## Using

For building Falco modules just use the `build-probe-binaries` script with the
Falco version we would like to build. For example for Falco 0.11.1

```
$ ./build-probe-binaries 0.11.1
```

This comand iterates the `builders` directory and invokes each builder. It will
put probes in `output` directory.

### Building probes for just one distribution

This is really useful for debugging builds or just for test new builders easily.
In this directory, just invoke the builder:

```
$ ./builders/build-debian 0.11.1
```

And this will build the probes for Debian.

## Building builder images

The source for the builder images is in the `docker` directory. Just `cd docker`
and follow the Makefile instructions. I suggest to build and push images in the
same command:

```
make FALCO_VERSION=0.11.1 build upload
```

And this will build the builder for Falco 0.11.1 image.
