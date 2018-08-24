FALCO_VERSION:=0.11.1
KERNEL_SOURCES:=${PWD}/..

build:
	docker build --build-arg FALCO_VERSION=${FALCO_VERSION} \
		. -t sysdig/falco-probe-builder:${FALCO_VERSION}

upload:
	docker push sysdig/falco-probe-builder:${FALCO_VERSION}

clean:
	rm -f output/*

test: test-fedora test-ubuntu test-rhel test-amazon test-amazon-2 test-coreos test-debian

test-fedora:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/4.17.14-102.fc27.x86_64:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/4.17.14-102.fc27.x86_64/lib/modules/4.17.14-102.fc27.x86_64/config | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/kernels/4.17.14-102.fc27.x86_64 \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-ubuntu:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/3.13.0-67/110:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/3.13.0-67/110/boot/config-3.13.0-67-generic | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/linux-headers-3.13.0-67-generic \
		-e KERNEL_VERSION="" \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-rhel:
	# RHEL 2.6.32 kernels requires a gcc < 5 and is not present on Debian unstable, thus not supported
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/3.10.0-327.10.1.el7.x86_64:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/3.10.0-327.10.1.el7.x86_64/boot/config-3.10.0-327.10.1.el7.x86_64 | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/kernels/3.10.0-327.10.1.el7.x86_64 \
		-e KERNEL_VERSION="" \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-amazon:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/4.14.62-65.117.amzn1.x86_64:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/4.14.62-65.117.amzn1.x86_64/boot/config-4.14.62-65.117.amzn1.x86_64 | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/kernels/4.14.62-65.117.amzn1.x86_64 \
		-e KERNEL_VERSION="" \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-amazon-2:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/4.14.47-63.37.amzn2.x86_64:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/4.14.47-63.37.amzn2.x86_64/boot/config-4.14.47-63.37.amzn2.x86_64 | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/kernels/4.14.47-63.37.amzn2.x86_64 \
		-e KERNEL_VERSION="" \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-coreos:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/coreos-1185.1.0/modules/4.7.3-coreos:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/coreos-1185.1.0/config | cut -d' ' -f1) \
		-e KERNELDIR=/build \
		-e KERNEL_VERSION="" \
		sysdig/falco-probe-builder:${FALCO_VERSION}

test-debian:
	docker run --rm \
		-v ${PWD}/output:/output \
		-v ${KERNEL_SOURCES}/3.2.0-4/3.2.78-1:/kernel:ro \
		-e HASH=$(shell md5sum ${KERNEL_SOURCES}/3.2.0-4/3.2.78-1/boot/config-3.2.0-4-amd64 | cut -d' ' -f1) \
		-e KERNELDIR=/usr/src/linux-headers-3.2.0-4-amd64 \
		-e KERNEL_VERSION=3.2.0-4-amd64 \
		sysdig/falco-probe-builder:${FALCO_VERSION}

.PHONY: build upload
