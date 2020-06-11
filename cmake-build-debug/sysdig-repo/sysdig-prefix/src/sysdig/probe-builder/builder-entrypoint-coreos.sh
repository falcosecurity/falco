#!/bin/bash

# required env vars:
# HASH
# HASH_ORIG
# KERNELDIR
# KERNEL_RELEASE
# OUTPUT
# PROBE_DEVICE_NAME
# PROBE_NAME
# PROBE_VERSION

set -euo pipefail

ARCH=$(uname -m)

if [[ -f "${KERNELDIR}/scripts/gcc-plugins/stackleak_plugin.so" ]]; then
	echo "Rebuilding gcc plugins for ${KERNELDIR}"
	(cd "${KERNELDIR}" && make gcc-plugins)
fi

(cd $KERNELDIR && make modules_prepare)

echo Building $PROBE_NAME-$PROBE_VERSION-$ARCH-$KERNEL_RELEASE-$HASH.ko

mkdir -p /build/sysdig
cd /build/sysdig

cmake -DCMAKE_BUILD_TYPE=Release -DPROBE_NAME=$PROBE_NAME -DPROBE_VERSION=$PROBE_VERSION -DPROBE_DEVICE_NAME=$PROBE_DEVICE_NAME -DCREATE_TEST_TARGETS=OFF /build/probe/sysdig
make driver
strip -g driver/$PROBE_NAME.ko

KO_VERSION=$(/sbin/modinfo driver/$PROBE_NAME.ko | grep vermagic | tr -s " " | cut -d " " -f 2)
if [ "$KO_VERSION" != "$KERNEL_RELEASE" ]; then
	echo "Corrupted probe, KO_VERSION " $KO_VERSION ", KERNEL_RELEASE " $KERNEL_RELEASE
	exit 1
fi

cp driver/$PROBE_NAME.ko $OUTPUT/$PROBE_NAME-$PROBE_VERSION-$ARCH-$KERNEL_RELEASE-$HASH.ko
cp driver/$PROBE_NAME.ko $OUTPUT/$PROBE_NAME-$PROBE_VERSION-$ARCH-$KERNEL_RELEASE-$HASH_ORIG.ko

