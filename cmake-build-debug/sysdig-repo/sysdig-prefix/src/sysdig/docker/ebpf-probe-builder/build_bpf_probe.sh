#!/bin/sh

set -eu

# Defaults
DRIVER_DIR=/opt/draios/src/draios-agent-0.1.1dev
KERNEL_DIR=/lib/modules/$(uname -r)/build
OUT_DIR=${HOME}/.sysdig

usage()
{
	echo "build_bpf_probe [-d <driver_path>] [-k <kernel_path>] [-o <output_path>]"
}

# Options parsing
while [ -n "${1-}" ]; do
	case $1 in
	-d | --driver )    shift
	                   DRIVER_DIR=$1
	                   ;;
	-k | --kernel )    shift
	                   KERNEL_DIR=$1
	                   ;;
	-o | --output )    shift
	                   OUT_DIR=$1
	                   ;;
	-h | --help )      usage
	                   exit
	                   ;;
	* )                usage
	                   exit 1
	                   ;;
	esac
	shift
done

mkdir -p ${HOME}/.sysdig

#
# Mapped volumes:
#  - ${OUT_DIR}: The directory that the probe gets put in. Defaults to ~/.sysdig
#  - ${DRIVER_DIR}: The prepared bpf driver code that gets written by the installer
#  - ${KERNEL_DIR}: The kmod build directory for the target kernel.
#  - /lib/modules: Unfortunately, on some distros (Debian / Ubuntu), there are
#    additional support directories (such as a -commmon counterpart to -amd64) which
#    need to be accessible for the makefile
#  - /usr: As with the above, on Debian based systems the /lib/modules tree will have
#    symlinks into /usr/lib/linux-kbuild* and these directories need to be present.

docker build -t ebpf-probe-builder:latest --pull .
docker images -q -f 'dangling=true' | xargs --no-run-if-empty docker rmi -f
docker run --rm -i -v ${OUT_DIR}:/out -v ${DRIVER_DIR}:/driver -v ${KERNEL_DIR}:/kernel -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -e BPF_PROBE_FILENAME=bpf_probe.o ebpf-probe-builder:latest

echo "Probe is in ${OUT_DIR}/"
