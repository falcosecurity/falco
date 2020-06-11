#!/bin/bash

set -euo pipefail

usage()
{
	cat >&2 <<EOF
Usage:
	docker run --rm \\
		-v /var/run/docker.sock:/var/run/docker.sock \\
		IMAGE -P [-b BUILDER_IMAGE_PREFIX/] [-- BUILDER_OPTIONS...]

	docker run --rm \\
		-v /var/run/docker.sock:/var/run/docker.sock \\
		-v WORKSPACE:/workspace \\
		-v SYSDIG:/sysdig \\
		-v KERNELS:/kernels \\
		IMAGE -B [-b BUILDER_IMAGE_PREFIX/] [-- BUILDER_OPTIONS...]

Required volumes:
	- /var/run/docker.sock for spawning build containers
	- WORKSPACE
		the main workspace, will be used to unpack kernel packages
		and run the actual build
	- SYSDIG
		the directory containing Sysdig sources in the version
		you wish to build
	- KERNELS
		the directory containing kernel packages (image, headers etc.)

Options:
	-B
		Build the probes

	-P
		Prepare the probe builder images ahead of time

	-b BUILDER_IMAGE_PREFIX/
		Use BUILDER_IMAGE_PREFIX/ as the prefix for all builder images.
		It should match the prefix used with the -P option below
		(in an earlier invocation)

EOF
	exit 1
}

get_host_mount()
{
	SOURCE=$(docker inspect $(hostname) | jq -r ".[0].Mounts[]|select(.Destination == \"$1\")|.Source")
	if [ -z "$SOURCE" ]
	then
		echo "Cannot find original location of $1" >&2
		echo >&2
		usage
	fi
	echo "$SOURCE"
}

build_probes()
{
	WORKSPACE_SRC=$(get_host_mount /workspace)  
	SYSDIG_SRC=$(get_host_mount /sysdig)  
	KERNELS_SRC=$(get_host_mount /kernels)  

	cd /workspace
	/builder/build-probe-binaries -B $WORKSPACE_SRC -s $SYSDIG_SRC -b "$BUILDER_IMAGE_PREFIX" "$@" /kernels/*
}

prepare_builders()
{
	for i in Dockerfile.* ; do docker build -t ${BUILDER_IMAGE_PREFIX}sysdig-probe-builder:${i#Dockerfile.} -f $i . ; done
}

if ! docker info &>/dev/null
then
	echo "Docker socket not available" >&2
	echo >&2
	usage
fi

BUILDER_IMAGE_PREFIX=
while getopts ":b:BP" opt
do
	case "$opt" in
		b)
			BUILDER_IMAGE_PREFIX=$OPTARG
			;;
		B)
			OP=build
			;;
		P)
			OP=prepare
			;;
		\?)
			echo "Invalid option $OPTARG" >&2
			echo "Did you mean to pass it to the probe builder? Add -- before" >&2
			echo >&2
			usage
			;;
		:)
			echo "Option $OPTARG requires an argument" >&2
			echo >&2
			usage
			;;
	esac
done

shift $((OPTIND - 1))

case "${OP:-}" in
	build)
		build_probes "$@"
		;;
	prepare)
		prepare_builders
		;;
	*)
		usage
		;;
esac
