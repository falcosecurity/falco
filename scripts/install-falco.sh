#!/bin/bash
#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of falco .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
set -e

function install_rpm {
	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		yum -q -y install curl
	fi

	if ! yum -q list dkms > /dev/null 2>&1; then
		echo "* Installing EPEL repository (for DKMS)"
		if [ $VERSION -eq 8 ]; then
			rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
		elif [ $VERSION -eq 7 ]; then
			rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
		else
			rpm --quiet -i https://mirrors.kernel.org/fedora-epel/6/i386/epel-release-6-8.noarch.rpm
		fi
	fi

	echo "* Installing falco public key"
	rpm --quiet --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public
	echo "* Installing falco repository"
	curl -s -o /etc/yum.repos.d/draios.repo https://s3.amazonaws.com/download.draios.com/stable/rpm/draios.repo
	echo "* Installing kernel headers"
	KERNEL_VERSION=$(uname -r)
	if [[ $KERNEL_VERSION == *PAE* ]]; then
		yum -q -y install kernel-PAE-devel-${KERNEL_VERSION%.PAE} || kernel_warning
	elif [[ $KERNEL_VERSION == *stab* ]]; then
		# It's OpenVZ kernel and we should install another package
		yum -q -y install vzkernel-devel-$KERNEL_VERSION || kernel_warning
	elif [[ $KERNEL_VERSION == *uek* ]]; then
		yum -q -y install kernel-uek-devel-$KERNEL_VERSION || kernel_warning
	else
		yum -q -y install kernel-devel-$KERNEL_VERSION || kernel_warning
	fi
	echo "* Installing falco"
	yum -q -y install falco
}

function install_deb {
	export DEBIAN_FRONTEND=noninteractive

	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		apt-get -qq -y install curl < /dev/null
	fi

	echo "* Installing Sysdig public key"
	curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -
	echo "* Installing falco repository"
	curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list
	apt-get -qq update < /dev/null
	echo "* Installing kernel headers"
	apt-get -qq -y install linux-headers-$(uname -r) < /dev/null || kernel_warning
	echo "* Installing falco"
	apt-get -qq -y install falco < /dev/null
}

function unsupported {
	echo 'Unsupported operating system. Please consider writing to the mailing list at'
	echo 'https://groups.google.com/forum/#!forum/sysdig or trying the manual'
	echo 'installation.'
	exit 1
}

function kernel_warning {
	echo "Unable to find kernel development files for the current kernel version" $(uname -r)
	echo "This usually means that your system is not up-to-date or you installed a custom kernel version."
	echo "The installation will continue but you'll need to install these yourself in order to use falco."
	echo 'Please write to the mailing list at https://groups.google.com/forum/#!forum/sysdig'
	echo "if you need further assistance."
}

if [ $(id -u) != 0 ]; then
	echo "Installer must be run as root (or with sudo)."
	exit 1
fi

echo "* Detecting operating system"

ARCH=$(uname -m)
if [[ ! $ARCH = *86 ]] && [ ! $ARCH = "x86_64" ] && [ ! $ARCH = "s390x" ]; then
	unsupported
fi

if [ $ARCH = "s390x" ]; then
	echo "------------"
	echo "WARNING: A Docker container is the only officially supported platform on s390x"
	echo "------------"
fi

if [ -f /etc/debian_version ]; then
	if [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		DISTRO=$DISTRIB_ID
		VERSION=${DISTRIB_RELEASE%%.*}
	else
		DISTRO="Debian"
		VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
	fi

	case "$DISTRO" in

		"Ubuntu")
			if [ $VERSION -ge 10 ]; then
				install_deb
			else
				unsupported
			fi
			;;

		"LinuxMint")
			if [ $VERSION -ge 9 ]; then
				install_deb
			else
				unsupported
			fi
			;;

		"Debian")
			if [ $VERSION -ge 6 ]; then
				install_deb
			elif [[ $VERSION == *sid* ]]; then
				install_deb
			else
				unsupported
			fi
			;;

		*)
			unsupported
			;;

	esac

elif [ -f /etc/system-release-cpe ]; then
	DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f3)

	# New Amazon Linux 2 distro
	if [[ -f /etc/image-id ]]; then
		AMZ_AMI_VERSION=$(cat /etc/image-id | grep 'image_name' | cut -d"=" -f2 | tr -d "\"")
	fi

	if [[ "${DISTRO}" == "o" ]] && [[ ${AMZ_AMI_VERSION} = *"amzn2"* ]]; then
		DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f4)
	fi

	VERSION=$(cat /etc/system-release-cpe | cut -d':' -f5 | cut -d'.' -f1 | sed 's/[^0-9]*//g')

	case "$DISTRO" in

		"oracle" | "centos" | "redhat")
			if [ $VERSION -ge 6 ]; then
				install_rpm
			else
				unsupported
			fi
			;;

		"amazon")
			install_rpm
			;;

		"fedoraproject")
			if [ $VERSION -ge 13 ]; then
				install_rpm
			else
				unsupported
			fi
			;;

		*)
			unsupported
			;;

	esac

else
	unsupported
fi

modprobe -r falco_probe
