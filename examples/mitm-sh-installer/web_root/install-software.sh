#!/bin/bash
#
# Copyright (C) 2013-2014 My Company inc.
#
# This file is part of my-software
#
# my-software is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# my-software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with my-software.  If not, see <http://www.gnu.org/licenses/>.
#
set -e

function install_rpm {
	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		yum -q -y install curl
	fi

	echo "*** Installing my-software public key"
	# A rpm --import command would normally be here

	echo "*** Installing my-software repository"
	# A curl path-to.repo <some url> would normally be here

	echo "*** Installing my-software"
	# A yum -q -y install my-software command would normally be here

	echo "*** my-software Installed!"
}

function install_deb {
	export DEBIAN_FRONTEND=noninteractive

	if ! hash curl > /dev/null 2>&1; then
		echo "* Installing curl"
		apt-get -qq -y install curl < /dev/null
	fi

	echo "*** Installing my-software public key"
	# A curl <url> | apt-key add - command would normally be here

	echo "*** Installing my-software repository"
	# A curl path-to.list <some url> would normally be here

	echo "*** Installing my-software"
	# An apt-get -qq -y install my-software command would normally be here

	echo "*** my-software Installed!"
}

function unsupported {
	echo 'Unsupported operating system. Please consider writing to the mailing list at'
	echo 'https://groups.google.com/forum/#!forum/my-software or trying the manual'
	echo 'installation.'
	exit 1
}

if [ $(id -u) != 0 ]; then
	echo "Installer must be run as root (or with sudo)."
#	exit 1
fi

echo "* Detecting operating system"

ARCH=$(uname -m)
if [[ ! $ARCH = *86 ]] && [ ! $ARCH = "x86_64" ]; then
	unsupported
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
