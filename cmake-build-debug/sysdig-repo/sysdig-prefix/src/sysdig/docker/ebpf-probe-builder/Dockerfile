FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

# Based on the sysdig container, used for building eBPF probe

RUN apt-get update \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
	clang-7 \
	gcc \
	libelf-dev \
	libelf1 \
	llvm-7 \
	make \
 && rm -rf /var/lib/apt/lists/*

# Use clang-7 as the default clang
RUN rm -rf /usr/bin/clang \
 && rm -rf /usr/bin/llc \
 && ln -s /usr/bin/clang-7 /usr/bin/clang \
 && ln -s /usr/bin/llc-7 /usr/bin/llc

COPY ./probe-builder-entrypoint.sh /

ENTRYPOINT ["/probe-builder-entrypoint.sh"]
