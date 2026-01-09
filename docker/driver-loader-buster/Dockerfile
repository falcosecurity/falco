FROM debian:buster

ARG FALCO_COMMIT_SHA
ARG FALCO_VERSION=latest

LABEL org.opencontainers.image.authors='The Falco Authors https://falco.org' \
      org.opencontainers.image.url='https://falco.org' \
      org.opencontainers.image.source='https://github.com/falcosecurity/falco' \
      org.opencontainers.image.vendor='Falco Organization' \
      org.opencontainers.image.licenses='Apache-2.0' \
      org.opencontainers.image.revision=${FALCO_COMMIT_SHA} \
      org.opencontainers.image.version=${FALCO_VERSION} \
      maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro falcosecurity/falco-driver-loader:latest-buster [driver] [options]"

ARG TARGETARCH

ARG VERSION_BUCKET=deb
ARG HOST_ROOT=/host
ARG HOME=/root
ENV FALCO_VERSION="${FALCO_VERSION}" \
    VERSION_BUCKET="${VERSION_BUCKET}" \
    HOST_ROOT="${HOST_ROOT}" \
    HOME="${HOME}"

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

# Use 20250630T203427Z debian apt snapshot as it still contains support for buster.
RUN cat <<EOF > /etc/apt/sources.list
deb http://snapshot.debian.org/archive/debian/20250630T203427Z buster main
deb http://snapshot.debian.org/archive/debian-security/20250630T203427Z buster/updates main
deb http://snapshot.debian.org/archive/debian/20250630T203427Z buster-updates main
EOF

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	bash-completion \
	bc \
	bison \
	clang-7 \
	ca-certificates \
	curl \
	dkms \
	flex \
	gnupg2 \
	gcc \
	jq \
	libc6-dev \
	libssl-dev \
	llvm-7 \
	netcat \
	patchelf \
	xz-utils \
	zstd \
	&& rm -rf /var/lib/apt/lists/*

RUN if [ "$TARGETARCH" = "amd64" ]; \
	then apt-get install -y --no-install-recommends libmpx2; \
	fi

# gcc 6 is no longer included in debian stable, but we need it to
# build kernel modules on the default debian-based ami used by
# kops. So grab copies we've saved from debian snapshots with the
# prefix https://snapshot.debian.org/archive/debian/20170517T033514Z
# or so.

RUN if [ "$TARGETARCH" = "amd64" ]; then curl -L -o libcilkrts5_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/libcilkrts5_6.3.0-18_${TARGETARCH}.deb; fi; \
	curl -L -o cpp-6_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/cpp-6_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o gcc-6-base_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/gcc-6-base_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o gcc-6_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/gcc-6_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o libasan3_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/libasan3_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o libgcc-6-dev_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/libgcc-6-dev_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o libubsan0_6.3.0-18_${TARGETARCH}.deb https://download.falco.org/dependencies/libubsan0_6.3.0-18_${TARGETARCH}.deb \
	&& curl -L -o libmpfr4_3.1.3-2_${TARGETARCH}.deb https://download.falco.org/dependencies/libmpfr4_3.1.3-2_${TARGETARCH}.deb \
	&& curl -L -o libisl15_0.18-1_${TARGETARCH}.deb https://download.falco.org/dependencies/libisl15_0.18-1_${TARGETARCH}.deb \
	&& dpkg -i cpp-6_6.3.0-18_${TARGETARCH}.deb gcc-6-base_6.3.0-18_${TARGETARCH}.deb gcc-6_6.3.0-18_${TARGETARCH}.deb libasan3_6.3.0-18_${TARGETARCH}.deb; \
	if [ "$TARGETARCH" = "amd64" ]; then dpkg -i libcilkrts5_6.3.0-18_${TARGETARCH}.deb; fi; \
	dpkg -i libgcc-6-dev_6.3.0-18_${TARGETARCH}.deb libubsan0_6.3.0-18_${TARGETARCH}.deb libmpfr4_3.1.3-2_${TARGETARCH}.deb libisl15_0.18-1_${TARGETARCH}.deb \
	&& rm -f cpp-6_6.3.0-18_${TARGETARCH}.deb gcc-6-base_6.3.0-18_${TARGETARCH}.deb gcc-6_6.3.0-18_${TARGETARCH}.deb libasan3_6.3.0-18_${TARGETARCH}.deb libcilkrts5_6.3.0-18_${TARGETARCH}.deb libgcc-6-dev_6.3.0-18_${TARGETARCH}.deb libubsan0_6.3.0-18_${TARGETARCH}.deb libmpfr4_3.1.3-2_${TARGETARCH}.deb libisl15_0.18-1_${TARGETARCH}.deb

# gcc 5 is no longer included in debian stable, but we need it to
# build centos kernels, which are 3.x based and explicitly want a gcc
# version 3, 4, or 5 compiler. So grab copies we've saved from debian
# snapshots with the prefix https://snapshot.debian.org/archive/debian/20190122T000000Z.

RUN if [ "$TARGETARCH" = "amd64" ]; then curl -L -o libmpx0_5.5.0-12_${TARGETARCH}.deb https://download.falco.org/dependencies/libmpx0_5.5.0-12_${TARGETARCH}.deb; fi; \
	curl -L -o cpp-5_5.5.0-12_${TARGETARCH}.deb https://download.falco.org/dependencies/cpp-5_5.5.0-12_${TARGETARCH}.deb \
	&& curl -L -o gcc-5-base_5.5.0-12_${TARGETARCH}.deb https://download.falco.org/dependencies/gcc-5-base_5.5.0-12_${TARGETARCH}.deb \
	&& curl -L -o gcc-5_5.5.0-12_${TARGETARCH}.deb https://download.falco.org/dependencies/gcc-5_5.5.0-12_${TARGETARCH}.deb \
	&& curl -L -o libasan2_5.5.0-12_${TARGETARCH}.deb	https://download.falco.org/dependencies/libasan2_5.5.0-12_${TARGETARCH}.deb \
	&& curl -L -o libgcc-5-dev_5.5.0-12_${TARGETARCH}.deb https://download.falco.org/dependencies/libgcc-5-dev_5.5.0-12_${TARGETARCH}.deb \
	&& curl -L -o libisl15_0.18-4_${TARGETARCH}.deb https://download.falco.org/dependencies/libisl15_0.18-4_${TARGETARCH}.deb \
	&& dpkg -i cpp-5_5.5.0-12_${TARGETARCH}.deb gcc-5-base_5.5.0-12_${TARGETARCH}.deb gcc-5_5.5.0-12_${TARGETARCH}.deb libasan2_5.5.0-12_${TARGETARCH}.deb; \
	if [ "$TARGETARCH" = "amd64" ]; then dpkg -i libmpx0_5.5.0-12_${TARGETARCH}.deb; fi; \
	dpkg -i libgcc-5-dev_5.5.0-12_${TARGETARCH}.deb libisl15_0.18-4_${TARGETARCH}.deb \
	&& rm -f cpp-5_5.5.0-12_${TARGETARCH}.deb gcc-5-base_5.5.0-12_${TARGETARCH}.deb gcc-5_5.5.0-12_${TARGETARCH}.deb libasan2_5.5.0-12_${TARGETARCH}.deb libgcc-5-dev_5.5.0-12_${TARGETARCH}.deb libisl15_0.18-4_${TARGETARCH}.deb libmpx0_5.5.0-12_${TARGETARCH}.deb

# Since our base Debian image ships with GCC 7 which breaks older kernels, revert the
# default to gcc-5.
RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc

RUN rm -rf /usr/bin/clang \
	&& rm -rf /usr/bin/llc \
	&& ln -s /usr/bin/clang-7 /usr/bin/clang \
	&& ln -s /usr/bin/llc-7 /usr/bin/llc

RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add - \
	&& echo "deb https://download.falco.org/packages/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
	&& apt-get update -y \
	&& if [ "$FALCO_VERSION" = "latest" ]; then FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco; else FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco=${FALCO_VERSION}; fi \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601 output.
ADD ./config/falco.iso8601_timeformat.yaml /etc/falco/config.d/

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

# debian:stable head contains binutils 2.31, which generates
# binaries that are incompatible with kernels < 4.16. So manually
# forcibly install binutils 2.30-22 instead.

RUN if [ "$TARGETARCH" = "amd64" ] ; then \
	curl -L -o binutils-x86-64-linux-gnu_2.30-22_${TARGETARCH}.deb https://download.falco.org/dependencies/binutils-x86-64-linux-gnu_2.30-22_${TARGETARCH}.deb; \
	else  \
	curl -L -o  binutils-aarch64-linux-gnu_2.30-22_${TARGETARCH}.deb https://download.falco.org/dependencies/binutils-aarch64-linux-gnu_2.30-22_${TARGETARCH}.deb; \
	fi

RUN curl -L -o binutils_2.30-22_${TARGETARCH}.deb https://download.falco.org/dependencies/binutils_2.30-22_${TARGETARCH}.deb \
	&& curl -L -o libbinutils_2.30-22_${TARGETARCH}.deb https://download.falco.org/dependencies/libbinutils_2.30-22_${TARGETARCH}.deb \
	&& curl -L -o binutils-common_2.30-22_${TARGETARCH}.deb https://download.falco.org/dependencies/binutils-common_2.30-22_${TARGETARCH}.deb \
	&& dpkg -i *binutils*.deb \
	&& rm -f *binutils*.deb

COPY docker/driver-loader-buster/docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
