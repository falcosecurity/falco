FROM debian:unstable

LABEL maintainer="Sysdig <support@sysdig.com>"

ENV FALCO_REPOSITORY stable

LABEL RUN="docker run -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro --name NAME IMAGE"

ENV SYSDIG_HOST_ROOT /host

ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

ADD http://download.draios.com/apt-draios-priority /etc/apt/preferences.d/

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
	bash-completion \
	bc \
	clang-7 \
	ca-certificates \
	curl \
	dkms \
	gnupg2 \
	gcc \
	jq \
	libc6-dev \
	libelf-dev \
	llvm-7 \
	netcat \
	xz-utils \
 && rm -rf /var/lib/apt/lists/*

# gcc 6 is no longer included in debian unstable, but we need it to
# build kernel modules on the default debian-based ami used by
# kops. So grab copies we've saved from debian snapshots with the
# prefix https://snapshot.debian.org/archive/debian/20170517T033514Z
# or so.

RUN curl -o cpp-6_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/cpp-6_6.3.0-18_amd64.deb \
    && curl -o gcc-6-base_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/gcc-6-base_6.3.0-18_amd64.deb \
    && curl -o gcc-6_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/gcc-6_6.3.0-18_amd64.deb \
    && curl -o libasan3_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libasan3_6.3.0-18_amd64.deb \
    && curl -o libcilkrts5_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libcilkrts5_6.3.0-18_amd64.deb \
    && curl -o libgcc-6-dev_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libgcc-6-dev_6.3.0-18_amd64.deb \
    && curl -o libubsan0_6.3.0-18_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libubsan0_6.3.0-18_amd64.deb \
    && curl -o libmpfr4_3.1.3-2_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libmpfr4_3.1.3-2_amd64.deb \
    && curl -o libisl15_0.18-1_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-6-debs/libisl15_0.18-1_amd64.deb \
    && dpkg -i cpp-6_6.3.0-18_amd64.deb gcc-6-base_6.3.0-18_amd64.deb gcc-6_6.3.0-18_amd64.deb libasan3_6.3.0-18_amd64.deb libcilkrts5_6.3.0-18_amd64.deb libgcc-6-dev_6.3.0-18_amd64.deb libubsan0_6.3.0-18_amd64.deb libmpfr4_3.1.3-2_amd64.deb libisl15_0.18-1_amd64.deb \
    && rm -f cpp-6_6.3.0-18_amd64.deb gcc-6-base_6.3.0-18_amd64.deb gcc-6_6.3.0-18_amd64.deb libasan3_6.3.0-18_amd64.deb libcilkrts5_6.3.0-18_amd64.deb libgcc-6-dev_6.3.0-18_amd64.deb libubsan0_6.3.0-18_amd64.deb libmpfr4_3.1.3-2_amd64.deb libisl15_0.18-1_amd64.deb

# gcc 5 is no longer included in debian unstable, but we need it to
# build centos kernels, which are 3.x based and explicitly want a gcc
# version 3, 4, or 5 compiler. So grab copies we've saved from debian
# snapshots with the prefix https://snapshot.debian.org/archive/debian/20190122T000000Z.

RUN curl -o cpp-5_5.5.0-12_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/cpp-5_5.5.0-12_amd64.deb \
 && curl -o gcc-5-base_5.5.0-12_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-5-base_5.5.0-12_amd64.deb \
 && curl -o gcc-5_5.5.0-12_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/gcc-5_5.5.0-12_amd64.deb \
 && curl -o libasan2_5.5.0-12_amd64.deb	https://s3.amazonaws.com/download.draios.com/dependencies/libasan2_5.5.0-12_amd64.deb \
 && curl -o libgcc-5-dev_5.5.0-12_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/libgcc-5-dev_5.5.0-12_amd64.deb \
 && curl -o libisl15_0.18-4_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/libisl15_0.18-4_amd64.deb \
 && curl -o libmpx0_5.5.0-12_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/libmpx0_5.5.0-12_amd64.deb \
 && dpkg -i cpp-5_5.5.0-12_amd64.deb gcc-5-base_5.5.0-12_amd64.deb gcc-5_5.5.0-12_amd64.deb libasan2_5.5.0-12_amd64.deb libgcc-5-dev_5.5.0-12_amd64.deb libisl15_0.18-4_amd64.deb libmpx0_5.5.0-12_amd64.deb \
 && rm -f cpp-5_5.5.0-12_amd64.deb gcc-5-base_5.5.0-12_amd64.deb gcc-5_5.5.0-12_amd64.deb libasan2_5.5.0-12_amd64.deb libgcc-5-dev_5.5.0-12_amd64.deb libisl15_0.18-4_amd64.deb libmpx0_5.5.0-12_amd64.deb

# Since our base Debian image ships with GCC 7 which breaks older kernels, revert the
# default to gcc-5.
RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc

RUN rm -rf /usr/bin/clang \
 && rm -rf /usr/bin/llc \
 && ln -s /usr/bin/clang-7 /usr/bin/clang \
 && ln -s /usr/bin/llc-7 /usr/bin/llc

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$FALCO_REPOSITORY/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends falco \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601
# output.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml > /etc/falco/falco.yaml.new \
 && mv /etc/falco/falco.yaml.new /etc/falco/falco.yaml

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
 && ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

# debian:unstable head contains binutils 2.31, which generates
# binaries that are incompatible with kernels < 4.16. So manually
# forcibly install binutils 2.30-22 instead.
RUN curl -s -o binutils_2.30-22_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/binutils_2.30-22_amd64.deb \
 && curl -s -o libbinutils_2.30-22_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/libbinutils_2.30-22_amd64.deb \
 && curl -s -o binutils-x86-64-linux-gnu_2.30-22_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/binutils-x86-64-linux-gnu_2.30-22_amd64.deb \
 && curl -s -o binutils-common_2.30-22_amd64.deb https://s3.amazonaws.com/download.draios.com/dependencies/binutils-common_2.30-22_amd64.deb \
 && dpkg -i *binutils*.deb \
 && rm -f *binutils*.deb

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
