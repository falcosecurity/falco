FROM sysdig/sysdig:latest

MAINTAINER Néstor Salceda <nestor.salceda@sysdig.com>

RUN apt-get update \
 && apt-get --fix-broken install -y \
 && apt-get install -y --no-install-recommends \
        s3cmd \
 && rm -rf /var/lib/apt/lists/*

# debian:unstable head contains binutils 2.31, which generates
# binaries that are incompatible with kernels < 4.16. So manually
# forcibly install binutils 2.30-22 instead.
RUN curl -s -o binutils_2.30-22_amd64.deb http://snapshot.debian.org/archive/debian/20180622T211149Z/pool/main/b/binutils/binutils_2.30-22_amd64.deb \
 && curl -s -o libbinutils_2.30-22_amd64.deb http://snapshot.debian.org/archive/debian/20180622T211149Z/pool/main/b/binutils/libbinutils_2.30-22_amd64.deb \
 && curl -s -o binutils-x86-64-linux-gnu_2.30-22_amd64.deb http://snapshot.debian.org/archive/debian/20180622T211149Z/pool/main/b/binutils/binutils-x86-64-linux-gnu_2.30-22_amd64.deb \
 && curl -s -o binutils-common_2.30-22_amd64.deb http://snapshot.debian.org/archive/debian/20180622T211149Z/pool/main/b/binutils/binutils-common_2.30-22_amd64.deb \
 && dpkg -i *binutils*.deb

ENV CAPTURE_DURATION 120

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
