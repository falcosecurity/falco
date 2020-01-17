FROM centos:8

LABEL name="falcosecurity/falco-builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build falcosecurity/falco-builder cmake"
LABEL maintainer="opensource@sysdig.com"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_WARNINGS_AS_ERRORS=ON
ARG MAKE_JOBS=4
ARG FALCO_VERSION

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS}
ENV MAKE_JOBS=${MAKE_JOBS}
ENV FALCO_VERSION=${FALCO_VERSION}

RUN dnf update -y
RUN dnf install 'dnf-command(config-manager)' -y
RUN dnf config-manager --set-enabled PowerTools -y
RUN dnf install -y gcc gcc-c++ clang llvm git make which libcurl-devel zlib-devel rpm-build libyaml-devel openssl-devel cmake ncurses-devel c-ares-devel autoconf automake libtool createrepo expect which glibc-static libstdc++-static elfutils-libelf-devel -y

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]
