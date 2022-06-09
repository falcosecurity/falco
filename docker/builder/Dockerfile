FROM centos:7

LABEL name="falcosecurity/falco-builder"
LABEL usage="docker run -v $PWD/..:/source -v $PWD/build:/build falcosecurity/falco-builder cmake"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_WARNINGS_AS_ERRORS=ON
ARG MAKE_JOBS=4
ARG FALCO_VERSION
ARG CMAKE_VERSION=3.22.5

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS}
ENV MAKE_JOBS=${MAKE_JOBS}
ENV FALCO_VERSION=${FALCO_VERSION}
ENV CMAKE_VERSION=${CMAKE_VERSION}

# build toolchain
RUN yum -y install centos-release-scl && \
    INSTALL_PKGS="devtoolset-7-gcc devtoolset-7-gcc-c++ devtoolset-7-toolchain devtoolset-7-libstdc++-devel devtoolset-7-elfutils-libelf-devel llvm-toolset-7.0 glibc-static autoconf automake libtool createrepo expect git which libcurl-devel zlib-devel rpm-build libyaml-devel" && \
    yum -y install --setopt=tsflags=nodocs $INSTALL_PKGS && \
    rpm -V $INSTALL_PKGS


RUN source scl_source enable devtoolset-7 llvm-toolset-7.0

RUN curl -L -o /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz https://github.com/kitware/cmake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz && \
    gzip -d /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz && \
    tar -xpf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar --directory=/tmp && \
    cp -R /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/* /usr && \
    rm -rf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)

COPY ./root /

# DTS
ENV BASH_ENV=/usr/bin/scl_enable \
    ENV=/usr/bin/scl_enable \
    PROMPT_COMMAND=". /usr/bin/scl_enable"

ENTRYPOINT ["entrypoint"]
CMD ["usage"]
