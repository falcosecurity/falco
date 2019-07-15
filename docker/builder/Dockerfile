FROM centos:7

LABEL name="falcosecurity/falco-builder"
LABEL usage="docker run -v /etc/passwd:/etc/passwd:ro -v $PWD/..:/source -v $PWD/build:/build falcosecurity/falco-builder"

ARG BUILD_TYPE=release
ARG BUILD_DRIVER=OFF
ARG BUILD_BPF=OFF
ARG BUILD_WARNINGS_AS_ERRORS=ON
ARG MAKE_JOBS=4

ENV BUILD_TYPE=${BUILD_TYPE}
ENV BUILD_DRIVER=${BUILD_DRIVER}
ENV BUILD_BPF=${BUILD_BPF}
ENV BUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS}
ENV MAKE_JOBS=${MAKE_JOBS}

ARG DOCKER_VERSION=1.11.0
ARG CMAKE_VERSION=3.5.0

RUN yum -y install centos-release-scl && \
    INSTALL_PKGS="devtoolset-7-gcc devtoolset-7-gcc-c++ devtoolset-7-toolchain devtoolset-7-libstdc++-devel devtoolset-7-elfutils-libelf-devel glibc-static autoconf automake libtool createrepo expect git which libcurl-devel zlib-devel rpm-build" && \
    yum -y install --setopt=tsflags=nodocs $INSTALL_PKGS && \
    rpm -V $INSTALL_PKGS

RUN source scl_source enable devtoolset-7 && \
    cd /tmp && \
    curl -L https://github.com/kitware/cmake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.tar.gz | tar xz; \
    cd cmake-${CMAKE_VERSION} && \
    ./bootstrap --system-curl && \
    make -j${MAKE_JOBS} && \
    make install && \
    rm -rf /tmp/cmake-${CMAKE_VERSION}

RUN cd /tmp && \
    curl -L https://get.docker.com/builds/Linux/x86_64/docker-${DOCKER_VERSION}.tgz | tar xz; \
    mv docker/docker /usr/local/bin/docker && \
    chmod +x /usr/local/bin/docker && \
    rm -rf /tmp/docker

# Note: Needs a fix into CMakeLists.txt # gcc gcc-c++
RUN yum -y install libyaml-devel

RUN yum clean all -y

COPY ./root /

# DTS
ENV BASH_ENV=/usr/bin/scl_enable \
    ENV=/usr/bin/scl_enable \
    PROMPT_COMMAND=". /usr/bin/scl_enable"

ENTRYPOINT ["entrypoint"]
CMD ["usage"]