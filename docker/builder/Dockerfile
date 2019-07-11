FROM centos:6

ENV FALCO_VERSION 0.1.1dev
ENV BUILD_TYPE Release
ENV BUILD_DRIVER OFF
ENV BUILD_BPF OFF
ENV BUILD_WARNINGS_AS_ERRORS ON
ENV MAKE_JOBS 4

ARG DOCKER_VERSION=1.11.0
ARG CMAKE_VERSION=3.14.5

RUN curl -o /etc/yum.repos.d/devtools-2.repo https://people.centos.org/tru/devtools-2/devtools-2.repo && \
        rpm -i http://mirror.pnl.gov/epel/6/i386/epel-release-6-8.noarch.rpm && \
        sed -e 's,$basearch,i386,' -e 's,$releasever\],$releasever-i686\],' /etc/yum.repos.d/devtools-2.repo > /etc/yum.repos.d/devtools-2-i686.repo && \
        yum -y install \
        createrepo \
        devtoolset-2-toolchain \
        dpkg \
        dpkg-devel \
        expect \
        gcc \
        gcc-c++ \
        git \
        glibc-static \
        libcurl-devel \
        make \
        curl \
        zlib-devel \
        pkg-config \
        rpm-build \
        unzip \
        wget \
        tar \
        autoconf \
        automake \
        libtool && \
        yum -y install \
        glibc-devel.i686 \
        devtoolset-2-libstdc++-devel.i686 \
        devtoolset-2-elfutils-libelf-devel && \
        yum clean all
RUN curl -o docker.tgz https://get.docker.com/builds/Linux/x86_64/docker-${DOCKER_VERSION}.tgz && \
        tar xfz docker.tgz docker/docker && \
        mv docker/docker /usr/local/bin/docker && \
        chmod +x /usr/local/bin/docker && \
        rm -fr docker.tgz docker/
RUN . /opt/rh/devtoolset-2/enable && \
        cd /tmp && \
        wget -nv -O - https://github.com/kitware/cmake/releases/download/v$CMAKE_VERSION/cmake-${CMAKE_VERSION}.tar.gz | tar zx; \
        cd /tmp/cmake-${CMAKE_VERSION} && \
        ./bootstrap --system-curl && \
        make -j${MAKE_JOBS} && \
        make install && \
        rm -rf /tmp/cmake-${CMAKE_VERSION}

# TEMPORARY until dependencies in CMakeLists.txt are fixed
RUN yum -y install libyaml-devel
COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
