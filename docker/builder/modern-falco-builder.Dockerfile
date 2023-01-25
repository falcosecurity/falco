
FROM centos:7 AS build-stage

# To build Falco you need to pass the cmake option
ARG CMAKE_OPTIONS=""
ARG MAKE_JOBS=6

# Install all the dependencies
WORKDIR /

RUN yum -y install centos-release-scl; \
    yum -y install devtoolset-9-gcc devtoolset-9-gcc-c++; \
    source scl_source enable devtoolset-9; \
    yum install -y git wget make m4 rpm-build

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-$(uname -m)/

# Copy Falco folder from the build context
COPY . /source
WORKDIR /build/release

# We need `make tests` and `make all` for integration tests.
RUN source scl_source enable devtoolset-9; \
    cmake ${CMAKE_OPTIONS} /source; \
    make falco -j${MAKE_JOBS}

RUN make package
RUN make tests -j${MAKE_JOBS}
RUN make all -j${MAKE_JOBS}

FROM scratch AS export-stage

ARG DEST_BUILD_DIR="/build"

COPY --from=build-stage /build/release/falco-*.tar.gz /packages/
COPY --from=build-stage /build/release/falco-*.deb /packages/
COPY --from=build-stage /build/release/falco-*.rpm /packages/
COPY --from=build-stage /build/release/ ${DEST_BUILD_DIR}
