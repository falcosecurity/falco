
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

RUN source scl_source enable devtoolset-9; \
    cmake ${CMAKE_OPTIONS} /source; \
    make falco -j${MAKE_JOBS}
RUN make package

# We need `make tests` and `make all` for integration tests.
RUN make tests -j${MAKE_JOBS}
RUN make all -j${MAKE_JOBS}

FROM scratch AS export-stage

ARG DEST_BUILD_DIR="/build"

COPY --from=build-stage /build/release/falco-*.tar.gz /packages/
COPY --from=build-stage /build/release/falco-*.deb /packages/
COPY --from=build-stage /build/release/falco-*.rpm /packages/

# This is what we need for integration tests. We don't export all the build directory
# outside the container since its size is almost 6 GB, we export only what is strictly necessary
# for integration tests.
# This is just a workaround to fix the CI build until we replace our actual testing framework.
COPY --from=build-stage /build/release/cloudtrail-plugin-prefix ${DEST_BUILD_DIR}/cloudtrail-plugin-prefix
COPY --from=build-stage /build/release/cloudtrail-rules-prefix ${DEST_BUILD_DIR}/cloudtrail-rules-prefix
COPY --from=build-stage /build/release/falcosecurity-rules-application-prefix ${DEST_BUILD_DIR}/falcosecurity-rules-application-prefix
COPY --from=build-stage /build/release/falcosecurity-rules-falco-prefix ${DEST_BUILD_DIR}/falcosecurity-rules-falco-prefix
COPY --from=build-stage /build/release/falcosecurity-rules-local-prefix ${DEST_BUILD_DIR}/falcosecurity-rules-local-prefix
COPY --from=build-stage /build/release/json-plugin-prefix ${DEST_BUILD_DIR}/json-plugin-prefix
COPY --from=build-stage /build/release/k8saudit-plugin-prefix ${DEST_BUILD_DIR}/k8saudit-plugin-prefix
COPY --from=build-stage /build/release/k8saudit-rules-prefix ${DEST_BUILD_DIR}/k8saudit-rules-prefix
COPY --from=build-stage /build/release/scripts ${DEST_BUILD_DIR}/scripts
COPY --from=build-stage /build/release/test ${DEST_BUILD_DIR}/test
COPY --from=build-stage /build/release/userspace/falco/falco ${DEST_BUILD_DIR}/userspace/falco/falco
COPY --from=build-stage /build/release/userspace/falco/config_falco.h ${DEST_BUILD_DIR}/userspace/falco/config_falco.h
COPY --from=build-stage /build/release/falco-*.tar.gz ${DEST_BUILD_DIR}/
COPY --from=build-stage /build/release/falco-*.deb ${DEST_BUILD_DIR}/
COPY --from=build-stage /build/release/falco-*.rpm ${DEST_BUILD_DIR}/
