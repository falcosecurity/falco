FROM cgr.dev/chainguard/wolfi-base

ARG FALCO_COMMIT_SHA
ARG FALCO_VERSION

LABEL org.opencontainers.image.authors='The Falco Authors https://falco.org' \
      org.opencontainers.image.url='https://falco.org' \
      org.opencontainers.image.source='https://github.com/falcosecurity/falco' \
      org.opencontainers.image.vendor='Falco Organization' \
      org.opencontainers.image.licenses='Apache-2.0' \
      org.opencontainers.image.revision=${FALCO_COMMIT_SHA} \
      org.opencontainers.image.version=${FALCO_VERSION} \
      maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro  -v /etc:/host/etc:ro falcosecurity/falco:latest"
# NOTE: for the "least privileged" use case, please refer to the official documentation

ARG VERSION_BUCKET=bin
ARG HOST_ROOT=/host
ARG HOME=/root

ENV FALCO_VERSION="${FALCO_VERSION}" \
    VERSION_BUCKET="${VERSION_BUCKET}" \
    HOST_ROOT="${HOST_ROOT}" \
    HOME="${HOME}"

RUN apk update && apk add curl ca-certificates jq libstdc++

WORKDIR /

RUN ARCH=$(uname -m) && \
    FALCO_VERSION_URLENCODED=$(echo -n "${FALCO_VERSION}" | jq -sRr @uri) && \
    echo "Downloading Falco ${FALCO_VERSION} for ${ARCH}" && \
    curl -L -o falco.tar.gz \
    https://download.falco.org/packages/${VERSION_BUCKET}/${ARCH}/falco-${FALCO_VERSION_URLENCODED}-${ARCH}.tar.gz && \
    tar -xvf falco.tar.gz && \
    rm -f falco.tar.gz && \
    mv falco-${FALCO_VERSION}-${ARCH} falco && \
    rm -rf /falco/usr/src/falco-* && \
    cp -r /falco/* / && \
    rm -rf /falco && \
    rm -rf /usr/bin/falcoctl /etc/falcoctl/


# Change the falco config within the container to enable ISO 8601 output.
ADD config/falco.iso8601_timeformat.yaml /etc/falco/config.d/

CMD ["/usr/bin/falco"]
