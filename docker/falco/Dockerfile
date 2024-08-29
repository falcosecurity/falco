FROM cgr.dev/chainguard/wolfi-base

LABEL maintainer="cncf-falco-dev@lists.cncf.io"
LABEL org.opencontainers.image.source="https://github.com/falcosecurity/falco"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro  -v /etc:/host/etc:ro falcosecurity/falco:latest"
# NOTE: for the "least privileged" use case, please refer to the official documentation

ARG FALCO_VERSION
ARG VERSION_BUCKET=bin

ENV FALCO_VERSION=${FALCO_VERSION}
ENV VERSION_BUCKET=${VERSION_BUCKET}
ENV HOST_ROOT /host
ENV HOME /root

RUN apk update && apk add curl ca-certificates jq libelf libstdc++

WORKDIR /

RUN FALCO_VERSION_URLENCODED=$(echo -n ${FALCO_VERSION}|jq -sRr @uri) && \
    curl -L -o falco.tar.gz \
    https://download.falco.org/packages/${VERSION_BUCKET}/$(uname -m)/falco-${FALCO_VERSION_URLENCODED}-$(uname -m).tar.gz && \
    tar -xvf falco.tar.gz && \
    rm -f falco.tar.gz && \
    mv falco-${FALCO_VERSION}-$(uname -m) falco && \
    rm -rf /falco/usr/src/falco-* && \
    cp -r /falco/* / && \
    rm -rf /falco

RUN sed -i -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' /etc/falco/falco.yaml

# Falcoctl is not included here.
RUN rm -rf /usr/bin/falcoctl /etc/falcoctl/

CMD ["/usr/bin/falco"]
