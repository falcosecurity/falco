FROM debian:12-slim

LABEL org.opencontainers.image.authors='The Falco Authors https://falco.org' \
      org.opencontainers.image.url='https://falco.org' \
      org.opencontainers.image.source='https://github.com/falcosecurity/falco' \
      org.opencontainers.image.vendor='Falco Organization' \
      org.opencontainers.image.licenses='Apache-2.0' \
      maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro -v /etc:/host/etc:ro falcosecurity/falco:latest-debian"

ARG FALCO_VERSION
ARG VERSION_BUCKET=deb

ENV FALCO_VERSION=${FALCO_VERSION}
ENV VERSION_BUCKET=${VERSION_BUCKET}

ENV HOST_ROOT /host
ENV HOME /root

RUN apt-get -y update && apt-get -y install ca-certificates curl jq ca-certificates gnupg2 \
	&& apt clean -y && rm -rf /var/lib/apt/lists/*

WORKDIR /

RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add - \
	&& echo "deb https://download.falco.org/packages/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
	&& apt-get update -y \
	&& if [ "$FALCO_VERSION" = "latest" ]; then FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco; else FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco=${FALCO_VERSION}; fi \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601 output.
ADD ./config/falco.iso8601_timeformat.yaml /etc/falco/config.d/

CMD ["/usr/bin/falco"]
