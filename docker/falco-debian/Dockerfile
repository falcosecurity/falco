FROM debian:12-slim

LABEL maintainer="cncf-falco-dev@lists.cncf.io"
LABEL org.opencontainers.image.source="https://github.com/falcosecurity/falco/docker/falco-debian"

LABEL usage="docker run -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro --name NAME IMAGE"

ARG FALCO_VERSION
ARG VERSION_BUCKET=deb

ENV FALCO_VERSION=${FALCO_VERSION}
ENV VERSION_BUCKET=${VERSION_BUCKET}

ENV HOST_ROOT /host
ENV HOME /root

RUN apt-get -y update && apt-get -y install ca-certificates curl jq libelf1 ca-certificates \
    && apt clean -y && rm -rf /var/lib/apt/lists/*

WORKDIR /

RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add - \
	&& echo "deb https://download.falco.org/packages/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
	&& apt-get update -y \
	&& if [ "$FALCO_VERSION" = "latest" ]; then FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco; else FALCO_DRIVER_CHOICE=none apt-get install -y --no-install-recommends falco=${FALCO_VERSION}; fi \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*
	
# Falcoctl is not included here.
RUN rm -rf /usr/bin/falcoctl /etc/falcoctl/

RUN sed -e -i 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml

CMD ["/usr/bin/falco"]
