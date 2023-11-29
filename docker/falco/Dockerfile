FROM debian:bookworm

LABEL maintainer="cncf-falco-dev@lists.cncf.io"
LABEL org.opencontainers.image.source="https://github.com/falcosecurity/falco"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc --name NAME IMAGE"

ARG TARGETARCH

ARG FALCO_VERSION=latest
ARG VERSION_BUCKET=deb
ENV VERSION_BUCKET=${VERSION_BUCKET}

ENV FALCO_VERSION=${FALCO_VERSION}
ENV HOST_ROOT /host
ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	bc \
	bison \
	ca-certificates \
	clang \
	curl \
	dkms \
	dwarves \
	flex \
	gcc \
	gcc-11 \
	gnupg2 \
	jq \
	libc6-dev \
	libelf-dev \
	libssl-dev \
	llvm \
	make \
	netcat-openbsd \
	patchelf \
	xz-utils \
	&& rm -rf /var/lib/apt/lists/*

RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add - \
	&& echo "deb https://download.falco.org/packages/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
	&& apt-get update -y \
	&& if [ "$FALCO_VERSION" = "latest" ]; then apt-get install -y --no-install-recommends falco; else apt-get install -y --no-install-recommends falco=${FALCO_VERSION}; fi \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601
# output.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml > /etc/falco/falco.yaml.new \
	&& mv /etc/falco/falco.yaml.new /etc/falco/falco.yaml

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
