ARG FALCO_IMAGE_TAG=latest
FROM docker.io/falcosecurity/falco:${FALCO_IMAGE_TAG}-debian

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

LABEL usage="docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro falcosecurity/falco-driver-loader:latest [driver] [options]"

ENV HOST_ROOT=/host
ENV HOME=/root

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
	libssl-dev \
	llvm \
	make \
	netcat-openbsd \
	patchelf \
	xz-utils \
	zstd \
	&& rm -rf /var/lib/apt/lists/*

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

COPY ./docker/driver-loader/docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
