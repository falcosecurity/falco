ARG FALCO_IMAGE_TAG=latest
FROM docker.io/falcosecurity/falco:${FALCO_IMAGE_TAG}-debian

LABEL maintainer="cncf-falco-dev@lists.cncf.io"
LABEL org.opencontainers.image.source="https://github.com/falcosecurity/falco"

LABEL usage="docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --name NAME IMAGE"

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
	zstd \
	&& rm -rf /var/lib/apt/lists/*
	
# Install latest falcoctl
RUN curl -L -o falcoct.tar.gz $(curl -s "https://api.github.com/repos/falcosecurity/falcoctl/releases/latest" | jq -r '.assets[] | select(.name|test(".linux_$TARGETARCH.tar.gz")) | .browser_download_url') && tar -xvf falcoctl.tar.gz && mv falcoctl /usr/bin

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
