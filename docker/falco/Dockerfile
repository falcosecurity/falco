FROM ubuntu:bionic

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc --name NAME IMAGE"

ARG FALCO_VERSION=latest

ENV FALCO_VERSION=${FALCO_VERSION}
ARG VERSION_BUCKET=deb
ENV VERSION_BUCKET=${VERSION_BUCKET}

ENV HOST_ROOT /host
ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	ca-certificates \
	gnupg2 \
	&& echo "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu bionic main" >> /etc/apt/sources.list \
	&& apt-key adv --keyserver keyserver.ubuntu.com --recv 1E9377A2BA9EF27F \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
	bash-completion \
	bc \
	clang-7 \
	curl \
	dkms \
	gcc-5 \
	gcc-6 \
	gcc-7 \
	gcc-8 \
	gcc-9 \
	jq \
	libc6-dev \
	libelf-dev \
	libmpx2 \
	llvm-7 \
	netcat \
	xz-utils \
	&& rm -rf /var/lib/apt/lists/*

# Since our base Debian image ships with GCC 7 which breaks older kernels, revert the
# default to gcc-5.
RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc

RUN rm -rf /usr/bin/clang \
	&& rm -rf /usr/bin/llc \
	&& ln -s /usr/bin/clang-7 /usr/bin/clang \
	&& ln -s /usr/bin/llc-7 /usr/bin/llc

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

RUN curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add - \
	&& echo "deb https://dl.bintray.com/falcosecurity/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
	&& apt-get update -y \
	&& if [ "$FALCO_VERSION" = "latest" ]; then apt-get install -y --no-install-recommends falco; else apt-get install -y --no-install-recommends falco=${FALCO_VERSION}; fi \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601
# output.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml > /etc/falco/falco.yaml.new \
	&& mv /etc/falco/falco.yaml.new /etc/falco/falco.yaml


COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
