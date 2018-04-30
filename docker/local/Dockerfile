FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

ENV FALCO_VERSION 0.1.1dev

LABEL RUN="docker run -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro --name NAME IMAGE"

ENV SYSDIG_HOST_ROOT /host

ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

ADD http://download.draios.com/apt-draios-priority /etc/apt/preferences.d/

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
	bash-completion \
	ca-certificates \
	curl \
	dkms \
	gnupg2 \
	gcc \
	gcc-5 \
	jq \
	libc6-dev \
	libelf-dev \
 && rm -rf /var/lib/apt/lists/*

# Since our base Debian image ships with GCC 7 which breaks older kernels, revert the
# default to gcc-5.
RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc

RUN ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

ADD falco-${FALCO_VERSION}-x86_64.deb /
RUN dpkg -i /falco-${FALCO_VERSION}-x86_64.deb

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
