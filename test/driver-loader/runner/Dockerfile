FROM ubuntu:18.04

ARG FALCO_VERSION=
RUN test -n FALCO_VERSION
ENV FALCO_VERSION ${FALCO_VERSION}
ENV DRIVER_VERSION=
ENV HOST_ROOT=/host

# Minimal set of deps required to run falco-driver-loader and falco
RUN apt-get update -y
RUN apt-get install -y --no-install-recommends \
	ca-certificates \
	libyaml-0-2 \
	dkms \
	curl \
	gcc \
	clang-7 \
	llvm-7 \
	libelf-dev

RUN rm -rf /usr/bin/clang \
	&& rm -rf /usr/bin/llc \
	&& ln -s /usr/bin/clang-7 /usr/bin/clang \
	&& ln -s /usr/bin/llc-7 /usr/bin/llc

RUN rm -rf /lib/modules \
	&& ln -s $HOST_ROOT/lib/modules /lib/modules

ADD falco-${FALCO_VERSION}-x86_64.tar.gz /
RUN cp -R /falco-${FALCO_VERSION}-x86_64/* /

COPY test.sh /
CMD /test.sh