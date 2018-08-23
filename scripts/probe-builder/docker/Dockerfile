ARG FALCO_VERSION
FROM sysdig/falco:${FALCO_VERSION}

MAINTAINER Néstor Salceda <nestor.salceda@sysdig.com>

ARG FALCO_VERSION
ENV FALCO_VERSION ${FALCO_VERSION}

RUN ln -s /usr/bin/gcc /usr/local/bin/gcc-4.6
RUN ln -s /usr/bin/gcc /usr/local/bin/gcc-4.8
RUN ln -s /usr/bin/gcc /usr/local/bin/gcc-4.9

RUN mkdir /output /kernel

ENV OUTPUT /output
ENV KERNEL /kernel

VOLUME ["/output", "/kernel"]

COPY build /build

ENTRYPOINT ["/build"]
