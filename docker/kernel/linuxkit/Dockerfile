ARG ALPINE_VERSION=3.10
ARG KERNEL_VERSION=4.9.184
ARG FALCO_VERSION=0.20.0

FROM linuxkit/kernel:${KERNEL_VERSION} AS ksrc
FROM falcosecurity/falco:${FALCO_VERSION}-minimal as falco
FROM alpine:${ALPINE_VERSION} AS probe-build
LABEL maintainer="cncf-falco-dev@lists.cncf.io"
ARG KERNEL_VERSION=4.9.184
ARG FALCO_VERSION=0.20.0
ENV FALCO_VERSION=${FALCO_VERSION}
ENV KERNEL_VERSION=${KERNEL_VERSION}

COPY --from=ksrc /kernel-dev.tar /
COPY --from=falco /usr/src/falco-${FALCO_VERSION} /usr/src/falco-${FALCO_VERSION}

RUN apk add --no-cache --update \
  build-base gcc abuild binutils \
  bc \
  autoconf && \
  export KERNELVER=`uname -r  | cut -d '-' -f 1`  && \
  export KERNELDIR=/usr/src/linux-headers-${KERNEL_VERSION}-linuxkit/ && \
  tar xf /kernel-dev.tar && \
  cd $KERNELDIR && \
  zcat /proc/1/root/proc/config.gz > .config && \
  make olddefconfig && \
  cd /usr/src/falco-${FALCO_VERSION} && \
  make && \
  apk del \
  build-base gcc abuild binutils \
  bc \
  autoconf

FROM alpine:${ALPINE_VERSION}
ARG FALCO_VERSION=0.20.0
ENV FALCO_VERSION=${FALCO_VERSION}
COPY --from=probe-build /usr/src/falco-${FALCO_VERSION}/falco-probe.ko /
CMD ["insmod","/falco-probe.ko"]
