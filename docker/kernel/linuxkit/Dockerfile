FROM linuxkit/kernel:4.9.184 AS ksrc
FROM falcosecurity/falco-minimal as falco
FROM alpine:3.10 AS probe-build
ARG FALCO_VERSION=0.17.0

COPY --from=ksrc /kernel-dev.tar /
COPY --from=falco /usr/src/falco-${FALCO_VERSION} /usr/src/falco-${FALCO_VERSION}

RUN apk add --no-cache --update \
    build-base gcc abuild binutils \
    bc \
    autoconf && \
  export KERNELVER=`uname -r  | cut -d '-' -f 1`  && \
  export KERNELDIR=/usr/src/linux-headers-4.9.184-linuxkit/ && \
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

FROM alpine:3.10
ARG FALCO_VERSION=0.17.0
COPY --from=probe-build /usr/src/falco-${FALCO_VERSION}/falco-probe.ko /
CMD ["insmod","/falco-probe.ko"] 
