FROM linuxkit/kernel:4.9.184 AS ksrc
FROM alpine:3.4 AS probe-build
ARG FALCOVER=0.17.0
ARG SYSDIGVER=0.26.2

COPY --from=ksrc /kernel-dev.tar /

RUN apk add --no-cache --update wget ca-certificates \
    build-base gcc abuild binutils \
    bc \
    cmake \
    git \
    autoconf && \
  export KERNELVER=`uname -r  | cut -d '-' -f 1`  && \
  export KERNELDIR=/usr/src/linux-headers-4.9.184-linuxkit/ && \
  tar xf /kernel-dev.tar && \
  cd $KERNELDIR && \
  zcat /proc/1/root/proc/config.gz > .config && \
  make olddefconfig && \
  mkdir -p /falco/build && \
  mkdir /src && \
  cd /src && \
  wget https://github.com/falcosecurity/falco/archive/$FALCOVER.tar.gz && \
  tar zxf $FALCOVER.tar.gz && \
  wget https://github.com/draios/sysdig/archive/$SYSDIGVER.tar.gz && \
  tar zxf $SYSDIGVER.tar.gz && \
  mv sysdig-$SYSDIGVER sysdig && \ 
  cd /falco/build && \
  cmake /src/falco-$FALCOVER && \
  make driver && \
  rm -rf /src && \
  apk del wget ca-certificates \
    build-base gcc abuild binutils \
    bc \
    cmake \
    git \
    autoconf

FROM alpine:3.4
COPY --from=probe-build /falco/build/driver/falco-probe.ko /
CMD ["insmod","/falco-probe.ko"] 
