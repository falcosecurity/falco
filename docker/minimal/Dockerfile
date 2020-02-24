FROM ubuntu:18.04 as ubuntu

LABEL maintainer="opensource@sysdig.com"

ARG FALCO_VERSION=0.20.0

ENV FALCO_VERSION=${FALCO_VERSION}

WORKDIR /

ADD https://s3.amazonaws.com/download.draios.com/stable/tgz/x86_64/falco-${FALCO_VERSION}-x86_64.tar.gz /

# ADD will download from URL and unntar
RUN apt-get update && \
    apt-get install -y libyaml-0-2 binutils && \
    # curl -O https://s3.amazonaws.com/download.draios.com/stable/tgz/x86_64/falco-${FALCO_VERSION}-x86_64.tar.gz && \
    tar xfzv falco-${FALCO_VERSION}-x86_64.tar.gz && \
    rm -f falco-${FALCO_VERSION}-x86_64.tar.gz && \
    mv falco-${FALCO_VERSION}-x86_64 falco && \
    strip falco/usr/bin/falco && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

FROM scratch

COPY --from=ubuntu /lib/x86_64-linux-gnu/libanl.so.1 \
    /lib/x86_64-linux-gnu/libc.so.6 \
    /lib/x86_64-linux-gnu/libdl.so.2 \
    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
    /lib/x86_64-linux-gnu/libm.so.6 \
    /lib/x86_64-linux-gnu/libnsl.so.1 \
    /lib/x86_64-linux-gnu/libnss_compat.so.2 \
    /lib/x86_64-linux-gnu/libnss_files.so.2 \
    /lib/x86_64-linux-gnu/libnss_nis.so.2 \
    /lib/x86_64-linux-gnu/libpthread.so.0 \
    /lib/x86_64-linux-gnu/librt.so.1 \
    /lib/x86_64-linux-gnu/libz.so.1 \
    /lib/x86_64-linux-gnu/

COPY --from=ubuntu /usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
    /usr/lib/x86_64-linux-gnu/libstdc++.so.6

COPY --from=ubuntu /usr/lib/x86_64-linux-gnu/libyaml-0.so.2.0.5 \
    /usr/lib/x86_64-linux-gnu/libyaml-0.so.2

COPY --from=ubuntu /etc/ld.so.cache \
    /etc/nsswitch.conf \
    /etc/ld.so.cache \
    /etc/passwd \
    /etc/group \
    /etc/

COPY --from=ubuntu /etc/default/nss /etc/default/nss
COPY --from=ubuntu /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2

COPY --from=ubuntu /falco /

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true"]
