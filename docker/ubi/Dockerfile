ARG UBI_VERSION
FROM registry.access.redhat.com/ubi8/ubi:${UBI_VERSION}

ARG FALCO_VERSION
RUN test -n "$FALCO_VERSION" || (echo "FALCO_VERSION  not set" && false)
ENV FALCO_VERSION=${FALCO_VERSION}

LABEL "name"="Falco Runtime Security"
LABEL "vendor"="Falco"
LABEL "version"="${FALCO_VERSION}"
LABEL "release"="${FALCO_VERSION}"
LABEL "ubi-version"="${UBI_VERSION}"
LABEL "summary"="Falco is a security policy engine that monitors system calls and cloud events, and fires alerts when security policies are violated."
LABEL "description"="Falco is a security policy engine that monitors system calls and cloud events, and fires alerts when security policies are violated."
LABEL "io.k8s.display-name"="Falco"
LABEL "io.k8s.description"="Falco is a security policy engine that monitors system calls and cloud events, and fires alerts when security policies are violated."
LABEL maintainer="cncf-falco-dev@lists.cncf.io"
LABEL usage="docker run -i -t --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc --name NAME IMAGE"


ENV HOST_ROOT /host
ENV HOME /root

RUN  dnf -y update && \
     dnf -y install \
	curl \
        make \
        cmake \
	gcc \
	llvm-toolset \
        clang \
        kmod \
	&& dnf -y clean all ; rm -rf /var/cache/{dnf,yum}

RUN mkdir /build && cd /build/ && curl --remote-name-all -L https://github.com/dell/dkms/archive/refs/tags/v3.0.3.tar.gz && \
     tar xvf v3.0.3.tar.gz && cd dkms-3.0.3 && make install-redhat && rm -rf /build

RUN mkdir /deploy && cd /deploy/ && curl --remote-name-all -L https://download.falco.org/packages/bin/x86_64/falco-${FALCO_VERSION}-x86_64.tar.gz && \
     cd / && tar --strip-components=1 -xvf /deploy/falco-${FALCO_VERSION}-x86_64.tar.gz && \
     rm -rf /deploy

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/bin/falco"]
