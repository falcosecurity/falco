ARG FALCO_IMAGE_TAG=latest
FROM falcosecurity/falco:${FALCO_IMAGE_TAG}

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

LABEL usage="docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --name NAME IMAGE"

ENV HOST_ROOT /host
ENV HOME /root

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]