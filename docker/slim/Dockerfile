FROM ubuntu:18.04

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

LABEL RUN="docker run -i -t -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro --name <name> <image>"

ARG VERSION_BUCKET=deb

ENV VERSION_BUCKET=${VERSION_BUCKET}

ENV HOST_ROOT /host
ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  # bash-completion \
  # bc \
  ca-certificates \
  curl \
  gnupg2 \
  jq \
  # netcat \
  # xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add - \
  && echo "deb https://dl.bintray.com/falcosecurity/${VERSION_BUCKET} stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list \
  && apt-get update -y \
  && apt-get install -y --no-install-recommends falco \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Change the falco config within the container to enable ISO 8601
# output.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml > /etc/falco/falco.yaml.new \
  && mv /etc/falco/falco.yaml.new /etc/falco/falco.yaml

# Some base images have an empty /lib/modules by default
# If it's not empty, docker build will fail instead of
# silently overwriting the existing directory
RUN rm -df /lib/modules \
  && ln -s $HOST_ROOT/lib/modules /lib/modules

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true"]
