FROM centos:7

LABEL maintainer="opensource@sysdig.com"

ARG FALCO_VERSION=
RUN test -n FALCO_VERSION
ENV FALCO_VERSION ${FALCO_VERSION}

RUN yum update -y
RUN yum install epel-release -y

ADD falco-${FALCO_VERSION}-x86_64.rpm /
RUN yum install -y /falco-${FALCO_VERSION}-x86_64.rpm

# Change the falco config within the container to enable ISO 8601 output.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /etc/falco/falco.yaml > /etc/falco/falco.yaml.new \
    && mv /etc/falco/falco.yaml.new /etc/falco/falco.yaml

# # The local container also copies some test trace files and
# # corresponding rules that are used when running regression tests.
# COPY source/testrules/*.yaml /rules/
# COPY traces/*.scap /traces/

VOLUME ["/rules"]
VOLUME ["/traces"]

CMD ["/usr/bin/falco"]
