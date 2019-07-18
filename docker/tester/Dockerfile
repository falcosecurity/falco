FROM centos:7

LABEL name="falcosecurity/falco-tester"
LABEL usage="docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/..:/source -v $PWD/build:/build -e FALCO_VERSION=<current_falco_version> --name <name> falcosecurity/falco-tester test"
LABEL maintainer="opensource@sysdig.com"

ENV FALCO_VERSION=
ENV BUILD_TYPE=release

RUN yum -y install epel-release && yum clean all -y && \
    yum -y install python-pip docker jq unzip && yum clean all -y

RUN pip install avocado-framework avocado-framework-plugin-varianter-yaml-to-mux

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]