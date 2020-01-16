FROM fedora:28

LABEL name="falcosecurity/falco-tester"
LABEL usage="docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/..:/source -v $PWD/build:/build -e FALCO_VERSION=<current_falco_version> --name <name> falcosecurity/falco-tester test"
LABEL maintainer="opensource@sysdig.com"

ENV FALCO_VERSION=
ENV BUILD_TYPE=release

RUN curl https://avocado-project.org/data/repos/avocado-fedora.repo -o /etc/yum.repos.d/avocado.repo && \
    dnf install -y docker findutils jq unzip python2-avocado python2-avocado-plugins-varianter-yaml-to-mux compat-openssl10 && dnf clean all

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]
