FROM fedora:31

LABEL name="falcosecurity/falco-tester"
LABEL usage="docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/..:/source -v $PWD/build:/build -e FALCO_VERSION=<current_falco_version> --name <name> falcosecurity/falco-tester test"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ENV FALCO_VERSION=
ENV BUILD_TYPE=release

RUN dnf install -y python2-pip python2 docker findutils jq unzip && dnf clean all
ENV PATH="/root/.local/bin/:${PATH}"
RUN pip2 install --user avocado-framework==69.0
RUN pip2 install --user avocado-framework-plugin-varianter-yaml-to-mux==69.0

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]
