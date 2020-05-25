FROM fedora:31

LABEL name="falcosecurity/falco-tester"
LABEL usage="docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/..:/source -v $PWD/build:/build --name <name> falcosecurity/falco-tester test"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ENV FALCO_VERSION=
ENV BUILD_TYPE=release

ADD https://github.com/fullstorydev/grpcurl/releases/download/v1.6.0/grpcurl_1.6.0_linux_x86_64.tar.gz /
RUN dnf install -y python-pip python docker findutils jq unzip && dnf clean all
ENV PATH="/root/.local/bin/:${PATH}"
RUN pip install --user avocado-framework==69.0
RUN pip install --user avocado-framework-plugin-varianter-yaml-to-mux==69.0
RUN tar -C /usr/bin -xvf grpcurl_1.6.0_linux_x86_64.tar.gz

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]
