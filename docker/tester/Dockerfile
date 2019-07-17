FROM centos:7

ENV FALCO_VERSION=
ENV BUILD_TYPE=release

RUN yum -y install epel-release && yum clean all -y && \
    yum -y install python-pip docker jq unzip && yum clean all -y

RUN pip install avocado-framework avocado-framework-plugin-varianter-yaml-to-mux

COPY ./root /

ENTRYPOINT ["entrypoint"]
CMD ["usage"]