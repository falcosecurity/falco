FROM centos:7

ENV FALCO_VERSION 0.1.1dev
ENV BUILD_TYPE Release

RUN yum -y install epel-release && \
    yum -y install \
      python-pip \
      docker \
      jq \
      unzip

RUN pip install avocado-framework avocado-framework-plugin-varianter-yaml-to-mux

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
