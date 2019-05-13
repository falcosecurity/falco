FROM registry.access.redhat.com/rhel7

MAINTAINER Sysdig Support Team <support@sysdig.com>

### Atomic/OpenShift Labels - https://github.com/projectatomic/ContainerApplicationGenericLabels
LABEL name="falco" \
      vendor="Sysdig" \
      url="http://falco.org/" \
      summary="Container Native runtime security" \
      description="Falco is an open source project for intrusion and abnormality detection for Cloud Native platforms." \
      run='docker run -d --name falco --restart always --privileged --net host --pid host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --shm-size=350m registry.connect.redhat.com/sysdig/falco'

COPY help.md /tmp/

ENV SYSDIG_HOST_ROOT /host
ENV HOME /root

ADD http://download.draios.com/stable/rpm/draios.repo /etc/yum.repos.d/draios.repo
RUN rpm --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public && \
    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum clean all && \
    REPOLIST=rhel-7-server-rpms,rhel-7-server-optional-rpms,epel,draios \
    INSTALL_PKGS="gcc dkms kernel-devel kernel-headers python golang-github-cpuguy83-go-md2man falco" && \
    yum -y update-minimal --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
      --security --sec-severity=Important --sec-severity=Critical && \
    yum -y install --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs ${INSTALL_PKGS} && \
### help file markdown to man conversion
    go-md2man -in /tmp/help.md -out /help.1 && \
### we delete everything on /usr/src/kernels otherwise it messes up docker-entrypoint.sh
    rm -fr /usr/src/kernels && \
    rm -df /lib/modules && ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules && \
    yum clean all

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
