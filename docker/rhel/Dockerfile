FROM registry.access.redhat.com/rhel7

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

### Atomic/OpenShift Labels - https://github.com/projectatomic/ContainerApplicationGenericLabels
LABEL name="falco"
LABEL vendor="falcosecurity"
LABEL url="http://falco.org"
LABEL summary="Cloud Native Runtime Security"
LABEL description="Falco is an open-source project for intrusion and abnormality detection for Cloud Native platforms."
LABEL run='docker run -d --name falco --restart always --privileged --net host --pid host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --shm-size=350m <image>'

COPY help.md /tmp/

ENV HOST_ROOT /host
ENV HOME /root

ADD https://falco.org/repo/falcosecurity-rpm.repo /etc/yum.repos.d/falcosecurity.repo
RUN rpm --import https://falco.org/repo/falcosecurity-3672BA8F.asc && \
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
    rm -df /lib/modules && ln -s $HOST_ROOT/lib/modules /lib/modules && \
    yum clean all

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/falco"]
