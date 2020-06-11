FROM alpine

RUN apk add \
    bash \
    gawk \
    grep \
	curl \
    dpkg \
	rpm2cpio \
	git \
	jq \
	multipath-tools \
	py3-lxml \
	wget \
    docker

ADD . /builder
WORKDIR /builder
ENTRYPOINT [ "/builder/main-builder-entrypoint.sh" ]
