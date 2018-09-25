FROM alpine:latest
MAINTAINER Néstor Salceda<nestor.salceda@sysdig.com>

RUN apk add --no-cache ca-certificates

COPY ./falco-sns /bin/

CMD ["/bin/falco-sns"]
