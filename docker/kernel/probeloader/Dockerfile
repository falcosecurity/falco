FROM golang:1.13-alpine AS build
ARG FALCOCTL_REF=feat/probe-installer

RUN apk --no-cache add build-base git gcc ca-certificates

RUN git clone https://github.com/falcosecurity/falcoctl.git /falcoctl

WORKDIR /falcoctl

RUN git checkout ${FALCOCTL_REF}
RUN go mod vendor
RUN CGO_ENABLED=0 GOOS=linux go build -a -o falcoctl -ldflags '-extldflags "-static"' .

FROM scratch
LABEL maintainer="opensource@sysdig.com"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /falcoctl/falcoctl /falcoctl
CMD ["/falcoctl", "install", "probe"]
