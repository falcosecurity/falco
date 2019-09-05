FROM golang:alpine AS build

RUN apk --no-cache add build-base git bzr mercurial gcc ca-certificates

COPY ./pkg /src/pkg/
COPY ./cmd /src/cmd/
COPY ./go.mod ./go.sum /src/

RUN cd /src && CGO_ENABLED=0 GOOS=linux go build -a -o httploader -ldflags '-extldflags "-static"' cmd/httploader/main.go

FROM scratch
LABEL maintainer="opensource@sysdig.com"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/httploader /httploader
CMD [ "/httploader" ]
