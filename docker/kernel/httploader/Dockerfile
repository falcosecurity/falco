FROM golang:alpine AS build

RUN apk --no-cache add build-base git bzr mercurial gcc ca-certificates

ADD ./httploader /src
RUN cd /src && go get golang.org/x/sys/unix && CGO_ENABLED=0 GOOS=linux go build -a -o httploader -ldflags '-extldflags "-static"' .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/httploader /
ENTRYPOINT /httploader