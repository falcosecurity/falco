FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY ./falco-sns /bin/

CMD ["/bin/falco-sns"]
