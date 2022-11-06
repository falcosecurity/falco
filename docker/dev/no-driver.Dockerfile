FROM ubuntu:22.04 AS builder

COPY ./falco.tar.gz /

WORKDIR /

# 1. We remove the Falco directory with the name related to the version and the arch
# 2. We remove the source folder
# 3. We remove the `falco-driver-loader` binary
RUN mkdir falco; \
    tar -xzf falco.tar.gz -C falco --strip-component 1; \
    rm -rf /falco/usr/src; \
    rm /falco/usr/bin/falco-driver-loader

# the time displayed in log messages and output messages will be in ISO 8601.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /falco/etc/falco/falco.yaml > /falco/etc/falco/falco.yaml.new; \
    mv /falco/etc/falco/falco.yaml.new /falco/etc/falco/falco.yaml

FROM debian:11-slim

COPY --from=builder /falco /

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true", "--modern-bpf"]
