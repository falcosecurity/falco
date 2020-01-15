FROM alpine:latest
LABEL maintainer="opensource@sysdig.com"
RUN apk add --no-cache bash g++ curl
COPY ./event_generator.cpp /usr/local/bin
COPY ./docker-entrypoint.sh ./k8s_event_generator.sh /
COPY ./yaml /yaml
RUN mkdir -p /var/lib/rpm
RUN g++ --std=c++0x /usr/local/bin/event_generator.cpp -o /usr/local/bin/event_generator
RUN curl -o /usr/local/bin/kubectl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && chmod +x /usr/local/bin/kubectl
ENTRYPOINT ["/docker-entrypoint.sh"]
