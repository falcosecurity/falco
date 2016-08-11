FROM alpine:latest
RUN apk add --no-cache bash g++
COPY ./event_generator.cpp /usr/local/bin
RUN mkdir -p /var/lib/rpm
RUN g++ --std=c++0x /usr/local/bin/event_generator.cpp -o /usr/local/bin/event_generator
CMD ["/usr/local/bin/event_generator"]
