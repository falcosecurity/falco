FROM docker:stable-dind

RUN set -ex \
    && apk add --no-cache \
    bash curl

COPY start-cron-and-dind.sh /usr/local/bin

ENTRYPOINT ["start-cron-and-dind.sh"]
CMD []


