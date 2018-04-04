#!/bin/sh

# Start docker-in-docker, but backgrounded with its output still going
# to stdout/stderr.
dockerd-entrypoint.sh &

# Start cron in the foreground with a moderate level of debugging to
# see job output.
crond -f -d 6


