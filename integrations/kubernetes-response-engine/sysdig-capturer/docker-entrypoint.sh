#!/bin/bash

set -eo

echo "* Setting up /usr/src links from host"

for i in $(ls $SYSDIG_HOST_ROOT/usr/src)
do
        ln -s $SYSDIG_HOST_ROOT/usr/src/$i /usr/src/$i
done

/usr/bin/sysdig-probe-loader

sysdig -S -M $CAPTURE_DURATION -pk -z -w /captures/$CAPTURE_FILE_NAME.scap.gz

if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ] && [ -n "$AWS_S3_BUCKET" ]; then
  s3cmd --access_key=$AWS_ACCESS_KEY_ID \
        --secret_key=$AWS_SECRET_ACCESS_KEY \
        put /captures/$CAPTURE_FILE_NAME.scap.gz $AWS_S3_BUCKET
fi
