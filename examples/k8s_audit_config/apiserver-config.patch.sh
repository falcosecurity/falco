#!/bin/sh

IFS=''

FILENAME=${1:-/etc/kubernetes/manifests/kube-apiserver.yaml}
VARIANT=${2:-minikube}

if grep audit-webhook-config-file $FILENAME ; then
    echo audit-webhook patch already applied
    exit 0
fi

TMPFILE="/tmp/kube-apiserver.yaml.patched"
rm -f "$TMPFILE"

APISERVER_PREFIX="    -"
APISERVER_LINE="- kube-apiserver"

if [ $VARIANT == "kops" ]; then
    APISERVER_PREFIX="     "
    APISERVER_LINE="/usr/local/bin/kube-apiserver"
fi

while read LINE
do
    echo "$LINE" >> "$TMPFILE"
    case "$LINE" in
        *$APISERVER_LINE*)
            echo "$APISERVER_PREFIX --audit-log-path=/var/lib/k8s_audit/audit.log" >> "$TMPFILE"
            echo "$APISERVER_PREFIX --audit-policy-file=/var/lib/k8s_audit/audit-policy.yaml" >> "$TMPFILE"
            echo "$APISERVER_PREFIX --audit-webhook-config-file=/var/lib/k8s_audit/webhook-config.yaml" >> "$TMPFILE"
            echo "$APISERVER_PREFIX --audit-webhook-batch-max-wait=5s" >> "$TMPFILE"
            ;;
        *"volumeMounts:"*)
            echo "    - mountPath: /var/lib/k8s_audit/" >> "$TMPFILE"
            echo "      name: data" >> "$TMPFILE"
            ;;
        *"volumes:"*)
            echo "  - hostPath:" >> "$TMPFILE"
            echo "      path: /var/lib/k8s_audit" >> "$TMPFILE"
            echo "    name: data" >> "$TMPFILE"
            ;;

    esac
done < "$FILENAME"

cp "$FILENAME" "/tmp/kube-apiserver.yaml.original"
cp "$TMPFILE" "$FILENAME"

