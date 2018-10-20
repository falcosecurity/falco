#!/bin/sh

IFS=''

FILENAME="/etc/kubernetes/manifests/kube-apiserver.yaml"

if grep audit-webhook-config-file $FILENAME ; then
    echo audit-webhook patch already applied
    exit 0
fi

TMPFILE="/tmp/kube-apiserver.yaml.patched"
rm -f "$TMPFILE"

while read LINE
do
    echo "$LINE" >> "$TMPFILE"
    case "$LINE" in
        *"- kube-apiserver"*)
            echo "    - --audit-log-path=/tmp/k8s_audit_config/audit.log" >> "$TMPFILE"
            echo "    - --audit-policy-file=/tmp/k8s_audit_config/audit-policy.yaml" >> "$TMPFILE"
            echo "    - --audit-webhook-config-file=/tmp/k8s_audit_config/webhook-config.yaml" >> "$TMPFILE"
            echo "    - --audit-webhook-batch-max-wait=5s" >> "$TMPFILE"
            ;;
        *"volumeMounts:"*)
            echo "    - mountPath: /tmp/k8s_audit_config/" >> "$TMPFILE"
            echo "      name: data" >> "$TMPFILE"
            ;;
        *"volumes:"*)
            echo "  - hostPath:" >> "$TMPFILE"
            echo "      path: /tmp/k8s_audit_config" >> "$TMPFILE"
            echo "    name: data" >> "$TMPFILE"
            ;;

    esac
done < "$FILENAME"

cp "$FILENAME" "/tmp/kube-apiserver.yaml.original"
cp "$TMPFILE" "$FILENAME"

