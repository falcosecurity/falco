#!/bin/sh

set -euo pipefail

IFS=''

FILENAME=${1:-/etc/kubernetes/manifests/kube-apiserver.yaml}
VARIANT=${2:-minikube}
AUDIT_TYPE=${3:-static}

if [ $AUDIT_TYPE == "static" ]; then
    if grep audit-webhook-config-file $FILENAME ; then
	echo audit-webhook patch already applied
	exit 0
    fi
else
    if grep audit-dynamic-configuration $FILENAME ; then
	echo audit-dynamic-configuration patch already applied
	exit 0
    fi
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
	    if [[ ($AUDIT_TYPE == "static" || $AUDIT_TYPE == "dynamic+log") ]]; then
		echo "$APISERVER_PREFIX --audit-log-path=/var/lib/k8s_audit/audit.log" >> "$TMPFILE"
		echo "$APISERVER_PREFIX --audit-policy-file=/var/lib/k8s_audit/audit-policy.yaml" >> "$TMPFILE"
		if [[ $AUDIT_TYPE == "static" ]]; then
		    echo "$APISERVER_PREFIX --audit-webhook-config-file=/var/lib/k8s_audit/webhook-config.yaml" >> "$TMPFILE"
		    echo "$APISERVER_PREFIX --audit-webhook-batch-max-wait=5s" >> "$TMPFILE"
		fi
	    fi
	    if [[ ($AUDIT_TYPE == "dynamic" || $AUDIT_TYPE == "dynamic+log") ]]; then
		echo "$APISERVER_PREFIX --audit-dynamic-configuration" >> "$TMPFILE"
		echo "$APISERVER_PREFIX --feature-gates=DynamicAuditing=true" >> "$TMPFILE"
		echo "$APISERVER_PREFIX --runtime-config=auditregistration.k8s.io/v1alpha1=true" >> "$TMPFILE"
	    fi
            ;;
        *"volumeMounts:"*)
	    if [[ ($AUDIT_TYPE == "static" || $AUDIT_TYPE == "dynamic+log") ]]; then
		echo "    - mountPath: /var/lib/k8s_audit/" >> "$TMPFILE"
		echo "      name: data" >> "$TMPFILE"
	    fi
            ;;
        *"volumes:"*)
	    if [[ ($AUDIT_TYPE == "static" || $AUDIT_TYPE == "dynamic+log") ]]; then
		echo "  - hostPath:" >> "$TMPFILE"
		echo "      path: /var/lib/k8s_audit" >> "$TMPFILE"
		echo "    name: data" >> "$TMPFILE"
	    fi
            ;;

    esac
done < "$FILENAME"

cp "$FILENAME" "/tmp/kube-apiserver.yaml.original"
cp "$TMPFILE" "$FILENAME"

