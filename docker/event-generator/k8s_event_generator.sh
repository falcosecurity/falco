#!/bin/bash

set -euo pipefail

# You can pass a specific falco rule name and only yaml files matching
# that rule will be considered. The default is "all", meaning all yaml
# files will be applied.

RULE=${1:-all}

# Replace any '/' in RULES with a '.' and any space with a dash. (K8s
# label values can not contain slashes/spaces)
RULE=$(echo "$RULE" | tr '/ ' '.-')

echo "***Testing kubectl configuration..."
kubectl version --short

while true; do

    RET=$(kubectl get namespaces --output=name | grep falco-event-generator || true)

    if [[ "$RET" == *falco-event-generator* ]]; then
	echo "***Deleting existing falco-event-generator namespace..."
	kubectl delete namespace falco-event-generator
    fi

    echo "***Creating falco-event-generator namespace..."
    kubectl create namespace falco-event-generator

    for file in yaml/*.yaml; do

	MATCH=0
	if [[ "${RULE}" == "all" ]]; then
	    MATCH=1
	else
	    RET=$(grep -E "falco.rules:.*${RULE}" $file || true)
	    if [[ "$RET" != "" ]]; then
		MATCH=1
	    fi
	fi

	if [[ $MATCH == 1 ]]; then
	    MESSAGES=$(grep -E 'message' $file | cut -d: -f2 | tr '\n' ',')
	    RULES=$(grep -E 'falco.rules' $file | cut -d: -f2 | tr '\n' ',')

	    # The message uses dashes in place of spaces, convert them back to spaces
	    MESSAGES=$(echo "$MESSAGES" | tr '-' ' ' | sed -e 's/ *//' | sed  -e 's/,$//')
	    RULES=$(echo "$RULES" | tr '-' ' '| tr '.' '/' | sed -e 's/ *//' | sed  -e 's/,$//')

	    echo "***$MESSAGES (Rule(s) $RULES)..."
	    kubectl apply -f $file
	    sleep 2
	fi
    done

    sleep 10
done
