#!/usr/bin/env bash

set -euo pipefail

VARIANT=${1:-minikube}
AUDIT_TYPE=${2:-static}

if [ "$VARIANT" == "minikube" ]; then
    APISERVER_HOST=$(minikube ip)
    SSH_KEY=$(minikube ssh-key)
    SSH_USER="docker"
    MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"
fi

if [ "$VARIANT" == "kops" ]; then
    # APISERVER_HOST=api.your-kops-cluster-name.com
    SSH_KEY=~/.ssh/id_rsa
    SSH_USER="admin"
    MANIFEST=/etc/kubernetes/manifests/kube-apiserver.manifest

    if [ -z "${APISERVER_HOST+xxx}" ]; then
	echo "***You must specify APISERVER_HOST with the name of your kops api server"
	exit 1
    fi
fi

echo "***Copying apiserver config patch script to apiserver..."
ssh -i $SSH_KEY "$SSH_USER@$APISERVER_HOST" "sudo mkdir -p /var/lib/k8s_audit && sudo chown $SSH_USER /var/lib/k8s_audit"
scp -i $SSH_KEY apiserver-config.patch.sh "$SSH_USER@$APISERVER_HOST:/var/lib/k8s_audit"

if [ "$AUDIT_TYPE" == "static" ]; then
    echo "***Copying audit policy/webhook files to apiserver..."
    scp -i $SSH_KEY audit-policy.yaml "$SSH_USER@$APISERVER_HOST:/var/lib/k8s_audit"
    scp -i $SSH_KEY webhook-config.yaml "$SSH_USER@$APISERVER_HOST:/var/lib/k8s_audit"
fi

if [ "$AUDIT_TYPE" == "dynamic+log" ]; then
    echo "***Copying audit policy file to apiserver..."
    scp -i $SSH_KEY audit-policy.yaml "$SSH_USER@$APISERVER_HOST:/var/lib/k8s_audit"
fi

echo "***Modifying k8s apiserver config (will result in apiserver restarting)..."

ssh -i $SSH_KEY "$SSH_USER@$APISERVER_HOST" "sudo bash /var/lib/k8s_audit/apiserver-config.patch.sh $MANIFEST $VARIANT $AUDIT_TYPE"

echo "***Done!"
