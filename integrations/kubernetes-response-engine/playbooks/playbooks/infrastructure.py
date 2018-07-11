import os
import json

from kubernetes import client, config
import requests


class KubernetesClient:
    def __init__(self):
        if 'KUBERNETES_LOAD_KUBE_CONFIG' in os.environ:
            config.load_kube_config()
        else:
            config.load_incluster_config()

        self._v1 = client.CoreV1Api()

    def delete_pod(self, name):
        namespace = self._find_pod_namespace(name)
        body = client.V1DeleteOptions()
        self._v1.delete_namespaced_pod(name=name,
                                       namespace=namespace,
                                       body=body)

    def exists_pod(self, name):
        response = self._v1.list_pod_for_all_namespaces(watch=False)
        for item in response.items:
            if item.metadata.name == name:
                if item.metadata.deletion_timestamp is None:
                    return True

        return False

    def _find_pod_namespace(self, name):
        response = self._v1.list_pod_for_all_namespaces(watch=False)
        for item in response.items:
            if item.metadata.name == name:
                return item.metadata.namespace

    def find_node_running_pod(self, name):
        response = self._v1.list_pod_for_all_namespaces(watch=False)
        for item in response.items:
            if item.metadata.name == name:
                return item.spec.node_name

    def taint_node(self, name, key, value, effect):
        body = client.V1Node(
            spec=client.V1NodeSpec(
                taints=[
                    client.V1Taint(key=key, value=value, effect=effect)
                ]
            )
        )

        return self._v1.patch_node(name, body)

    def add_label_to_pod(self, name, label, value):
        namespace = self._find_pod_namespace(name)

        body = client.V1Pod(
            metadata=client.V1ObjectMeta(
                labels={label: value}
            )
        )

        return self._v1.patch_namespaced_pod(name, namespace, body)


class SlackClient:
    def __init__(self, slack_webhook_url):
        self._slack_webhook_url = slack_webhook_url

    def post_message(self, message):
        requests.post(self._slack_webhook_url,
                      data=json.dumps(message))
