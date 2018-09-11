import os
import json
import http

from kubernetes import client, config
import requests


class KubernetesClient:
    def __init__(self):
        if 'KUBERNETES_LOAD_KUBE_CONFIG' in os.environ:
            config.load_kube_config()
        else:
            config.load_incluster_config()

        self._v1 = client.CoreV1Api()
        self._batch_v1 = client.BatchV1Api()

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

    def start_sysdig_capture_for(self, pod_name, event_time,
                                 duration_in_seconds, s3_bucket,
                                 aws_access_key_id, aws_secret_access_key):
        job_name = 'sysdig-{}-{}'.format(pod_name, event_time)

        node_name = self.find_node_running_pod(pod_name)
        namespace = self._find_pod_namespace(pod_name)
        body = self._build_sysdig_capture_job_body(job_name,
                                                   node_name,
                                                   duration_in_seconds,
                                                   s3_bucket,
                                                   aws_access_key_id,
                                                   aws_secret_access_key)

        return self._batch_v1.create_namespaced_job(namespace, body)

    def _build_sysdig_capture_job_body(self, job_name, node_name,
                                       duration_in_seconds, s3_bucket,
                                       aws_access_key_id, aws_secret_access_key):
        return client.V1Job(
            metadata=client.V1ObjectMeta(
                name=job_name
            ),
            spec=client.V1JobSpec(
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        name=job_name
                    ),
                    spec=client.V1PodSpec(
                        containers=[client.V1Container(
                            name='capturer',
                            image='sysdig/capturer',
                            image_pull_policy='Always',
                            security_context=client.V1SecurityContext(
                                privileged=True
                            ),
                            env=[
                                client.V1EnvVar(
                                    name='AWS_S3_BUCKET',
                                    value=s3_bucket
                                ),
                                client.V1EnvVar(
                                    name='CAPTURE_DURATION',
                                    value=str(duration_in_seconds)
                                ),
                                client.V1EnvVar(
                                    name='CAPTURE_FILE_NAME',
                                    value=job_name
                                ),
                                client.V1EnvVar(
                                    name='AWS_ACCESS_KEY_ID',
                                    value=aws_access_key_id,
                                ),
                                client.V1EnvVar(
                                    name='AWS_SECRET_ACCESS_KEY',
                                    value=aws_secret_access_key,
                                )
                            ],
                            volume_mounts=[
                                client.V1VolumeMount(
                                    mount_path='/host/var/run/docker.sock',
                                    name='docker-socket'
                                ),
                                client.V1VolumeMount(
                                    mount_path='/host/dev',
                                    name='dev-fs'
                                ),
                                client.V1VolumeMount(
                                    mount_path='/host/proc',
                                    name='proc-fs',
                                    read_only=True
                                ),
                                client.V1VolumeMount(
                                    mount_path='/host/boot',
                                    name='boot-fs',
                                    read_only=True
                                ),
                                client.V1VolumeMount(
                                    mount_path='/host/lib/modules',
                                    name='lib-modules',
                                    read_only=True
                                ),
                                client.V1VolumeMount(
                                    mount_path='/host/usr',
                                    name='usr-fs',
                                    read_only=True
                                ),
                                client.V1VolumeMount(
                                    mount_path='/dev/shm',
                                    name='dshm'
                                )
                            ]
                        )],
                        volumes=[
                            client.V1Volume(
                                name='dshm',
                                empty_dir=client.V1EmptyDirVolumeSource(
                                    medium='Memory'
                                )
                            ),
                            client.V1Volume(
                                name='docker-socket',
                                host_path=client.V1HostPathVolumeSource(
                                    path='/var/run/docker.sock'
                                )
                            ),
                            client.V1Volume(
                                name='dev-fs',
                                host_path=client.V1HostPathVolumeSource(

                                    path='/dev'
                                )
                            ),
                            client.V1Volume(
                                name='proc-fs',
                                host_path=client.V1HostPathVolumeSource(
                                    path='/proc'
                                )
                            ),

                            client.V1Volume(
                                name='boot-fs',
                                host_path=client.V1HostPathVolumeSource(
                                    path='/boot'
                                )
                            ),
                            client.V1Volume(
                                name='lib-modules',
                                host_path=client.V1HostPathVolumeSource(
                                    path='/lib/modules'
                                )
                            ),
                            client.V1Volume(
                                name='usr-fs',
                                host_path=client.V1HostPathVolumeSource(
                                    path='/usr'
                                )
                            )
                        ],
                        node_name=node_name,
                        restart_policy='Never'
                    )
                )
            )
        )


class SlackClient:
    def __init__(self, slack_webhook_url):
        self._slack_webhook_url = slack_webhook_url

    def post_message(self, message):
        requests.post(self._slack_webhook_url,
                      data=json.dumps(message))


class DemistoClient:
    def __init__(self, api_key, base_url, verify_ssl=True):
        self._api_key = api_key
        self._base_url = base_url
        self._verify_ssl = verify_ssl

    def create_incident(self, incident):
        response = requests.post(self._base_url + '/incident',
                                 headers=self._headers(),
                                 data=json.dumps(incident),
                                 verify=self._verify_ssl)

        if response.status_code != http.HTTPStatus.CREATED:
            raise RuntimeError(response.text)

    def _headers(self):
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': self._api_key,
        }
