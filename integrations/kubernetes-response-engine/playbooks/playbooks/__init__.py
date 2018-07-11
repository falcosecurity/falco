import maya


class DeletePod:
    def __init__(self, k8s_client):
        self._k8s_client = k8s_client

    def run(self, alert):
        pod_name = alert['output_fields']['k8s.pod.name']

        self._k8s_client.delete_pod(pod_name)


class AddMessageToSlack:
    def __init__(self, slack_client):
        self._slack_client = slack_client

    def run(self, alert):
        message = self._build_slack_message(alert)
        self._slack_client.post_message(message)

        return message

    def _build_slack_message(self, alert):
        return {
            'text': self._output(alert),
            'attachments':  [{
                'color': self._color_from(alert['priority']),
                'fields': [
                    {
                        'title': 'Rule',
                        'value': alert['rule'],
                        'short': False
                    },
                    {
                        'title': 'Priority',
                        'value': alert['priority'],
                        'short': True
                    },
                    {
                        'title': 'Time',
                        'value': str(maya.parse(alert['time'])),
                        'short': True
                    },
                    {
                        'title': 'Kubernetes Pod Name',
                        'value': alert['output_fields']['k8s.pod.name'],
                        'short': True
                    },
                    {
                        'title': 'Container Id',
                        'value': alert['output_fields']['container.id'],
                        'short': True
                    }
                ]
            }]
        }

    def _output(self, alert):
        output = alert['output'].split(': ')[1]
        priority_plus_whitespace_length = len(alert['priority']) + 1

        return output[priority_plus_whitespace_length:]

    _COLORS = {
        'Emergency': '#b12737',
        'Alert': '#f24141',
        'Critical': '#fc7335',
        'Error': '#f28143',
        'Warning': '#f9c414',
        'Notice': '#397ec3',
        'Informational': '#8fc0e7',
        'Debug': '#8fc0e7',
    }

    def _color_from(self, priority):
        return self._COLORS.get(priority, '#eeeeee')


class TaintNode:
    def __init__(self, k8s_client, key, value, effect):
        self._k8s_client = k8s_client
        self._key = key
        self._value = value
        self._effect = effect

    def run(self, alert):
        pod = alert['output_fields']['k8s.pod.name']
        node = self._k8s_client.find_node_running_pod(pod)

        self._k8s_client.taint_node(node, self._key, self._value, self._effect)


class NetworkIsolatePod:
    def __init__(self, k8s_client):
        self._k8s_client = k8s_client

    def run(self, alert):
        pod = alert['output_fields']['k8s.pod.name']

        self._k8s_client.add_label_to_pod(pod, 'isolated', 'true')
