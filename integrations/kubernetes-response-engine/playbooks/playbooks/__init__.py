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
            'text': _output_from_alert(alert),
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


def _output_from_alert(alert):
    output = alert['output'].split(': ')[1]
    priority_plus_whitespace_length = len(alert['priority']) + 1

    return output[priority_plus_whitespace_length:]


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


class CreateIncidentInDemisto:
    def __init__(self, demisto_client):
        self._demisto_client = demisto_client

    def run(self, alert):
        incident = {
            'type': 'Policy Violation',
            'name': alert['rule'],
            'details': _output_from_alert(alert),
            'severity': self._severity_from(alert['priority']),
            'occurred': alert['time'],
            'labels': [
                {'type': 'Brand', 'value': 'Sysdig'},
                {'type': 'Application', 'value': 'Falco'},
                {'type': 'container.id', 'value': alert['output_fields']['container.id']},
                {'type': 'k8s.pod.name', 'value': alert['output_fields']['k8s.pod.name']}
            ]
        }
        self._demisto_client.create_incident(incident)

        return incident

    def _severity_from(self, priority):
        return self._SEVERITIES.get(priority, 0)

    _SEVERITIES = {
        'Emergency': 4,
        'Alert': 4,
        'Critical': 4,
        'Error': 3,
        'Warning': 2,
        'Notice': 1,
        'Informational': 5,
        'Debug': 5,
    }
