import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.TaintNode(
    infrastructure.KubernetesClient(),
    os.environ.get('TAINT_KEY', 'falco/alert'),
    os.environ.get('TAINT_VALUE', 'true'),
    os.environ.get('TAINT_EFFECT', 'NoSchedule')
)


def handler(event, context):
    playbook.run(playbooks.falco_alert(event))
