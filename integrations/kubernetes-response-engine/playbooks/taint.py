import sys
import os.path
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__))))

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
    playbook.run(event['data'])
