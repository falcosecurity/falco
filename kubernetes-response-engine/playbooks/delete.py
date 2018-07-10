import sys
import os.path
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__))))

import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.DeletePod(
    infrastructure.KubernetesClient()
)


def handler(event, context):
    playbook.run(event['data'])
