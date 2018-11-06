import sys
import os.path
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__))))

import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.StartSysdigCaptureForContainer(
    infrastructure.KubernetesClient(),
    int(os.environ.get('CAPTURE_DURATION', 120)),
    os.environ['AWS_S3_BUCKET'],
    os.environ['AWS_ACCESS_KEY_ID'],
    os.environ['AWS_SECRET_ACCESS_KEY']
)


def handler(event, context):
    playbook.run(event['data'])
