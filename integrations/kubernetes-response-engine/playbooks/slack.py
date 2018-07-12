import sys
import os.path
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__))))

import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.AddMessageToSlack(
    infrastructure.SlackClient(os.environ['SLACK_WEBHOOK_URL'])
)


def handler(event, context):
    playbook.run(event['data'])
