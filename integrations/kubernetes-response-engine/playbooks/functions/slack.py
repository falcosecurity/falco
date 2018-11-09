import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.AddMessageToSlack(
    infrastructure.SlackClient(os.environ['SLACK_WEBHOOK_URL'])
)


def handler(event, context):
    playbook.run(playbooks.falco_alert(event))
