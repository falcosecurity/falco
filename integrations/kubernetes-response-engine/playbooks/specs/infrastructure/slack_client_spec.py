from mamba import description, it

import os

from playbooks import infrastructure


with description(infrastructure.SlackClient) as self:
    with it('posts a message to #kubeless-demo channel'):
        slack_client = infrastructure.SlackClient(os.environ['SLACK_WEBHOOK_URL'])

        message = {
            'text': 'Hello from Python! :metal:'
        }

        slack_client.post_message(message)
