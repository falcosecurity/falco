import sys
import os.path
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__))))

import os
import playbooks
from playbooks import infrastructure


playbook = playbooks.CreateIncidentInDemisto(
    infrastructure.DemistoClient(os.environ['DEMISTO_API_KEY'],
                                 os.environ['DEMISTO_BASE_URL'])
)


def handler(event, context):
    playbook.run(event['data'])
