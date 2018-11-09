import playbooks
from playbooks import infrastructure


playbook = playbooks.NetworkIsolatePod(
    infrastructure.KubernetesClient()
)


def handler(event, context):
    playbook.run(playbooks.falco_alert(event))
