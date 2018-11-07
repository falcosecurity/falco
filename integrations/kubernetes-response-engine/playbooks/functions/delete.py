import playbooks
from playbooks import infrastructure


playbook = playbooks.DeletePod(
    infrastructure.KubernetesClient()
)


def handler(event, context):
    playbook.run(playbooks.falco_alert(event))
