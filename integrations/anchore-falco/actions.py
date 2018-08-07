import string

FALCO_RULE_TEMPLATE = string.Template('''
- macro: anchore_stop_policy_evaluation_containers
  condition: container.image.id in ($images)

- rule: Run Anchore Containers with Stop Policy Evaluation
  desc: Detect containers which does not receive a positive Policy Evaluation from Anchore Engine.

  condition: evt.type=execve and proc.vpid=1 and container and anchore_stop_policy_evaluation_containers
  output: A stop policy evaluation container from anchore has started (%container.info image=%container.image)
  priority: INFO
  tags: [container]
''')


class CreateFalcoRuleFromAnchoreStopPolicyResults:
    def __init__(self, anchore_client):
        self._anchore_client = anchore_client

    def run(self):
        images = self._anchore_client.get_images_with_policy_result('stop')

        images = ['"{}"'.format(image) for image in images]
        return FALCO_RULE_TEMPLATE.substitute(images=', '.join(images))
