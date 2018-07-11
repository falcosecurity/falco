from mamba import description, it, before
from expects import expect

from doublex import Spy, when
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks


with description(playbooks.TaintNode) as self:
    with before.each:
        self.k8s_client = Spy(infrastructure.KubernetesClient)
        self.key = 'falco/alert'
        self.value = 'true'
        self.effect = 'NoSchedule'
        self.playbook = playbooks.TaintNode(self.k8s_client,
                                            self.key,
                                            self.value,
                                            self.effect)

    with it('taints the node'):
        pod_name = 'any pod name'
        alert = {'output_fields': {'k8s.pod.name': pod_name}}

        node = 'any node'
        when(self.k8s_client).find_node_running_pod(pod_name).returns(node)

        self.playbook.run(alert)

        expect(self.k8s_client.taint_node).to(have_been_called_with(node,
                                                                    self.key,
                                                                    self.value,
                                                                    self.effect))
