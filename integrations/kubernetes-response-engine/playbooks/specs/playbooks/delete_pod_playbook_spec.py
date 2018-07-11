from mamba import description, it, before
from expects import expect

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks


with description(playbooks.DeletePod) as self:
    with before.each:
        self.k8s_client = Spy(infrastructure.KubernetesClient)
        self.playbook = playbooks.DeletePod(self.k8s_client)

    with it('deletes a pod'):
        pod_name = 'a pod name'
        alert = {'output_fields': {'k8s.pod.name': pod_name}}

        self.playbook.run(alert)

        expect(self.k8s_client.delete_pod).to(have_been_called_with(pod_name))
