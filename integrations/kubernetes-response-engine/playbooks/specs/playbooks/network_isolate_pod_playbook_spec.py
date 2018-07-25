from mamba import description, it, before
from expects import expect

from doublex import Spy
from doublex_expects import have_been_called

from playbooks import infrastructure
import playbooks


with description(playbooks.NetworkIsolatePod) as self:
    with before.each:
        self.k8s_client = Spy(infrastructure.KubernetesClient)
        self.playbook = playbooks.NetworkIsolatePod(self.k8s_client)

    with it('adds isolation label to pod'):
        pod_name = 'any pod name'
        alert = {'output_fields': {'k8s.pod.name': pod_name}}

        self.playbook.run(alert)

        expect(self.k8s_client.add_label_to_pod).to(have_been_called)
