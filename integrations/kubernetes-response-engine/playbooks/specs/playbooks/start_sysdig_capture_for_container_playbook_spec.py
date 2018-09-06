from mamba import description, it, before
from expects import expect

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks


with description(playbooks.StartSysdigCaptureForContainer) as self:
    with before.each:
        self.k8s_client = Spy(infrastructure.KubernetesClient)
        self.playbook = playbooks.StartSysdigCaptureForContainer(self.k8s_client)

    with it('add starts capturing job in same node than Pod alerted'):
        pod_name = 'any pod name'
        container_id = 'any container id'
        alert = {'output_fields': {
            'k8s.pod.name': pod_name,
            'container.id': container_id
        }}

        self.playbook.run(alert)

        expect(self.k8s_client.start_sysdig_capture_for)\
            .to(have_been_called_with(pod_name, container_id))
