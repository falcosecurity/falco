from mamba import description, context, it, before
from expects import expect, be_false, be_true, start_with, equal, have_key, be_none

import subprocess
import os.path
import time

from playbooks import infrastructure


with description(infrastructure.KubernetesClient) as self:
    with before.each:
        self.kubernetes_client = infrastructure.KubernetesClient()

    with context('when checking if a pod exists'):
        with before.each:
            self._create_nginx_pod()

        with context('and pod exists'):
            with it('returns true'):
                expect(self.kubernetes_client.exists_pod('nginx')).to(be_true)

        with context('and pod does not exist'):
            with it('returns false'):
                self.kubernetes_client.delete_pod('nginx')

                expect(self.kubernetes_client.exists_pod('nginx')).to(be_false)

    with it('finds node running pod'):
        self._create_nginx_pod()

        node = self.kubernetes_client.find_node_running_pod('nginx')

        expect(node).to(start_with('gke-sysdig-work-default-pool'))

    with it('taints node'):
        self._create_nginx_pod()

        node_name = self.kubernetes_client.find_node_running_pod('nginx')

        node = self.kubernetes_client.taint_node(node_name,
                                                 'playbooks',
                                                 'true',
                                                 'NoSchedule')

        expect(node.spec.taints[0].effect).to(equal('NoSchedule'))
        expect(node.spec.taints[0].key).to(equal('playbooks'))
        expect(node.spec.taints[0].value).to(equal('true'))

    with it('adds label to a pod'):
        self._create_nginx_pod()

        pod = self.kubernetes_client.add_label_to_pod('nginx',
                                                      'testing',
                                                      'true')

        expect(pod.metadata.labels).to(have_key('testing', 'true'))

    with it('starts sysdig capture for'):
        self._create_nginx_pod()

        job = self.kubernetes_client.start_sysdig_capture_for('nginx',
                                                              int(time.time()),
                                                              10,
                                                              'any s3 bucket',
                                                              'any aws key id',
                                                              'any aws secret key')

        expect(job).not_to(be_none)

    def _create_nginx_pod(self):
        current_directory = os.path.dirname(os.path.realpath(__file__))
        pod_manifesto = os.path.join(current_directory,
                                     '..',
                                     'support',
                                     'deployment.yaml')

        subprocess.run(['kubectl', 'create', '-f', pod_manifesto])
