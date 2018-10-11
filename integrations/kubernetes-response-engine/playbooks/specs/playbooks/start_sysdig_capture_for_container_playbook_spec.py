from mamba import description, it, before
from expects import expect

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks


with description(playbooks.StartSysdigCaptureForContainer) as self:
    with before.each:
        self.k8s_client = Spy(infrastructure.KubernetesClient)
        self.duration_in_seconds = 'any duration in seconds'
        self.s3_bucket = 'any s3 bucket url'
        self.aws_access_key_id = 'any aws access key id'
        self.aws_secret_access_key = 'any aws secret access key'
        self.playbook = playbooks.StartSysdigCaptureForContainer(self.k8s_client,
                                                                 self.duration_in_seconds,
                                                                 self.s3_bucket,
                                                                 self.aws_access_key_id,
                                                                 self.aws_secret_access_key)

    with it('add starts capturing job in same node than Pod alerted'):
        pod_name = 'any pod name'
        event_time = 'any event time'
        alert = {'output_fields': {
            'k8s.pod.name': pod_name,
            'evt.time': event_time,
        }}

        self.playbook.run(alert)

        expect(self.k8s_client.start_sysdig_capture_for)\
            .to(have_been_called_with(pod_name,
                                      event_time,
                                      self.duration_in_seconds,
                                      self.s3_bucket,
                                      self.aws_access_key_id,
                                      self.aws_secret_access_key))
