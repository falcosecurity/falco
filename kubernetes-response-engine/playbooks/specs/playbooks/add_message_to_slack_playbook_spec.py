from mamba import description, it, before, context
from expects import expect, have_key, have_keys, contain

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks



with description(playbooks.AddMessageToSlack) as self:
    with before.each:
        self.slack_client = Spy(infrastructure.SlackClient)
        self.playbook = playbooks.AddMessageToSlack(self.slack_client)

    with context('when publishing a message to slack'):
        with before.each:
            self.alert = {
                "output": "10:22:15.576767292: Notice Unexpected setuid call by non-sudo, non-root program (user=bin cur_uid=2 parent=event_generator command=event_generator  uid=root) k8s.pod=falco-event-generator-6fd89678f9-cdkvz container=1c76f49f40b4",
                "output_fields": {
                    "container.id": "1c76f49f40b4",
                    "evt.arg.uid": "root",
                    "evt.time": 1527157335576767292,
                    "k8s.pod.name": "falco-event-generator-6fd89678f9-cdkvz",
                    "proc.cmdline": "event_generator ",
                    "proc.pname": "event_generator",
                    "user.name": "bin",
                    "user.uid": 2
                },
                "priority": "Notice",
                "rule": "Non sudo setuid",
                "time": "2018-05-24T10:22:15.576767292Z"
            }

            self.message = self.playbook.run(self.alert)

        with it('publishes message to slack'):
            expect(self.slack_client.post_message).to(have_been_called_with(self.message))

        with it('includes falco output'):
            falco_output = 'Unexpected setuid call by non-sudo, non-root program (user=bin cur_uid=2 parent=event_generator command=event_generator  uid=root) k8s.pod=falco-event-generator-6fd89678f9-cdkvz container=1c76f49f40b4'

            expect(self.message).to(have_key('text', falco_output))

        with it('includes color based on priority'):
            expect(self.message['attachments'][0]).to(have_key('color'))

        with it('includes priority'):
            expect(self.message['attachments'][0]['fields']).to(contain(have_keys(title='Priority', value='Notice')))

        with it('includes rule name'):
            expect(self.message['attachments'][0]['fields']).to(contain(have_keys(title='Rule', value='Non sudo setuid')))

        with it('includes time when alert happened'):
            expect(self.message['attachments'][0]['fields']).to(contain(have_keys(title='Time', value='Thu, 24 May 2018 10:22:15 GMT')))

        with it('includes kubernetes pod name'):
            expect(self.message['attachments'][0]['fields']).to(contain(have_keys(title='Kubernetes Pod Name', value='falco-event-generator-6fd89678f9-cdkvz')))

        with it('includes container id'):
            expect(self.message['attachments'][0]['fields']).to(contain(have_keys(title='Container Id', value='1c76f49f40b4')))
