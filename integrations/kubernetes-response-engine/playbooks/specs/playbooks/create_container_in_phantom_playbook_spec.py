from mamba import description, it, before, context
from expects import expect, have_key

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks


with description(playbooks.CreateContainerInPhantom) as self:
    with before.each:
        self.phantom_client = Spy(infrastructure.PhantomClient)
        self.playbook = playbooks.CreateContainerInPhantom(self.phantom_client)

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

        self.container = self.playbook.run(self.alert)

    with it('creates the container in phantom'):
        expect(self.phantom_client.create_container).to(have_been_called_with(self.container))

    with it('includes falco output'):
        falco_output = 'Unexpected setuid call by non-sudo, non-root program (user=bin cur_uid=2 parent=event_generator command=event_generator  uid=root) k8s.pod=falco-event-generator-6fd89678f9-cdkvz container=1c76f49f40b4'

        expect(self.container).to(have_key('description', falco_output))

    with it('includes severity'):
        expect(self.container).to(have_key('severity', 'low'))

    with it('includes rule name'):
        expect(self.container).to(have_key('name', 'Non sudo setuid'))

    with it('includes time when alert happened'):
        expect(self.container).to(have_key('start_time', '2018-05-24T10:22:15.576767Z'))

    with it('includes label'):
        expect(self.container).to(have_key('label', 'events'))

    with it('includes status'):
        expect(self.container).to(have_key('status', 'new'))

    with context('when building additional data'):
        with it('includes kubernetes pod name'):
            expect(self.container['data']).to(have_key('k8s.pod.name', 'falco-event-generator-6fd89678f9-cdkvz'))

        with it('includes container id'):
            expect(self.container['data']).to(have_key('container.id', '1c76f49f40b4'))
