from mamba import description, it, before, context
from expects import expect, have_key, have_keys, contain

from doublex import Spy
from doublex_expects import have_been_called_with

from playbooks import infrastructure
import playbooks

import os


with description(playbooks.CreateIncidentInDemisto) as self:
    with before.each:
        self.demisto_client = Spy(infrastructure.DemistoClient)
        self.playbook = playbooks.CreateIncidentInDemisto(self.demisto_client)

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

            self.incident = self.playbook.run(self.alert)

        with it('creates incident in demisto'):
            expect(self.demisto_client.create_incident).to(have_been_called_with(self.incident))

        with it('sets incident type as Policy Violation'):
            expect(self.incident).to(have_key('type', 'Policy Violation'))

        with it('includes rule name'):
            expect(self.incident).to(have_key('name', 'Non sudo setuid'))

        with it('includes falco output'):
            falco_output = 'Unexpected setuid call by non-sudo, non-root program (user=bin cur_uid=2 parent=event_generator command=event_generator  uid=root) k8s.pod=falco-event-generator-6fd89678f9-cdkvz container=1c76f49f40b4'

            expect(self.incident).to(have_key('details', falco_output))

        with it('includes severity'):
            expect(self.incident).to(have_key('severity', 1))

        with it('includes time when alert happened'):
            expect(self.incident).to(have_key('occurred', "2018-05-24T10:22:15.576767292Z"))

        with context('when adding labels'):
            with it('includes Sysdig as Brand'):
                expect(self.incident['labels']).to(contain(have_keys(type='Brand', value='Sysdig')))

            with it('includes Falco as Application'):
                expect(self.incident['labels']).to(contain(have_keys(type='Application', value='Falco')))

            with it('includes container.id'):
                expect(self.incident['labels']).to(contain(have_keys(type='container.id', value='1c76f49f40b4')))

            with it('includes k8s.pod.name'):
                expect(self.incident['labels']).to(contain(have_keys(type='k8s.pod.name', value='falco-event-generator-6fd89678f9-cdkvz')))
