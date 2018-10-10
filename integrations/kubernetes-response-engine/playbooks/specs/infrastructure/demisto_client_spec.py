from mamba import description, it, context, before
from expects import expect, raise_error

import os

from playbooks import infrastructure


with description(infrastructure.DemistoClient) as self:
    with before.each:
        self.demisto_client = infrastructure.DemistoClient(
            os.environ['DEMISTO_API_KEY'],
            os.environ['DEMISTO_BASE_URL'],
            verify_ssl=False
        )

    with it('creates an incident'):
        incident = {
            "type": "Policy Violation",
            "name": "Falco incident",
            "severity": 2,
            "details": "Some incident details"
        }

        self.demisto_client.create_incident(incident)

    with context('when an error happens'):
        with it('raises an exception'):
            incident = {}

            expect(lambda: self.demisto_client.create_incident(incident)).\
                to(raise_error(RuntimeError))
