from mamba import description, it, before, context
from expects import expect, be_none, raise_error

import os

from playbooks import infrastructure


with description(infrastructure.PhantomClient) as self:
    with before.each:
        self.phantom_client = infrastructure.PhantomClient(
            os.environ['PHANTOM_USER'],
            os.environ['PHANTOM_PASSWORD'],
            os.environ['PHANTOM_BASE_URL'],
            verify_ssl=False
        )

    with it('creates a container in Phantom Server'):
        container = {
            'name': 'My Container',
            'description': 'Useful description of this container.',
            'label': 'events',
            'run_automation': False,
            'severity': 'high',
            'status': 'new',
            'start_time': '2015-03-21T19:28:13.759Z',
        }

        container = self.phantom_client.create_container(container)

        expect(container['id']).not_to(be_none)

    with context('when an error happens'):
        with it('raises an error'):
            container = {
                'description': 'Useful description of this container.',
                'label': 'events',
                'run_automation': False,
                'severity': 'high',
                'status': 'new',
                'start_time': '2015-03-21T19:28:13.759Z',
            }

            expect(lambda: self.phantom_client.create_container(container))\
                .to(raise_error(RuntimeError))
