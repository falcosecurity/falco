from mamba import description, it
from expects import expect, have_length, be_above

import os

import infrastructure


with description(infrastructure.AnchoreClient) as self:
    with it('retrieves images with stop policy results'):
        user = os.environ['ANCHORE_CLI_USER']
        password = os.environ['ANCHORE_CLI_PASS']
        url = os.environ['ANCHORE_CLI_URL']

        client = infrastructure.AnchoreClient(user, password, url, True)

        result = client.get_images_with_policy_result('stop')

        expect(result).to(have_length(be_above(1)))
