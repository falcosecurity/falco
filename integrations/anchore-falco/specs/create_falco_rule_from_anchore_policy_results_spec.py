from mamba import description, it, before
from expects import expect, contain

from doublex import Stub, when

import actions
import infrastructure


with description(actions.CreateFalcoRuleFromAnchoreStopPolicyResults) as self:
    with before.each:
        self.anchore_client = Stub(infrastructure.AnchoreClient)
        self.action = actions.CreateFalcoRuleFromAnchoreStopPolicyResults(self.anchore_client)

    with it('queries Anchore Server for images with Stop as policy results'):
        image_id = 'any image id'
        when(self.anchore_client).get_images_with_policy_result('stop').returns([image_id])

        result = self.action.run()

        expect(result).to(contain(image_id))
