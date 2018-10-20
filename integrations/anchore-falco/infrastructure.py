import requests


class AnchoreClient:
    def __init__(self, user, password, url, ssl_verify):
        self._user = user
        self._password = password
        self._url = url
        self._ssl_verify = ssl_verify

    def get_images_with_policy_result(self, policy_result):
        results = []
        for image in self._get_all_images():
            final_action = self._evaluate_image(image)

            if final_action == 'stop':
                results.append(image['image_id'])

        return results

    def _get_all_images(self):
        response = self._do_get_request(self._url + '/images')
        return [
            {
                'image_id': image['image_detail'][0]['imageId'],
                'image_digest': image['image_detail'][0]['imageDigest'],
                'full_tag': image['image_detail'][0]['fulltag']
            } for image in response.json()]

    def _do_get_request(self, url):
        return requests.get(url,
                            auth=(self._user, self._password),
                            verify=self._ssl_verify,
                            headers={'Content-Type': 'application/json'})

    def _evaluate_image(self, image):
        response = self._do_get_request(self._url + '/images/{}/check?tag={}'.format(image['image_digest'], image['full_tag']))
        if response.status_code == 200:
            return response.json()[0][image['image_digest']][image['full_tag']][0]['detail']['result']['final_action']
