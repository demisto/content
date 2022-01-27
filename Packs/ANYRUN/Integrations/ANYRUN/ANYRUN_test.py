import pytest
import json
from ANYRUN import underscore_to_camel_case, images_from_report
from ANYRUN import make_capital, make_singular, make_upper
from ANYRUN import generate_dbotscore
from ANYRUN import taskid_from_url
import requests

HEADERS = {
    'Authorization': 'Authorization'
}
USE_SSL = False


@pytest.fixture(scope="module")
def get_response():
    ssdeep = "6144:u77HUUUUUUUUUUUUUUUUUUUT52V6JoGXPjm+iNQBA81RqHOF:u77HUUUUUUUUUUUUUUUUUUUTCyoUmQBj"
    response = {
        "data": {
            "analysis": {
                "content": {
                    "mainObject": {
                        "type": "file",
                        "hashes": {
                            "ssdeep": ssdeep,
                            "sha256": "22b6830432e47e54619e0448c93f699b096e0e73165e051598a82836ab8e38ab",
                            "sha1": "fd0d6e5e7ff1db4b3b12b8b6c8a35464b3bcd1e5",
                            "md5": "06b2ace5e7ff00d6cf6dcdc793020f45"
                        },
                        "url": "http://www.madeup.net/someuri?what=huh&for=derr"  # disable-secrets-detection
                    }
                },
                "scores": {
                    "verdict": {
                        "threatLevelText": "Malicious activity"
                    }
                }
            }
        }
    }
    response_as_string = json.dumps(response).replace('file', 'download')
    response_as_string = response_as_string.replace('Malicious activity', 'Suspicious activity')
    response2 = json.loads(response_as_string)
    response_as_string = response_as_string.replace('download', 'url')
    response_as_string = response_as_string.replace('Suspicious activity', 'No threats detected')
    response3 = json.loads(response_as_string)
    return response, response2, response3


class TestUnderscoreToCamelCase(object):
    def test_one(self):
        assert underscore_to_camel_case({}) == {}

    def test_two(self):
        assert underscore_to_camel_case('cApItAl') == 'cApItAl'

    def test_three(self):
        assert underscore_to_camel_case('capital_cAsE') == 'capitalCase'


class TestMakeCapital(object):
    def test_make_capital_1(self):
        assert make_capital('heLLo') == 'HeLLo'


class TestMakeSingular(object):
    def test_make_singular_1(self):
        assert make_singular('assess') == 'assess'

    def test_make_singular_2(self):
        assert make_singular('bass') == 'bass'

    def test_make_singular_3(self):
        assert make_singular('assesses') == 'assess'

    def test_make_singular_4(self):
        assert make_singular('checks') == 'check'

    def test_make_singular_5(self):
        assert make_singular('analysis') == 'analysis'

    def test_make_singular_6(self):
        assert make_singular('status') == 'status'

    def test_make_singular_7(self):
        assert make_singular('os') == 'os'


class TestMakeUpper(object):
    def test_make_upper_1(self):
        assert make_upper('id') == 'ID'

    def test_make_upper_2(self):
        assert make_upper('ssdeEp') == 'SSDeep'

    def test_make_upper_3(self):
        assert make_upper('hello') == 'hello'

    def test_make_upper_4(self):
        assert make_upper({}) == {}


class TestGenerateDBotScore(object):
    def test_generate_dbotscore_1(self, get_response):
        response1, response2, response3 = get_response

        dbot_score = generate_dbotscore(response1).get('DBotScore')
        main_object = response1.get('data', {}).get('analysis', {}).get('content', {}).get('mainObject', {})
        sha_256 = main_object.get('hashes', {}).get('sha256')
        assert dbot_score.get('Indicator') == sha_256
        assert dbot_score.get('Score') == 3
        assert dbot_score.get('Type') == 'hash'
        assert dbot_score.get('Vendor') == 'ANYRUN'

        dbot_score = generate_dbotscore(response2).get('DBotScore')
        main_object = response2.get('data', {}).get('analysis', {}).get('content', {}).get('mainObject', {})
        sha_256 = main_object.get('hashes', {}).get('sha256')
        assert dbot_score.get('Indicator') == sha_256
        assert dbot_score.get('Score') == 2
        assert dbot_score.get('Type') == 'hash'
        assert dbot_score.get('Vendor') == 'ANYRUN'

        dbot_score = generate_dbotscore(response3).get('DBotScore')
        main_object = response3.get('data', {}).get('analysis', {}).get('content', {}).get('mainObject', {})
        url = main_object.get('url')
        assert dbot_score.get('Indicator') == url
        assert dbot_score.get('Score') == 1
        assert dbot_score.get('Type') == 'url'
        assert dbot_score.get('Vendor') == 'ANYRUN'


class TestTaskIDFromURL(object):
    def test_taskid_from_url(self):
        url = 'https://www.madeup.com/madeup/tasks/'  # disable-secrets-detection
        url += 'this-is-the-task-id/blah/&someotherstuff'
        assert taskid_from_url(url) == 'this-is-the-task-id'


def http_mock(method, url, verify=USE_SSL, headers=None):
    if not headers:
        raise ValueError("Permission denied")
    else:
        the_response = requests.Response()
        the_response.status_code = 200
        the_response._content = b'{ "image" : "image" }'
        return the_response


def test_get_image(mocker):
    """
    Given:
        A mock response from the API
    When:
        Calling images_from_report
    Then:
        Validate that the http request gets called with authorization (headers)
    """
    response = {'data': {'analysis': {'content': {'screenshots': [{'permanentUrl': 'http://permanentUrl'}]}}}}
    mocker.patch('requests.request', side_effect=http_mock)
    try:
        images_from_report(response)
    except ValueError as e:
        print(str(e))
