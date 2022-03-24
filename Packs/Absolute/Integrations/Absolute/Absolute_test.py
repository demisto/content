import json
import io
from datetime import datetime

import pytest
from pytest import raises

from CommonServerPython import DemistoException
from Absolute import Client, DATE_FORMAT

EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY = """GET
/v2/reporting/devices

host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""

EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY = """PUT
/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf
substringof%28%27760001%27%2C%20esn%29%20eq%20true
host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""

EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY = """POST
/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf
substringof%28%27760001%27%2C%20esn%29%20eq%20true%20or%20availablePhysicalMemroyBytes%20lt%201073741824
host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
4c4cba4fe89f96921d32cf91d4bd4415f524050ffe82c840446e7110a622a025"""


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('url', ['https://absolute.com', 'absolute.com'])
def test_invalid_absolute_api_url(url):
    from Absolute import validate_absolute_api_url
    with raises(DemistoException):
        validate_absolute_api_url(url)


def create_client(base_url: str = 'https://api.absolute.com', token_id: str = 'token',
                  secret_key: str = 'secret', verify: bool = False, proxy: bool = False):
    x_abs_date = datetime.strptime('20170926T172213Z', DATE_FORMAT).strftime(DATE_FORMAT)
    headers = {"host": base_url.split('https://')[-1], "content-type": "application/json", "x-abs-date": x_abs_date}
    return Client(proxy=proxy, verify=verify, base_url=base_url, token_id=token_id,
                  secret_key=secret_key, headers=headers, x_abs_date=x_abs_date)


@pytest.mark.parametrize('method, canonical_uri ,query_string, payload, expected_canonical_request',
                         [
                             ('GET', '/v2/reporting/devices', '', '', EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY),
                             ('PUT', '/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf',
                              "substringof('760001', esn) eq true", '',
                              EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY),
                             ('POST', '/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf',
                              "substringof('760001', esn) eq true or availablePhysicalMemroyBytes lt 1073741824",
                              json.dumps([{'deviceUid': 'e93f2464-2766-4a6b-8f00-66c8fb13e23a'}]),
                              EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY),
                         ])
def test_create_canonical_request(method, canonical_uri, query_string, payload, expected_canonical_request):
    client = create_client()
    canonical_res = client.create_canonical_request(method=method, canonical_uri=canonical_uri,
                                                    query_string=query_string,
                                                    payload=payload)
    assert canonical_res == expected_canonical_request
