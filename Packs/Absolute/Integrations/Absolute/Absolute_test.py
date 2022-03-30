import json
import io
from datetime import datetime
from freezegun import freeze_time

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

EXPECTED_SIGNING_STRING_PUT = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
c23103585b2b6d617f4a88afa1e76731cf6215ef329fdd0024030ca21a4933b4"""

EXPECTED_SIGNING_STRING_POST = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
ed080b5e0df239b4f747d510a388eefe3b4876730e6f09a9e3d953f36983aec3"""

EXPECTED_SIGNING_STRING_GET = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
1b42a7b1f96d459efdbeceba5ee624d92caeb3ab3ca196268be55bc89c61cd93"""

GET_REQUEST_SIGNATURE = "ab87d64d18610852565a2821625dfef1f19403673afe2f7f511ef185269d2334"
PUT_REQUEST_SIGNATURE = "1d025c22f7fea8d14eb8416e863a12bf17daaa637c59ee98ed19a89509e69132"
POST_REQUEST_SIGNATURE = "2355cede6fe99bf852ec7e4bc7dc450445fac9458814ef81d1a1b0906aac750b"

SIGNING_KEY = b'\xe5_\xf5\x90o+\xa2\xe4\x00\xa4\x89\xd2\x1d\xa32B^\x19\xb7\xbdyy^:1\xd0\xdd\\\x87N\x02M'

GET_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20220330/cadc/abs1, " \
                          "SignedHeaders=host;content-type;x-abs-date, " \
                          "Signature=ab87d64d18610852565a2821625dfef1f19403673afe2f7f511ef185269d2334"
PUT_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20220330/cadc/abs1, " \
                          "SignedHeaders=host;content-type;x-abs-date, " \
                          "Signature=1d025c22f7fea8d14eb8416e863a12bf17daaa637c59ee98ed19a89509e69132"
POST_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20220330/cadc/abs1, " \
                           "SignedHeaders=host;content-type;x-abs-date, " \
                           "Signature=2355cede6fe99bf852ec7e4bc7dc450445fac9458814ef81d1a1b0906aac750b"


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


@pytest.mark.parametrize('canonical_req, expected_signing_string',
                         [(EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY, EXPECTED_SIGNING_STRING_GET),
                          (EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY, EXPECTED_SIGNING_STRING_PUT),
                          (EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY, EXPECTED_SIGNING_STRING_POST)])
@freeze_time("2017-09-26 17:22:13 UTC")
def test_create_signing_string(canonical_req, expected_signing_string):
    client = create_client()
    assert client.create_signing_string(canonical_req) == expected_signing_string


@freeze_time("2017-09-26 17:22:13 UTC")
def test_create_signing_key():
    client = create_client()
    assert client.create_signing_key() == SIGNING_KEY


@pytest.mark.parametrize('signing_string, expected_signature',
                         [(EXPECTED_SIGNING_STRING_GET, GET_REQUEST_SIGNATURE),
                          (EXPECTED_SIGNING_STRING_PUT, PUT_REQUEST_SIGNATURE),
                          (EXPECTED_SIGNING_STRING_POST, POST_REQUEST_SIGNATURE)])
def test_create_signature(signing_string, expected_signature):
    client = create_client()
    assert client.create_signature(signing_string, SIGNING_KEY) == expected_signature


@pytest.mark.parametrize('signature, expected_authorization_header',
                         [(GET_REQUEST_SIGNATURE, GET_REQUEST_AUTH_HEADER),
                          (PUT_REQUEST_SIGNATURE, PUT_REQUEST_AUTH_HEADER),
                          (POST_REQUEST_SIGNATURE, POST_REQUEST_AUTH_HEADER)])
def test_add_authorization_header(signature, expected_authorization_header):
    client = create_client()
    assert client.add_authorization_header(signature) == expected_authorization_header


def test_get_custom_device_field_list_command(mocker):
    from Absolute import get_custom_device_field_list_command
    client = create_client()
    response = util_load_json('test_data/custom_device_field_list_response.json')
    mocker.patch.object(client, 'api_request_absolute', return_value=response)
    command_result = get_custom_device_field_list_command(client=client,
                                                          args={'device_id': '02b9daa4-8e60-4640-8b15-76d41ecf6a94'})
    assert command_result.outputs == {'DeviceUID': response.get('deviceUid'), 'ESN': response.get('esn'),
                                      'CDFValues': [{'CDFUID': 'njazpLrEQwqeFDqk4yQCfg', 'FieldName': 'Asset Number',
                                                     'FieldKey': 1, 'CategoryCode': 'ESNCOLUMN',
                                                     'FieldValue': 'No Asset Tag', 'Type': 'Text'},
                                                    {'CDFUID': '7PwIrjEXTAqvpb5WdV2w', 'FieldName': 'Assigned Username',
                                                     'FieldKey': 3, 'CategoryCode': 'ESNCOLUMN',
                                                     'FieldValue': '', 'Type': 'Text'}]}
