import io
import json

import mock
from behave import *

import demistomock as demisto
from CommonServerPython import DBotScoreReliability
from Packs.ipinfo.Integrations.ipinfo_v2.ipinfo_v2 import ipinfo_ip_command, Client, BRAND_NAME


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@given('an ip-address which is valid')
def step_impl(context):
    context.ip = '1.1.1.1'


@when("running the ip command")
def step_impl(context):
    mock_response = util_load_json('Packs/ipinfo/Integrations/ipinfo_v2/test_data/ip_1.1.1.1_response.json')

    mock.patch.object(
        Client, 'http_request', return_value=mock_response
    )
    mock.patch.object(demisto, 'callingContext',
                      return_value={'context': {'IntegrationBrand': BRAND_NAME}, 'integration': True})
    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)

    context.response = ipinfo_ip_command(client=client, ip=context.ip)


@then('the result should contain valid info')
def step_impl(context):
    expected_outputs = {
        'Address': '1.1.1.1',
        'Hostname': 'one.one.one.one',
        'ASN': 'AS13335',
        'ASOwner': 'Cloudflare, Inc.',
        'Tags': [],
        'Organization': None,
        'Geo': {'Location': '34.0522,-118.2437', 'Country': 'US', 'Description': 'Los Angeles, California, 90076, US'},
        'Registrar': None
    }
    assert context.response[0][1].outputs == expected_outputs



