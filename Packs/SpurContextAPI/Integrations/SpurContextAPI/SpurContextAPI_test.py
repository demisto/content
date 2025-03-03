"""SpurContextAPI Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the SpurContextAPI Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorld

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the HelloWorld API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import pytest
from SpurContextAPI import Client, SpurIP, enrich_command, ip_command, test_module, main, Common, DBotScoreType

# Sample API response for testing
MOCK_HTTP_RESPONSE = {
    "as": {
        "number": 30083,
        "organization": "AS-30083-GO-DADDY-COM-LLC"
    },
    "client": {
        "behaviors": ["TOR_PROXY_USER"],
        "concentration": {
            "city": "Weldon Spring",
            "country": "US",
            "density": 0.202,
            "geohash": "9yz",
            "skew": 45,
            "state": "Missouri"
        },
        "count": 14,
        "countries": 1,
        "proxies": ["LUMINATI_PROXY", "SHIFTER_PROXY"],
        "spread": 4941431,
        "types": ["MOBILE", "DESKTOP"]
    },
    "infrastructure": "DATACENTER",
    "ip": "1.1.1.1",
    "location": {
        "city": "St Louis",
        "country": "US",
        "state": "Missouri"
    },
    "risks": ["WEB_SCRAPING", "TUNNEL"],
    "services": ["IPSEC", "OPENVPN"],
    "tunnels": [
        {
            "anonymous": True,
            "entries": ["1.1.1.1"],
            "exits": ["1.1.1.1"],
            "operator": "NORD_VPN",
            "type": "VPN"
        }
    ]
}


@pytest.fixture()
def client(mocker):
    client = Client(base_url="https://api.spur.us/", verify=False, headers={"Authorization": "Bearer test"})
    mocker.patch.object(Client, '_http_request', return_value=MOCK_HTTP_RESPONSE)
    return client


def test_enrich_command(client):
    args = {'ip': '1.1.1.1'}
    result = enrich_command(client, args)
    assert result.outputs['ip'] == MOCK_HTTP_RESPONSE['ip']


def test_ip_command(client):
    args = {'ip': '1.1.1.1'}
    results = ip_command(client, args)[0]
    assert isinstance(results.indicator, SpurIP)
    assert results.indicator.risks == MOCK_HTTP_RESPONSE['risks']


def test_test_module(client):
    result = test_module(client)
    assert result == 'ok'


def test_spur_ip_to_context():
    ip = '1.1.1.1'
    asn = 'AS12345'
    as_owner = 'Test AS'
    client_types = ['MOBILE', 'DESKTOP']
    risks = ['WEB_SCRAPING', 'TUNNEL']
    tunnels = {
        'type': 'VPN',
        'operator': 'NORD_VPN',
        'anonymous': True,
        'entries': ['1.1.1.1'],
        'exits': ['1.1.1.1']
    }
    ip_indicator = SpurIP(
        ip=ip,
        asn=asn,
        as_owner=as_owner,
        client_types=client_types,
        dbot_score=Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="SpurContextAPI",
            score=Common.DBotScore.NONE,
        ),
        risks=risks,
        tunnels=tunnels
    )

    context = ip_indicator.to_context()
    context_path = context[Common.IP.CONTEXT_PATH]

    assert context_path['Address'] == ip
    assert context_path['ASN'] == asn
    assert context_path['ASOwner'] == as_owner
    assert context_path['Risks'] == risks
    assert context_path['ClientTypes'] == client_types
    assert context_path['Tunnels'] == tunnels


def test_main_enrich_command(mocker):
    mocker.patch('SpurContextAPI.demisto.command', return_value='spur-context-api-enrich')
    mocker.patch('SpurContextAPI.demisto.args', return_value={'ip': '1.1.1.1'})
    mock_enrich = mocker.patch('SpurContextAPI.enrich_command')
    mocker.patch('SpurContextAPI.return_results')
    main()

    mock_enrich.assert_called_once_with(mocker.ANY, {'ip': '1.1.1.1'})
