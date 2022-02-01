import pytest
from CommonServerPython import *
from PANOSPolicyOptimizer import Client, policy_optimizer_get_rules_command


BASE_URL = 'https://test.com'


def get_firewall_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='test', device_group='', verify=False, tid=0)


def get_panorama_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='', device_group='test', verify=False, tid=0)


QUERYING_RULES_PARAMS = [
    (
        get_firewall_instance_client(),
        ['main'],
        False
    ),
    (
        get_panorama_instance_client(),
        ['post', 'pre'],
        True
    )
]


@pytest.mark.parametrize("client, positions, is_cms_selected", QUERYING_RULES_PARAMS)
def test_body_request_is_valid_when_querying_rules(mocker, client, positions, is_cms_selected):
    """
    Given
        - a client.

    When
        - querying rules in firewall/panorama instances.

    Then
        - Verify that the body request that was sent is correct for each type of instance.
    """
    mocker.patch.object(client, 'token_generator', return_value='123')
    response = requests.Response()
    response._content = b'{"type":"rpc","tid":"51","action":"PanDirect","method":"run",' \
                        b'"predefinedCacheUpdate":"true","result":{"@status":"success",' \
                        b'"result":{"@total-count":"0","@count":"0","@max-bytes":"0"}}}'

    response_mocker = mocker.patch.object(client.session, 'post', return_value=response)

    policy_optimizer_get_rules_command(
        client=client, args={'timeframe': '30', 'usage': 'Unused', 'exclude': 'false'}
    )

    tid = 1
    for position, calling_args in zip(positions, response_mocker.call_args_list):
        assert calling_args.kwargs['json'] == {
            'action': 'PanDirect',
            'method': 'run',
            'data': [
                '123',
                'PoliciesDirect.getPoliciesByUsage',
                [
                    {
                        'type': 'security', 'position': position, 'vsysName': 'test',
                        'isCmsSelected': is_cms_selected, 'isMultiVsys': False, 'showGrouped': False,
                        'usageAttributes': {
                            'timeframe': '30', 'usage': 'Unused', 'exclude': False, 'exclude-reset-text': '90'
                        },
                        'pageContext': 'rule_usage'
                    }
                ]
            ],
            'type': 'rpc',
            'tid': tid
        }
        tid += 1


CLIENTS = [
    get_firewall_instance_client(),
    get_panorama_instance_client()
]


@pytest.mark.parametrize("client", CLIENTS)
def test_querying_rules_is_valid(mocker, client):
    """
    Given
        - a client instance and a valid mocked response.

    When
        - querying rules in firewall/panorama instances.

    Then
        - Verify that the output for both cases returns expected responses.
    """
    mocker.patch.object(client, 'token_generator', return_value='123')
    response = requests.Response()
    response._content = b'{"type":"rpc","tid":"51","action":"PanDirect","method":"run",' \
                        b'"predefinedCacheUpdate":"true","result":{"@status":"success","result":{"@total-count":"1",' \
                        b'"@count":"1","entry":[{"@name":"test",' \
                        b'"@uuid":"123",' \
                        b'"@__recordInfo":"{\\"permission\\":\\"readwrite\\",\\"xpathId\\":\\"vsys\\",\\"vsysName\\' \
                        b'":\\"Lab-Devices\\",\\"position\\":\\"post\\"}","action":"drop","description":"any","source' \
                        b'":{"member":["5.5.5.5"]},"destination":{"member":["any"]},"application":' \
                        b'{"member":["any"]},"source-user":{"member":["any"]},"from":{"member":["any"]},"to":' \
                        b'{"member":["any"]},"service":{"member":["any"]},"negate-source":"no","negate-destination":' \
                        b'"no","disabled":"no","option":{"disable-server-response-inspection":"no"}' \
                        b',"rule-state":"Unused","rule-creation-timestamp":"1626849818",' \
                        b'"rule-modification-timestamp":"1626849818"}]}}}'

    mocker.patch.object(client.session, 'post', return_value=response)
    rules = policy_optimizer_get_rules_command(
        client=client, args={'timeframe': '30', 'usage': 'Unused', 'exclude': 'false'}
    )

    assert isinstance(rules.outputs, list)
    assert len(rules.outputs) > 0
    assert 'PolicyOptimizer UnusedRules' in rules.readable_output
