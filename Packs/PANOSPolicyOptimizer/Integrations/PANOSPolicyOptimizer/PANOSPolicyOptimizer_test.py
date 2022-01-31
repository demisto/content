import pytest
from CommonServerPython import *
from PANOSPolicyOptimizer import Client, policy_optimizer_get_rules_command


BASE_URL = 'https://test.com'


@pytest.fixture()
def panorama_instance_client(mocker):
    client = Client(url=BASE_URL, username='test', password='test', vsys='', device_group='test', verify=False, tid=0)
    mocker.patch.object(client, 'token_generator', return_value='123')
    return client


@pytest.fixture()
def firewall_instance_client(mocker):
    client = Client(url=BASE_URL, username='test', password='test', vsys='test', device_group='', verify=False, tid=0)
    mocker.patch.object(client, 'token_generator', return_value='123')
    return client


def test_body_request_is_valid_when_querying_rules_in_panorama_instances(mocker, panorama_instance_client):
    """
    Given
        - panorama instance.

    When
        - querying rules in panorama instances.

    Then
        - Verify that the body request that was sent is correct for panorama instances.
    """
    response = requests.Response()
    response._content = b'{"type":"rpc","tid":"51","action":"PanDirect","method":"run",' \
                        b'"predefinedCacheUpdate":"true","result":{"@status":"success",' \
                        b'"result":{"@total-count":"0","@count":"0","@max-bytes":"0"}}}'

    response_mocker = mocker.patch.object(panorama_instance_client.session, 'post', return_value=response)

    policy_optimizer_get_rules_command(
        client=panorama_instance_client, args={'timeframe': '30', 'usage': 'Unused', 'exclude': 'false'}
    )

    assert response_mocker.call_args.kwargs['json'] == {
            'action': 'PanDirect',
            'method': 'run',
            'data': [
                '123',
                'PoliciesDirect.getPoliciesByUsage', [
                    {
                        'type': 'security', 'position': 'pre', 'vsysName': 'test', 'isCmsSelected': True,
                        'isMultiVsys': False, 'showGrouped': False, 'usageAttributes': {
                        'timeframe': '30', 'usage': 'Unused', 'exclude': False, 'exclude-reset-text': '90'
                        },
                        'pageContext': 'rule_usage'
                    }
                ]
            ],
            'type': 'rpc',
            'tid': 1
        }
