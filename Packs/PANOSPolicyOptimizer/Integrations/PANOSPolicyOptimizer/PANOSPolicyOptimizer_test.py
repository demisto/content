import pytest
import io
from CommonServerPython import *
from PANOSPolicyOptimizer import Client, policy_optimizer_get_rules_command, policy_optimizer_get_dag_command


BASE_URL = 'https://test.com'


def get_firewall_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='test', device_group='', verify=False, tid=0)


def get_panorama_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='', device_group='test', verify=False, tid=0)


def read_json_file(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


QUERYING_RULES_PARAMS = [
    (
        get_firewall_instance_client(),
        'main',
    ),
    (
        get_panorama_instance_client(),
        'pre',
    ),
    (
        get_panorama_instance_client(),
        'post',
    )
]


@pytest.mark.parametrize("client, position", QUERYING_RULES_PARAMS)
def test_body_request_is_valid_when_querying_rules(mocker, client, position):
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
    response._content = b'{}'

    response_mocker = mocker.patch.object(client.session, 'post', return_value=response)

    policy_optimizer_get_rules_command(
        client=client, args={
            'timeframe': '30', 'usage': 'Unused', 'exclude': 'false', 'rule_type': 'security', 'position': position
        }
    )
    assert response_mocker.call_args.kwargs['json'] == {
        'action': 'PanDirect',
        'method': 'run',
        'data': [
            '123',
            'PoliciesDirect.getPoliciesByUsage',
            [
                {
                    'type': 'security', 'position': position, 'vsysName': 'test',
                    'isCmsSelected': client.is_cms_selected, 'isMultiVsys': False, 'showGrouped': False,
                    'usageAttributes': {
                        'timeframe': '30', 'usage': 'Unused', 'exclude': False, 'exclude-reset-text': '90'
                    },
                    'pageContext': 'rule_usage'
                }
            ]
        ],
        'type': 'rpc',
        'tid': 1
    }


CLIENTS = [
    get_firewall_instance_client(),
    get_panorama_instance_client()
]


@pytest.mark.parametrize("client", CLIENTS)
def test_querying_rules_is_valid(mocker, client):
    """
    Given
        - a client instance and a valid mocked security rules response.

    When
        - querying rules in firewall/panorama instances.

    Then
        - Verify that the output for both cases returns expected responses.
    """
    mocker.patch.object(client, 'token_generator', return_value='123')
    mocker.patch.object(client.session, 'post')
    mocker.patch.object(json, 'loads', return_value=read_json_file(path='test_data/valid_security_rules_response.json'))

    rules = policy_optimizer_get_rules_command(
        client=client, args={'timeframe': '30', 'usage': 'Unused', 'exclude': 'false'}
    )

    assert isinstance(rules.outputs, list)
    assert len(rules.outputs) > 0
    assert 'PolicyOptimizer Unused-security-rules' in rules.readable_output


@pytest.mark.parametrize("client", CLIENTS)
def test_querying_invalid_dynamic_address_group_response(mocker, client):
    """
    Given
        - a response which indicates no dynamic address group was found.

    When
        - querying for a specific dynamic group.

    Then
        - a valid error response is returned.
    """
    mocker.patch.object(client, 'token_generator', return_value='123')
    mocker.patch.object(client.session, 'post')
    mocker.patch.object(
        json, 'loads', return_value=read_json_file(path='test_data/invalid_dynamic_group_response.json')
    )

    with pytest.raises(Exception, match=f'Dynamic Address Group dag_test_ag was not found.'):
        policy_optimizer_get_dag_command(client=client, args={'dag': 'dag_test_ag'})
