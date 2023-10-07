import pytest
from CommonServerPython import *
from PANOSPolicyOptimizer import Client, policy_optimizer_get_rules_command, policy_optimizer_get_dag_command, define_position,\
    get_policy_optimizer_statistics_command, policy_optimizer_no_apps_command, policy_optimizer_get_unused_apps_command,\
    is_cms_selected

BASE_URL = 'https://test.com'


def get_firewall_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='test', device_group='', verify=False, tid=0, version='8')


def get_panorama_instance_client():
    return Client(url=BASE_URL, username='test', password='test', vsys='', device_group='test', verify=False, tid=0, version='8')


def read_json_file(path):
    with open(path, encoding='utf-8') as f:
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

QUERYING_RULES_PARAMS_WITH_VERSION = [
    (get_firewall_instance_client(), 'pre', '9.0.0', 'main'),
    (get_panorama_instance_client(), 'pre', '10.2.0', 'pre'),
    (get_panorama_instance_client(), 'post', '9.0.0', 'main')]

QUERYING_RULES_PARAMS_WITH_VERSION_AND_FLAG = [
    (get_firewall_instance_client(), 'pre', '9.0.0', 'main', False, False),
    (get_panorama_instance_client(), 'pre', '10.2.0', 'pre', True, True),
    (get_panorama_instance_client(), 'post', '9.0.0', 'main', True, False)]


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

    client.session_metadata["headers"] = 'test'
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


@pytest.mark.parametrize("client, position, version, excepted_position", QUERYING_RULES_PARAMS_WITH_VERSION)
def test_body_request_is_valid_when_querying_policy_optimizer_statistics(mocker, client, position, version, excepted_position):
    """
    Given
        - a client.
    When
        - querying policy optimizer statistics in firewall/panorama instances.

    Then
        - Verify that the body request that was sent is correct for each type of instance.
        case1: PAN-OS 9.0.0 should always return main.
        case2: Panorama 10.2.0 should will return pre, the given position argument.
        case3: Panorama 9.0.0 should always return main.
    """
    client.version = version
    mocker.patch.object(client, 'token_generator', return_value='123')
    response = requests.Response()
    response._content = b'{"result":{"result":{"entry":[{"@name":"test","text":"test"}]}}}'

    response_mocker = mocker.patch.object(client.session, 'post', return_value=response)

    client.session_metadata["headers"] = 'test'
    get_policy_optimizer_statistics_command(
        client=client, args={
            'position': position
        }
    )
    assert response_mocker.call_args.kwargs['json'] == {'action': 'PanDirect', 'method': 'run', 'data': [
        '123', 'PoliciesDirect.getRuleCountInRuleUsage', [{'type': 'security',
                                                           'position': excepted_position, 'vsysName': 'test'}]],
                                                        'type': 'rpc', 'tid': 1}


@pytest.mark.parametrize("client, position, version, excepted_position, flag, expected_flag",
                         QUERYING_RULES_PARAMS_WITH_VERSION_AND_FLAG)
def test_body_request_is_valid_when_querying_policy_optimizer_no_apps(mocker, client, position,
                                                                      version, excepted_position, flag, expected_flag):
    """
    Given
        - a client.
    When
        - querying policy optimizer no apps in firewall/panorama instances.

    Then
        - Verify that the body request that was sent is correct for each type of instance.
        case1: PAN-OS 9.0.0 should always return main, and the isCmsSelected flag should be False.
        case2: Panorama 10.2.0 should will return pre, the given position argument, and the isCmsSelected flag should be True.
        case3: Panorama 9.0.0 should always return main, and the isCmsSelected flag should be False due to the given vresion.
    """
    client.version = version
    mocker.patch.object(client, 'token_generator', return_value='123')
    response = requests.Response()
    response._content = b'{"result":{"result":{"entry":[{"@name":"test","text":"test"}]}}}'

    response_mocker = mocker.patch.object(client.session, 'post', return_value=response)

    client.session_metadata["headers"] = 'test'
    policy_optimizer_no_apps_command(
        client=client, args={
            'position': position
        }
    )
    assert response_mocker.call_args.kwargs['json'] == {'action': 'PanDirect', 'method': 'run',
                                                        'data': ['123', 'PoliciesDirect.getPoliciesByUsage',
                                                                 [{'type': 'security', 'position': excepted_position,
                                                                   'vsysName': 'test', 'isCmsSelected': expected_flag,
                                                                   'isMultiVsys': False, 'showGrouped': False,
                                                                   'usageAttributes': {'timeframeTag': '30',
                                                                                       'application/member': 'any',
                                                                                       'apps-seen-count': "geq '1'",
                                                                                       'action': 'allow'},
                                                                   'pageContext': 'app_usage', 'field': '$.bytes',
                                                                   'direction': 'DESC'}]], 'type': 'rpc', 'tid': 1}


@pytest.mark.parametrize("client, position, version, excepted_position, flag, expected_flag",
                         QUERYING_RULES_PARAMS_WITH_VERSION_AND_FLAG)
def test_body_request_is_valid_when_querying_policy_optimizer_unused_apps(mocker, client, position,
                                                                          version, excepted_position, flag, expected_flag):
    """
    Given
        - a client.
    When
        - querying policy optimizer unused_apps in firewall/panorama instances.

    Then
        - Verify that the body request that was sent is correct for each type of instance.
        case1: PAN-OS 9.0.0 should always return main, and the isCmsSelected flag should be False.
        case2: Panorama 10.2.0 should will return pre, the given position argument, and the isCmsSelected flag should be True.
        case3: Panorama 9.0.0 should always return main, and the isCmsSelected flag should be False due to the given vresion.
    """
    client.version = version
    mocker.patch.object(client, 'token_generator', return_value='123')
    response = requests.Response()
    response._content = b'{"result":{"result":{"entry":[{"@name":"test","text":"test"}]}}}'
    response_mocker = mocker.patch.object(client.session, 'post', return_value=response)

    client.session_metadata["headers"] = 'test'
    client.session_metadata["dit"] = 0
    policy_optimizer_get_unused_apps_command(
        client=client, args={
            'position': position
        }
    )
    assert response_mocker.call_args.kwargs['json'] == {'action': 'PanDirect', 'method': 'run',
                                                        'data': ['123', 'PoliciesDirect.getPoliciesByUsage',
                                                                 [{'type': 'security', 'position': excepted_position,
                                                                   'vsysName': 'test', 'serialNumber': '',
                                                                   'isCmsSelected': expected_flag,
                                                                   'isMultiVsys': False, 'showGrouped': False,
                                                                   'usageAttributes': {'timeframeTag': '30',
                                                                                       'application/member': 'unused',
                                                                                       'action': 'allow'},
                                                                   'pageContext': 'app_usage', 'field': '$.bytes',
                                                                   'direction': 'DESC'}]], 'type': 'rpc', 'tid': 2}


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

    client.session_metadata["headers"] = 'test'
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
        - an entry indicating that no dynamic address group was found.
    """
    mocker.patch.object(client, 'token_generator', return_value='123')
    mocker.patch.object(client.session, 'post')
    mocker.patch.object(
        json, 'loads', return_value=read_json_file(path='test_data/invalid_dynamic_group_response.json')
    )

    client.session_metadata["headers"] = 'test'
    dag = policy_optimizer_get_dag_command(client=client, args={'dag': 'dag_test_ag'})
    assert dag.readable_output == 'Dynamic Address Group dag_test_ag was not found.'


@pytest.mark.parametrize('version , output',
                         [('9.0.0', 'f6f4061a1bddc1c04d8109b39f581270'),
                          ('10.2.1', '590c9f8430c7435807df8ba9a476e3f1295d46ef210f6efae2043a4c085a569e')])
def test_token_generator(mocker, version, output):
    """
    Given:
        version of PAN-OS.
    When:
        running token_generator.
    Then:
        return the correct token.
        case 1: PAN-OS 9.0.0 should return a token generated with md5.
        case 2: PAN-OS 10.2.1 should return a token generated with sha256.
    """
    client = get_firewall_instance_client()
    client.version = version
    client.session_metadata['cookie_key'] = 'test'
    assert client.token_generator() == output


def test_extract_csrf():
    client = get_firewall_instance_client()
    assert client.extract_csrf(
        '<input type="hidden" name="_csrf" value="422JE5PO1WARA1I91CB5FRS99UQ65RF31P9Y3L4T" />') == \
           '422JE5PO1WARA1I91CB5FRS99UQ65RF31P9Y3L4T'  # noqa


@pytest.mark.parametrize("position, num_of_rules", [('both', 3), ('pre', 2), ('post', 1)])
def test_get_unused_rules(mocker, position, num_of_rules):
    """

    Given: position of unused rules (pre, post or any)

    When: running pan-os-po-get-rules for unused rules

    Then: return rules based on their location

    """

    def mock_policy_optimizer_get_rules(timeframe: str, usage: str, exclude: bool, position: str, rule_type: str):
        pre = {'result': {'result': {'entry': ['test1', 'test2']}}}
        post = {'result': {'result': {'entry': ['test3']}}}
        if position == 'pre':
            return pre
        else:
            return post

    client = get_panorama_instance_client()
    mocker.patch.object(client, 'policy_optimizer_get_rules', side_effect=mock_policy_optimizer_get_rules)
    args = {'timeframe': '',
            'usage': 'test',
            'exclude': 'false',
            'position': position,
            'rule_type': 'unused'
            }
    rules = policy_optimizer_get_rules_command(client, args).outputs

    assert len(rules) == num_of_rules


@pytest.mark.parametrize("version, position , is_panorama, res",
                         [('8', "post", True, "main"), ('9', "post", False, "main"), ('10.3', "post", True, "post")])
def test_define_position(mocker, version, position, is_panorama, res):
    """
    Given:
        - version of PAN-OS.
        - position of the rule.
        -  is_panorama flag.
    When:
        - running define_position.
    Then:
        - return the correct position.
        case 1: PAN-OS 8 should always return main.
        case 2: PAN-OS 9 should always return main.
        case 3: PAN-OS 10.3 should return post as its input.
    """
    assert define_position(version=version, args={"position": position}, is_panorama=is_panorama) == res


@pytest.mark.parametrize("version, is_panorama, res",
                         [('8', True, False), ('9', False, False), ('10.3', True, True)])
def test_isCmsSelected(version, is_panorama, res):
    """
    Given:
        - version of PAN-OS.
        - is_panorama flag.
    When:
        - running is_cms_selected.
    Then:
        - return the correct flag.
        case 1: PAN-OS 8 should always return False.
        case 2: PAN-OS 9 should always return False.
        case 3: PAN-OS 10.3 should return True.
    """
    assert is_cms_selected(version=version, is_panorama=is_panorama) == res
