import json
from pathlib import Path
from typing import Any
import pytest
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


"""POLICIES"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {"policyName": "test", "policyId": "test"},
        "Enter a name or ID but not both"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_list_policy_command_failed(demisto_args, expected_results):
    """
    Given:
        - agentId or hostName

    When:
        - Get list of all the policies

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import list_policy_command

    client = ""

    with pytest.raises(Exception) as e:
        list_policy_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {'hostSetId': "test", "policyId": "test"},
        "Enter a Policy Id or Host Set Id but not both"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_list_host_set_policy_command_failed(demisto_args, expected_results):
    """
    Given:
        - hostSetId or policyId

    When:
        - Get specific policy by Policy Id or policies by Host Set Id

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import list_host_set_policy_command

    client = ""

    with pytest.raises(Exception) as e:
        list_host_set_policy_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # Given only one argument instead of two
        {"policyId": "test"},
        "policy ID and hostSetId are required"
    ),
    (
        # Given only one argument instead of two
        {"hostSetId": "test"},
        "policy ID and hostSetId are required"
    ),
    (
        # No arguments given
        {},
        "policy ID and hostSetId are required"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_assign_host_set_policy_command_failed(demisto_args, expected_results):
    """
    Given:
        - agentId or hostName

    When:
        - assigning host set to the policy

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import assign_host_set_policy_command

    client = ""

    with pytest.raises(Exception) as e:
        assign_host_set_policy_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_LIST_POLICY = [
    (
        {'policyId': 'test', 'hostSetId': 'test'},
        Exception('400'),
        'This hostset may already be included in this policy'
    ),
    (
        {'policyId': 'test', 'hostSetId': 'test'},
        'test',
        'Success'
    )
]


@pytest.mark.parametrize('demisto_args, return_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_LIST_POLICY)
def test_assign_host_set_policy_command(mocker, demisto_args, return_mocker, expected_results):

    from FireEyeHXv2 import assign_host_set_policy_command, Client

    mocker.patch.object(Client, 'assign_host_set_policy_request', side_effect=return_mocker)

    result = assign_host_set_policy_command(Client, demisto_args)

    assert result.readable_output == expected_results
    pass


UPSERT_COMMAND_DATA_CASES_LIST_POLICY = [
    (
        {'policyId': 11, 'enabled': 'test', 'limit': 5, 'offset': 2},
        {'policy_id': 11, 'enabled': 'test', 'limit': 5, 'offset': 2, 'name': None}
    ),
    (
        {'policyName': 'test'},
        {'policy_id': None, 'enabled': None, 'limit': 50, 'offset': 0, 'name': 'test'}
    )
]


@pytest.mark.parametrize('demisto_args, call_args', UPSERT_COMMAND_DATA_CASES_LIST_POLICY)
def test_list_policy_command(mocker, demisto_args, call_args):

    from FireEyeHXv2 import list_policy_command, Client
    return_value = {
        'data': {
            'entries': [{'_id': 'test', 'name': 'test', 'description': 'test', 'priority': 'test', 'enabled': 'test'}]
        }
    }

    policies = mocker.patch.object(Client, 'list_policy_request', return_value=return_value)
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value='test')

    list_policy_command(Client, demisto_args)

    assert policies.call_args.kwargs['policy_id'] == call_args['policy_id']
    assert policies.call_args.kwargs['offset'] == call_args['offset']
    assert policies.call_args.kwargs['limit'] == call_args['limit']
    assert policies.call_args.kwargs['name'] == call_args['name']
    assert policies.call_args.kwargs['enabled'] == call_args['enabled']


UPSERT_COMMAND_DATA_CASES_LIST_HOST_SET_POLICY = [
    (
        {'hostSetId': 11},
        {"hostSetId": 1, "hostSetPolicy": 0},
        {}
    ),
    (
        {},
        {"hostSetId": 0, "hostSetPolicy": 1},
        {'limit': 50, 'offset': 0}
    ),
    (
        {'limit': 5, 'offset': 2},
        {"hostSetId": 0, "hostSetPolicy": 1},
        {'limit': 5, 'offset': 2}
    )
]


@pytest.mark.parametrize('demisto_args, call_count, call_args', UPSERT_COMMAND_DATA_CASES_LIST_HOST_SET_POLICY)
def test_list_host_set_policy_command(mocker, demisto_args, call_count, call_args):

    from FireEyeHXv2 import list_host_set_policy_command, Client
    return_value = {'data': {'entries': [{'policy_id': 'test', 'persist_id': 'test'}]}}

    hostSetId = mocker.patch.object(Client, 'list_host_set_policy_by_hostSetId_request', return_value=return_value)
    hostSetPolicy = mocker.patch.object(Client, 'list_host_set_policy_request', return_value=return_value)
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value='test')

    list_host_set_policy_command(Client, demisto_args)

    assert hostSetId.call_count == call_count['hostSetId']
    assert hostSetPolicy.call_count == call_count['hostSetPolicy']

    if hostSetPolicy.call_count != 0:
        assert hostSetPolicy.call_args.kwargs['offset'] == call_args['offset']
        assert hostSetPolicy.call_args.kwargs['limit'] == call_args['limit']


UPSERT_COMMAND_DATA_CASES_DELETE_POLICY = [
    (
        {'hostSetId': 11, 'policyId': 'test'},
        Exception('404'),
        'polisy ID - test or Host Set ID - 11 Not Found'
    ),
    (
        {'hostSetId': 11, 'policyId': 'test'},
        'test',
        'Success'
    )
]


@pytest.mark.parametrize('demisto_args, exception, expected_results', UPSERT_COMMAND_DATA_CASES_DELETE_POLICY)
def test_delete_host_set_policy_command(mocker, demisto_args, exception, expected_results):

    from FireEyeHXv2 import delete_host_set_policy_command, Client

    mocker.patch.object(Client, 'delete_host_set_policy_request', side_effect=exception)

    result = delete_host_set_policy_command(Client, demisto_args)
    assert result.readable_output == expected_results


"""HOSTS"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {},
        "Please provide either agentId or hostName"
    ),
    (
        {'agentId': 'test'},
        "agentId test is not correct"
    ),
    (
        {'hostName': 'test'},
        'test is not found'
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_host_information_command_failed(mocker, demisto_args, expected_results):

    from FireEyeHXv2 import get_host_information_command, Client

    mocker.patch.object(Client, "get_hosts_by_agentId_request", return_value={})
    mocker.patch.object(Client, "get_hosts_request", return_value={})
    with pytest.raises(Exception) as e:
        get_host_information_command(Client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_HOST_INFORMATION = [
    (
        # No arguments given
        {"agentId": "test"},
        {"agentId": 1, "hostName": 0},
        isinstance({}, dict)
    ),
    (
        # No arguments given
        {"hostName": "test"},
        {"agentId": 0, "hostName": 1},
        isinstance({}, dict)
    )
]


@pytest.mark.parametrize('demisto_args, call_count, expected_results', UPSERT_COMMAND_DATA_CASES_HOST_INFORMATION)
def test_host_information(mocker, demisto_args, call_count, expected_results):

    from FireEyeHXv2 import get_host_information_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    host_by_agentId = mocker.patch.object(client, "get_hosts_by_agentId_request", return_value={"data": {}})
    host_by_hostName = mocker.patch.object(client, "get_hosts_request", return_value={"data": {"entries": [{}]}})
    result = get_host_information_command(client, demisto_args)
    assert host_by_agentId.call_count == call_count["agentId"]
    assert host_by_hostName.call_count == call_count["hostName"]
    assert isinstance(result.outputs, dict) == expected_results


UPSERT_COMMAND_DATA_CASES_GET_ALL_HOSTS = [
    (
        {},
        {"hosts_partial": 2},
        [{"data": {"entries": [{}]}}, {"data": {"entries": []}}],
        [list, dict]
    ),
    (
        {},
        {"hosts_partial": 1},
        [{"data": {"entries": []}}],
        [list, 0]
    )
]


@pytest.mark.parametrize('demisto_args, call_count, return_value_mock, expected_results', UPSERT_COMMAND_DATA_CASES_GET_ALL_HOSTS)
def test_get_all_hosts_information(mocker, demisto_args, call_count, return_value_mock, expected_results):

    from FireEyeHXv2 import get_all_hosts_information_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    hosts_partial = mocker.patch.object(client, "get_hosts_request", side_effect=return_value_mock)
    result = get_all_hosts_information_command(client, demisto_args)
    assert hosts_partial.call_count == call_count["hosts_partial"]
    assert isinstance(result.outputs, expected_results[0])
    if result.outputs:
        assert isinstance(result.outputs[0], expected_results[1])
    else:
        assert len(result.outputs) == expected_results[1]


UPSERT_COMMAND_DATA_CASES_GET_HOST_INFORMATION = [
    (
        {"hostSetID": "test"},
        {"data": {}},
        list
    ),
    (
        {},
        {"data": {"entries": []}},
        list
    )
]


@pytest.mark.parametrize('demisto_args, return_value_mock, expected_results', UPSERT_COMMAND_DATA_CASES_GET_HOST_INFORMATION)
def test_get_host_set_information(mocker, demisto_args, return_value_mock, expected_results):

    from FireEyeHXv2 import get_host_set_information_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    mocker.patch.object(client, "get_host_set_information_request", return_value=return_value_mock)
    result = get_host_set_information_command(client, demisto_args)
    assert isinstance(result.outputs, expected_results)


"""CONTAINMENT"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {},
        "Please provide either agentId or hostName"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_host_containment_command_failed(demisto_args, expected_results):
    """
    Given:
        - agentId or hostName

    When:
        - Get Host information

    Then:
        - failing when missing required data
    """

    from FireEyeHXv2 import host_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        host_containment_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {},
        "Agent ID is required"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_approve_containment_command_failed(demisto_args, expected_results):
    """
    Given:
        - agentId

    When:
        - approve containment to the request contain

    Then:
        - failing when missing required data
    """

    from FireEyeHXv2 import approve_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        approve_containment_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "One of the following arguments is required -> [agentId, hostName]"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_cancel_containment_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import cancel_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        cancel_containment_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_HOST_CONTAINMENT = [
    (
        {"hostName": "test"},
        1,
        None,
        dict
    ),
    (
        {"agentId": "test"},
        0,
        None,
        dict
    ),
    (
        {"agentId": "test"},
        0,
        Exception("422"),
        "You do not have the required permissions for containment approve\nThe containment request sent, but it is not approve."
    ),
    (
        {"agentId": "test"},
        0,
        Exception("409"),
        "This host may already in containment"
    )
]


@pytest.mark.parametrize('demisto_args, call_count, return_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_HOST_CONTAINMENT)
def test_host_containment(mocker, demisto_args, call_count, return_mocker, expected_results):

    from FireEyeHXv2 import host_containment_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    get_agentId = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value="")
    mocker.patch.object(client, "host_containmet_request", return_value=None)
    mocker.patch.object(client, "approve_containment_request", side_effect=return_mocker)
    mocker.patch.object(client, "get_hosts_by_agentId_request", return_value={"data": {}})
    result = host_containment_command(client, demisto_args)
    if not isinstance(return_mocker, Exception):
        assert get_agentId.call_count == call_count
        assert len(result) == 2
        assert isinstance(result[1].outputs, expected_results)
    else:
        assert result[0].readable_output == expected_results


UPSERT_COMMAND_DATA_CASES_APPROVE_CONTAINMENT = [
    (
        {"agentId": "test"},
        1
    )
]


@pytest.mark.parametrize('demisto_args, call_count', UPSERT_COMMAND_DATA_CASES_APPROVE_CONTAINMENT)
def test_approve_containment_command(mocker, demisto_args, call_count):

    from FireEyeHXv2 import approve_containment_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    call_request = mocker.patch.object(client, "approve_containment_request", return_value=None)

    approve_containment_command(client, demisto_args)
    assert call_request.call_count == call_count


UPSERT_COMMAND_DATA_CASES_CANCEL_CONTAINMENT = [
    (
        {"hostName": "test"},
        1
    ),
    (
        {"agentId": "test"},
        0
    )
]


@pytest.mark.parametrize('demisto_args, call_count', UPSERT_COMMAND_DATA_CASES_CANCEL_CONTAINMENT)
def test_cancel_containment_command(mocker, demisto_args, call_count):

    from FireEyeHXv2 import cancel_containment_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    get_agentId = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value="")
    mocker.patch.object(client, "cancel_containment_request", return_value=None)
    cancel_containment_command(client, demisto_args)
    assert get_agentId.call_count == call_count


UPSERT_COMMAND_DATA_CASES_LIST_CONTAINMENT = [
    (
        {"offset": 2, "limit": 5},
        {"offset": 2, "limit": 5}
    ),
    (
        {},
        {"offset": 0, "limit": 50}
    )
]


@pytest.mark.parametrize('demisto_args, args_call', UPSERT_COMMAND_DATA_CASES_LIST_CONTAINMENT)
def test_get_list_containment_command(mocker, demisto_args, args_call):

    from FireEyeHXv2 import get_list_containment_command, Client

    request = mocker.patch.object(Client, "get_list_containment_request", return_value={"data": {"entries": []}})
    mocker.patch("FireEyeHXv2.tableToMarkdown", return_value=" ")

    get_list_containment_command(Client, demisto_args)

    assert request.call_args.kwargs['offset'] == args_call['offset']
    assert request.call_args.kwargs['limit'] == args_call['limit']


"""INDICATORS"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # Given only one argument instead of two
        {"category": "test"},
        "The category and name arguments are required"
    ),
    (
        # Given only one argument instead of two
        {"name": "test"},
        "The category and name arguments are required"
    ),
    (
        # No arguments given
        {},
        "The category and name arguments are required"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_indicator_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import get_indicator_command

    client = ""

    with pytest.raises(Exception) as e:
        get_indicator_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {"name": "test", "condition": "test"},
        "All of the following arguments are required -> ['name','category','condition']"
    ),
    (
        {"category": "test", "name": "test"},
        "All of the following arguments are required -> ['name','category','condition']"
    ),
    (
        {"category": "test", "condition": "test"},
        "All of the following arguments are required -> ['name','category','condition']"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_append_conditions_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import append_conditions_command

    client = ""

    with pytest.raises(Exception) as e:
        append_conditions_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_ENABLED_CONDITIONS = [
    (
        "test",
        "test",
        [{"data": {"entries": ["test", "test"]}}, {"data": {"entries": []}}],
        2
    ),
    (
        "test",
        "test",
        [{"data": {"entries": []}}],
        0
    )
]


@pytest.mark.parametrize('category, name, results_mock, expected_results', UPSERT_COMMAND_DATA_CASES_ENABLED_CONDITIONS)
def test_get_all_enabled_conditions(mocker, category, name, results_mock, expected_results):

    from FireEyeHXv2 import get_all_enabled_conditions, Client

    mocker.patch.object(Client, "get_indicator_conditions_request", side_effect=results_mock)
    result = get_all_enabled_conditions(Client, category, name)

    assert len(result) == expected_results


UPSERT_COMMAND_DATA_CASES_GET_INDICATOR = [
    (
        {'category': 'test', 'name': 'test'}
    )
]


@pytest.mark.parametrize('demisto_args', UPSERT_COMMAND_DATA_CASES_GET_INDICATOR)
def test_get_indicator_command(mocker, demisto_args):

    from FireEyeHXv2 import get_indicator_command, Client

    mocker.patch.object(Client, 'get_indicator_request', return_value='test')
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value='test')
    mocker.patch('FireEyeHXv2.get_indicator_conditions', return_value='test')
    mocker.patch('FireEyeHXv2.get_indicator_entry', return_value='test')
    result = get_indicator_command(Client, demisto_args)

    assert isinstance(result, list)


UPSERT_COMMAND_DATA_CASES_GET_ALL_INDICATORS = [
    (
        2,
        [{"data": {"entries": ["test", "test"]}}, {"data": {"entries": []}}],
        2
    ),
    (
        2,
        [{"data": {"entries": []}}],
        0
    ),
    (
        1,
        [{"data": {"entries": ["test", "test"]}}, {"data": {"entries": []}}],
        1
    )
]


@pytest.mark.parametrize('limit, results_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_GET_ALL_INDICATORS)
def test_get_all_indicators(mocker, limit, results_mocker, expected_results):

    from FireEyeHXv2 import get_all_indicators, Client

    mocker.patch.object(Client, "get_indicators_request", side_effect=results_mocker)
    result = get_all_indicators(Client, limit=limit)

    assert len(result) == expected_results


UPSERT_COMMAND_DATA_CASES_GET_INDICATORS = [
    (
        {'limit': 5, 'alerted': 'yes', 'sort': 'createdBy'}
    )
]


@pytest.mark.parametrize('demisto_args', UPSERT_COMMAND_DATA_CASES_GET_INDICATORS)
def test_get_indicators_command(mocker, demisto_args):

    from FireEyeHXv2 import get_indicators_command, Client

    get_all_indicators = mocker.patch('FireEyeHXv2.get_all_indicators', return_value=[])
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value=' ')
    result = get_indicators_command(Client, demisto_args)

    assert get_all_indicators.call_args.kwargs['limit'] == 5
    assert get_all_indicators.call_args.kwargs['alerted'] is True
    assert get_all_indicators.call_args.kwargs['sort'] == 'created_by'
    assert isinstance(result, object)


UPSERT_COMMAND_DATA_CASES_GET_INDICATOR_RESULT = [
    (
        {'event_type': 'fileWriteEvent'},
        'File'
    ),
    (
        {'event_type': 'ipv4NetworkEvent'},
        'Ip'
    ),
    (
        {'event_type': 'Unknown'},
        None
    )
]


@pytest.mark.parametrize('args, expected_results', UPSERT_COMMAND_DATA_CASES_GET_INDICATOR_RESULT)
def test_get_indicator_command_result(mocker, args, expected_results):

    from FireEyeHXv2 import get_indicator_command_result

    mocker.patch('FireEyeHXv2.general_context_from_event', return_value='test')
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value='test')

    result = get_indicator_command_result(args)

    assert result.outputs_prefix == expected_results


"""SEARCH"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Search Id is must be"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_search_stop_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import search_stop_command

    client = ""

    with pytest.raises(Exception) as e:
        search_stop_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Search Id is must be"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_search_result_get_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import search_result_get_command

    client = ""

    with pytest.raises(Exception) as e:
        search_result_get_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "One of the following arguments is required -> [agentsIds, hostsNames, hostSet, hostSetName]"
    ),
    (
        {'hostsNames': 'WIN10X64'},
        "One of the following arguments is required -> [dnsHostname, fileFullPath, fileMD5Hash, ipAddress, fieldSearchName]"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_start_search_command_failed(mocker, demisto_args, expected_results):

    from FireEyeHXv2 import start_search_command

    client = ""

    mocker.patch('FireEyeHXv2.organize_search_body_host', return_value={'hosts': [{'_id': ''}]})
    with pytest.raises(Exception) as e:
        start_search_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_START_SEARCH = [
    (
        {"searchId": 12},
        {"data": {"state": "RUNNING", "stats": {"search_state": {"MATCHED": 0, "PENDING": 1}}}},
        [False, '12']
    ),
    (
        {"searchId": 12},
        {"data": {"state": "STOPPED", "stats": {"search_state": {"MATCHED": 0, "PENDING": 1}}}},
        [True, '12']
    ),
    (
        {"searchId": 12, "stopSearch": "stop"},
        {"data": {"state": "RUNNING", "stats": {"search_state": {"MATCHED": 0, "PENDING": 0}}}},
        [False, '12']
    ),
    (
        {"searchId": 12, "limit": 2},
        {"data": {"state": "STOPPED", "stats": {"search_state": {"MATCHED": 2, "PENDING": 1}}}},
        [True, '12']
    )
]


@pytest.mark.parametrize('args, searchInfo, expected_results', UPSERT_COMMAND_DATA_CASES_START_SEARCH)
def test_start_search_command(mocker, args, searchInfo, expected_results):

    from FireEyeHXv2 import start_search_command, Client

    mocker.patch.object(Client, "get_search_by_id_request", return_value=searchInfo)
    _, result_bool, result_id = start_search_command(Client, args)

    assert result_bool == expected_results[0]
    assert result_id == expected_results[1]


UPSERT_COMMAND_DATA_CASES_SEARCH_RESULT = [
    (
        {'searchId': '11,12'},
        {'search_result_request': 2, 'tableToMarkdown': 2, 'search_stop': 0, 'search_delete': 0},
        list
    ),
    (
        {'searchId': '11'},
        {'search_result_request': 1, 'tableToMarkdown': 1, 'search_stop': 0, 'search_delete': 0},
        list
    ),
    (
        {'searchId': '11', 'stopSearch': 'stop'},
        {'search_result_request': 1, 'tableToMarkdown': 1, 'search_stop': 1, 'search_delete': 0},
        list
    ),
    (
        {'searchId': '11', 'stopSearch': 'stopAndDelete'},
        {'search_result_request': 1, 'tableToMarkdown': 1, 'search_stop': 0, 'search_delete': 1},
        list
    )
]


@pytest.mark.parametrize('demisto_args, call_count, expected_results', UPSERT_COMMAND_DATA_CASES_SEARCH_RESULT)
def test_search_result_get_command(mocker, demisto_args, call_count, expected_results):

    from FireEyeHXv2 import search_result_get_command, Client

    search_result_request = mocker.patch.object(Client, 'search_result_get_request', return_value={'data': {'entries': [{}]}})
    search_stop = mocker.patch.object(Client, 'search_stop_request')
    search_delete = mocker.patch.object(Client, 'delete_search_request')
    tableToMarkdown = mocker.patch('FireEyeHXv2.tableToMarkdown', return_value=' ')
    result = search_result_get_command(Client, demisto_args)

    assert tableToMarkdown.call_count == call_count['tableToMarkdown']
    assert search_result_request.call_count == call_count['search_result_request']
    assert isinstance(result, expected_results)
    assert search_stop.call_count == call_count['search_stop']
    assert search_delete.call_count == call_count['search_delete']


UPSERT_COMMAND_DATA_CASES_SEARCH_LIST = [
    (
        {'searchId': '11,12'},
        {'search_by_id': 2, 'search_request': 0}
    ),
    (
        {},
        {'search_by_id': 0, 'search_request': 1}
    )
]


@pytest.mark.parametrize('demisto_args, call_count', UPSERT_COMMAND_DATA_CASES_SEARCH_LIST)
def test_get_search_list_command(mocker, demisto_args, call_count):

    from FireEyeHXv2 import get_search_list_command, Client

    search_by_id = mocker.patch.object(Client, 'get_search_by_id_request', return_value={'data': {}})
    search_request = mocker.patch.object(Client, 'get_search_list_request', return_value={'data': {'entries': {}}})
    mocker.patch('FireEyeHXv2.tableToMarkdown', return_value='test')
    result = get_search_list_command(Client, demisto_args)

    assert search_by_id.call_count == call_count['search_by_id']
    assert search_request.call_count == call_count['search_request']
    assert isinstance(result, object)


UPSERT_COMMAND_DATA_CASES_SEARCH_DELETE = [
    (
        {"searchId": "2,3,4"},
        [None, Exception("404"), None],
        "Results\nSearch Id 2: Deleted successfully\nSearch Id 3: Not Found\nSearch Id 4: Deleted successfully"
    ),
    (
        {"searchId": "2"},
        [Exception("400")],
        "Results\nSearch Id 2: Failed to delete search"
    )
]


@pytest.mark.parametrize('demisto_args, return_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_SEARCH_DELETE)
def test_search_delete_command(mocker, demisto_args, return_mocker, expected_results):

    from FireEyeHXv2 import search_delete_command, Client

    mocker.patch.object(Client, "delete_search_request", side_effect=return_mocker)
    result = search_delete_command(Client, demisto_args)

    assert result.readable_output == expected_results


UPSERT_COMMAND_DATA_CASES_SEARCH_STOP = [
    (
        {"searchId": "2,3,4"},
        [{"data": ""}, Exception("404"), {"data": ""}],
        "Results\nSearch Id 2: Success\nSearch Id 3: Not Found\nSearch Id 4: Success"
    )
]


@pytest.mark.parametrize('demisto_args, return_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_SEARCH_STOP)
def test_search_stop_command(mocker, demisto_args, return_mocker, expected_results):

    from FireEyeHXv2 import search_stop_command, Client

    mocker.patch.object(Client, "search_stop_request", side_effect=return_mocker)
    result = search_stop_command(Client, demisto_args)

    assert result.readable_output == expected_results


"""ACQUISITIONS"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Please provide either agentId or hostName"
    ),
    (
        {"agentId": "test"},
        "If the script is not provided, defaultSystemScript must be specified"
    ),
    (
        {"agentId": "test", "script": "test"},
        "If the script is provided, script name must be specified as well"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_data_acquisition_failed(demisto_args, expected_results):

    from FireEyeHXv2 import get_data_acquisition

    client = ""

    with pytest.raises(Exception) as e:
        get_data_acquisition(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Acquisition Id is required"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_delete_data_acquisition_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import delete_data_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        delete_data_acquisition_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Please provide either agentId or hostName"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_file_acquisition_command_failed(demisto_args, expected_results):
    """
    Given:
        - searchId or hostName

    When:
        - ""

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import file_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        file_acquisition_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        # No arguments given
        {},
        "Please provide acquisitionId"
    )
]


@pytest.mark.parametrize('demisto_args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_data_acquisition_command_failed(demisto_args, expected_results):

    from FireEyeHXv2 import get_data_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        get_data_acquisition_command(client, demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES_DATA_ACQUISITION = [
    (
        {"hostName": "test", "defaultSystemScript": "win"},
        1
    ),
    (
        {"agentId": "test", "defaultSystemScript": "win"},
        0
    )
]


@pytest.mark.parametrize('demisto_args, call_count', UPSERT_COMMAND_DATA_CASES_DATA_ACQUISITION)
def test_data_acquisition(mocker, demisto_args, call_count):

    from FireEyeHXv2 import get_data_acquisition, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    get_agentId = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value="")
    mocker.patch.object(client, "data_acquisition_request", return_value={"data": ""})
    get_data_acquisition(client, demisto_args)
    assert get_agentId.call_count == call_count


UPSERT_COMMAND_DATA_CASES_DATA_ACQUISITION2 = [
    (
        {},
        "RUNNING",
        [False, '12', 1, None]
    ),
    (
        {"acquisition_id": '12'},
        "COMPLETE",
        [True, '12', 0, {'state': 'COMPLETE'}]
    )
]


@pytest.mark.parametrize('demisto_args, state, expected_results', UPSERT_COMMAND_DATA_CASES_DATA_ACQUISITION2)
def test_data_acquisition_command(mocker, demisto_args, state, expected_results):

    from FireEyeHXv2 import data_acquisition_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    data_acquisition_call = mocker.patch("FireEyeHXv2.get_data_acquisition", return_value={"_id": '12'})
    mocker.patch.object(client, "data_acquisition_information_request", return_value={"state": state})
    _, result_bool, result_id = data_acquisition_command(client, demisto_args)

    assert result_bool == expected_results[0]
    assert result_id == expected_results[1]
    assert data_acquisition_call.call_count == expected_results[2]
    assert demisto_args.get('acquisition_info') == expected_results[3]


UPSERT_COMMAND_DATA_CASES_FILE_ACQUISITION = [
    (
        {"hostName": "test"},
        "RUNNING",
        [False, '12', 1]
    ),
    (
        {"agentId": "test"},
        "RUNNING",
        [False, '12', 0]
    ),
    (
        {"acquisition_id": '12'},
        "COMPLETE",
        [True, '12', 0]
    )
]


@pytest.mark.parametrize('demisto_args, state, expected_results', UPSERT_COMMAND_DATA_CASES_FILE_ACQUISITION)
def test_file_acquisition_command(mocker, demisto_args, state, expected_results):

    from FireEyeHXv2 import file_acquisition_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    get_agentId = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value={"agentId": "test"})
    mocker.patch.object(client, "file_acquisition_request", return_value={"_id": '12'})
    mocker.patch.object(client, "file_acquisition_information_request", return_value={"state": state})
    _, result_bool, result_id = file_acquisition_command(client, demisto_args)

    assert result_bool == expected_results[0]
    assert result_id == expected_results[1]
    assert get_agentId.call_count == expected_results[2]


UPSERT_COMMAND_DATA_CASES_GET_ACQUISITION = [

    (
        {"acquisitionId": "test"},
        "COMPLETE",
        {"get_data": 1}
    ),
    (
        {"acquisitionId": "test"},
        "RUNNING",
        {"get_data": 0}
    )
]


@pytest.mark.parametrize('demisto_args, state, call_count', UPSERT_COMMAND_DATA_CASES_GET_ACQUISITION)
def test_get_data_acquisition_command(mocker, demisto_args, state, call_count):

    from FireEyeHXv2 import get_data_acquisition_command, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    mocker.patch.object(client, "data_acquisition_information_request", return_value={"host": {"_id": "test"}, "state": state})
    mocker.patch.object(client, "get_hosts_by_agentId_request", return_value={"data": {}})
    get_data_call = mocker.patch.object(client, "data_collection_request", return_value="test")
    mocker.patch("FireEyeHXv2.fileResult", return_value="test")
    get_data_acquisition_command(client, demisto_args)
    assert get_data_call.call_count == call_count["get_data"]


"""ALERTS"""


UPSERT_COMMAND_DATA_CASES_GET_ALERTS = [
    (
        {"limit": 2},
        [{"data": {"entries": ["test", "test"]}}, {"data": {"entries": []}}],
        2
    ),
    (
        {"limit": 2},
        [{"data": {"entries": []}}],
        0
    ),
    (
        {"limit": 1},
        [{"data": {"entries": ["test", "test"]}}, {"data": {"entries": []}}],
        1
    )
]


@pytest.mark.parametrize('demisto_args, results_mocker, expected_results', UPSERT_COMMAND_DATA_CASES_GET_ALERTS)
def test_get_alerts(mocker, demisto_args, results_mocker, expected_results):

    from FireEyeHXv2 import get_alerts, Client

    mocker.patch.object(Client, "get_alerts_request", side_effect=results_mocker)
    result = get_alerts(Client, demisto_args)

    assert len(result) == expected_results


UPSERT_COMMAND_DATA_CASES_GET_ALL_ALERTS = [
    (
        {'sort': 'agentId', 'hostName': 'test', 'limit': 5, 'MALsource': 'yes', 'EXDsource': 'yes', 'IOCsource': 'yes'},
        [
            {
                'event_type': 'regKeyEvent',
                'event_values': {
                    'regKeyEvent/path': 'test',
                    'regKeyEvent/valueName': 'test',
                    'regKeyEvent/value': 'test'
                }
            },
            {'event_type': 'test'}

        ],
        {'sort': 'agent._id+ascending', 'agentId': 'test', 'limit': 5, 'source': ['mal', 'exd', 'ioc']},
        {'get_agent_id': 1, 'general_context': 1}
    ),
    (
        {},
        [
            {
                'event_type': 'regKeyEvent',
                'event_values': {
                    'regKeyEvent/path': 'test',
                    'regKeyEvent/valueName': 'test',
                    'regKeyEvent/value': 'test'
                }
            }
        ],
        {'sort': None, 'agentId': None, 'limit': 50, 'source': None},
        {'get_agent_id': 0}
    )
]


@pytest.mark.parametrize('demisto_args, return_mocker,  call_args, call_count', UPSERT_COMMAND_DATA_CASES_GET_ALL_ALERTS)
def test_get_all_alerts_command(mocker, demisto_args, return_mocker, call_args, call_count):

    from FireEyeHXv2 import get_all_alerts_command, Client

    get_agent_id = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value='test')
    alerts = mocker.patch("FireEyeHXv2.get_alerts", return_value=return_mocker)
    mocker.patch("FireEyeHXv2.tableToMarkdown", return_value='test')
    mocker.patch("FireEyeHXv2.get_alert_entry", return_value='test')

    get_all_alerts_command(Client, demisto_args)

    assert alerts.call_args.args[1].get('sort') == call_args['sort']
    assert alerts.call_args.args[1].get('agentId') == call_args['agentId']
    assert alerts.call_args.args[1].get('limit') == call_args['limit']
    assert alerts.call_args.args[1].get('source') == call_args['source']

    assert get_agent_id.call_count == call_count['get_agent_id']


"""HELPERS"""


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        ('fieldSearchName', 'test'),
        {},
        'fieldSearchOperator and fieldSearchValue are required arguments'
    ),
    (
        ('dnsHostname', 'test'),
        {},
        'dnsHostnameOperator is required argument'
    )
]


@pytest.mark.parametrize('argForQuery, args, expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_organize_search_body_query_failed(argForQuery, args, expected_results):

    from FireEyeHXv2 import organize_search_body_query

    with pytest.raises(Exception) as e:
        organize_search_body_query(argForQuery, args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_ORGANIZE_SEARCH_BODY = [
    (
        ('fieldSearchName', 'test'),
        {'fieldSearchOperator': 'test', 'fieldSearchValue': 'test,test2,test3'},
        {'field': 'test', 'operator': 'test', 'value': 'test', 'len': 3}
    ),
    (
        ('dnsHostname', 'test'),
        {'dnsHostnameOperator': 'test'},
        {'field': 'DNS Hostname', 'operator': 'test', 'value': 'test', 'len': 1}
    )
]


@pytest.mark.parametrize('argForQuery, args, expected_results', UPSERT_COMMAND_DATA_ORGANIZE_SEARCH_BODY)
def test_organize_search_body_query(argForQuery, args, expected_results):

    from FireEyeHXv2 import organize_search_body_query

    result = organize_search_body_query(argForQuery=argForQuery, args=args)

    assert result[0]['field'] == expected_results['field']
    assert result[0]['operator'] == expected_results['operator']
    assert result[0]['value'] == expected_results['value']
    assert len(result) == expected_results['len']


UPSERT_COMMAND_DATA_CASES_ONE_FROM_LIST = [
    (
        ["test1", "test2"],
        {"test1": 1},
        ("test1", 1)
    ),
    (
        ["test1", "test2"],
        {"test1": 1, "test2": 2},
        False
    ),
    (
        ["test1", "test2"],
        {},
        False
    )
]


@pytest.mark.parametrize('demisto_arg1, demisto_arg2, expected_results', UPSERT_COMMAND_DATA_CASES_ONE_FROM_LIST)
def test_oneFromList(demisto_arg1, demisto_arg2, expected_results):

    from FireEyeHXv2 import oneFromList

    result = oneFromList(list_of_args=demisto_arg1, args=demisto_arg2)
    assert result == expected_results


UPSERT_COMMAND_DATA_CASES_REPORTED_AT = [
    (
        "1990-06-24T22:16:26.865Z",
        "1990-06-24T22:16:26.866Z"
    ),
    (
        "1990-06-24T22:16:26.999Z",
        "1990-06-24T22:16:27.000Z"
    ),
    (
        "1990-06-24T22:16:26.004Z",
        "1990-06-24T22:16:26.005Z"
    ),
    (
        "1990-06-24T22:16:26.065Z",
        "1990-06-24T22:16:26.066Z"
    )
]


@pytest.mark.parametrize('reported_at, expected_results', UPSERT_COMMAND_DATA_CASES_REPORTED_AT)
def test_organize_reported_at(reported_at, expected_results):

    from FireEyeHXv2 import organize_reported_at

    result = organize_reported_at(reported_at)

    assert result == expected_results


UPSERT_COMMAND_DATA_CASES_SEARCH_BODY = [
    (
        ("hostsNames", "localhost"),
        {"get_agent_id": 1, "get_host_set": 0}
    ),
    (
        ("agentsIds", "GfLI00Q4zpidezw9I11rV6"),
        {"get_agent_id": 0, "get_host_set": 0}
    ),
    (
        ("hostSetName", "Demisto"),
        {"get_agent_id": 0, "get_host_set": 1}
    ),
    (
        ("hostSet", 1001),
        {"get_agent_id": 0, "get_host_set": 0}
    )
]


@pytest.mark.parametrize('args, call_count', UPSERT_COMMAND_DATA_CASES_SEARCH_BODY)
def test_organize_search_body_host(mocker, args, call_count):

    from FireEyeHXv2 import organize_search_body_host, Client

    get_agent_id = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value=None)
    get_host_set = mocker.patch.object(
        Client,
        "get_host_set_information_request",
        return_value={"data": {"entries": [{"_id": "test"}]}})
    organize_search_body_host(Client, arg=args, body={})

    assert get_agent_id.call_count == call_count["get_agent_id"]
    assert get_host_set.call_count == call_count["get_host_set"]


UPSERT_COMMAND_DATA_CASES_GENERAL_CONTEXT_EVENT = [
    (
        {'event_type': 'fileWriteEvent',
            'event_values':
                {'fileWriteEvent/fileName': 'test',
                    'fileWriteEvent/md5': 'test',
                    'fileWriteEvent/fileExtension': 'test',
                    'fileWriteEvent/fullPath': 'test'}},
        object
    ),
    (
        {'event_type': 'test', 'event_values': {}},
        None
    )
]


@pytest.mark.parametrize('args, expected_results', UPSERT_COMMAND_DATA_CASES_GENERAL_CONTEXT_EVENT)
def test_general_context_from_event(args, expected_results):

    from FireEyeHXv2 import general_context_from_event

    result = general_context_from_event(args)

    if not result:
        assert result == expected_results
    else:
        assert isinstance(result, expected_results)


UPSERT_COMMAND_DATA_CASES_QUERY_FETCH = [

    (
        {"reported_at": "1990-06-24T22:16:26.865Z", "first_fetch": "1990-06-23T22:16:26.865Z"},
        "1990-06-24T22:16:26.865Z"
    ),
    (
        {"reported_at": None, "first_fetch": "1990-06-23T22:16:26.865Z"},
        "1990-06-23T22:16:26.865Z"
    )
]


@pytest.mark.parametrize('args, expected_results', UPSERT_COMMAND_DATA_CASES_QUERY_FETCH)
def test_query_fetch(mocker, args, expected_results):

    from FireEyeHXv2 import query_fetch

    mocker.patch("FireEyeHXv2.parse_date_range", return_value=["test", "test"])
    mocker.patch("FireEyeHXv2.timestamp_to_datestring", return_value="1990-06-23T22:16:26.865Z")
    result = query_fetch(reported_at=args.get("reported_at"), first_fetch=args.get("first_fetch"))

    assert expected_results in result


UPSERT_COMMAND_DATA_CASES_FETCH_INCIDENTS = [

    (
        {"reported_at": "1990-06-24T22:16:26.865Z", 'max_fetch': 60},
        [{"reported_at": "test"}, {"reported_at": "test"}],
        {"parse_alert": 2, "reported_at": 1, "setLastRun": 1, "limit": 60}

    ),
    (
        {'max_fetch': 10},
        [{"reported_at": "test"}, {"reported_at": "test"}],
        {"parse_alert": 2, "reported_at": 0, "setLastRun": 1, "limit": 10}
    ),
    (
        {},
        [],
        {"parse_alert": 0, "reported_at": 0, "setLastRun": 0, "limit": 50}
    )
]


@pytest.mark.parametrize('demisto_args, alerts_return, expected_call', UPSERT_COMMAND_DATA_CASES_FETCH_INCIDENTS)
def test_fetch_incidents(mocker, demisto_args, alerts_return, expected_call):

    from FireEyeHXv2 import fetch_incidents, Client

    mocker.patch("FireEyeHXv2.demisto.getLastRun", return_value=demisto_args)
    setLastRun = mocker.patch("FireEyeHXv2.demisto.setLastRun", return_value=demisto_args.get('last_run'))
    mocker.patch("FireEyeHXv2.query_fetch", return_value="test")
    reported_at = mocker.patch("FireEyeHXv2.organize_reported_at", return_value="test")
    get_alerts_call = mocker.patch("FireEyeHXv2.get_alerts", return_value=alerts_return)
    parse_alert = mocker.patch("FireEyeHXv2.parse_alert_to_incident", return_value="test")
    fetch_incidents(Client, demisto_args)

    assert get_alerts_call.call_args[0][1]['limit'] == expected_call['limit']
    assert parse_alert.call_count == expected_call["parse_alert"]
    assert reported_at.call_count == expected_call["reported_at"]
    assert setLastRun.call_count == expected_call["setLastRun"]


UPSERT_COMMAND_DATA_CASES_RUN_COMMANDS_WITHOUT_POLLING = [
    (
        {"cmd": "fireeye-hx-search"},
        {"search": 1, "data_acquisition": 0, "file_acquisition": 0}
    ),
    (
        {"cmd": "fireeye-hx-data-acquisition"},
        {"search": 0, "data_acquisition": 1, "file_acquisition": 0}
    ),
    (
        {"cmd": "fireeye-hx-file-acquisition"},
        {"search": 0, "data_acquisition": 0, "file_acquisition": 1}
    )
]


@pytest.mark.parametrize('demisto_args, call_count', UPSERT_COMMAND_DATA_CASES_RUN_COMMANDS_WITHOUT_POLLING)
def test_run_commands_without_polling(mocker, demisto_args, call_count):

    from FireEyeHXv2 import run_commands_without_polling, Client

    search = mocker.patch("FireEyeHXv2.start_search_command", return_value=["test", "_", "_"])
    data_acquisition = mocker.patch("FireEyeHXv2.data_acquisition_command", return_value=["test", "_", "_"])
    file_acquisition = mocker.patch("FireEyeHXv2.file_acquisition_command", return_value=["test", "_", "_"])

    run_commands_without_polling(Client, demisto_args)

    assert search.call_count == call_count["search"]
    assert data_acquisition.call_count == call_count['data_acquisition']
    assert file_acquisition.call_count == call_count['file_acquisition']


TEST_DELETE_INDICATOR_ARGS = (204, 'Successfully deleted indicator indicator_name from the category category'), \
                             (404, 'Failed deleting indicator indicator_name from the category category')


@pytest.mark.parametrize('status_code,expected_output', TEST_DELETE_INDICATOR_ARGS)
def test_delete_indicator_command(mocker, requests_mock, status_code: int, expected_output: str):
    base_url = 'https://example.com'
    indicator_name = 'indicator_name'
    category = 'category'
    from FireEyeHXv2 import delete_indicator_command, Client
    mocker.patch.object(Client, 'get_token_request', return_value='')
    request = requests_mock.delete(f"{base_url}/indicators/{category}/{indicator_name}",
                                   status_code=status_code,
                                   json={})
    client = Client(base_url)
    command_result = delete_indicator_command(client, {'indicator_name': indicator_name, 'category': category})
    assert command_result.readable_output.split(":")[0] == expected_output
    assert request.call_count == 1


@pytest.mark.parametrize('status_code,expected_output_prefix',
                         ((204, 'Successfully deleted'), (404, 'Failed deleting'), (418, 'Failed deleting')))
def test_delete_indicator_condition_command(mocker, requests_mock, status_code: int, expected_output_prefix: str):
    base_url = 'https://example.com'
    indicator_name = 'indicator_name'
    category = 'category'
    indicator_type = 'type'
    condition_id = 'condition_id'
    response_message = 'error message'

    from FireEyeHXv2 import Client, delete_condition_command
    mocker.patch.object(Client, 'get_token_request', return_value='')
    request = requests_mock.delete(f"{base_url}/indicators/{category}/{indicator_name}/"
                                   f"conditions/{indicator_type}/{condition_id}",
                                   status_code=status_code,
                                   json={'message': response_message})
    client = Client(base_url)
    command_result = delete_condition_command(client, {'indicator_name': indicator_name, 'category': category,
                                                       'type': indicator_type, 'condition_id': condition_id})
    human_readable_args = f'condition {condition_id} ({indicator_type}) of indicator {indicator_name} ({category})'
    assert request.call_count == 1
    readable_parts = command_result.readable_output.split(":")

    assert readable_parts[0] == f'{expected_output_prefix} {human_readable_args}'
    if status_code >= 400:
        assert 'message' in readable_parts[1]
    else:
        assert len(readable_parts) == 1


@pytest.mark.parametrize('file_name,status_code', (('list_indicators_success.json', 200),
                                                   ('list_indicators_unprocessable.json', 402)))
def test_list_indicator_categories_command(mocker, requests_mock, file_name: str, status_code: int):
    base_url = 'https://example.com'
    test_data_folder = Path(__file__).absolute().parent / 'test_data'
    mocked_response = json.loads((test_data_folder / 'responses' / file_name).read_text())
    expected_context = json.loads((test_data_folder / 'expected_context' / file_name).read_text())

    from FireEyeHXv2 import list_indicator_categories_command, Client
    mocker.patch.object(Client, 'get_token_request', return_value='')
    request = requests_mock.get(f'{base_url}/indicator_categories', status_code=status_code, json=mocked_response)
    client = Client(base_url)
    command_result = list_indicator_categories_command(client, {'search': 'foo', 'limit': 49})
    command_result.raw_response = command_result.raw_response or None
    assert command_result.to_context() == expected_context
    assert request.called_once
    assert request.last_request._url_parts.query == 'limit=49&search=foo'


def test_delete_host_set_command(mocker):
    """
    Given:
        - host set id

    When:
        - Calling the delete_host_set_request

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import delete_host_set_command, Client
    base_url = 'https://example.com'
    args = {'host_set_id': 'host_set_id'}

    mocker.patch.object(Client, 'get_token_request', return_value='')
    mocker.patch.object(Client, 'delete_host_set_request', return_value='')

    client = Client(base_url)
    command_result = delete_host_set_command(client, args)
    assert command_result.readable_output == 'Host set host_set_id was deleted successfully'


def test_create_static_host_set_command(mocker):
    """
    Given:
        - Host set name, host set ids

    When:
        - Calling the update_static_host_set_command

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import create_static_host_set_command, Client
    base_url = 'https://example.com'
    args = {'host_set_name': 'host_set_name',
            'hosts_ids': 'hosts_ids'}

    mocker.patch.object(Client, 'get_token_request', return_value='')
    mocker.patch.object(Client, 'create_static_host_set_request', return_value={'data':
                                                                                {'_id': 'host_set_id',
                                                                                 '_revision': '20220719071022107807465576'}})

    client = Client(base_url)
    command_result = create_static_host_set_command(client, args)
    assert command_result.readable_output == 'Static Host Set host_set_name with id host_set_id was created successfully.'


def test_create_dynamic_host_set_command(mocker):
    """
    Given:
        - Host set name, query

    When:
        - Calling the create_dynamic_host_set command

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import create_dynamic_host_set_command, Client
    base_url = 'https://example.com'
    args = {'host_set_name': 'host_set_name',
            'query': 'query'}

    mocker.patch.object(Client, 'get_token_request', return_value='')
    mocker.patch.object(Client, 'create_dynamic_host_set_request', return_value={'data':
                                                                                 {'_id': 'host_set_id',
                                                                                  '_revision': '20220719071022107807465576'}})

    client = Client(base_url)
    command_result = create_dynamic_host_set_command(client, args)
    assert command_result.readable_output == 'Dynamic Host Set host_set_name with id host_set_id was created successfully.'


@pytest.mark.parametrize('args, expected_results', [({'host_set_name': 'host_set_name',
                                                      'query': 'query',
                                                      'query_key': 'query_key'},
                                                     'Cannot use free text query with other query operators, Please use one.'),
                                                    ({'host_set_name': 'host_set_name'},
                                                     'Please provide a free text query,'
                                                     ' or add all of the query operators toghether.')])
def test_create_dynamic_host_set_command_failed(args, expected_results):
    """
    Given:
        - Host set name, query or query_key

    When:
        - Calling the create_dynamic_host_set command

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import create_dynamic_host_set_command

    client = ""

    with pytest.raises(Exception) as e:
        create_dynamic_host_set_command(client, args)
    assert str(e.value) == expected_results


def test_update_static_host_set_command(mocker):
    """
    Given:
        - Host set name, host set id, hosts set to add and host sets to remove

    When:
        - Calling the update_static_host_set_command

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import update_static_host_set_command, Client
    base_url = 'https://example.com'
    args = {
        'host_set_id': 'host_set_id',
        'host_set_name': 'host_set_name',
        'add_host_ids': 'add_host_ids',
        'remove_host_ids': 'remove_host_ids'
    }

    mocker.patch.object(Client, 'get_token_request', return_value='')
    mocker.patch.object(Client, 'update_static_host_set_request', return_value={'data':
                                                                                {'_id': 'host_set_id',
                                                                                 '_revision': '20220719071022107807465576'}})

    client = Client(base_url)
    command_result = update_static_host_set_command(client, args)
    assert command_result.readable_output == 'Static Host Set host_set_name was updated successfully.'


def test_update_dynamic_host_set_command(mocker):
    """
    Given:
        - Host set name, query and host set id

    When:
        - Calling the update_dynamic_host_set command

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import update_dynamic_host_set_command, Client
    base_url = 'https://example.com'
    args = {'host_set_name': 'host_set_name',
            'host_set_id': 'host_set_id',
            'query': 'query'}

    mocker.patch.object(Client, 'get_token_request', return_value='')
    mocker.patch.object(Client, 'update_dynamic_host_set_request', return_value={'data':
                                                                                 {'_id': 'host_set_id',
                                                                                  '_revision': '20220719071022107807465576'}})

    client = Client(base_url)
    command_result = update_dynamic_host_set_command(client, args)
    assert command_result.readable_output == 'Dynamic Host Set host_set_name was updated successfully.'


@pytest.mark.parametrize('args, expected_results', [({'host_set_name': 'host_set_name',
                                                      'query': 'query',
                                                      'query_key': 'query_key'},
                                                     'Cannot use free text query with other query operators, Please use one.'),
                                                    ({'host_set_name': 'host_set_name'},
                                                     'Please provide a free text query,'
                                                     ' or add all of the query operators toghether.')])
def test_update_dynamic_host_set_command_failed(args, expected_results):
    """
    Given:
        - Host set name, query or query_key

    When:
        - Calling the update_dynamic_host_set command

    Then:
        - failing when missing required data
    """
    from FireEyeHXv2 import update_dynamic_host_set_command
    client = ""

    with pytest.raises(Exception) as e:
        update_dynamic_host_set_command(client, args)
    assert str(e.value) == expected_results


def test_create_dynamic_host_request_body(mocker):
    """
    Given:
        - Host set name, query or query arguments

    When:
        - Calling the update_dynamic_host_set command

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import Client
    host_set_name = 'host_set_name'
    query = {'query': 'query'}
    query_key = 'query_key'
    query_value = 'query_value'
    query_operator = 'query_operator'
    base_url = 'https://example.com'

    mocker.patch.object(Client, 'get_token_request', return_value='')
    client = Client(base_url)
    result = client.create_dynamic_host_request_body(host_set_name, query, '', '', '')
    assert result == {'name': 'host_set_name', 'query': {'query': 'query'}}

    result = client.create_dynamic_host_request_body(host_set_name, '', query_key, query_value, query_operator)
    assert result == {'name': 'host_set_name', 'query': {'key': 'query_key',
                                                         'operator': 'query_operator',
                                                         'value': 'query_value'}}


def test_create_static_host_request_body(mocker):
    """
    Given:
        - Host set name, host set id, hosts set to add and host sets to remove

    When:
        - Calling the create_static_host_request_body

    Then:
        - ensure the command ran successfully
    """
    from FireEyeHXv2 import Client
    host_set_name = 'host_set_name'
    host_ids_to_add = 'host_ids_to_add'
    host_ids_to_remove = 'host_ids_to_remove'

    base_url = 'https://example.com'

    mocker.patch.object(Client, 'get_token_request', return_value='')
    client = Client(base_url)
    result = client.create_static_host_request_body(host_set_name, host_ids_to_add, host_ids_to_remove)
    assert result == {'changes': [{'add': 'host_ids_to_add', 'command': 'change', 'remove': 'host_ids_to_remove'}],
                      'name': 'host_set_name'}


def test_informative_error_in_get_token(mocker):
    """
    Given:
        - 401 error occured in get_token

    When:
        - init the client and the get token was called
    Then:
        - ensure informative message returned
    """

    from FireEyeHXv2 import Client
    mocker.patch.object(Client, '_http_request', side_effect=DemistoException('Incorrect user id or password'))

    with pytest.raises(Exception) as err:
        Client('test_client')

    assert str(err.value) == 'Unauthorized - Incorrect user id or password'


def test_headers_file_acquisition_package_request(requests_mock, mocker):
    """
    Given:
        - mock client, acquisition_id
    When:
        - running the file_acquisition_package_request
    Then:
        - ensure that the headers of this command is what expected:
            1. Token exists
            2. Header Accept is octet-stream
    """
    from FireEyeHXv2 import Client

    base_url = 'https://example.com/hx/api/v3'
    mocker.patch.object(Client, 'get_token_request', return_value='test')
    client = Client(base_url=base_url, auth=('username', 'password'), verify=True, proxy=False)
    url = 'https://example.com/hx/api/v3/acqs/files/acquisition_id.zip'

    requests_mock.get(url, json={'some_bytes': 'test'})
    client.file_acquisition_package_request('acquisition_id')
    assert requests_mock.request_history[0].headers.get('Accept') == 'application/octet-stream'
    assert requests_mock.request_history[0].headers.get('X-FeApi-Token') == 'test'


@pytest.mark.parametrize(
    'baseurl, expected_error',
    [
        (
            '<dummy_url>/hx',
            'The base URL is invalid please set the base URL without including /hx'
        ),
        (
            '<dummy_url>/hx/',
            'The base URL is invalid please set the base URL without including /hx'
        ),
        (
            '<dummy_url>/hx/api',
            'The base URL is invalid please set the base URL without including /hx/api'
        ),
        (
            '<dummy_url>/hx/api/',
            'The base URL is invalid please set the base URL without including /hx/api'
        ),
        (
            '<dummy_url>/hx/api/v3',
            'The base URL is invalid please set the base URL without including /hx/api/v3'
        ),
        (
            '<dummy_url>/hx/api/v3/',
            'The base URL is invalid please set the base URL without including /hx/api/v3'
        )
    ]
)
def test_validate_base_url(baseurl: str, expected_error: str):
    from FireEyeHXv2 import validate_base_url

    with pytest.raises(ValueError) as e:
        validate_base_url(baseurl)
    assert str(e.value) == expected_error


CREATE_INDICATOR_ARGS = {
    'category': 'test_cat',
    'name': 'test_name',
    'display_name': 'test_display_name',
    'description': 'test_desc',
    'platforms': ['platform1', 'platform2'],
    'data': {
        '_id': 'test'
    }
}


def test_create_indicator_command(monkeypatch):
    import FireEyeHXv2

    class MockClient:
        def __init__(self, base_url):
            pass

        def get_token_request(self):
            return "mock_token"

        def new_indicator_request(self, category, body: dict[str, Any]):
            return CREATE_INDICATOR_ARGS

    monkeypatch.setattr(FireEyeHXv2, "Client", MockClient)

    args = CREATE_INDICATOR_ARGS
    from FireEyeHXv2 import Client, create_indicator_command
    client = Client(base_url='https://www.example.com')
    command_result = create_indicator_command(client=client, args=args)
    assert command_result.raw_response == CREATE_INDICATOR_ARGS
