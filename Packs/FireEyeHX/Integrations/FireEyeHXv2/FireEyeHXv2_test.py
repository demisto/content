import json
import io
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    mocker.patch('FireEyeHXv2.indicator_entry', return_value='test')
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
        [True, '12']
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

    from FireEyeHXv2 import data_acquisition

    client = ""

    with pytest.raises(Exception) as e:
        data_acquisition(client, demisto_args)
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
    """
    Given:
        - searchId

    When:
        - get result specific search by search Id

    Then:
        - failing when missing required data
    """
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
    """
    Given:
        - acquisitionId

    When:
        - ""

    Then:
        - failing when missing required data
    """
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

    from FireEyeHXv2 import data_acquisition, Client
    mocker.patch.object(Client, "get_token_request", return_value="test")
    client = Client(
        base_url="base_url",
        verify=False,
        proxy=True,
        auth=("userName", "password"))

    get_agentId = mocker.patch("FireEyeHXv2.get_agent_id_by_host_name", return_value="")
    mocker.patch.object(client, "data_acquisition_request", return_value={"data": ""})
    data_acquisition(client, demisto_args)
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

    data_acquisition_call = mocker.patch("FireEyeHXv2.data_acquisition", return_value={"_id": '12'})
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
        organize_search_body_query(argForQuery, **args)
    assert str(e.value) == expected_results


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

    result = oneFromList(listOfArgs=demisto_arg1, **demisto_arg2)
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
        {"reported_at": "1990-06-24T22:16:26.865Z"},
        [{"reported_at": "test"}, {"reported_at": "test"}],
        {"parse_alert": 2, "reported_at": 1, "setLastRun": 1}

    ),
    (
        {},
        [{"reported_at": "test"}, {"reported_at": "test"}],
        {"parse_alert": 2, "reported_at": 0, "setLastRun": 1}
    ),
    (
        {},
        [],
        {"parse_alert": 0, "reported_at": 0, "setLastRun": 0}
    )
]


@pytest.mark.parametrize('demisto_args, alerts_return, call_count', UPSERT_COMMAND_DATA_CASES_FETCH_INCIDENTS)
def test_fetch_incidents(mocker, demisto_args, alerts_return, call_count):

    from FireEyeHXv2 import fetch_incidents, Client

    mocker.patch("FireEyeHXv2.demisto.getLastRun", return_value=demisto_args)
    setLastRun = mocker.patch("FireEyeHXv2.demisto.setLastRun", return_value=demisto_args.get('last_run'))
    mocker.patch("FireEyeHXv2.query_fetch", return_value="test")
    reported_at = mocker.patch("FireEyeHXv2.organize_reported_at", return_value="test")
    mocker.patch("FireEyeHXv2.get_alerts", return_value=alerts_return)
    parse_alert = mocker.patch("FireEyeHXv2.parse_alert_to_incident", return_value="test")
    fetch_incidents(Client, demisto_args)

    assert parse_alert.call_count == call_count["parse_alert"]
    assert reported_at.call_count == call_count["reported_at"]
    assert setLastRun.call_count == call_count["setLastRun"]
