"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
# from Packs.FireEyeHX.Integrations.FireEyeHX.CommonServerPython import CommandResults
from http.client import responses
import demistomock as demisto
import json
import io
import pytest

from CommonServerPython import CommandResults
def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


UPSERT_COMMAND_DATA_BAD_CASES=[
    (
        {'policyName':"test","policyId":"test"},
        "Enter a name or ID but not both"
    )
]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_list_policy_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - agentId or hostName

    When:
        - Get list of all the policies

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import  list_policy_command

    client = ""#Client(base_url='some_mock_url', verify=False)
    
    with pytest.raises(Exception) as e:
        list_policy_command(client, demisto_args)
    assert str(e.value) == expected_results 


UPSERT_COMMAND_DATA_BAD_CASES=[
    (
        {'hostSetId':"test","policyId":"test"},
        "Enter a Policy Id or Host Set Id but not both"
    )
]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_list_host_set_policy_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - hostSetId or policyId

    When:
        - Get specific policy by Policy Id or policies by Host Set Id 

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import  list_host_set_policy_command

    client = ""#Client(base_url='some_mock_url', verify=False)
    
    with pytest.raises(Exception) as e:
        list_host_set_policy_command(client, demisto_args)
    assert str(e.value) == expected_results 


UPSERT_COMMAND_DATA_BAD_CASES=[
    (
        # Given only one argument instead of two
        {"policyId":"test"},
        "policy ID and hostSetId are required"
    ),
    (
        # Given only one argument instead of two
        {"hostSetId":"test"},
        "policy ID and hostSetId are required"
    ),
    (
        # No arguments given
        {},
        "policy ID and hostSetId are required"
    )

] 
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_assign_host_set_policy_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - agentId or hostName

    When:
        - assigning host set to the policy

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import  assign_host_set_policy_command

    client = ""#Client(base_url='some_mock_url', verify=False)
    
    with pytest.raises(Exception) as e:
        assign_host_set_policy_command(client, demisto_args)
    assert str(e.value) == expected_results 


UPSERT_COMMAND_DATA_BAD_CASES=[

    (
        {},
        "Please provide either agentId or hostName"
    )
    
] 
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_host_information_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - agentId or hostName

    When:
        - Get Host information

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import  get_host_information_command

    client = ""#Client(base_url='some_mock_url', verify=False)
    
    with pytest.raises(Exception) as e:
        get_host_information_command(client, demisto_args)
    assert str(e.value) == expected_results 


UPSERT_COMMAND_DATA_BAD_CASES=[

    (
        {},
        "Please provide either agentId or hostName"
    )
    
]    
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_host_containment_command_faild(demisto_args,expected_results):

    """
    Given:
        - agentId or hostName

    When:
        - Get Host information

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import host_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        host_containment_command(client,demisto_args)
    assert str(e.value) == expected_results

UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {},
        "Agent ID is required"
    )
]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_approve_containment_command_faild(demisto_args,expected_results):

    """
    Given:
        - agentId

    When:
        - approve containment to the request contain

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import approve_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        approve_containment_command(client,demisto_args)
    assert str(e.value) == expected_results

UPSERT_COMMAND_DATA_BAD_CASES = [
    
    (
        # No arguments given
        {},
        "One of the following arguments is required -> [agentId, hostName]"
    )
]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_cancel_containment_command_faild(demisto_args,expected_results):

    """
    Given:
        - agentId or hostName

    When:
        - cancel containment for specific host

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import cancel_containment_command

    client = ""

    with pytest.raises(Exception) as e:
        cancel_containment_command(client,demisto_args)
    assert str(e.value) == expected_results
    
UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # Given only one argument instead of two
        {"category":"test"},
        "The category and name arguments are required"
    ),
    (
        # Given only one argument instead of two
        {"name":"test"},
        "The category and name arguments are required"
    ),
    (
        # No arguments given
        {},
        "The category and name arguments are required"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_indicator_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - category or name

    When:
        - get specific indicator by category and name

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import get_indicator_command

    client = ""

    with pytest.raises(Exception) as e:
        get_indicator_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Search Id is must be"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_search_stop_command_faild(demisto_args,expected_results):

    """
    Given:
        - searchId

    When:
        - Stop a specific search by search Id  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import search_stop_command

    client = ""

    with pytest.raises(Exception) as e:
        search_stop_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # Given only one argument instead of two
        {"name":"test","condition":"test"},
        "All of the following arguments are required -> ['name','category','condition']"
    ),
    (
        # Given only one argument instead of two
        {"category":"test","name":"test"},
        "All of the following arguments are required -> ['name','category','condition']"
    ),
    (
        # No arguments given
        {"category":"test","condition":"test"},
        "All of the following arguments are required -> ['name','category','condition']"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_append_conditions_command_faild(demisto_args,expected_results):

    """
    Given:
        - category and name and condition

    When:
        - append condition to specific indicator by category and name and body 

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import append_conditions_command

    client = ""

    with pytest.raises(Exception) as e:
        append_conditions_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Search Id is must be"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_search_result_get_command_faiild(demisto_args,expected_results):

    """
    Given:
        - searchId

    When:
        - get result specific search by search Id  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import search_result_get_command

    client = ""

    with pytest.raises(Exception) as e:
        search_result_get_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Please provide either agentId or hostName"
    ),
    (
        {"agentId":"test"},
        "If the script is not provided, defaultSystemScript must be specified"
    ),
    (
        {"agentId":"test","script":"test"},
        "If the script is provided, script name must be specified as well"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_data_acquisition_faiild(demisto_args,expected_results):

    """
    Given:
        - searchId

    When:
        - get result specific search by search Id  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import data_acquisition

    client = ""

    with pytest.raises(Exception) as e:
        data_acquisition(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Acquisition Id is required"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_delete_data_acquisition_command_faiild(demisto_args,expected_results):

    """
    Given:
        - searchId

    When:
        - get result specific search by search Id  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import delete_data_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        delete_data_acquisition_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Please provide either agentId or hostName"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_file_acquisition_command_faiild(demisto_args,expected_results):

    """
    Given:
        - searchId or hostName

    When:
        - ""  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import file_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        file_acquisition_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_BAD_CASES = [

    (
        # No arguments given
        {},
        "Please provide acquisitionId"
    )

]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_get_data_acquisition_command_faiild(demisto_args,expected_results):

    """
    Given:
        - acquisitionId

    When:
        - ""  

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import get_data_acquisition_command

    client = ""

    with pytest.raises(Exception) as e:
        get_data_acquisition_command(client,demisto_args)
    assert str(e.value) == expected_results


UPSERT_COMMAND_DATA_CASES = [

    (
        # No arguments given
        {"agentId":"test"},
        {"agentId":1,"hostName":0},
        isinstance({},dict)
    ),
    (
        # No arguments given
        {"hostName":"test"},
        {"agentId":0,"hostName":1},
        isinstance({},dict)
    )

]
@pytest.mark.parametrize('demisto_args,call_count,expected_results', UPSERT_COMMAND_DATA_CASES)
def test_host_information(mocker,demisto_args,call_count,expected_results):

    from FireEyeHX_v2 import get_host_information_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    host_by_agentId = mocker.patch.object(client,"get_hosts_by_agentId_request",return_value={"data":{}})
    host_by_hostName = mocker.patch.object(client,"get_hosts_request",return_value={"data":{"entries":[{}]}})
    result = get_host_information_command(client,demisto_args)
    assert host_by_agentId.call_count == call_count["agentId"]
    assert host_by_hostName.call_count == call_count["hostName"] 
    assert isinstance(result.outputs,dict) == expected_results

UPSERT_COMMAND_DATA_CASES2 = [

    (
        
        {},
        {"hosts_partial":2},
        [{"data":{"entries":[{}]}},{"data":{"entries":[]}}],
        [list,dict]
        
    ),
    (
        {},
        {"hosts_partial":1},
        [{"data":{"entries":[]}}],
        [list,0] 
    )

]
@pytest.mark.parametrize('demisto_args,call_count,return_value_mock,expected_results', UPSERT_COMMAND_DATA_CASES2)
def test_get_all_hosts_information(mocker,demisto_args,call_count,return_value_mock,expected_results):

    from FireEyeHX_v2 import get_all_hosts_information_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    hosts_partial = mocker.patch.object(client,"get_hosts_request",side_effect=return_value_mock)
    result = get_all_hosts_information_command(client,demisto_args)
    #assert host_by_agentId.call_count == call_count["agentId"]
    assert hosts_partial.call_count == call_count["hosts_partial"] 
    assert isinstance(result.outputs,expected_results[0]) == True
    if result.outputs:
        assert isinstance(result.outputs[0],expected_results[1]) == True
    else:
        assert len(result.outputs) == expected_results[1]

UPSERT_COMMAND_DATA_CASES2 = [

    (
        
        {"hostSetID":"test"},
        {"data":{}},
        list
        
    ),
    (
        {},
        {"data":{"entries":[]}},
        list 
    )

]
@pytest.mark.parametrize('demisto_args,return_value_mock,expected_results', UPSERT_COMMAND_DATA_CASES2)
def test_get_host_set_information(mocker,demisto_args,return_value_mock,expected_results):

    from FireEyeHX_v2 import get_host_set_information_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    mocker.patch.object(client,"get_host_set_information_request",return_value=return_value_mock)
    result = get_host_set_information_command(client,demisto_args)
    #assert host_by_agentId.call_count == call_count["agentId"]
    assert isinstance(result.outputs,expected_results) == True


UPSERT_COMMAND_DATA_CASES3 = [

    (
        {"hostName":"test"},
        1,
        dict
    ),
    (
        {"agentId":"test"},
        0,
        dict 
    )
]
@pytest.mark.parametrize('demisto_args,call_count,expected_results', UPSERT_COMMAND_DATA_CASES3)
def test_host_containment(mocker,demisto_args,call_count,expected_results):

    from FireEyeHX_v2 import host_containment_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    get_agentId = mocker.patch("FireEyeHX_v2.get_agent_id_by_host_name",return_value="")
    mocker.patch.object(client,"host_containmet_request",return_value=None)
    mocker.patch.object(client,"get_hosts_by_agentId_request",return_value={"data":{}})
    result = host_containment_command(client,demisto_args)
    assert get_agentId.call_count == call_count
    assert len(result) == 2
    assert isinstance(result[1].outputs,expected_results) == True


UPSERT_COMMAND_DATA_CASES4 = [

    (
        {"agentId":"test"},
        1
    )
]
@pytest.mark.parametrize('demisto_args,call_count', UPSERT_COMMAND_DATA_CASES4)
def test_approve_containment_command(mocker,demisto_args,call_count):

    from FireEyeHX_v2 import approve_containment_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    
    call_request = mocker.patch.object(client,"approve_containment_request",return_value=None)
    
    result = approve_containment_command(client,demisto_args)
    assert call_request.call_count == call_count


UPSERT_COMMAND_DATA_CASES5 = [

    (
        {"hostName":"test"},
        1
    ),
    (
        {"agentId":"test"},
        0
    )
]
@pytest.mark.parametrize('demisto_args,call_count', UPSERT_COMMAND_DATA_CASES5)
def test_cancel_containment_command(mocker,demisto_args,call_count):

    from FireEyeHX_v2 import cancel_containment_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    get_agentId = mocker.patch("FireEyeHX_v2.get_agent_id_by_host_name",return_value="")
    mocker.patch.object(client,"cancel_containment_request",return_value=None)
    result = cancel_containment_command(client,demisto_args)
    assert get_agentId.call_count == call_count


UPSERT_COMMAND_DATA_CASES6 = [

    (
        {"hostName":"test","defaultSystemScript":"win"},
        1
    ),
    (
        {"agentId":"test","defaultSystemScript":"win"},
        0
    )
]
@pytest.mark.parametrize('demisto_args,call_count', UPSERT_COMMAND_DATA_CASES6)
def test_data_acquisition(mocker,demisto_args,call_count):

    from FireEyeHX_v2 import data_acquisition, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    get_agentId = mocker.patch("FireEyeHX_v2.get_agent_id_by_host_name",return_value="")
    mocker.patch.object(client,"data_acquisition_request",return_value={"data":""})
    result = data_acquisition(client,demisto_args)
    assert get_agentId.call_count == call_count


UPSERT_COMMAND_DATA_CASES7 = [

    (
        {},
        "RUNNING",
        {"data_acquisition_call":1,"ScheduledCommand_call":1},
        CommandResults
    ),
    (
        {"acquisition_id":"test"},
        "COMPLETE",
        {"data_acquisition_call":0,"ScheduledCommand_call":0},
        list
    )
]
@pytest.mark.parametrize('demisto_args,state,call_count,expected_results', UPSERT_COMMAND_DATA_CASES7)
def test_data_acquisition_command(mocker,demisto_args,state,call_count,expected_results):

    from FireEyeHX_v2 import data_acquisition_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    data_acquisition_call = mocker.patch("FireEyeHX_v2.data_acquisition",return_value={"_id":"test"})
    mocker.patch.object(client,"data_acquisition_information_request",return_value={"state":state})
    mocker.patch.object(client,"data_collection_request",return_value="")
    ScheduledCommand_call = mocker.patch("FireEyeHX_v2.ScheduledCommand",return_value="test")
    result = data_acquisition_command(client,demisto_args)
    assert ScheduledCommand_call.call_count == call_count["ScheduledCommand_call"]
    assert data_acquisition_call.call_count == call_count["data_acquisition_call"]
    assert isinstance(result, expected_results) == True


UPSERT_COMMAND_DATA_CASES8 = [

    (
        {"hostName":"test"},
        "RUNNING",
        {"get_agentId":1,"ScheduledCommand":1},
        CommandResults
    ),
    (
        {"agentId":"test"},
        "RUNNING",
        {"get_agentId":0,"ScheduledCommand":1},
        CommandResults
    ),
    (
        {"acquisition_id":"test"},
        "COMPLETE",
        {"get_agentId":0,"ScheduledCommand":0},
        list
    )
]
@pytest.mark.parametrize('demisto_args,state,call_count,expected_results', UPSERT_COMMAND_DATA_CASES8)
def test_file_acquisition_command(mocker,demisto_args,state,call_count,expected_results):

    from FireEyeHX_v2 import file_acquisition_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    get_agentId = mocker.patch("FireEyeHX_v2.get_agent_id_by_host_name",return_value={"agentId":"test"})
    mocker.patch.object(client,"file_acquisition_information_request",return_value={"state":state})
    mocker.patch.object(client,"file_acquisition_request",return_value={"_id":"test"})
    mocker.patch.object(client,"file_acquisition_package_request",return_value={"state":state})
    ScheduledCommand_call = mocker.patch("FireEyeHX_v2.ScheduledCommand",return_value="test")
    mocker.patch("FireEyeHX_v2.fileResult",return_value="test")
    mocker.patch("FireEyeHX_v2.os.path.splitext",return_value="test")
    result = file_acquisition_command(client,demisto_args)
    assert ScheduledCommand_call.call_count == call_count["ScheduledCommand"]
    assert get_agentId.call_count == call_count["get_agentId"]
    assert isinstance(result, expected_results) == True


UPSERT_COMMAND_DATA_CASES8 = [

    (
        {"acquisitionId":"test"},
        "COMPLETE",
        {"get_data":1},
        list
    ),
    (
        {"acquisitionId":"test"},
        "RUNNING",
        {"get_data":0},
        CommandResults
    )
]
@pytest.mark.parametrize('demisto_args,state,call_count,expected_results', UPSERT_COMMAND_DATA_CASES8)
def test_get_data_acquisition_command(mocker,demisto_args,state,call_count,expected_results):

    from FireEyeHX_v2 import get_data_acquisition_command, Client
    mocker.patch.object(Client,"get_token_request",return_value="test")
    client = Client(
            base_url="base_url",
            verify=False,
            proxy=True,
            auth=("userName","password"))
    
    mocker.patch.object(client,"data_acquisition_information_request",return_value={"host":{"_id":"test"},"state":state})
    mocker.patch.object(client,"get_hosts_by_agentId_request",return_value={"data":{}})
    get_data_call = mocker.patch.object(client,"data_collection_request",return_value="test")
    mocker.patch("FireEyeHX_v2.fileResult",return_value="test")
    result = get_data_acquisition_command(client,demisto_args)
    assert get_data_call.call_count == call_count["get_data"]
    assert isinstance(result, expected_results) == True





#TODO: ADD HERE unit tests for every command
