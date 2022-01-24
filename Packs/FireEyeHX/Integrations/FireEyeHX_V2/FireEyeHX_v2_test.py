"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import demistomock as demisto
import json
import io
import pytest

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

UPSERT_COMMAND_DATA_BAD_CASES=[
    (
        {'agentId':"","hostName":""},
        "Please provide either agentId or hostName"
    ),
    (
        {"agentId":"Hqb2ns3oui1fpzg0BxI1Ch"},
        "agentId Hqb2ns3oui1fpzg0BxI1Ch is not correct"
    ),
    (
        {"hostName":"111"},
        "111 is not found"
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
        - Get Host information

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
        {'policyName':"test","policyId":"test"},
        "Enter a Policy Id or Host Set Id but not both"
    )
]
@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA_BAD_CASES)
def test_list_host_set_policy_command_faild(demisto_args,expected_results):
    
    """
    Given:
        - agentId or hostName

    When:
        - Get Host information

    Then:
        - failing when missing required data
    """

    from FireEyeHX_v2 import  list_host_set_policy_command

    client = ""#Client(base_url='some_mock_url', verify=False)
    
    with pytest.raises(Exception) as e:
        list_host_set_policy_command(client, demisto_args)
    assert str(e.value) == expected_results 

    
# TODO: ADD HERE unit tests for every command
