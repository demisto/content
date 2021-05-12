"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import CofenseIntelligenceV2
from CommonServerPython import *
import demistomock as demisto
import pytest
import requests
import json
import io
from CofenseIntelligenceV2 import *
import demistomock as
def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {
        'dummy': 'this is a dummy response'
    }
    response = baseintegration_dummy_command(client, args)

    mock_response = util_load_json('test_data/baseintegration-dummy.json')

    assert response.outputs == mock_response


def test_threats_analysis():
    indicator='email1'
    threshold='Major'
    mock_threats = util_load_json('test_data/test_threats.json').get('threats')
    mock_md_data =util_load_json('test_data/test_threats.json').get('mock_md_data')
    mock_dbot_score = util_load_json('test_data/test_threats.json').get('mock_dbot_score')
    md_data, dbot_score = threats_analysis(mock_threats, indicator, threshold)
    assert mock_dbot_score == dbot_score
    assert mock_md_data == md_data

def test_create_threat_md_row():
    threat=util_load_json('test_data/test_threats.json').get('threats')[0]
    severity_level=util_load_json('test_data/test_threats.json').get('mock_dbot_score')
    threat_md_row=create_threat_md_row(threat, severity_level)
    mock_threat_md_row = util_load_json('test_data/test_threats.json').get('mock_md_data')[0]
    assert mock_threat_md_row == threat_md_row


def test_extracted_string(mocker):
    mock_args={'str': 'str', 'limit': '10'}
    mock_base_url = 'mock_base_url'
    mock_username ='mock_username'
    mock_password = 'mock_password'
    headers: Dict = {
        "Authorization": f"Basic {base64.b64encode(':'.join([mock_username, mock_password]).encode()).decode().strip()}"
    }
    client = CofenseIntelligenceV2.Client(
        base_url=mock_base_url,
        verify=True,
        headers=headers,
        proxy=False)
    return_value=util_load_json('test_data/test_threats.json')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    mock_response=extracted_string(client, mock_args)
    with requests_mock
    return CommandResults(
        outputs_prefix='CofenseIntelligence',
        outputs_key_field='id',
        outputs={'CofenseIntelligence': {"String": string, "NumOfThreats": count_threats}},
        raw_response=result,
        readable_output=tableToMarkdown(f'There are {count_threats} threats regarding your string search\n', md_data))

def test_pipeline_query_command(mocker):
    """
        Given:
            collection - where to search.
            pipeline - json pipeline query

        When:
            calling `pipeline_query_command`

        Then:
            validate the readable output and context
        """
    client = Client(['aaaaa'], 'a', 'b', 'd')
    return_value = [
        {'title': 'test_title', 'color': 'red', 'year': '2019', '_id': '6034a5a62f605638740dba55'},
        {'title': 'test_title', 'color': 'yellow', 'year': '2020', '_id': '6034a5c52f605638740dba57'}
    ]
    mocker.patch.object(client, 'pipeline_query', return_value=return_value)
    readable_outputs, outputs, raw_response = pipeline_query_command(
        client=client,
        collection='test_collection',
        pipeline="[{\"$match\": {\"title\": \"test_title\"}}]"
    )

    expected_context = list()
    for item in copy.deepcopy(raw_response):
        item.update({'collection': 'test_collection'})
        expected_context.append(item)

    assert 'Total of 2 entries were found in MongoDB collection' in readable_outputs
    assert outputs.get('MongoDB.Entry(val._id === obj._id && obj.collection === val.collection)') == expected_context

