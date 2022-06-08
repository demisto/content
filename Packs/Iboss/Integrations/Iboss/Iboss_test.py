"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import demistomock as demisto
import CommonServerPython
from CommonServerPython import urljoin
import pytest
import json
import requests_mock
import datetime

from Iboss import Client

client = Client(username="michael.forgione@iboss.com", password="123Sally!!", account_settings_id="150819"
                , verify=False, proxy=False)
resp = client.remove_entity_from_block_list("notorange.com")
print(resp)

def get_mock_client(mocker):
    from Iboss import Client
    client = Client(username="user", password="123", account_settings_id="123", verify=False, proxy=False)
    dt_future = datetime.datetime.now() + datetime.timedelta(days=7)
    mocker.patch.object(client, '_get_cloud_token', return_value="abc")
    mocker.patch.object(client, "_get_cloud_settings_tokens", return_value=("def", "ghi", str(dt_future)))
    mocker.patch.object(client, "_get_primary_gateway", return_value="pswg.com")
    mocker.patch.object(client, "_get_swg_xsrf_token", return_value="jkl")
    return client


def test_add_entity_to_block_list(requests_mock, mocker):
    """
        Scenario: Add entry to allow list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A add_entity_to_allow_list command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import add_entity_to_block_list_command
    client = get_mock_client(mocker)

    requests_mock.put(
        f'https://pswg.com/json/controls/blockList?currentPolicyBeingEdited=1',
        json={'message': 'URL added successfully.'})

    args = {
        "entity": "google.com,demisto.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "60"
    }

    result = add_entity_to_block_list_command(client, args=args)

    assert len(result) == 2
    assert result[0].outputs.get("message") == "URL added successfully."
    assert result[1].outputs.get("message") == "URL added successfully."


def test_add_entity_to_allow_list(requests_mock, mocker):
    """
        Scenario: Add multiple entries to allow list
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A add_entity_to_block_list command is called and the entry is added.
        Then:
         - Ensure number of items is correct.
         - Ensure a sample value from the API matches what is generated in the context.
    """
    from Iboss import add_entity_to_allow_list_command

    client = get_mock_client(mocker)
    requests_mock.put(
        f'https://pswg.com/json/controls/allowList?currentPolicyBeingEdited=1',
        json={'message': 'URL added successfully.'})

    args = {
        "entity": "google.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = add_entity_to_allow_list_command(client, args=args)

    assert len(result) == 1
    assert result[0].outputs.get("message") == "URL added successfully."


def test_remove_entity_from_allow_list_no_exist(requests_mock, mocker):
    """
           Scenario: Attempt to remove entry from allow list that is not present on list
           Given:
            - User has provided valid credentials and arguments.
           When:
            - A remove_entity_from_allow_list command is called and but entry is not removed because it is not present on list
           Then:
            - Ensure number of items is correct.
            - Ensure a sample value from the API matches what is generated in the context.
       """
    from Iboss import remove_entity_from_allow_list_command

    client = get_mock_client(mocker)
    requests_mock.delete(
        f'https://pswg.com/json/controls/allowList?currentPolicyBeingEdited=1',
        json={'message': 'URL not found in list.'})

    args = {
        "entity": "google.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = remove_entity_from_allow_list_command(client, args=args)

    assert len(result) == 1
    assert result[0].outputs.get("message") == "URL not found in list."


def test_remove_entity_from_block_list(requests_mock, mocker):
    """
           Scenario: Attempt to remove multiple entries from allow list
           Given:
            - User has provided valid credentials and arguments.
           When:
            - A remove_entity_from_block_list command is called and entries
           Then:
            - Ensure number of items is correct.
            - Ensure a sample value from the API matches what is generated in the context.
       """
    from Iboss import remove_entity_from_block_list_command

    client = get_mock_client(mocker)
    requests_mock.delete(
        f'https://pswg.com/json/controls/blockList?currentPolicyBeingEdited=1',
        json={'message': 'URL removed successfully.'})

    args = {
        "entity": "google.com, demisto.com",
        "current_policy_being_edited": "1",
        "allow_keyword": "0",
        "direction": "2",
        "start_port": "0",
        "end_port": "0",
        "global": "0",
        "is_regex": "0",
        "priority": "0",
        "time_url_expires_in_minutes": "0"
    }

    result = remove_entity_from_block_list_command(client, args=args)

    assert len(result) == 2
    assert result[0].outputs.get("message") == "URL removed successfully."
    assert result[1].outputs.get("message") == "URL removed successfully."


def test_ip_lookup(requests_mock, mocker):
    """
       Scenario: Attempt to lookup IP reputation (suspicious due to unreachable)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - An `ip command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is suspicious
        - Ensure iboss metadata indicates site unreachable
        - Ensure iboss metadata show redirect
   """
    from Iboss import ip_lookup

    client = get_mock_client(mocker)

    http_data = {'activeMalwareSubscription': 1,
                 'categories': '0000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                 'categorized': 'true', 'googleSafeBrowsingDescription': '', 'googleSafeBrowsingEnabled': 1,
                 'googleSafeBrowsingIsSafeUrl': 1, 'googleSafeBrowsingSuccess': 1, 'googleSafeBrowsingSupport': 1,
                 'isSafeUrl': 0, 'malwareEngineAnalysisDescription': 'Redirect - Redirects to: https://1.1.1.1/',
                 'malwareEngineAnalysisEnabled': 1, 'malwareEngineAnalysisSuccess': 1, 'malwareEngineIsSafeUrl': 1,
                 'malwareEngineResultCode': 3, 'message': 'Status: Url Known. Please see categories below.',
                 'realtimeCloudLookupDomainIsGrey': 0, 'realtimeCloudLookupEnabled': 1,
                 'realtimeCloudLookupIsSafeUrl': 1, 'realtimeCloudLookupRiskDescription': '',
                 'realtimeCloudLookupSuccess': 1, 'reputationDatabaseBotnetDetection': 0,
                 'reputationDatabaseEnabled': 1, 'reputationDatabaseIsSafeUrl': 1, 'reputationDatabaseLookupSuccess': 1,
                 'reputationDatabaseMalwareDetection': 0, 'url': '1.1.1.1',
                 'webRequestHeuristicBlockUnreachableSites': '1',
                 'webRequestHeuristicDescription': 'Heuristic Engine Detection', 'webRequestHeuristicIsSafeUrl': 0,
                 'webRequestHeuristicLevelHighScore': '79', 'webRequestHeuristicLevelLowScore': '10',
                 'webRequestHeuristicLevelMediumScore': '60', 'webRequestHeuristicLevelNoneScore': '0',
                 'webRequestHeuristicProtectionActionHigh': '0', 'webRequestHeuristicProtectionActionLow': '0',
                 'webRequestHeuristicProtectionActionMedium': '0', 'webRequestHeuristicProtectionLevel': '1',
                 'webRequestHeuristicSuccess': 1, 'webRequestHeuristicSupport': 1}

    requests_mock.post(
        f'https://pswg.com/json/controls/urlLookup',
        json=http_data)

    results = ip_lookup(client, {"ip": "1.1.1.1"})

    assert results[0].outputs['DBotScore']['Score'] == 2
    assert results[0].outputs['iboss'][
               'malwareEngineAnalysisDescription'] == "Redirect - Redirects to: https://1.1.1.1/"
    assert results[0].outputs['iboss']['webRequestHeuristicBlockUnreachableSites'] == "1"


def test_domain_lookup(requests_mock, mocker):
    """
       Scenario: Attempt to lookup domain reputation (malicious due to reputation)
       Given:
        - User has provided valid credentials and arguments.
       When:
        - A url command is called
       Then:
        - Ensure number of items is correct.
        - Ensure a sample value from the API matches what is generated in the context.
        - Ensure DBotScore is malicious
        - Ensure Malicious context message exists
        - Ensure reputationDatabaseMalwareDetection == 1
   """
    from Iboss import domain_lookup

    client = get_mock_client(mocker)

    http_data = {"activeMalwareSubscription": 1,
                 "categories": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                 "categorized": "true", "googleSafeBrowsingDescription": "", "googleSafeBrowsingEnabled": 1,
                 "googleSafeBrowsingIsSafeUrl": 1, "googleSafeBrowsingSuccess": 1, "googleSafeBrowsingSupport": 1,
                 "isSafeUrl": 0, "malwareEngineAnalysisDescription": "Unreachable - HTTP Error Code: 503",
                 "malwareEngineAnalysisEnabled": 1, "malwareEngineAnalysisSuccess": 1, "malwareEngineIsSafeUrl": 1,
                 "malwareEngineResultCode": 2, "message": "Status: Suspicious Url. Please see below.",
                 "realtimeCloudLookupDomainIsGrey": 0, "realtimeCloudLookupEnabled": 1,
                 "realtimeCloudLookupIsSafeUrl": 1, "realtimeCloudLookupRiskDescription": "",
                 "realtimeCloudLookupSuccess": 1, "reputationDatabaseBotnetDetection": 0,
                 "reputationDatabaseEnabled": 1, "reputationDatabaseIsSafeUrl": 0, "reputationDatabaseLookupSuccess": 1,
                 "reputationDatabaseMalwareDetection": 1, "url": "myetherevvalliet.com",
                 "webRequestHeuristicBlockUnreachableSites": "1",
                 "webRequestHeuristicDescription": "Heuristic Engine Detection", "webRequestHeuristicIsSafeUrl": 0,
                 "webRequestHeuristicLevelHighScore": "79", "webRequestHeuristicLevelLowScore": "10",
                 "webRequestHeuristicLevelMediumScore": "60", "webRequestHeuristicLevelNoneScore": "0",
                 "webRequestHeuristicProtectionActionHigh": "0", "webRequestHeuristicProtectionActionLow": "0",
                 "webRequestHeuristicProtectionActionMedium": "0", "webRequestHeuristicProtectionLevel": "1",
                 "webRequestHeuristicSuccess": 1, "webRequestHeuristicSupport": 1}

    requests_mock.post(
        f'https://pswg.com/json/controls/urlLookup',
        json=http_data)

    results = domain_lookup(client, {"domain": "myetherevvalliet.com"})

    assert results[0].outputs['DBotScore']['Score'] == 3
    assert results[0].outputs['Domain']['Malicious']['Description'] == "Status: Suspicious Url. Please see below; Unreachable - HTTP Error Code: 503; Heuristic Engine Detection"
    assert results[0].outputs['iboss']['reputationDatabaseMalwareDetection'] == 1
