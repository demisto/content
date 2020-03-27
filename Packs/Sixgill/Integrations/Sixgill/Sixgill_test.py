import pytest
import copy
import demistomock as demisto


incidents_list = [{'alert_name': 'someSecretAlert2', 'content': '', 'date': '2019-08-06 23:20:35', 'id': '1',
                   'lang': 'English', 'langcode': 'en', 'read': False, 'severity': 10,
                   'threat_level': 'emerging', 'threats': ['Phishing'], 'title': 'someSecretAlert2',
                   'user_id': '123'},
                  {'alert_name': 'someSecretAlert4', 'content': '', 'date': '2019-08-18 09:58:10', 'id': '2',
                   'read': False, 'severity': 10, 'threat_level': 'imminent',
                   'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert4', 'user_id': '132'},
                  {'alert_name': 'someSecretAlert1', 'content': '', 'date': '2019-08-18 22:58:23', 'id': '3',
                   'read': False, 'severity': 10, 'threat_level': 'imminent',
                   'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert1', 'user_id': '123'},
                  {'alert_name': 'someSecretAlert2', 'content': '', 'date': '2019-08-19 19:27:24', 'id': '4',
                   'lang': 'English', 'langcode': 'en', 'read': False, 'severity': 10,
                   'threat_level': 'emerging', 'threats': ['Phishing'], 'title': 'someSecretAlert2',
                   'user_id': '123'},
                  {'alert_name': 'someSecretAlert3', 'content': '', 'date': '2019-08-22 08:27:19', 'id': '5',
                   'read': False, 'severity': 10, 'threat_level': 'imminent',
                   'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert3', 'user_id': '123'},
                  {'alert_name': 'someSecretAlert1', 'content': '', 'date': '2019-08-22 08:43:15', 'id': '6',
                   'read': False, 'severity': 10, 'threat_level': 'imminent',
                   'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert1', 'user_id': '123'}]

iocs_bundle = {"id": "bundle--716fd67b-ba74-44db-8d4c-2efde05ddbaa",
               "objects": [
                   {"created": "2017-01-20T00:00:00.000Z", "definition": {"tlp": "amber"}, "definition_type": "tlp",
                    "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "type": "marking-definition"},
                   {"created": "2019-12-26T00:00:00Z",
                    "definition": {"statement": "Copyright Sixgill 2020. All rights reserved."},
                    "definition_type": "statement", "id": "marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                    "type": "marking-definition"},
                   {"created": "2020-01-09T07:31:16.708Z",
                    "description": "Shell access to this domain is being sold on dark web markets",
                    "id": "indicator--7fc19d6d-2d58-45d6-a410-85554b12aea9",
                    "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                    "labels": ["compromised", "shell", "webshell"], "lang": "en", "modified": "2020-01-09T07:31:16.708Z",
                    "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                    "pattern": "[domain-name:value = 'somewebsite.com']", "sixgill_actor": "some_actor",
                    "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_1", "sixgill_feedname": "compromised_sites",
                    "sixgill_postid": "6e407c41fe6591d591cd8bbf0d105f7c15ed8991",
                    "sixgill_posttitle": "Credit Card Debt Help,       somewebsite.com",
                    "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator",
                    "valid_from": "2019-12-07T00:57:04Z"},
                   {"created": "2020-01-09T07:31:16.824Z",
                    "description": "Shell access to this domain is being sold on dark web markets",
                    "id": "indicator--67b2378f-cbdd-4263-b1c4-668014d376f2",
                    "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                    "labels": ["compromised", "shell", "webshell"], "lang": "ru", "modified": "2020-01-09T07:31:16.824Z",
                    "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                    "pattern": "[domain-name:value = 'somewebsite.com']", "sixgill_actor": "some_actor",
                    "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_1", "sixgill_feedname": "compromised_sites",
                    "sixgill_postid": "59f08fbf692f84f15353a5e946d2a1cebab92418",
                    "sixgill_posttitle": "somewebsite.com",
                    "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator",
                    "valid_from": "2019-12-06T17:10:04Z"},
                   {"created": "2020-01-09T07:31:16.757Z",
                    "description": "Shell access to this domain is being sold on dark web markets",
                    "id": "indicator--6e8b5f57-3ee2-4c4a-9283-8547754dfa09",
                    "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                    "labels": ["compromised", "shell", "webshell"], "lang": "en", "modified": "2020-01-09T07:31:16.757Z",
                    "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                    "pattern": "[domain-name:value = 'somewebsite.com']", "sixgill_actor": "some_actor",
                    "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_1", "sixgill_feedname": "compromised_sites",
                    "sixgill_postid": "f46cdfc3332d9a04aa63078d82c1e453fd76ba50",
                    "sixgill_posttitle": "somewebsite.com", "sixgill_severity": 70,
                    "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator",
                    "valid_from": "2019-12-06T23:24:51Z"},
                   {"created": "2020-01-09T07:31:16.834Z",
                    "description": "Shell access to this domain is being sold on dark web markets",
                    "id": "indicator--85d3d87b-76ed-4cab-b709-a43dfbdc5d8d",
                    "kill_chain_phases": [{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"}],
                    "labels": ["compromised", "shell", "webshell"], "lang": "en", "modified": "2020-01-09T07:31:16.834Z",
                    "object_marking_refs": ["marking-definition--41eaaf7c-0bc0-4c56-abdf-d89a7f096ac4",
                                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                    "pattern": "[domain-name:value = 'somewebsite.com']", "sixgill_actor": "some_actor",
                    "sixgill_confidence": 90, "sixgill_feedid": "darkfeed_1", "sixgill_feedname": "compromised_sites",
                    "sixgill_postid": "c3f266e67f163e1a6181c0789e225baba89212a2",
                    "sixgill_posttitle": "somewebsite.com",
                    "sixgill_severity": 70, "sixgill_source": "market_magbo", "spec_version": "2.0", "type": "indicator",
                    "valid_from": "2019-12-06T14:37:16Z"}
               ],
               "spec_version": "2.0",
               "type": "bundle"}

expected_alert_output = [
    {'name': 'someSecretAlert2', 'occurred': '2019-08-06T23:20:35.000000Z', 'details': '', 'severity': 2,
     'rawJSON': '{"alert_name": "someSecretAlert2", "content": "", "date": "2019-08-06 23:20:35", '
                '"id": "1", "lang": "English", "langcode": "en", "read": false, "threat_level": "emerging", '
                '"threats": ["Phishing"], "title": "someSecretAlert2", "user_id": "123", "sixgill_severity": 10}'},
    {'name': 'someSecretAlert4', 'occurred': '2019-08-18T09:58:10.000000Z', 'details': '', 'severity': 3,
     'rawJSON': '{"alert_name": "someSecretAlert4", "content": "", "date": "2019-08-18 09:58:10", '
                '"id": "2", "read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                '"title": "someSecretAlert4", "user_id": "132", "sixgill_severity": 10}'},
    {'name': 'someSecretAlert1', 'occurred': '2019-08-18T22:58:23.000000Z', 'details': '', 'severity': 3,
     'rawJSON': '{"alert_name": "someSecretAlert1", "content": "", "date": "2019-08-18 22:58:23", '
                '"id": "3", "read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                '"title": "someSecretAlert1", "user_id": "123", "sixgill_severity": 10}'},
    {'name': 'someSecretAlert2', 'occurred': '2019-08-19T19:27:24.000000Z', 'details': '', 'severity': 2,
     'rawJSON': '{"alert_name": "someSecretAlert2", "content": "", "date": "2019-08-19 19:27:24", '
                '"id": "4", "lang": "English", "langcode": "en", "read": false, "threat_level": "emerging", '
                '"threats": ["Phishing"], "title": "someSecretAlert2", "user_id": "123", "sixgill_severity": 10}'},
    {'name': 'someSecretAlert3', 'occurred': '2019-08-22T08:27:19.000000Z', 'details': '', 'severity': 3,
     'rawJSON': '{"alert_name": "someSecretAlert3", "content": "", "date": "2019-08-22 08:27:19", '
                '"id": "5", "read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                '"title": "someSecretAlert3", "user_id": "123", "sixgill_severity": 10}'},
    {'name': 'someSecretAlert1', 'occurred': '2019-08-22T08:43:15.000000Z', 'details': '', 'severity': 3,
     'rawJSON': '{"alert_name": "someSecretAlert1", "content": "", "date": "2019-08-22 08:43:15", '
                '"id": "6", "read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                '"title": "someSecretAlert1", "user_id": "123", "sixgill_severity": 10}'}]

expected_ioc_output = {'Contents': '', 'ContentsFormat': 'markdown', 'Type': 9,
                       'File': 'bundle--716fd67b-ba74-44db-8d4c-2efde05ddbaa.json',
                       'FileID': '',
                       'HumanReadable': '# Fetched 4 DarkFeed indicators'}


class MockedResponse(object):
    def __init__(self, status_code):
        self.status_code = status_code
        self.ok = True if self.status_code == 200 else False


def get_incidents_list():
    return copy.deepcopy(incidents_list)


def init_params():
    return {
        'client_id': 'WRONG_CLIENT_ID_TEST',
        'client_secret': 'CLIENT_SECRET_TEST',
    }


def test_test_module_raise_exception(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())

    from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
    mocker.patch.object(SixgillAuthRequest, 'send', return_value=MockedResponse(400))

    from Sixgill import test_module

    with pytest.raises(Exception):
        test_module()


def test_test_module(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())

    from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
    mocker.patch.object(SixgillAuthRequest, 'send', return_value=MockedResponse(200))

    from Sixgill import test_module
    test_module()


def test_fetch_incidents(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '1547567249000'})
    mocker.patch.object(demisto, 'incidents')

    from sixgill.sixgill_alert_client import SixgillAlertClient

    mocker.patch.object(SixgillAlertClient, 'get_alert', return_value=get_incidents_list())
    mocker.patch.object(SixgillAlertClient, 'mark_digested_item', return_value=None)

    from Sixgill import fetch_incidents
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]

    assert(len(incidents) == 6)
    assert (incidents == expected_alert_output)


def test_get_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch.object(demisto, 'results')

    from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient

    mocker.patch.object(SixgillDarkFeedClient, 'get_bundle', return_value=iocs_bundle)
    mocker.patch.object(SixgillDarkFeedClient, 'commit_indicators', return_value=None)

    from Sixgill import sixgill_get_indicators_command
    sixgill_get_indicators_command()

    assert demisto.results.call_count == 1
    results = demisto.results.call_args_list[0][0][0]
    results['FileID'] = ''
    assert results == expected_ioc_output


def test_item_to_incident():
    from Sixgill import item_to_incident
    output = item_to_incident(get_incidents_list()[0])
    assert output == expected_alert_output[0]
