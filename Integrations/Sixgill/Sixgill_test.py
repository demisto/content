import pytest
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

iocs_list = [{"alert_id": "None",
              "alert_name": "AllIpsUndergroundFeedRule",
              "consumer": "random",
              "consumer_specific_info": {
                  "fields": {
                      "itype": "suspicious_ip",
                      "tags": [
                          "DarkWeb"
                      ],
                      "threat_type": None,
                      "value": "1.1.1.1"
                  },
                  "type": "indicator"
              },
              "doc_id": "123456789",
              "feed_owner_id": "123456",
              "importance": 1,
              "source_id": "c-1231",
              "source_item": {
                  "access": "Dark Web",
                  "creator": "theworker",
                  "date": "2019-03-29T19:59:00",
                  "ip": "1.1.1.1",
                  "site": "dread",
                  "tags": [
                      "IP",
                      "IP_v4",
                      "IP_global"
                  ]
              },
              "source_type": "ES",
              "update_time": "2019-05-12 13:33:05"}, {"alert_id": "None",
                                                      "alert_name": "AllIpsUndergroundFeedRule",
                                                      "consumer": "random",
                                                      "consumer_specific_info": {
                                                          "fields": {
                                                              "itype": "suspicious_ip",
                                                              "tags": [
                                                                  "DarkWeb"
                                                              ],
                                                              "threat_type": None,
                                                              "value": "2.2.2.2"
                                                          },
                                                          "type": "indicator"
                                                      },
                                                      "doc_id": "123456789",
                                                      "feed_owner_id": "123456",
                                                      "importance": 1,
                                                      "source_id": "c-1231",
                                                      "source_item": {
                                                          "access": "Dark Web",
                                                          "creator": "theworker",
                                                          "date": "2019-03-29T19:59:00",
                                                          "ip": "2.2.2.2",
                                                          "site": "dread",
                                                          "tags": [
                                                              "IP",
                                                              "IP_v4",
                                                              "IP_global"
                                                          ]
                                                      },
                                                      "source_type": "ES",
                                                      "update_time": "2019-05-12 13:33:05"},
             {"alert_id": "None",
              "alert_name": "HashesFeedRule",
              "consumer": "random",
              "consumer_specific_info": {
                  "fields": {
                      "itype": "mal_md5",
                      "tags": [
                          "DarkWeb",
                          "MD5"
                      ],
                      "threat_type": None,
                      "value": "abafbadfbafbafb"
                  },
                  "type": "indicator"
              },
              "doc_id": "123456789",
              "feed_owner_id": "123456",
              "importance": 1,
              "source_id": "c-1231",
              "source_item": {
                  "access": "Dark Web",
                  "creator": "theworker",
                  "date": "2019-03-29T19:59:00",
                  "ip": "abafbadfbafbafb",
                  "site": "dread",
                  "tags": [
                      "MD5"
                  ]
              }}]


expected_alert_output = [{'name': 'someSecretAlert2', 'occurred': '2019-08-06T23:20:35.000000Z', 'details': '', 'severity': 2,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert2", "content": "", "date": "2019-08-06 23:20:35", '
                                     '"lang": "English", "langcode": "en", "read": false, "threat_level": "emerging", '
                                     '"threats": ["Phishing"], "title": "someSecretAlert2"}'},
                         {'name': 'someSecretAlert4', 'occurred': '2019-08-18T09:58:10.000000Z', 'details': '', 'severity': 3,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert4", "content": "", "date": "2019-08-18 09:58:10", '
                                     '"read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                                     '"title": "someSecretAlert4"}'},
                         {'name': 'someSecretAlert1', 'occurred': '2019-08-18T22:58:23.000000Z', 'details': '', 'severity': 3,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert1", "content": "", "date": "2019-08-18 22:58:23", '
                                     '"read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                                     '"title": "someSecretAlert1"}'},
                         {'name': 'someSecretAlert2', 'occurred': '2019-08-19T19:27:24.000000Z', 'details': '', 'severity': 2,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert2", "content": "", "date": "2019-08-19 19:27:24", '
                                     '"lang": "English", "langcode": "en", "read": false, "threat_level": "emerging", '
                                     '"threats": ["Phishing"], "title": "someSecretAlert2"}'},
                         {'name': 'someSecretAlert3', 'occurred': '2019-08-22T08:27:19.000000Z', 'details': '', 'severity': 3,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert3", "content": "", "date": "2019-08-22 08:27:19", '
                                     '"read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                                     '"title": "someSecretAlert3"}'},
                         {'name': 'someSecretAlert1', 'occurred': '2019-08-22T08:43:15.000000Z', 'details': '', 'severity': 3,
                          'type': 'SixgillAlert',
                          'rawJSON': '{"alert_name": "someSecretAlert1", "content": "", "date": "2019-08-22 08:43:15", '
                                     '"read": false, "threat_level": "imminent", "threats": ["Data Leak", "Phishing"], '
                                     '"title": "someSecretAlert1"}'}]

expected_raw_output = [
    {'alert_name': 'someSecretAlert2', 'content': '', 'date': '2019-08-06 23:20:35', 'lang': 'English',
     'langcode': 'en', 'read': False, 'threat_level': 'emerging', 'threats': ['Phishing'], 'title': 'someSecretAlert2'},
    {'alert_name': 'someSecretAlert4', 'content': '', 'date': '2019-08-18 09:58:10', 'id': '2', 'read': False,
     'severity': 10, 'threat_level': 'imminent', 'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert4',
     'user_id': '132'},
    {'alert_name': 'someSecretAlert1', 'content': '', 'date': '2019-08-18 22:58:23', 'id': '3', 'read': False,
     'severity': 10, 'threat_level': 'imminent', 'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert1',
     'user_id': '123'},
    {'alert_name': 'someSecretAlert2', 'content': '', 'date': '2019-08-19 19:27:24', 'id': '4', 'lang': 'English',
     'langcode': 'en', 'read': False, 'severity': 10, 'threat_level': 'emerging', 'threats': ['Phishing'],
     'title': 'someSecretAlert2', 'user_id': '123'},
    {'alert_name': 'someSecretAlert3', 'content': '', 'date': '2019-08-22 08:27:19', 'id': '5', 'read': False,
     'severity': 10, 'threat_level': 'imminent', 'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert3',
     'user_id': '123'},
    {'alert_name': 'someSecretAlert1', 'content': '', 'date': '2019-08-22 08:43:15', 'id': '6', 'read': False,
     'severity': 10, 'threat_level': 'imminent', 'threats': ['Data Leak', 'Phishing'], 'title': 'someSecretAlert1',
     'user_id': '123'}, {'alert_id': 'None', 'alert_name': 'AllIpsUndergroundFeedRule', 'consumer': 'random',
                         'consumer_specific_info': {
                             'fields': {'itype': 'suspicious_ip', 'tags': ['DarkWeb'], 'threat_type': None,
                                        'value': '1.1.1.1'}, 'type': 'indicator'}, 'doc_id': '123456789',
                         'feed_owner_id': '123456', 'importance': 1, 'source_id': 'c-1231',
                         'source_item': {'access': 'Dark Web', 'creator': 'theworker', 'date': '2019-03-29T19:59:00',
                                         'ip': '1.1.1.1', 'site': 'dread', 'tags': ['IP', 'IP_v4', 'IP_global']},
                         'source_type': 'ES', 'update_time': '2019-05-12 13:33:05', 'id': '123456789'},
    {'alert_id': 'None', 'alert_name': 'AllIpsUndergroundFeedRule', 'consumer': 'random', 'consumer_specific_info': {
        'fields': {'itype': 'suspicious_ip', 'tags': ['DarkWeb'], 'threat_type': None, 'value': '2.2.2.2'},
        'type': 'indicator'}, 'doc_id': '123456789', 'feed_owner_id': '123456', 'importance': 1, 'source_id': 'c-1231',
     'source_item': {'access': 'Dark Web', 'creator': 'theworker', 'date': '2019-03-29T19:59:00', 'ip': '2.2.2.2',
                     'site': 'dread', 'tags': ['IP', 'IP_v4', 'IP_global']}, 'source_type': 'ES',
     'update_time': '2019-05-12 13:33:05', 'id': '123456789'},
    {'alert_id': 'None', 'alert_name': 'HashesFeedRule', 'consumer': 'random', 'consumer_specific_info': {
        'fields': {'itype': 'mal_md5', 'tags': ['DarkWeb', 'MD5'], 'threat_type': None, 'value': 'abafbadfbafbafb'},
        'type': 'indicator'}, 'doc_id': '123456789', 'feed_owner_id': '123456', 'importance': 1, 'source_id': 'c-1231',
     'source_item': {'access': 'Dark Web', 'creator': 'theworker', 'date': '2019-03-29T19:59:00',
                     'ip': 'abafbadfbafbafb', 'site': 'dread', 'tags': ['MD5']}, 'id': '123456789'}]

expected_iocs = {'IP(val.Address == obj.Address)': [{'Address': '1.1.1.1'}, {'Address': '2.2.2.2'}],
                 'File(val.MD5 == obj.MD5)': [{'MD5': 'abafbadfbafbafb', 'Tags': 'DarkWeb, MD5'}]}


class MockedResponse(object):
    def __init__(self, status_code):
        self.status_code = status_code
        self.ok = True if self.status_code == 200 else False


def init_params():
    return {
        'client_id': 'WRONG_CLIENT_ID_TEST',
        'client_secret': 'CLIENT_SECRET_TEST',
    }


def test_is_ioc():
    from Sixgill import is_ioc

    output = is_ioc(incidents_list[0])
    assert output is False

    output = is_ioc(iocs_list[0])
    assert output is True


def test_handle_indicator():
    from Sixgill import handle_indicator

    indicator = {}

    output = handle_indicator(indicator, incidents_list[0])
    assert output is False
    assert indicator == {}

    output = handle_indicator(indicator, iocs_list[0])
    assert output is True
    assert indicator == {'IP(val.Address == obj.Address)': [{'Address': '1.1.1.1'}]}


def test_handle_alerts():
    from Sixgill import handle_alerts

    incidents = []

    output = handle_alerts(incidents, iocs_list[0])
    assert output is False
    assert incidents == []

    output = handle_alerts(incidents, incidents_list[0])
    assert output is True
    assert incidents == [expected_alert_output[0]]


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

    from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient

    mocker.patch.object(SixgillDarkFeedClient, 'get_incidents', return_value=incidents_list + iocs_list)
    mocker.patch.object(SixgillDarkFeedClient, 'mark_digested_item', return_value=None)

    from Sixgill import fetch_incidents
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]

    assert(len(incidents) == 6)
    assert (incidents == expected_alert_output)


def test_get_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())

    from sixgill.sixgill_darkfeed_client import SixgillDarkFeedClient

    mocker.patch.object(SixgillDarkFeedClient, 'get_incidents', return_value=incidents_list + iocs_list)
    mocker.patch.object(SixgillDarkFeedClient, 'mark_digested_item', return_value=None)

    from Sixgill import get_indicators
    readable_output, outputs, raw_response = get_indicators()

    assert readable_output == '### Sixgill\'s DarkFeed indicators: \n|File(val.MD5 == obj.MD5)|' \
                              'IP(val.Address == obj.Address)|\n|---|---|\n| {\'MD5\': \'abafbadfbafbafb\', ' \
                              '\'Tags\': \'DarkWeb, MD5\'} | {\'Address\': \'1.1.1.1\'},<br>' \
                              '{\'Address\': \'2.2.2.2\'} |\n'
    assert outputs == expected_iocs
    assert raw_response == expected_raw_output


def test_item_to_incident():
    from Sixgill import item_to_incident
    output = item_to_incident(incidents_list[0])
    assert output == expected_alert_output[0]
