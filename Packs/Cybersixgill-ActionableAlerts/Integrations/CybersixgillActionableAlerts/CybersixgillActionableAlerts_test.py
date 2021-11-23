import pytest
import copy
import demistomock as demisto

incidents_list = [
    {'alert_name': 'Your organization was potentially targeted by a ransomware group',
     'content': 'text',
     'date': '2021-11-08 06:01:05', 'id': '6188bd21017198385e228437', 'read': True, 'severity': 1,
     'site': 'rw_everest', 'status': {'name': 'in_treatment', 'user': '60b604a048ce2cb294629a2d'}, 'threat_level':
         'imminent', 'threats': ['Brand Protection', 'Data Leak'],
     'title': 'Your organization was potentially targeted '
              'by a ransomware group', 'user_id':
         '5d233575f8db38787dbe24b6'}, {'alert_name': 'Gift Cards of {organization_name} are Sold on the Underground ',
                                       'category': 'regular', 'content': 'text',
                                       'date': '2021-11-02 06:00:27', 'id': '6180d4011dbb8edcb496ec8b',
                                       'lang': 'English', 'langcode': 'en', 'read': False, 'severity': 1, 'status':
                                           {'name': 'treatment_required', 'user': '604f58a6dc7c8a8437fd8154'},
                                       'sub_alerts': [], 'threat_level': 'imminent',
                                       'threats': ['Fraud'],
                                       'title': 'Gift Cards of Sixgill are Sold on the Underground ',
                                       'user_id': '5d233575f8db38787dbe24b6'}, {
        'alert_name': "Access to {matched_domain_names}, One of {organization_name}'s Assets, was Compromised and "
                      "Offered for Sale on a Compromised Endpoint Market",
        'category': 'regular',
        'content': 'text',
        'date': '2021-11-02 06:00:16', 'id': '6180d3f01dbb8edcb496ec86', 'lang': 'English', 'langcode': 'en',
        'read': False, 'severity': 1, 'sub_alerts': [], 'threat_level': 'imminent',
        'threats': ['Compromised Accounts'],
        'title': "Access to your organization's Assets was Compromised and Offered for Sale on a Compromised Endpoint "
                 "Market",
        'user_id': '5d233575f8db38787dbe24b6'}]

info_item = {
    "additional_info": {
        "matched_domain_names": [],
        "matched_organization_aliases": ["Walmart"],
        "organization_name": "Cybersixgill",
        "site": "rw_everest",
        "template_id": "5fd0d2acddd06410ac5348d1",
        "vendor": "Sixgill"
    },
    "alert_id": "616ffed97a1b66036a138f73",
    "alert_name": "Your organization was potentially targeted by a ransomware group",
    "alert_type": "QueryBasedManagedAlertRule",
    "assessment": "text",
    "category": "regular",
    "content_type": "search_result_item",
    "description": "A ransomware group posted on its leak site, rw_everest, focusing on \"Walmart\" ",
    "es_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
    "es_item": {},
    "id": "6188bd21017198385e228437",
    "lang": "English",
    "langcode": "en",
    "read": True,
    "recommendations": [],
    "severity": 1,
    "site": "rw_everest",
    "status": {
        "name": "in_treatment",
        "user": "60b604a048ce2cb294629a2d"
    },
    "summary": "",
    "threat_level": "imminent",
    "threats": [
        "Brand Protection",
        "Data Leak"
    ],
    "title": "Your organization was potentially targeted by a ransomware group",
    "update_time": "2021-11-08 06:01:05",
    "user_id": "5d233575f8db38787dbe24b6"
}

content_item = {
    "content": {
        "items": [
            {
                "_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
                "_source": {
                    "_op_type": "update",
                    "category": "Ransomware",
                    "collection_date": "2021-05-11T13:11:46",
                    "comments_count": 0,
                    "content": "text",
                    "creator": "Everest ransom team",
                    "date": "2021-05-11T13:11:46",
                    "enrichment_version": 46,
                    "financial": {
                        "iban": [],
                        "swift": []
                    },
                    "id": "44",
                    "ips": [],
                    "lang": "en",
                    "length": {
                        "content": 688,
                        "title": 34
                    },
                    "location": [
                        "Calgary",
                        "Canada",
                        "Coquitlam",
                        "Kelowna"
                    ],
                    "modules": [
                        "ddw"
                    ],
                    "organization": [
                        "Traugott Building Contractors Inc."
                    ],
                    "pds": {
                        "email_address": [
                            "example@com"
                        ],
                        "phone_number": [
                            "000000"
                        ]
                    },
                    "product": [
                        "Alberta T2E 6M6 Canada"
                    ],
                    "rep_grade": 1,
                    "site": "rw_everest",
                    "site_grade": 5,
                    "source_type": "rw",
                    "sub_category": "",
                    "tags": [
                        "Ransomware",
                        "Phone_number",
                        "email",
                        "Email_address"
                    ],
                    "title": "Traugott Building Contractors Inc.",
                    "type": "post",
                    "update_date": "2021-11-07T15:58:04.131371"
                },
                "triggered_alert": True
            },
            {
                "_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
                "_source": {
                    "category": "Ransomware",
                    "collection_date": "2021-11-07T14:55:26",
                    "comments_count": 0,
                    "content": "text",
                    "creator": "Everest ransom team",
                    "date": "2021-11-07T14:55:26",
                    "enrichment_version": 46,
                    "financial": {
                        "iban": [],
                        "swift": []
                    },
                    "id": "44",
                    "ips": [],
                    "lang": "en",
                    "length": {
                        "content": 688,
                        "title": 34
                    },
                    "location": [
                        "Calgary",
                        "Canada",
                        "Coquitlam",
                        "Kelowna"
                    ],
                    "modules": [
                        "ddw"
                    ],
                    "pds": {
                        "email_address": [
                            "example@com"
                        ],
                        "phone_number": [
                            "000000"
                        ]
                    },
                    "rep_grade": 1,
                    "site": "rw_everest",
                    "site_grade": 5,
                    "source_type": "rw",
                    "sub_category": "",
                    "tags": [
                        "Ransomware",
                        "Phone_number",
                        "email",
                        "Email_address"
                    ],
                    "title": "Traugott Building Contractors Inc.",
                    "type": "post",
                    "update_date": "2021-11-07T14:56:48.135426"
                },
                "triggered_alert": True
            }
        ],
        "total": 2
    },
    "content_type": "search_result_item"
}

expected_alert_output = [{'name': 'Your organization was potentially targeted by a ransomware group',
                          'occurred': '2021-11-08T06:01:05.000000Z', 'severity': 3,
                          'CustomFields': {'cybersixgillthreatlevel': 'imminent',

                                           'cybersixgillthreattype': ['Brand Protection', 'Data Leak'],
                                           'cybersixgillassessment': 'text',
                                           'cybersixgillrecommendations': '',
                                           'incidentlink': 'https://portal.cybersixgill.com'
                                                           '/#/?actionable_alert=6188bd21017198385e228437',
                                           'cybersixgillstatus': 'In Treatment',
                                           'cybersixgillsite': 'rw_everest',
                                           'cybersixgillactor': None,
                                           'cybersixgilltriggeredassets': ['Walmart']},
                          'status': 1,
                          'details': 'A ransomware group posted on its leak site, rw_everest, focusing on "Walmart" '
                                     '\n\n\n\n',
                          'rawJSON': '{"additional_info": {"matched_domain_names": '
                                     '[], "matched_organization_aliases": ["Walmart"], '
                                     '"organization_name": "Cybersixgill", "site": "rw_everest", "template_id": '
                                     '"5fd0d2acddd06410ac5348d1", "vendor": "Sixgill"}, "alert_id": '
                                     '"616ffed97a1b66036a138f73", "alert_name": "Your organization was potentially '
                                     'targeted by a ransomware group", "alert_type": "QueryBasedManagedAlertRule", '
                                     '"assessment": "text", "category": "regular", '
                                     '"content_type": "search_result_item", "description": "A ransomware group posted '
                                     'on its leak site, rw_everest, focusing on \\"Walmart\\" ", '
                                     '"es_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75", "es_item": {}, '
                                     '"id": "6188bd21017198385e228437", "lang": "English", "langcode": "en", '
                                     '"read": true, "recommendations": [], "severity": 1, "site": "rw_everest", '
                                     '"status": {"name": "in_treatment", "user": "60b604a048ce2cb294629a2d"}, '
                                     '"summary": "", "threat_level": "imminent", "threats": ["Brand Protection", '
                                     '"Data Leak"], "title": "Your organization was potentially targeted by a '
                                     'ransomware group", "update_time": "2021-11-08 06:01:05", "user_id": '
                                     '"5d233575f8db38787dbe24b6", "date": "2021-11-08 06:01:05"}'}]


class MockedResponse(object):
    def __init__(self, status_code):
        self.status_code = status_code
        self.ok = True if self.status_code == 200 else False


def get_incidents_list():
    return copy.deepcopy(incidents_list)


def get_info_item():
    return copy.deepcopy(info_item)


def get_content_item():
    return copy.deepcopy(content_item)


def init_params():
    return {
        'client_id': 'WRONG_CLIENT_ID_TEST',
        'client_secret': 'CLIENT_SECRET_TEST',
    }


def test_test_module_raise_exception(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(400))

    from CybersixgillActionableAlerts import test_module

    with pytest.raises(Exception):
        test_module()


def test_test_module(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(200))

    from CybersixgillActionableAlerts import test_module
    test_module()


def test_fetch_incidents(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_fetch_time': '2021-11-07 06:01:05'})
    mocker.patch.object(demisto, 'incidents')

    from sixgill.sixgill_actionable_alert_client import SixgillActionableAlertClient

    mocker.patch.object(SixgillActionableAlertClient, 'get_actionable_alerts_bulk', return_value=get_incidents_list())
    mocker.patch.object(SixgillActionableAlertClient, 'get_actionable_alert', return_value=get_info_item())
    mocker.patch.object(SixgillActionableAlertClient, 'get_actionable_alert_content', return_value=get_content_item())

    from CybersixgillActionableAlerts import fetch_incidents
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]

    assert (len(incidents) == 1)
    assert (incidents == expected_alert_output)
