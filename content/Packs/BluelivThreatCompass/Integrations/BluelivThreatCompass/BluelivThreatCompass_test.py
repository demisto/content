import demistomock as demisto
import re
from BluelivThreatCompass import Client, resource_set_tlp, resource_fav, set_resource_rating
from BluelivThreatCompass import search_resource, search_resource_by_id, set_resource_status
from BluelivThreatCompass import module_get_labels, resource_add_label, set_resource_read_status


def test_blueliv_search_resource(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("Credentials", "credentials")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {
        "list": [
            {
                "changed_at": 1589581524000,
                "checked_at": 1589581524000,
                "created_at": 1589581524000,
                "customer": 0,
                "email": 0,
                "employee": 0,
                "external": 0,
                "fav": "NOT_STARRED",
                "followedUp": False,
                "history": [],
                "id": 10696519,
                "issued": False,
                "labels": [
                    {
                        "background_color": 37810,
                        "id": 1303,
                        "name": "Botnet Credentials",
                        "text_color": 16777215,
                        "type": "MODULE_LABEL"
                    },
                    {
                        "background_color": 16777215,
                        "id": 2259,
                        "name": "Clear Password",
                        "text_color": 0,
                        "type": "MODULE_LABEL"
                    }
                ],
                "module_id": 1,
                "module_name": "Credentials",
                "module_short_name": "CRED-C0",
                "module_type": "CREDENTIALS",
                "num_cred": 3,
                "read": True,
                "resource_type": "GENERIC",
                "searchPhrase": "example.com",
                "title": "example.com",
                "tlpStatus": "RED",
                "user_rating": 0
            }
        ],
        "total_resources": 10
    }
    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('GET', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"limit": 1}
    search_resource(client, args)

    results = demisto.results.call_args[0][0]
    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatCompass.' + module_type[0] + '(val.id && val.id == obj.id)', {})

    assert demisto.get(ind[0], "title") == "example.com"
    assert demisto.get(ind[0], "num_cred") == 3


def test_blueliv_search_resource_by_id(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("Credentials", "credentials")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {
        "changed_at": 1589581524000,
        "checked_at": 1589581524000,
        "created_at": 1589581524000,
        "credentials": [
            {
                "classification": "UNCLASSIFIED",
                "id": "5ebf04c5dfe30b2200c09c5e",
                "isEmail": False,
                "password": "somepassword",
                "portalUrl": "https://example.com/login/sso",
                "reportedAt": 1589576900000,
                "stolenData": [{"stolenAt": 1589548528000}],
                "type": "OSKI",
                "userPassword": "somepassword",
                "username": "someuser"
            },
            {
                "classification": "UNCLASSIFIED",
                "id": "5ebf049edfe30b2200c0985b",
                "isEmail": False,
                "password": "somepassword",
                "portalUrl": "https://example.com/register",
                "reportedAt": 1589576862000,
                "stolenData": [{"stolenAt": 1589548528000}],
                "type": "OSKI",
                "userPassword": "somepassword",
                "username": "someuser"
            }
        ],
        "customer": 0,
        "email": 0,
        "employee": 0,
        "external": 0,
        "fav": "NOT_STARRED",
        "followedUp": False,
        "history": [],
        "id": 10696519,
        "issued": True,
        "labels": [
            {
                "background_color": 37810,
                "id": 1303,
                "name": "Botnet Credentials",
                "text_color": 16777215,
                "type": "GLOBAL"
            },
            {
                "background_color": 16777215,
                "id": 2259,
                "name": "Clear Password",
                "text_color": 0,
                "type": "MODULE_LABEL"
            }
        ],
        "module_id": 1,
        "module_type": "null",
        "num_cred": 2,
        "read": True,
        "resource_type": "GENERIC",
        "searchPhrase": "example.com",
        "title": "example.com",
        "tlpStatus": "RED",
        "user_rating": 0
    }
    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('GET', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10696519}
    search_resource_by_id(client, args)

    results = demisto.results.call_args[0][0]
    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatCompass.' + module_type[0] + '(val.id && val.id == obj.id)', {})

    assert ind.get("credentials", [{}])[0].get("type", "") == "OSKI"
    assert demisto.get(ind, "tlpStatus") == "RED"


def test_blueliv_set_resource_status(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {
        "code": 0,
        "error": False,
        "field": "",
        "httpCode": 200,
        "message": "ok.user_result",
        "token": None
    }
    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "status": "positive"}
    set_resource_status(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "Status changed to positive."


def test_blueliv_resource_set_read_status(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {"field": "[10712044]",
                        "message": "ok.successful_markas",
                        "error": False,
                        "token": None,
                        "code": 0,
                        "httpCode": 200}

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "read": "false"}
    set_resource_read_status(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "Read status changed to false."


def test_blueliv_resource_assign_rating(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {"field": "",
                        "message": "ok.successful_rate",
                        "error": False,
                        "token": None,
                        "code": 0,
                        "httpCode": 200}

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "rating": 3}
    set_resource_rating(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "Rating changed to 3."


def test_blueliv_resource_fav(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {"field": "",
                        "message": "ok.successful_fav",
                        "error": False,
                        "token": None,
                        "code": 0,
                        "httpCode": 200}

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "favourite": "User"}
    resource_fav(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "Resource favourite masked as User correctly."


def test_blueliv_resource_set_tlp(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {"field": "",
                        "message": "ok.tlp_updated",
                        "error": False,
                        "token": None,
                        "code": 0,
                        "httpCode": 200}

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "tlp": "Amber"}
    resource_set_tlp(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "TLP changed to Amber."


def test_blueliv_resource_set_label(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = {"field": "",
                        "message": "ok.successful_save",
                        "error": False,
                        "token": None,
                        "code": 0,
                        "httpCode": 200}

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('PUT', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    args = {"id": 10712044, "labelId": "1306"}
    resource_add_label(client, args)

    results = demisto.results.call_args[0][0]

    assert results.get('Contents', "") == "Label 1306 correctly added."


def test_blueliv_module_get_labels(mocker, requests_mock):
    server_url = "https://demisto.blueliv.com/api/v2"
    organization = 1
    module = 1
    module_type = ("DataLeakage", "data_leakage")

    url = '{}/organization/{}/module/{}/{}'.format(server_url, organization, module, module_type[1])
    matcher = re.compile('{}.*'.format(url))

    blueliv_response = [
        {
            "bgColorHex": "#0093B2",
            "id": 1303,
            "label": "Botnet Credentials",
            "labelProtected": True,
            "labelTypeId": 9,
            "labelTypeName": "Credentials Type",
            "moduleId": None,
            "moduleName": None,
            "moduleTypeId": None,
            "organizationId": None,
            "organizationName": None,
            "prioritized": True,
            "textColorHex": "#FFFFFF"
        },
        {
            "bgColorHex": "#00B388",
            "id": 1310,
            "label": "Brand Abuse Profile",
            "labelProtected": True,
            "labelTypeId": 12,
            "labelTypeName": "ThreatOrigin",
            "moduleId": None,
            "moduleName": None,
            "moduleTypeId": None,
            "organizationId": None,
            "organizationName": None,
            "prioritized": True,
            "textColorHex": "#FFFFFF"
        }
    ]

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('GET', matcher, json=blueliv_response)

    client = Client(server_url, False, False, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type[0])

    module_get_labels(client)

    results = demisto.results.call_args[0][0]

    assert len(results.get('Contents', [])) == 2
    assert results.get('Contents', [])[0].get("id", 0) == 1303
    assert results.get('Contents', [])[1].get("bgColorHex", "") == "#00B388"
