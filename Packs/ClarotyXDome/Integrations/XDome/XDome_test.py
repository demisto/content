"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import pytest
import demistomock as demisto
from XDome import Client

INTEGRATION_PARAMS = {
    "url": "https://not.really.api.claroty.com",
    "credentials": {"password": "some_api_key"},
    "initial_fetch_time": "7 days",
    "alert_types": None,
    "fetch_only_unresolved": True,
}


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=INTEGRATION_PARAMS)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


DEVICE_ALERT_ERROR_RESPONSE = {
    "detail": [
        {
            "loc": [
                "string"
            ],
            "msg": "string",
            "type": "string"
        }
    ]
}

DEVICE_ALERT_SUCCESS_RESPONSE = {
    "devices_alerts": [
        {
            "alert_assignees": [],
            "alert_category": "Risk",
            "alert_class": "predefined",
            "alert_id": 2,
            "alert_labels": [
                "Top Priority"
            ],
            "alert_type_name": "Outdated Firmware",
            "device_alert_detected_time": "2023-10-19T16:21:01+00:00",
            "device_alert_status": "Unresolved",
            "device_alert_updated_time": "2023-10-19T16:21:01+00:00",
            "device_assignees": [
                "Admin"
            ],
            "device_category": "Medical",
            "device_first_seen_list": [
                "2023-10-19T16:32:04.127979+00:00"
            ],
            "device_ip_list": [
                "1.1.1.1"
            ],
            "device_labels": [],
            "device_last_seen_list": [
                "2023-10-19T16:32:01+00:00"
            ],
            "device_mac_list": [
                "1a:2b:3c:d4:e5:f6"
            ],
            "device_network_list": [
                "Corporate"
            ],
            "device_purdue_level": "Level 4",
            "device_retired": False,
            "device_risk_score": "Very Low",
            "device_site_name": "New York General Hospital",
            "device_subcategory": "Patient Devices",
            "device_type": "Patient Monitor",
            "device_uid": "f342efb7-4f4a-4ac0-8045-0711fb2c5528",
            "alert_name": "alert name here",
            "device_name": "device name here",
        }
    ]
}

DEVICE_VULNERABILITY_ERROR_RESPONSE = DEVICE_ALERT_ERROR_RESPONSE

DEVICE_VULNERABILITY_SUCCESS_RESPONSE = {
    "devices_vulnerabilities": [
        {
            "device_assignees": [],
            "device_category": "Medical",
            "device_labels": [],
            "device_network_list": [
                "Corporate"
            ],
            "device_purdue_level": "Level 4",
            "device_retired": False,
            "device_risk_score": "Medium",
            "device_site_name": "Main Campus",
            "device_subcategory": "Clinical IoT",
            "device_type": "Nurse Call",
            "device_uid": "811997e7-cb4f-448f-9b68-68022d745404",
            "vulnerability_affected_products": "* All the Wi-Fi devices\n"
                                               "* Aruba:\n"
                                               "    - ArubaOS 6.4.x: prior to 6.4.4.25\n"
                                               "    - ArubaOS 6.5.x: prior to 6.5.4.19\n"
                                               "    - ArubaOS 8.3.x: prior to 8.3.0.15\n"
                                               "    - ArubaOS 8.5.x: prior to 8.5.0.12\n"
                                               "    - ArubaOS 8.6.x: prior to 8.6.0.8\n"
                                               "    - ArubaOS 8.7.x: prior to 8.7.1.2\n"
                                               "    - Aruba instant AP\n"
                                               "* SUSE:\n"
                                               "    - SUSE Linux Enterprise Server 15\n"
                                               "    - SUSE Linux Enterprise Desktop 15\n"
                                               "    - SUSE Linux Enterprise Server 12\n"
                                               "    - SUSE Linux Enterprise Desktop 12\n"
                                               "    - SUSE Linux Enterprise Server 11\n"
                                               "    - SUSE Linux Enterprise Desktop 11\n"
                                               "* Synology:\n"
                                               "    - RT2600ac\n"
                                               "    - MR2200ac\n"
                                               "    - RT1900ac\n"
                                               "* Microsoft - according to the affected versions detailed in the attached "
                                               "advisories.\n"
                                               "* Juniper:\n"
                                               "    * the following models affected in specific versions and see attached "
                                               "advisory:\n"
                                               "        - AP12 / AP21 / AP32 / AP33 / AP41 / AP43 / AP61 / AP63 / SRX series",
            "vulnerability_cve_ids": [
                "CVE-2020-11111",
                "CVE-2020-22222",
                "CVE-2020-33333",
                "CVE-2020-44444",
                "CVE-2020-55555",
                "CVE-2020-66666",
                "CVE-2020-77777",
                "CVE-2020-88888",
                "CVE-2020-99999",
                "CVE-2020-00000",
                "CVE-2020-12121",
                "CVE-2020-13131"
            ],
            "vulnerability_cvss_v2_exploitability_subscore": 6.5,
            "vulnerability_cvss_v2_score": 3.3,
            "vulnerability_cvss_v3_exploitability_subscore": 2.8,
            "vulnerability_cvss_v3_score": 6.5,
            "vulnerability_description": "A collection of new 12 security vulnerabilities that affect Wi-Fi devices.\n"
                                         "An adversary that is within range of a victim's Wi-Fi network can abuse these "
                                         "vulnerabilities to\n"
                                         "steal user information or attack devices.\n"
                                         "Three of the discovered vulnerabilities are design flaws in the Wi-Fi standard and "
                                         "therefore\n"
                                         "affect most devices. On top of this, several other vulnerabilities were discovered that"
                                         " are\n"
                                         "caused by widespread programming mistakes in Wi-Fi products.\n"
                                         "Experiments indicate that every Wi-Fi product is affected by at least one "
                                         "vulnerability\n"
                                         "and that most products are affected by several vulnerabilities.\n"
                                         "The discovered vulnerabilities affect all modern security protocols of Wi-Fi, including"
                                         " the\n"
                                         "latest WPA3.\n"
                                         "The design flaws are hard to abuse because doing so requires user interaction or is "
                                         "only possible\n"
                                         "when using uncommon network settings. As a result, in practice the biggest concern are "
                                         "the\n"
                                         "programming mistakes in Wi-Fi products since several of them are trivial to exploit.\n"
                                         "When a website is configured with HSTS to always use HTTPS as an extra layer of "
                                         "security,\n"
                                         "the transmitted data cannot be stolen",
            "vulnerability_id": "ALKIFVSA",
            "vulnerability_is_known_exploited": False,
            "vulnerability_last_updated": "2019-08-24T18:56:24.888211+00:00",
            "vulnerability_name": "FragAttacks",
            "vulnerability_published_date": "2021-05-12T00:00:00.485000+00:00",
            "vulnerability_recommendations": "some vulnerability recommendations",
            "vulnerability_relevance": "Potentially Relevant",
            "vulnerability_relevance_sources": [
                "Claroty"
            ],
            "vulnerability_sources": [
                {
                    "name": "vulnerability source name 1",
                    "url": "https://not.really.vulnerability.source.url"
                }
            ],
            "vulnerability_type": "Platform"
        }
    ]
}


@pytest.fixture
def xdome_client_mock(mocker):
    def _xdome_client_mock():
        client = Client(base_url="https://not.really.api.claroty.com/api/v1/")
        mocker.patch.object(client, "get_device_alert_relations", return_value=DEVICE_ALERT_SUCCESS_RESPONSE)
        mocker.patch.object(
            client, "get_device_vulnerability_relations", return_value=DEVICE_VULNERABILITY_SUCCESS_RESPONSE
        )
        mocker.patch.object(client, "set_device_alert_relations", return_value=None)
        return client

    return _xdome_client_mock


DEVICE_ALERT_VALID_RAW_ARGS = {
    "limit": 1,
    "filter_by": json.dumps({
        "operation": "and",
        "operands": [
            {"field": "alert_id", "operation": "in", "value": [2]},
            {"field": "device_uid", "operation": "in", "value": ["f342efb7-4f4a-4ac0-8045-0711fb2c5528"]},
        ]
    })
}


def test_get_device_alert_relations(xdome_client_mock):
    from XDome import get_device_alert_relations_command

    cmd_res = get_device_alert_relations_command(xdome_client_mock(), DEVICE_ALERT_VALID_RAW_ARGS)
    expected_device_alert_pairs = DEVICE_ALERT_SUCCESS_RESPONSE["devices_alerts"]
    assert cmd_res.raw_response == expected_device_alert_pairs
    assert cmd_res.outputs == {
        "XDome.DeviceAlert(val.device_uid == obj.device_uid && val.alert_id == obj.alert_id)": expected_device_alert_pairs
    }


DEVICE_VULNERABILITY_VALID_RAW_ARGS = {
    "limit": 1,
    "filter_by": json.dumps({
        "operation": "and",
        "operands": [
            {"field": "vulnerability_id", "operation": "in", "value": ["ALKIFVSA"]},
            {"field": "device_uid", "operation": "in", "value": ["811997e7-cb4f-448f-9b68-68022d745404"]},
        ]
    })
}


def test_get_device_vulnerability_relations(xdome_client_mock):
    from XDome import get_device_vulnerability_relations_command

    cmd_res = get_device_vulnerability_relations_command(xdome_client_mock(), DEVICE_VULNERABILITY_VALID_RAW_ARGS)
    expected_device_vulnerability_pairs = DEVICE_VULNERABILITY_SUCCESS_RESPONSE["devices_vulnerabilities"]
    assert cmd_res.raw_response == expected_device_vulnerability_pairs
    assert cmd_res.outputs == {
        "XDome.DeviceVulnerability(val.device_uid == obj.device_uid && val.vulnerability_id == obj.vulnerability_id)": (
            expected_device_vulnerability_pairs
        )
    }


RESOLVE_DEVICE_ALERT_VALID_RAW_ARGS = {
    "alert_id": 123,
    "device_uids": json.dumps(["asdf-asdf-asdf-asdf", "qwer-wqer-qwer-wqer"]),
    "status": "resolve",
}


def test_resolve_device_alert_relations(xdome_client_mock):
    from XDome import set_device_alert_relations_command

    cmd_res = set_device_alert_relations_command(xdome_client_mock(), RESOLVE_DEVICE_ALERT_VALID_RAW_ARGS)
    assert cmd_res.raw_response == "success"
    assert cmd_res.readable_output == "success"


def test_fetch_incidents(xdome_client_mock):
    from XDome import fetch_incidents

    next_run, incidents = fetch_incidents(
        xdome_client_mock(), last_run={}, initial_fetch_time="1 day", alert_types=None, fetch_only_unresolved=True
    )

    mock_pair = DEVICE_ALERT_SUCCESS_RESPONSE["devices_alerts"][0]

    incident = incidents[0]
    assert incident == {
        "dbotMirrorId": f"{mock_pair['alert_id']}↔{mock_pair['device_uid']}",
        "name": f"Alert “{mock_pair['alert_name']}” on Device “{mock_pair['device_name']}”",
        "occurred": mock_pair["device_alert_updated_time"],
        "rawJSON": json.dumps(mock_pair),
    }
    assert next_run == {"last_fetch": incident["occurred"], "latest_ids": [incident["dbotMirrorId"]]}
