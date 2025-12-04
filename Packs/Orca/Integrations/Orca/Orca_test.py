from datetime import datetime

import pytest
import json
import requests
from Orca import OrcaClient, BaseClient, DEMISTO_OCCURRED_FORMAT, fetch_incidents, STEP_FETCH, \
    set_alert_severity, get_alert_event_log, set_alert_status, verify_alert, API_QUERY_ALERTS_URL, \
    get_incident_from_alert, get_incidents_from_alerts

from CommonServerPython import DemistoException

DUMMY_ORCA_API_DNS_NAME = "https://dummy.io/api"

mock_alerts_response = {
    "status": "success",
    "data": [
        {
            "Type": "Alert",
            "Name": "orca-1003",
            "Cluster_unique_id": "AzureNetworkSecurityGroupRule_832879455555_00000000-0000-0000-0000-000000000001",
            "Last_seen": "2025-11-06T09:35:31+00:00",
            "AlertId": "orca-1003",
            "AlertSource": "Orca Scan",
            "AlertType": "Malware",
            "AssetData": {
                "asset_name": "test-nsg-001",
                "asset_type": "AzureNetworkSecurityGroup",
                "asset_vpcs": [],
                "asset_state": "enabled",
                "account_name": "test-account-001",
                "asset_regions": [],
                "asset_category": "Network",
                "cloud_provider": "azure",
                "cloud_vendor_id": "00000000-0000-0000-0000-000000000001",
                "asset_tags_info_list": [],
                "custom_tags_info_list": [],
                "cluster_type": None,
                "vm_id": None,
                "asset_labels": None,
                "resource_group_name": None,
                "cluster_name": "test-nsg-001",
            },
            "Category": "Malware",
            "CommentsCount": 0,
            "CreatedAt": "2025-10-13T14:33:27+00:00",
            "Description": "Azure Network Security Group have rule that allow unrestricted access from the Internet",
            "Details": "Network security group contains rules that allow unrestricted access from the Internet - including all protocols (TCP,UDP,ICMP) ",
            "IsLive": True,
            "Labels": ["mitre: discovery", "CSPM", "source: Orca Scan"],
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "LastUpdated": "2025-11-06T09:35:31+00:00",
            "MitreCategory": "discovery",
            "MitreTechniques": ["System Network Connections Discovery (T1049)"],
            "OrcaScore": 4.7,
            "Recommendation": "Configure networking rules to allow incoming traffic from allowed IP addresses only.",
            "RemediationConsole": [
                ">1. Sign in to **[Azure Portal](https://portal.azure.com/)**.",
                ">2. Navigate to the **Network security groups** service.",
                ">8. Click **Save**.",
            ],
            "RiskFindings": {
                "id": "b063104b-3fb7-4c4d-f94e-ef7b68a13b0b",
                "data": {
                    "Region": {"model": "Inventory", "value": "eastus"},
                    "ResourceGroup": {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "name": "test-rg-001",
                        "type": "AzureResourceGroup",
                    },
                    "NetworkInterfaceIds": {
                        "model": "AzureNetworkSecurityGroup",
                        "value": [],
                    },
                },
                "name": "aviad-test-fuse-nsg",
                "type": "AzureNetworkSecurityGroup",
                "asset_unique_id": "AzureNetworkSecurityGroup_832879455555_00000000-0000-0000-0000-000000000001",
            },
            "RiskLevel": "low",
            "RiskLevelTime": "2025-10-13T14:33:27+00:00",
            "RuleId": "r51b45e2442",
            "RuleSource": "Orca",
            "RuleType": "az_nsg_ingress_unrestricted",
            "Score": 3,
            "ScoreVector": {
                "AlertBaseScore": {
                    "score": 5.2,
                    "Features": [
                        {
                            "score": 0.7,
                            "value": "Remote",
                            "weight": 1,
                            "category": "Attack Probability",
                            "display_name": "Required Access",
                            "effect_level": 3,
                            "impact_level": 1.6,
                            "feature_description": "The network access type required by the attacker to take advantage of this risk",
                        },
                    ],
                    "display_name": "Alert Base Score",
                },
            },
            "Severity": "hazardous",
            "Source": "test-nsg-001",
            "Status": "open",
            "StatusTime": "2025-10-13T14:33:27+00:00",
            "Title": "Azure Network Security Group have rule that allow unrestricted access from the Internet",
            "GroupUniqueId": "AzureNetworkSecurityGroup_832879455555_00000000-0000-0000-0000-000000000001",
            "Last_sync": "2025-11-06T09:35:40+00:00",
        },
        {
            "Type": "Alert",
            "Name": "orca-1108",
            "Cluster_unique_id": "AzureStorageAccount_832879455555_00000000-0000-0000-0000-000000000001",
            "Last_seen": "2025-11-06T09:35:31+00:00",
            "AlertId": "orca-1108",
            "AlertSource": "Orca Scan",
            "AlertType": "Azure Storage account's Customer-Managed Keys encryption is disabled",
            "AssetData": {
                "asset_name": "test-storage-001",
                "asset_type": "AzureStorageAccount",
                "asset_vpcs": [],
                "asset_state": "enabled",
                "account_name": "test-account-001",
                "asset_regions": [],
                "asset_category": "Storage",
                "cloud_provider": "azure",
                "cloud_vendor_id": "00000000-0000-0000-0000-000000000001",
                "asset_tags_info_list": [],
                "custom_tags_info_list": [],
                "cluster_type": None,
                "vm_id": None,
                "asset_labels": None,
                "resource_group_name": None,
                "cluster_name": "test-storage-001",
            },
            "Category": "Data protection",
            "CommentsCount": 0,
            "CreatedAt": "2025-10-13T14:33:27+00:00",
            "CveIds": [],
            "Description": "Azure Storage account's Customer-Managed Keys encryption is disabled",
            "Details": "Configuring the storage account to use BYOK (Use Your Own Key) provides ",
            "IsLive": True,
            "Labels": ["mitre: collection", "CSPM", "source: Orca Scan"],
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "LastUpdated": "2025-11-06T09:35:31+00:00",
            "MitreCategory": "collection",
            "MitreTechniques": ["Data from Cloud Storage (T1530)"],
            "OrcaScore": 6.4,
            "Recommendation": "Configure Customer-Managed Keys encryption for your storage account - test-storage-001.",
            "RemediationCli": [
                "Using **",
                ">1. Set Customer-managed key for your storage account:",
                "**`az storage account update --name <storage account name",
            ],
            "RemediationConsole": [
                ">1. Sign in to **[Azure Portal](https://portal.azure.com/)**.",
                ">2. Click **Save**.",
            ],
            "RiskFindings": {
                "id": "b063104b-377b-f7ba-b371-863412eb76e5",
                "data": {
                    "Kind": {"model": "AzureStorageAccount", "value": "Storage"},
                    "Encryption": {
                        "model": "AzureStorageAccount",
                        "value": '',
                    }
                },
                "name": "test-storage-001",
                "type": "AzureStorageAccount",
                "asset_unique_id": "AzureStorageAccount_832879455555_00000000-0000-0000-0000-000000000001",
            },
            "RiskLevel": "medium",
            "RiskLevelTime": "2025-10-13T14:33:27+00:00",
            "RuleId": "rbd4f02765d",
            "RuleSource": "Orca",
            "RuleType": "az_storage_not_encrypted_with_byok",
            "Score": 2,
            "ScoreVector": {
                "AlertBaseScore": {
                    "score": 6.0,
                    "Features": [
                        {
                            "score": 0.7,
                            "value": "Remote",
                            "weight": 1,
                            "category": "Attack Probability",
                            "display_name": "Required Access",
                            "effect_level": 3,
                            "impact_level": 1.6,
                            "feature_description": "The network access type required by the attacker to take advantage of this risk",
                        },
                    ],
                    "display_name": "Alert Base Score",
                }
            },
            "Severity": "imminent compromise",
            "Source": "test-storage-001",
            "Status": "open",
            "StatusTime": "2025-10-13T14:33:27+00:00",
            "Title": "Azure Storage account's Customer-Managed Keys encryption is disabled",
            "GroupUniqueId": "AzureStorageAccount_832879455555_00000000-0000-0000-0000-000000000001",
            "Last_sync": "2025-11-06T09:35:40+00:00",
        },
    ],
    "total_items": 2657
}


@pytest.fixture
def orca_client() -> OrcaClient:
    api_token = "dummy api key"
    client = BaseClient(
        base_url=DUMMY_ORCA_API_DNS_NAME,
        verify=True,
        headers={
            'Authorization': f'Token {api_token}'
        },
        proxy=True)
    return OrcaClient(client=client)


def test_get_alerts_by_type_malware_should_succeed(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {
        "status": "success",
        "total_items": 1,
        "data": [
            mock_alerts_response["data"][0]
        ]
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    res = orca_client.get_alerts_by_filter(alert_type="Malware")
    assert res[0] == mock_response['data'][0]


def test_get_alerts_by_non_existent_type_should_return_empty_list(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {
        "status": "success",
        "total_items": 1,
        "data": []
    }

    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    res = orca_client.get_alerts_by_filter(alert_type="non_existent_alert_type")
    assert res == []


def test_fetch_incidents_first_run_should_succeed(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_alerts_response)
    last_run, fetched_incidents = fetch_incidents(
        orca_client,
        last_run={'lastRun': None},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert fetched_incidents[0]['name'] == 'orca-1003'
    loaded_raw_alert = json.loads(fetched_incidents[0]['rawJSON'])
    assert loaded_raw_alert['demisto_score'] == 1
    assert fetched_incidents[1]['name'] == 'orca-1108'
    loaded_raw_alert = json.loads(fetched_incidents[1]['rawJSON'])
    assert loaded_raw_alert['demisto_score'] == 2
    assert last_run["lastRun"] is not None


def test_fetch_incidents_not_first_run_return_empty(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json={"status": "success", "data": []})

    # validates that fetch-incidents is returning an a empty list when it is not the first run
    last_run, fetched_incidents = fetch_incidents(
        orca_client,
        last_run={'step': "fetch", 'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert fetched_incidents == []


def test_test_module_success(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {
        "status": "success",
        "data": []
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    res = orca_client.validate_api_key()
    assert res == "ok"


def test_test_module_fail(requests_mock, orca_client: OrcaClient, mocker) -> None:
    return_error_mock = mocker.patch("Orca.return_error")

    mock_response = {"status": "failure", "error": "There is no Automation Rule assigned to API token"}
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", status_code=400, json={"status": "failure"})
    orca_client.validate_api_key()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[1]["message"]
    assert err_msg == "Test failed because the Orca API token that was entered is invalid, please provide a valid API token"

    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", status_code=400, json=mock_response)
    orca_client.validate_api_key()
    assert return_error_mock.call_count == 2
    err_msg = err_msg = return_error_mock.call_args[1]["message"]
    assert err_msg == "There is no Automation Rule assigned to API token"


def test_fetch_all_alerts(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = mock_alerts_response.copy()  # deepcopy not needed
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)

    # Get first page
    last_run, fetched_incidents = fetch_incidents(
        orca_client, {'lastRun': None},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert len(fetched_incidents) == 2
    assert last_run['fetch_page'] == 2
    assert last_run['step'] == STEP_FETCH
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)

    # Get next page
    last_run, fetched_incidents = fetch_incidents(
        orca_client, last_run,
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert len(fetched_incidents) == 2
    assert last_run['step'] == STEP_FETCH
    assert last_run['fetch_page'] == 3

    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json={"status": "success", "data": []})
    # No pages and no updates
    last_run, fetched_incidents = fetch_incidents(
        orca_client, last_run,
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert last_run['step'] == STEP_FETCH
    assert len(fetched_incidents) == 0


def test_orca_set_alert_severity(requests_mock, orca_client: OrcaClient) -> None:
    alert_id = "orca-52"

    requests_mock.put(f"{DUMMY_ORCA_API_DNS_NAME}/alerts/{alert_id}/severity", json={
        "user_email": "test@test.com",
        "alert_id": alert_id,
        "details": {
            "description": "Alert risk level changed",
            "severity": "Hazardous"
        }
    })

    response = set_alert_severity(orca_client=orca_client, args={
        "alert_id": alert_id,
        "score": 6
    })
    assert response.to_context()["Contents"]["details"]["severity"] == "Hazardous"


def test_orca_get_alert_event_log(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.get(
        f"{DUMMY_ORCA_API_DNS_NAME}/alerts/orca-1/event_log?limit=20&start_at_index=0&type=dismiss",
        json={
            "event_log": [
                {
                    "id": None,
                    "unique_id": "None",
                    "user_email": "",
                    "user_name": None,
                    "alert_id": "orca-1",
                    "asset_unique_id": "1",
                    "create_time": "2020-01-01T01:01:01+00:00",
                    "type": "set_status",
                    "sub_type": "open",
                    "details": {
                        "description": "Alert status changed",
                        "from": None,
                        "to": "open"
                    }
                }
            ],
            "total_count": 1
        }
    )

    args = {
        "alert_id": "orca-1",
        "limit": 20,
        "start_at_index": 0,
        "type": "dismiss"
    }
    result = get_alert_event_log(orca_client, args)

    content = result.to_context()["Contents"]
    assert content[0]["alert_id"] == "orca-1"
    assert content[0]["type"] == "set_status"


def test_orca_set_alert_status(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.put(
        f"{DUMMY_ORCA_API_DNS_NAME}/alerts/orca-1/status/open",
        json={
            "status": "success",
            "data": {
                "id": None,
                "unique_id": "None",
                "user_email": "test@ut.test",
                "user_name": "User User",
                "alert_id": "orca-1",
                "asset_unique_id": "1",
                "create_time": "2020-01-01T01:01:01+00:00",
                "type": "set_status",
                "sub_type": "open",
                "details": {
                    "description": "Alert status changed",
                    "from": "snoozed",
                    "to": "open"
                }
            }
        }
    )
    args = {
        "alert_id": "orca-1",
        "status": "open"
    }
    result = set_alert_status(orca_client, args)
    content = result.to_context()["Contents"]
    assert content["status"] == "open"


def test_orca_verify_alert(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.put(
        f"{DUMMY_ORCA_API_DNS_NAME}/alerts/orca-1/verify",
        json={
            "status": "scanning"
        }
    )
    args = {
        "alert_id": "orca-1"
    }
    result = verify_alert(orca_client, args)
    content = result.to_context()["Contents"]
    assert content["status"] == "scanning"


def test_orca_download_malicious_file(requests_mock, orca_client) -> None:
    requests_mock.get(
        f"{DUMMY_ORCA_API_DNS_NAME}/alerts/orca-1/download_malicious_file",
        json={
            "status": "success", "malicious_file.png": "malicious_file.png",
            "link": "https://aws.com/download/malicious_file.png"
        }
    )

    requests_mock.get(
        "https://aws.com/download/malicious_file.png",
        text="Hello World"
    )
    response = orca_client.download_malicious_file(alert_id="orca-1")
    assert response == {'filename': 'malicious_file.png', 'file': b'Hello World'}


def test_orca_download_malicious_file__error(requests_mock, orca_client):
    requests_mock.get(
        f"{DUMMY_ORCA_API_DNS_NAME}/alerts/orca-1/download_malicious_file",
        json={
            "status": "success", "malicious_file.png": "malicious_file.png",
            "link": "https://aws.com/download/malicious_file.png"
        }
    )
    requests_mock.get(
        "https://aws.com/download/malicious_file.png",
        status_code=404
    )
    with pytest.raises(DemistoException):
        orca_client.download_malicious_file("orca-1")


def test_pagination_with_remainder(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test pagination with remainder - 10 items with limit=3 should result in 4 pages
    This tests the ceiling division fix for pagination calculation
    """
    # Create 10 mock alerts
    mock_alerts = [
        {
            "AlertId": f"orca-{i}",
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "RiskLevel": "low",
        }
        for i in range(1, 11)
    ]
    
    # Page 1: items 1-3
    mock_response_page1 = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts[0:3]
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_page1)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=3)
    assert len(alerts) == 3
    assert is_last_page is False  # Should not be last page (4 pages total)
    
    # Page 2: items 4-6
    mock_response_page2 = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts[3:6]
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_page2)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=2, limit=3)
    assert len(alerts) == 3
    assert is_last_page is False
    
    # Page 3: items 7-9
    mock_response_page3 = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts[6:9]
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_page3)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=3, limit=3)
    assert len(alerts) == 3
    assert is_last_page is False
    
    # Page 4: item 10 (last page)
    mock_response_page4 = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts[9:10]
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_page4)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=4, limit=3)
    assert len(alerts) == 1
    assert is_last_page is True  # Should be last page


def test_missing_alert_id() -> None:
    """
    Test behavior when AlertId is missing from alert
    """
    alert_without_id = {
        "LastSeen": "2025-10-24T13:37:01+00:00",
        "RiskLevel": "high",
        "Title": "Test Alert"
    }
    
    incident = get_incident_from_alert(alert_without_id)
    # Should still create incident with empty name
    assert incident['name'] == ""
    assert incident['severity'] == 3  # high maps to 3
    assert 'occurred' in incident
    assert 'rawJSON' in incident


def test_invalid_risk_level() -> None:
    """
    Test behavior with invalid RiskLevel values (non-string)
    """
    # Test with integer RiskLevel
    alert_with_int_risk = {
        "AlertId": "orca-test-1",
        "LastSeen": "2025-10-24T13:37:01+00:00",
        "RiskLevel": 5  # Invalid: should be string
    }
    
    incident = get_incident_from_alert(alert_with_int_risk)
    assert incident['name'] == "orca-test-1"
    assert incident['severity'] == 0  # Should map to 0 (unknown) for invalid RiskLevel
    
    # Test with None RiskLevel
    alert_with_none_risk = {
        "AlertId": "orca-test-2",
        "LastSeen": "2025-10-24T13:37:01+00:00",
        "RiskLevel": None
    }
    
    incident = get_incident_from_alert(alert_with_none_risk)
    assert incident['name'] == "orca-test-2"
    assert incident['severity'] == 0  # Should map to 0 (unknown) for None RiskLevel
    
    # Test with missing RiskLevel
    alert_without_risk = {
        "AlertId": "orca-test-3",
        "LastSeen": "2025-10-24T13:37:01+00:00"
    }
    
    incident = get_incident_from_alert(alert_without_risk)
    assert incident['name'] == "orca-test-3"
    assert incident['severity'] == 0  # Should map to 0 (unknown) for missing RiskLevel


def test_empty_data_response(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test when API returns "data": null instead of "data": []
    """
    mock_response_null_data = {
        "status": "success",
        "total_items": 0,
        "data": None  # API returns null instead of empty list
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_null_data)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page
    assert alerts == []
    assert is_last_page is True


def test_page_beyond_total(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test behavior when requesting page beyond available pages
    """
    # Mock response with 5 total items, limit 3 = 2 pages
    mock_response = {
        "status": "success",
        "total_items": 5,
        "data": []  # Empty because page 3 doesn't exist
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=3, limit=3)
    
    # Should return empty list
    assert alerts == []
    # total_pages = (5 + 3 - 1) // 3 = 2, so page 3 >= 2 = True (is_last_page)
    assert is_last_page is True


def test_get_alerts_with_invalid_page(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts with invalid page parameter (None, 0, negative)
    """
    mock_response = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts_response["data"][:2]
    }
    
    # Test with None page
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=None, limit=10)
    assert len(alerts) == 2
    # Page should default to 1
    
    # Test with 0 page
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=0, limit=10)
    assert len(alerts) == 2
    # Page should default to 1
    
    # Test with negative page
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=-1, limit=10)
    assert len(alerts) == 2
    # Page should default to 1


def test_get_alerts_with_invalid_limit(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts with invalid limit parameter (0, negative)
    """
    mock_response = {
        "status": "success",
        "total_items": 10,
        "data": mock_alerts_response["data"][:2]
    }
    
    # Test with 0 limit
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=0)
    assert len(alerts) == 2
    # Limit should default to ORCA_API_LIMIT (500)
    
    # Test with negative limit
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=-5)
    assert len(alerts) == 2
    # Limit should default to ORCA_API_LIMIT (500)


def test_get_alerts_error_response(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts when API returns error status
    """
    mock_error_response = {
        "status": "failure",
        "error": "Invalid API token"
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_error_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page on error
    assert alerts == []
    assert is_last_page is True


def test_get_alerts_read_timeout(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts when API request times out
    """
    requests_mock.post(
        f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}",
        exc=requests.exceptions.ReadTimeout("Connection timeout")
    )
    
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page on timeout
    assert alerts == []
    assert is_last_page is True


def test_get_incidents_from_alerts_with_invalid_data() -> None:
    """
    Test get_incidents_from_alerts with alerts containing invalid data
    """
    alerts_with_invalid_data = [
        {
            "AlertId": "orca-valid-1",
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "RiskLevel": "high"
        },
        {
            # Missing AlertId
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "RiskLevel": "medium"
        },
        {
            "AlertId": "orca-valid-2",
            # Missing LastSeen
            "RiskLevel": "low"
        },
        {
            "AlertId": "orca-invalid-risk",
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "RiskLevel": 123  # Invalid: integer instead of string
        }
    ]
    
    incidents = get_incidents_from_alerts(alerts_with_invalid_data)
    
    # Should process all alerts, handling invalid data gracefully
    assert len(incidents) == 4
    assert incidents[0]['name'] == "orca-valid-1"
    assert incidents[0]['severity'] == 3  # high
    assert incidents[1]['name'] == ""  # Missing AlertId
    assert incidents[2]['name'] == "orca-valid-2"
    assert incidents[3]['name'] == "orca-invalid-risk"
    assert incidents[3]['severity'] == 0  # Invalid RiskLevel maps to 0


def test_get_alerts_with_total_items_zero(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts when total_items is 0
    """
    mock_response = {
        "status": "success",
        "total_items": 0,
        "data": []
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page
    assert alerts == []
    assert is_last_page is True


def test_get_alerts_with_non_list_data_type(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts when API returns non-list data type (dict, string, etc.)
    """
    # Test with dict instead of list
    mock_response_dict = {
        "status": "success",
        "total_items": 1,
        "data": {"alert": "data"}  # Should be a list
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_dict)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page due to invalid data type
    assert alerts == []
    assert is_last_page is True
    
    # Test with string instead of list
    mock_response_string = {
        "status": "success",
        "total_items": 1,
        "data": "invalid"  # Should be a list
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_string)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page due to invalid data type
    assert alerts == []
    assert is_last_page is True


def test_get_alerts_with_demisto_exception(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts when DemistoException is raised
    """
    from CommonServerPython import DemistoException
    
    requests_mock.post(
        f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}",
        exc=DemistoException("API Error")
    )
    
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    # Should return empty list and mark as last page on exception
    assert alerts == []
    assert is_last_page is True


def test_get_incident_from_alert_with_missing_last_seen() -> None:
    """
    Test get_incident_from_alert when LastSeen is missing
    Should use current time as fallback
    """
    alert_without_last_seen = {
        "AlertId": "orca-test-1",
        "RiskLevel": "high"
        # Missing LastSeen
    }
    
    incident = get_incident_from_alert(alert_without_last_seen)
    
    # Should create incident with current time as occurred
    assert incident['name'] == "orca-test-1"
    assert incident['severity'] == 3  # high
    assert 'occurred' in incident
    assert incident['occurred'] is not None
    # Should be a valid ISO format timestamp
    assert 'T' in incident['occurred'] or 'Z' in incident['occurred']


def test_fetch_incidents_pagination_edge_cases(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test fetch_incidents with pagination edge cases
    """
    # Test with exactly one page of results
    mock_response_one_page = {
        "status": "success",
        "total_items": 2,
        "data": [
            {
                "AlertId": "orca-1",
                "LastSeen": "2025-10-24T13:37:01+00:00",
                "RiskLevel": "high"
            },
            {
                "AlertId": "orca-2",
                "LastSeen": "2025-10-24T13:37:01+00:00",
                "RiskLevel": "medium"
            }
        ]
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_one_page)
    last_run, incidents = fetch_incidents(
        orca_client,
        last_run={'lastRun': None},
        max_fetch=10,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    
    # Should fetch all items and mark as last page
    assert len(incidents) == 2
    assert last_run['fetch_page'] == 1  # Reset to 1 on last page
    assert 'lastRun' in last_run
    
    # Test pagination with remainder - fetch page 1 of 2 pages (5 items, limit 3)
    mock_response_page1 = {
        "status": "success",
        "total_items": 5,
        "data": [
            {"AlertId": f"orca-{i}", "LastSeen": "2025-10-24T13:37:01+00:00", "RiskLevel": "low"}
            for i in range(1, 4)
        ]
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response_page1)
    last_run, incidents = fetch_incidents(
        orca_client,
        last_run={'lastRun': None},
        max_fetch=3,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    
    assert len(incidents) == 3
    assert last_run['fetch_page'] == 2  # Should increment to next page
    assert last_run['step'] == STEP_FETCH


def test_get_incident_from_alert_with_all_risk_levels() -> None:
    """
    Test get_incident_from_alert with all valid RiskLevel values
    """
    risk_levels = ["critical", "high", "medium", "low", "informational"]
    expected_severities = [4, 3, 2, 1, 0.5]
    
    for risk_level, expected_severity in zip(risk_levels, expected_severities):
        alert = {
            "AlertId": f"orca-{risk_level}",
            "LastSeen": "2025-10-24T13:37:01+00:00",
            "RiskLevel": risk_level
        }
        
        incident = get_incident_from_alert(alert)
        
        assert incident['name'] == f"orca-{risk_level}"
        assert incident['severity'] == expected_severity


def test_get_incident_from_alert_with_unknown_risk_level() -> None:
    """
    Test get_incident_from_alert with unknown RiskLevel value
    """
    alert = {
        "AlertId": "orca-unknown",
        "LastSeen": "2025-10-24T13:37:01+00:00",
        "RiskLevel": "unknown_level"  # Not in mapping
    }
    
    incident = get_incident_from_alert(alert)
    
    # Should map to 0 (unknown)
    assert incident['name'] == "orca-unknown"
    assert incident['severity'] == 0


def test_get_alerts_with_empty_string_risk_level(requests_mock, orca_client: OrcaClient) -> None:
    """
    Test get_alerts and incident creation with empty string RiskLevel
    """
    mock_response = {
        "status": "success",
        "total_items": 1,
        "data": [
            {
                "AlertId": "orca-empty-risk",
                "LastSeen": "2025-10-24T13:37:01+00:00",
                "RiskLevel": ""  # Empty string
            }
        ]
    }
    
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}{API_QUERY_ALERTS_URL}", json=mock_response)
    alerts, is_last_page = orca_client.get_alerts(time_from=None, page=1, limit=10)
    
    assert len(alerts) == 1
    
    # Test incident creation with empty string RiskLevel
    incident = get_incident_from_alert(alerts[0])
    assert incident['name'] == "orca-empty-risk"
    assert incident['severity'] == 0  # Empty string should map to 0
