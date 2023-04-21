from datetime import datetime

import pytest
import json
from Orca import OrcaClient, BaseClient, DEMISTO_OCCURRED_FORMAT, fetch_incidents, STEP_INIT, STEP_FETCH, \
    set_alert_severity, get_alert_event_log, set_alert_status, verify_alert

from CommonServerPython import DemistoException

DUMMY_ORCA_API_DNS_NAME = "https://dummy.io/api"

mock_alerts_response = {
    "version": "0.1.0",
    "status": "success",
    "total_items": 58,
    "total_ungrouped_items": 58,
    "total_supported_items": 10000,
    "data": [
        {
            "type": "malware",
            "rule_id": "r1111ea1111",
            "type_string": "Malware",
            "type_key": "/test_eicar_file",
            "category": "Malware",
            "description": "Malware EICAR-Test-File found on asset",
            "details": "We have detected a file infected with EICAR-Test-File on the asset.",
            "recommendation": "Remediate the host and attend additional "
                              "alerts on the host to close the infection path.",
            "alert_labels": [
                "malware_found"
            ],
            "asset_category": "Storage",
            "cloud_provider_id": "111111111111",
            "cloud_provider": "aws",
            "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
            "cloud_vendor_id": "111111111111",
            "account_name": "111111111111",
            "asset_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
            "asset_name": "scan-me-s3-bucket-s8rrr",
            "asset_type": "storage",
            "asset_type_string": "AWS S3 Bucket",
            "group_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
            "group_name": "scan-me-s3-bucket-s8rrr",
            "group_type": "storage",
            "group_type_string": "NonGroup",
            "group_val": "nongroup",
            "cluster_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
            "cluster_name": "scan-me-s3-bucket-s8rrr",
            "cluster_type": "storage",
            "level": 0,
            "asset_state": "enabled",
            "asset_labels": [
                "internet_facing",
                "pii"
            ],
            "asset_vendor_id": "scan-me-s3-bucket-s8rrr",
            "asset_regions": [
                "us-east-1"
            ],
            "asset_regions_names": [
                "N. Virginia"
            ],
            "source": "test_eicar_file",
            "findings": {
                "malware": [
                    {
                        "type": "malware",
                        "labels": [
                            "malware_found"
                        ],
                        "virus_names": [
                            "EICAR-Test-File"
                        ],
                        "modification_time": "2020-04-26T14:26:11+00:00",
                        "file": "/test_eicar_file",
                        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                        "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                        "md5": "44d88612fea8a8f36de82e1278abb02f",
                        "has_macro": False
                    }
                ]
            },
            "configuration": {
                "user_status": "closed",
                "jira_issue_link": "https://www.jira.com/myproject",
                "jira_issue": "TP-41"
            },
            "state": {
                "alert_id": "orca-59",
                "status": "in_progress",
                "status_time": "2020-12-30T09:57:33+00:00",
                "created_at": "2020-11-08T12:58:52+00:00",
                "last_seen": "2020-12-30T10:35:46+00:00",
                "score": 1,
                "severity": "compromised",
                "low_since": None,
                "high_since": "2020-12-15T15:33:49+00:00",
                "in_verification": None,
                "risk_level": "low",
            },
            "priv": {
                "key": "3ea22222274111114b011111bb311111",
                "score": 1,
                "orig_score": 1,
                "alert_id": "orca-59",
                "full_scan_time": "2020-12-30T10:35:46+00:00",
                "organization_id": "11111111-1111-1111-1111-c111881c1111",
                "organization_name": "Orca Security",
                "context": "data",
                "account_action_id_ctx": {
                    "data": "11111111-1111-1111-1111-8a529a011111"
                },
                "scan_id_ctx": {
                    "data": "11111111-1111-1111-1111-8a529a011111_111111111111_bucket-111111e11111-us-east-1"
                },
                "first_seen": "2020-11-08T13:03:37+00:00"
            },
            "hdr": {
                "asset_category": "Storage",
                "organization_id": "11111111-1111-1111-1111-c111881c1111",
                "organization_name": "Orca Security",
                "cloud_provider": "aws",
                "cloud_provider_id": "111111111111",
                "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
                "context": "data",
                "asset_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "asset_type": "storage",
                "asset_type_string": "AWS S3 Bucket",
                "asset_name": "scan-me-s3-bucket-s8rrr",
                "group_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "group_name": "scan-me-s3-bucket-s8rrr",
                "group_type": "storage",
                "group_type_string": "NonGroup",
                "cluster_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "cluster_type": "storage",
                "cluster_name": "scan-me-s3-bucket-s8rrr",
                "level": 0,
                "group_val": "nongroup",
                "asset_vendor_id": "scan-me-s3-bucket-s8rrr",
                "cloud_vendor_id": "111111111111",
                "asset_state": "enabled",
                "account_name": "111111111111",
                "asset_labels": [
                    "internet_facing"
                ]
            },
            "insert_time": "2020-12-30T10:45:21+00:00"
        },
        {
            "type": "malware",
            "rule_id": "r1111ea1111",
            "type_string": "Malware",
            "type_key": "/usr/local/bin/eicarcom2.zip",
            "category": "Malware",
            "description": "Malware EICAR-Test-File found on asset",
            "details": "We have detected a file infected with EICAR-Test-File on the asset.",
            "recommendation": "Remediate the host and attend additional "
                              "alerts on the host to close the infection path.",
            "alert_labels": [
                "malware_found"
            ],
            "asset_category": "Image",
            "cloud_provider_id": "111111111111",
            "cloud_provider": "aws",
            "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
            "cloud_vendor_id": "111111111111",
            "account_name": "111111111111",
            "asset_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
            "asset_name": "my_test_image-1231asdasjdn",
            "asset_type": "vmimage",
            "asset_type_string": "VM Image",
            "group_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
            "group_name": "my_test_image-1231asdasjdn",
            "group_type": "vmimage",
            "group_type_string": "NonGroup",
            "group_val": "nongroup",
            "cluster_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
            "cluster_name": "my_test_image-1231asdasjdn",
            "cluster_type": "vmimage",
            "level": 0,
            "asset_vendor_id": "ami-11111c111111d7911",
            "asset_distribution_name": "Ubuntu",
            "asset_distribution_version": "18.04",
            "asset_role_names": [
                "mysql",
                "ssh",
                "haproxy",
                "postgresql"
            ],
            "source": "eicarcom2.zip",
            "findings": {
                "malware": [
                    {
                        "type": "malware",
                        "labels": [
                            "malware_found"
                        ],
                        "virus_names": [
                            "EICAR-Test-File"
                        ],
                        "modification_time": "2019-07-09T21:16:26+00:00",
                        "file": "/usr/local/bin/eicarcom2.zip",
                        "sha256": "e1105070ba828007508566e28a2b8d4c65d192e9eaf3b7868382b7cae747b397",
                        "sha1": "bec1b52d350d721c7e22a6d4bb0a92909893a3ae",
                        "md5": "e4968ef99266df7c9a1f0637d2389dab",
                        "has_macro": False
                    }
                ]
            },
            "configuration": {},
            "state": {
                "alert_id": "orca-242",
                "status": "open",
                "status_time": "2020-11-08T12:58:54+00:00",
                "created_at": "2020-11-08T12:58:54+00:00",
                "last_seen": "2020-12-30T10:35:48+00:00",
                "score": 9,
                "severity": "compromised",
                "low_since": None,
                "high_since": "2020-11-08T13:04:32+00:00",
                "in_verification": None,
                "risk_level": "critical",
            },
            "priv": {
                "key": "3696080647d937b881eee2cfdd6c3943",
                "score": 1,
                "orig_score": 1,
                "alert_id": "orca-242",
                "full_scan_time": "2020-12-30T10:35:48+00:00",
                "organization_id": "11111111-1111-1111-1111-c111881c1111",
                "organization_name": "Orca Security",
                "context": "data",
                "account_action_id_ctx": {
                    "data": "11111111-1111-1111-1111-8a529a011111"
                },
                "scan_id_ctx": {
                    "data": "11111111-1111-1111-1111-8a529a011111_111111111111_ami-11111c111111d7911"
                },
                "first_seen": "2020-11-08T13:04:32+00:00"
            },
            "hdr": {
                "asset_category": "Image",
                "organization_id": "11111111-1111-1111-1111-c111881c1111",
                "organization_name": "Orca Security",
                "cloud_provider": "aws",
                "cloud_provider_id": "111111111111",
                "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
                "context": "data",
                "asset_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
                "asset_type": "vmimage",
                "asset_type_string": "VM Image",
                "asset_name": "my_test_image-1231asdasjdn",
                "group_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
                "group_name": "my_test_image-1231asdasjdn",
                "group_type": "vmimage",
                "group_type_string": "NonGroup",
                "cluster_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
                "cluster_type": "vmimage",
                "cluster_name": "my_test_image-1231asdasjdn",
                "level": 0,
                "group_val": "nongroup",
                "asset_vendor_id": "ami-11111c111111d7911",
                "cloud_vendor_id": "111111111111",
                "account_name": "111111111111"
            },
            "insert_time": "2020-12-30T10:44:11+00:00"
        }
    ]
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
        "version": "0.1.0",
        "status": "success",
        "total_items": 6,
        "total_ungrouped_items": 6,
        "total_supported_items": 10000,
        "data": [
            {
                "type": "malware",
                "rule_id": "r1111ea1111",
                "type_string": "Malware",
                "type_key": "/test_eicar_file",
                "category": "Malware",
                "description": "Malware EICAR-Test-File found on asset",
                "details": "We have detected a file infected with EICAR-Test-File on the asset.",
                "recommendation": "Remediate the host and attend additional "
                                  "alerts on the host to close the infection path.",
                "alert_labels": [
                    "malware_found"
                ],
                "asset_category": "Storage",
                "cloud_provider_id": "111111111111",
                "cloud_provider": "aws",
                "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
                "cloud_vendor_id": "111111111111",
                "account_name": "111111111111",
                "asset_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "asset_name": "scan-me-s3-bucket-s8rrr",
                "asset_type": "storage",
                "asset_type_string": "AWS S3 Bucket",
                "group_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "group_name": "scan-me-s3-bucket-s8rrr",
                "group_type": "storage",
                "group_type_string": "NonGroup",
                "group_val": "nongroup",
                "cluster_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                "cluster_name": "scan-me-s3-bucket-s8rrr",
                "cluster_type": "storage",
                "level": 0,
                "asset_state": "enabled",
                "asset_labels": [
                    "internet_facing",
                    "pii"
                ],
                "asset_vendor_id": "scan-me-s3-bucket-s8rrr",
                "asset_regions": [
                    "us-east-1"
                ],
                "asset_regions_names": [
                    "N. Virginia"
                ],
                "source": "test_eicar_file",
                "findings": {
                    "malware": [
                        {
                            "type": "malware",
                            "labels": [
                                "malware_found"
                            ],
                            "virus_names": [
                                "EICAR-Test-File"
                            ],
                            "modification_time": "2020-04-26T14:26:11+00:00",
                            "file": "/test_eicar_file",
                            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                            "md5": "44d88612fea8a8f36de82e1278abb02f",
                            "has_macro": False
                        }
                    ]
                },
                "configuration": {
                    "user_status": "closed",
                    "jira_issue_link": "https://www.jira.com/myproject",
                    "jira_issue": "TP-41"
                },
                "state": {
                    "alert_id": "orca-59",
                    "status": "in_progress",
                    "status_time": "2020-12-30T09:57:33+00:00",
                    "created_at": "2020-11-08T12:58:52+00:00",
                    "last_seen": "2020-12-30T10:35:46+00:00",
                    "score": 1,
                    "severity": "compromised",
                    "low_since": None,
                    "high_since": "2020-12-15T15:33:49+00:00",
                    "in_verification": None
                },
                "priv": {
                    "key": "3ea22222274111114b011111bb311111",
                    "score": 1,
                    "orig_score": 1,
                    "alert_id": "orca-59",
                    "full_scan_time": "2020-12-30T10:35:46+00:00",
                    "organization_id": "11111111-1111-1111-1111-c111881c1111",
                    "organization_name": "Orca Security",
                    "context": "data",
                    "account_action_id_ctx": {
                        "data": "11111111-1111-1111-1111-8a529a011111"
                    },
                    "scan_id_ctx": {
                        "data": "11111111-1111-1111-1111-8a529a011111_111111111111_bucket-111111e11111-us-east-1"
                    },
                    "first_seen": "2020-11-08T13:03:37+00:00"
                },
                "hdr": {
                    "asset_category": "Storage",
                    "organization_id": "11111111-1111-1111-1111-c111881c1111",
                    "organization_name": "Orca Security",
                    "cloud_provider": "aws",
                    "cloud_provider_id": "111111111111",
                    "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
                    "context": "data",
                    "asset_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                    "asset_type": "storage",
                    "asset_type_string": "AWS S3 Bucket",
                    "asset_name": "scan-me-s3-bucket-s8rrr",
                    "group_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                    "group_name": "scan-me-s3-bucket-s8rrr",
                    "group_type": "storage",
                    "group_type_string": "NonGroup",
                    "cluster_unique_id": "storage_111111e11111_scan-me-s3-bucket-s8rrr",
                    "cluster_type": "storage",
                    "cluster_name": "scan-me-s3-bucket-s8rrr",
                    "level": 0,
                    "group_val": "nongroup",
                    "asset_vendor_id": "scan-me-s3-bucket-s8rrr",
                    "cloud_vendor_id": "111111111111",
                    "asset_state": "enabled",
                    "account_name": "111111111111",
                    "asset_labels": [
                        "internet_facing"
                    ]
                },
                "insert_time": "2020-12-30T10:45:21+00:00"
            }
        ]
    }
    requests_mock.get(f"{DUMMY_ORCA_API_DNS_NAME}/alerts?type=malware", json=mock_response)
    res = orca_client.get_alerts_by_filter(alert_type="malware")
    assert res[0] == mock_response['data'][0]


def test_get_alerts_by_non_existent_type_should_return_empty_list(requests_mock, orca_client: OrcaClient) -> None:
    NON_EXISTENT_ALERT_TYPE = "non_existent_alert_type"
    mock_response = {
        "version": "0.1.0",
        "status": "success",
        "total_items": 0,
        "total_ungrouped_items": 0,
        "total_supported_items": 10000,
        "data": []}

    requests_mock.get(f"{DUMMY_ORCA_API_DNS_NAME}/alerts?type={NON_EXISTENT_ALERT_TYPE}", json=mock_response)
    res = orca_client.get_alerts_by_filter(alert_type=NON_EXISTENT_ALERT_TYPE)
    assert res == []


def test_fetch_incidents_first_run_should_succeed(requests_mock, orca_client: OrcaClient) -> None:
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", json=mock_alerts_response)
    last_run, fetched_incidents = fetch_incidents(
        orca_client,
        last_run={'lastRun': None},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert fetched_incidents[0]['name'] == 'orca-59'
    loaded_raw_alert = json.loads(fetched_incidents[0]['rawJSON'])
    assert loaded_raw_alert['demisto_score'] == 1
    assert fetched_incidents[1]['name'] == 'orca-242'
    loaded_raw_alert = json.loads(fetched_incidents[1]['rawJSON'])
    assert loaded_raw_alert['demisto_score'] == 4
    assert last_run["lastRun"] is not None


def test_fetch_incidents_not_first_run_return_empty(orca_client: OrcaClient) -> None:
    # validates that fetch-incidents is returning an a empty list when it is not the first run
    last_run, fetched_incidents = fetch_incidents(
        orca_client,
        last_run={'step': "fetch", 'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert fetched_incidents == []


def test_get_asset_should_succeed(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {
        "type": "vmimage",
        "asset_category": "Image",
        "asset_subcategory": "VM Image",
        "cloud_provider_id": "111111111111",
        "cloud_provider": "aws",
        "cloud_account_id": "10b11111-1111-1111-91d5-11111de11111",
        "cloud_vendor_id": "111111111111",
        "account_name": "111111111111",
        "asset_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
        "asset_name": "my_test_image-1231asdasjdn",
        "asset_type": "vmimage",
        "asset_type_string": "VM Image",
        "group_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
        "group_name": "my_test_image-1231asdasjdn",
        "group_type": "vmimage",
        "group_type_string": "NonGroup",
        "cluster_unique_id": "vmimage_111111e11111_ami-11111c111111d7911",
        "cluster_name": "my_test_image-1231asdasjdn",
        "cluster_type": "vmimage",
        "level": 0,
        "asset_vendor_id": "ami-11111c111111d7911",
        "internet_facing": False,
        "internet_facing_new": False,
        "create_time": "2020-07-28T09:10:01+00:00",
        "container_id": "main",
        "compute": {
            "distribution_name": "Ubuntu",
            "distribution_version": "18.04",
            "disks": [
                {
                    "size": "7.75 GB",
                    "used": "2.06 GB"
                }
            ],
            "total_disks_bytes": 8326123520,
            "roles": [
                {
                    "type": "database",
                    "name": "mysql",
                    "is_public": False,
                    "detected_evidence": [
                        "/var/lib/mysql/mysqldb2",
                        "/var/lib/mysql/mysqldb1"
                    ]
                },
                {
                    "type": "ssh",
                    "name": "ssh",
                    "is_public": False
                },
                {
                    "type": "web",
                    "name": "haproxy",
                    "is_public": False
                },
                {
                    "type": "database",
                    "name": "postgresql",
                    "is_public": False,
                    "detected_evidence": [
                        "/var/lib/postgresql/10/main/base/1",
                        "/var/lib/postgresql/10/main",
                        "/var/lib/postgresql/10/main/base/13017",
                        "/var/lib/postgresql/10/main/base/16384",
                        "/var/lib/postgresql/10/main/base/13018"
                    ]
                }
            ]
        },
        "vmimage": {
            "image_id": "ami-11111c111111d7911",
            "image_owner_id": "111111111111",
            "image_name": "my_test_image-1231asdasjdn",
            "image_description": ""
        },
        "configuration": {},
        "state": {
            "status": "exists",
            "status_time": "2020-11-08T13:04:34+00:00",
            "created_at": "2020-11-08T13:04:34+00:00",
            "last_seen": "2020-12-30T10:44:11+00:00",
            "score": 1,
            "severity": "compromised",
            "safe_since": None,
            "unsafe_since": "2020-11-08T13:04:34+00:00"
        }
    }
    requests_mock.get(f"{DUMMY_ORCA_API_DNS_NAME}/assets/vmimage_111111e11111_ami-11111c111111d7911",
                      json=mock_response)
    res = orca_client.get_asset(asset_unique_id="vmimage_111111e11111_ami-11111c111111d7911")
    assert res == mock_response


def test_get_asset_nonexistent(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {"error": ""}
    requests_mock.get(f"{DUMMY_ORCA_API_DNS_NAME}/assets/1234567", json=mock_response)
    res = orca_client.get_asset(asset_unique_id="1234567")
    assert res == "Asset Not Found"


def test_test_module_success(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = {
        "status": "success",
        "data": []
    }
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", json=mock_response)
    res = orca_client.validate_api_key()
    assert res == "ok"


def test_test_module_fail(requests_mock, orca_client: OrcaClient, mocker) -> None:
    return_error_mock = mocker.patch("Orca.return_error")

    mock_response = {"status": "failure", "error": "There is no Automation Rule assigned to API token"}
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", status_code=200, json={"status": "failure"})
    orca_client.validate_api_key()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[1]["message"]
    assert err_msg == "Test failed because the Orca API token that was entered is invalid, please provide a valid API token"

    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", status_code=400, json=mock_response)
    orca_client.validate_api_key()
    assert return_error_mock.call_count == 2
    err_msg = err_msg = return_error_mock.call_args[1]["message"]
    assert err_msg == "There is no Automation Rule assigned to API token"


def test_fetch_all_alerts(requests_mock, orca_client: OrcaClient) -> None:
    mock_response = mock_alerts_response.copy()  # deepcopy not needed
    mock_response["next_page_token"] = "NEXT_PAGE"
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", json=mock_response)

    # Get first page
    last_run, fetched_incidents = fetch_incidents(
        orca_client, {'lastRun': None},
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert len(fetched_incidents) == 2
    assert last_run['next_page_token'] == 'NEXT_PAGE'
    assert last_run['step'] == STEP_INIT
    mock_response["next_page_token"] = None  # type: ignore
    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", json=mock_response)

    # Get next page
    last_run, fetched_incidents = fetch_incidents(
        orca_client, last_run,
        max_fetch=20,
        pull_existing_alerts=True,
        first_fetch_time=None
    )
    assert len(fetched_incidents) == 2
    assert last_run['step'] == STEP_FETCH
    assert 'next_page_token' not in last_run

    requests_mock.post(f"{DUMMY_ORCA_API_DNS_NAME}/rules/query/alerts", json={"status": "success", "data": []})
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
