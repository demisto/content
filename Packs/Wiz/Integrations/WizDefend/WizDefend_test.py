import copy
import pytest
from unittest.mock import patch
import demistomock as demisto

from CommonServerPython import DemistoException

integration_params = {
    'url': 'http://test.io',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '7 days',
    'max_fetch': 5
}

integration_params_with_auth_url = copy.deepcopy(integration_params)
integration_params_with_auth_url.update({"auth_endpoint": "https://auth.wiz.io/oauth/token"})

TEST_TOKEN = '123456789'


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params_with_auth_url)


test_detection_response = {
    "data": {
        "detections": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "issue": {
                        "id": "12345678-9876-1234-5678-cc0a24716e0b",
                        "url": "https://app.wiz.io/issues/12345678-9876-1234-5678-cc0a24716e0b"
                    },
                    "ruleMatch": {
                        "rule": {
                            "id": "12345678-4321-4321-4321-3792e8a03318",
                            "name": "Suspicious activity detected",
                            "sourceType": "THREAT_DETECTION",
                            "securitySubCategories": [
                                {
                                    "title": "T1078 - Valid Accounts",
                                    "category": {
                                        "name": "MITRE ATT&CK",
                                        "framework": {
                                            "name": "MITRE"
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "description": "Suspicious activity detected on EC2 instance",
                    "severity": "CRITICAL",
                    "createdAt": "2022-01-02T15:46:34Z",
                    "cloudAccounts": [
                        {
                            "cloudProvider": "AWS",
                            "externalId": "123456789012",
                            "name": "Production",
                            "linkedProjects": [
                                {
                                    "id": "project-123",
                                    "name": "Core Infrastructure"
                                }
                            ]
                        }
                    ],
                    "cloudOrganizations": [
                        {
                            "cloudProvider": "AWS",
                            "externalId": "o-abcdefghij",
                            "name": "Main Organization"
                        }
                    ],
                    "startedAt": "2022-01-02T15:30:00Z",
                    "endedAt": "2022-01-02T15:45:00Z",
                    "actors": [
                        {
                            "id": "actor-123",
                            "externalId": "AIDACKCEVSQ6C2EXAMPLE",
                            "name": "user@example.com",
                            "type": "USER",
                            "nativeType": "IAM_USER",
                            "actingAs": None
                        }
                    ],
                    "primaryActor": {
                        "id": "actor-123"
                    },
                    "resources": [
                        {
                            "id": "resource-123",
                            "externalId": "i-12345abcdef",
                            "name": "web-server-01",
                            "type": "VIRTUAL_MACHINE",
                            "nativeType": "ec2",
                            "region": "us-east-1",
                            "cloudAccount": {
                                "cloudProvider": "AWS",
                                "externalId": "123456789012",
                                "name": "Production"
                            },
                            "kubernetesNamespace": None,
                            "kubernetesCluster": None
                        }
                    ],
                    "primaryResource": {
                        "id": "resource-123"
                    },
                    "triggeringEvents": {
                        "nodes": [
                            {
                                "id": "event-123",
                                "origin": "AWS_CLOUDTRAIL",
                                "name": "ConsoleLogin",
                                "description": "Successful login to the AWS Console",
                                "cloudProviderUrl": "https://console.aws.amazon.com",
                                "cloudPlatform": "AWS",
                                "timestamp": "2022-01-02T15:35:00Z",
                                "source": "console.amazonaws.com",
                                "category": "USER_ACTIVITY",
                                "status": "SUCCESS",
                                "actor": {
                                    "id": "actor-123",
                                    "actingAs": None
                                },
                                "actorIP": "203.0.113.1",
                                "actorIPMeta": {
                                    "country": "United States",
                                    "autonomousSystemNumber": "16509",
                                    "autonomousSystemOrganization": "Amazon.com, Inc.",
                                    "reputation": "NEUTRAL",
                                    "reputationDescription": "No known threats",
                                    "reputationSource": "VirusTotal",
                                    "relatedAttackGroupNames": None,
                                    "customIPRanges": None
                                },
                                "resources": [
                                    {
                                        "id": "resource-123"
                                    }
                                ],
                                "extraDetails": None
                            }
                        ]
                    }
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_detection_by_id(checkAPIerrors):
    from WizDefend import get_detection

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_detection(detection_id='12345678-1234-1234-1234-d25e16359c19')
    assert res == result_response


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_detection_by_issue_id(checkAPIerrors):
    from WizDefend import get_detection

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_detection(issue_id='12345678-9876-1234-5678-cc0a24716e0b')
    assert res == result_response


def test_get_detection_fail_no_parameters(capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        res = get_detection()
        assert "You must provide either either detection_id or issue_id." in res


def test_get_detection_invalid_detection_id(capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        res = get_detection(detection_id='invalid-id')
        assert "Wrong format: detection_id should be in UUID format." in res


def test_get_detection_invalid_issue_id(capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        res = get_detection(issue_id='invalid-id')
        assert "Wrong format: issue_id should be in UUID format." in res


@patch('WizDefend.checkAPIerrors', return_value={"data": {"detections": {"nodes": []}}})
def test_get_detection_not_found(checkAPIerrors, capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        res = get_detection(detection_id='12345678-1234-1234-1234-d25e16359c19')
        assert res == {}


@patch('WizDefend.checkAPIerrors', side_effect=DemistoException('API error'))
def test_get_detection_api_error(checkAPIerrors, capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        try:
            get_detection(detection_id='12345678-1234-1234-1234-d25e16359c19')
            assert False  # Should not reach here
        except DemistoException as e:
            assert 'API error' in str(e)


test_multiple_detections_response = {
    "data": {
        "detections": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "severity": "CRITICAL",
                    "description": "Detection 1"
                },
                {
                    "id": "87654321-4321-4321-4321-d25e16359c19",
                    "severity": "HIGH",
                    "description": "Detection 2"
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}


@patch('WizDefend.checkAPIerrors', return_value=test_multiple_detections_response)
def test_get_detection_multiple_ids(checkAPIerrors):
    from WizDefend import get_detection

    detection_ids = ['12345678-1234-1234-1234-d25e16359c19', '87654321-4321-4321-4321-d25e16359c19']

    res = get_detection(detection_id=detection_ids)
    assert len(res) == 2
    assert res[0]['id'] == detection_ids[0]
    assert res[1]['id'] == detection_ids[1]


def test_get_detection_mixed_valid_invalid_ids(capfd):
    with capfd.disabled():
        from WizDefend import get_detection

        detection_ids = ['12345678-1234-1234-1234-d25e16359c19', 'invalid-id']

        res = get_detection(detection_id=detection_ids)
        assert "Wrong format: detection_id should be in UUID format." in res


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_filtered_detections_by_id(checkAPIerrors):
    from WizDefend import get_filtered_detections

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_filtered_detections(
        detection_type=None,
        detection_platform=None,
        resource_id=None,
        detection_id='12345678-1234-1234-1234-d25e16359c19',
        severity=None,
        limit=500
    )
    assert res == result_response


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_filtered_detections_by_type(checkAPIerrors):
    from WizDefend import get_filtered_detections

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_filtered_detections(
        detection_type='MATCH_ONLY',
        detection_platform=None,
        resource_id=None,
        detection_id=None,
        severity=None,
        limit=500
    )
    assert res == result_response


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_filtered_detections_by_platform(checkAPIerrors):
    from WizDefend import get_filtered_detections

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_filtered_detections(
        detection_type=None,
        detection_platform='AWS',
        resource_id=None,
        detection_id=None,
        severity=None,
        limit=500
    )
    assert res == result_response


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_filtered_detections_by_resource_id(checkAPIerrors):
    from WizDefend import get_filtered_detections

    result_response = test_detection_response["data"]["detections"]["nodes"]

    res = get_filtered_detections(
        detection_type=None,
        detection_platform=None,
        resource_id='i-12345abcdef',
        detection_id=None,
        severity=None,
        limit=500
    )
    assert res == result_response


@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
def test_get_filtered_detections_by_severity(checkAPIerrors):
    from WizDefend import get_filtered_detections

    result_response = test_detection_response["data"]["detections"]["nodes"]

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        res = get_filtered_detections(
            detection_type=None,
            detection_platform=None,
            resource_id=None,
            detection_id=None,
            severity=severity,
            limit=500
        )
        assert res == result_response


def test_get_filtered_detections_invalid_severity(capfd):
    with capfd.disabled():
        from WizDefend import get_filtered_detections

        res = get_filtered_detections(
            detection_type=None,
            detection_platform=None,
            resource_id=None,
            detection_id=None,
            severity='INVALID',
            limit=500
        )
        assert "You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL" in res


def test_get_filtered_detections_no_parameters(capfd):
    with capfd.disabled():
        from WizDefend import get_filtered_detections

        res = get_filtered_detections(
            detection_type=None,
            detection_platform=None,
            resource_id=None,
            detection_id=None,
            severity=None,
            limit=500
        )
        assert "You should pass (at least) one of the following parameters" in res


@patch('WizDefend.checkAPIerrors',
       return_value={"data": {"detections": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}})
def test_get_filtered_detections_empty_result(checkAPIerrors):
    from WizDefend import get_filtered_detections

    res = get_filtered_detections(
        detection_type='MATCH_ONLY',
        detection_platform=None,
        resource_id=None,
        detection_id=None,
        severity=None,
        limit=500
    )
    assert res == {}


test_paginated_detections_response = [
    {
        "data": {
            "detections": {
                "nodes": [
                    {
                        "id": "page1-detection-1",
                        "severity": "CRITICAL"
                    },
                    {
                        "id": "page1-detection-2",
                        "severity": "HIGH"
                    }
                ],
                "pageInfo": {
                    "hasNextPage": True,
                    "endCursor": "cursor1"
                }
            }
        }
    },
    {
        "data": {
            "detections": {
                "nodes": [
                    {
                        "id": "page2-detection-1",
                        "severity": "MEDIUM"
                    },
                    {
                        "id": "page2-detection-2",
                        "severity": "LOW"
                    }
                ],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": "cursor2"
                }
            }
        }
    }
]


@patch('WizDefend.checkAPIerrors', side_effect=test_paginated_detections_response)
def test_get_filtered_detections_pagination(checkAPIerrors):
    from WizDefend import get_filtered_detections

    res = get_filtered_detections(
        detection_type='MATCH_ONLY',
        detection_platform=None,
        resource_id=None,
        detection_id=None,
        severity=None,
        limit=500
    )

    # Should have combined results from both pages
    assert len(res) == 4
    assert res[0]['id'] == 'page1-detection-1'
    assert res[1]['id'] == 'page1-detection-2'
    assert res[2]['id'] == 'page2-detection-1'
    assert res[3]['id'] == 'page2-detection-2'


# Test translate_severity function
def test_translate_severity():
    from WizDefend import translate_severity

    # Test all severity levels
    assert translate_severity({"severity": "CRITICAL"}) == 4
    assert translate_severity({"severity": "HIGH"}) == 3
    assert translate_severity({"severity": "MEDIUM"}) == 2
    assert translate_severity({"severity": "LOW"}) == 1
    assert translate_severity({"severity": "INFORMATIONAL"}) == 0.5
    assert translate_severity({"severity": "UNKNOWN"}) is None


# Test invalid UUID validation
def test_is_valid_uuid():
    from WizDefend import is_valid_uuid

    # Valid UUIDs
    assert is_valid_uuid('12345678-1234-1234-1234-123456789012') is True
    assert is_valid_uuid('00000000-0000-0000-0000-000000000000') is True

    # Invalid UUIDs
    assert is_valid_uuid('not-a-uuid') is False
    assert is_valid_uuid('12345678-1234-1234-1234') is False  # Too short
    assert is_valid_uuid('12345678123412341234123456789012') is False  # No hyphens
    assert is_valid_uuid(12345) is False  # Not a string
    assert is_valid_uuid(None) is False  # None value


# Test fetch_incidents function
test_fetch_incidents_response = {
    "data": {
        "detections": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "severity": "CRITICAL",
                    "createdAt": "2022-01-02T15:46:34Z",
                    "sourceRule": {
                        "name": "Suspicious Activity"
                    }
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}


@patch('WizDefend.checkAPIerrors', return_value=test_fetch_incidents_response)
@patch('WizDefend.demisto.incidents')
@patch('WizDefend.demisto.setLastRun')
def test_fetch_incidents(mock_set_last_run, mock_incidents, checkAPIerrors):
    from WizDefend import fetch_incidents

    fetch_incidents(max_fetch=10)

    # Check that incidents were created with correct data
    incidents_arg = mock_incidents.call_args[0][0]
    assert len(incidents_arg) == 1
    assert incidents_arg[0]['name'] == 'Suspicious Activity - 12345678-1234-1234-1234-d25e16359c19'
    assert incidents_arg[0]['occurred'] == '2022-01-02T15:46:34Z'
    assert incidents_arg[0]['severity'] == 4

    # Check that LastRun was set
    assert mock_set_last_run.called


# Test main function for command handling
@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
@patch('WizDefend.demisto.command', return_value='wiz-get-detection')
@patch('WizDefend.demisto.args', return_value={'detection_id': '12345678-1234-1234-1234-d25e16359c19'})
@patch('WizDefend.return_results')
def test_main_get_detection_command(mock_return_results, mock_args, mock_command, mock_check_api, mock_token):
    from WizDefend import main

    main()

    # Check that return_results was called with the right CommandResults
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == 'Wiz.Manager.Detection'
    assert command_results.outputs == test_detection_response["data"]["detections"]["nodes"]


@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
@patch('WizDefend.demisto.command', return_value='wiz-get-detections')
@patch('WizDefend.demisto.args', return_value={'severity': 'CRITICAL'})
@patch('WizDefend.return_results')
def test_main_get_detections_command(mock_return_results, mock_args, mock_command, mock_check_api, mock_token):
    from WizDefend import main

    main()

    # Check that return_results was called with the right CommandResults
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == 'Wiz.Manager.Detections'
    assert command_results.outputs == test_detection_response["data"]["detections"]["nodes"]


@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.checkAPIerrors', return_value=test_detection_response)
@patch('WizDefend.demisto.command', return_value='test-module')
@patch('WizDefend.demisto.results')
def test_main_test_module_command(mock_results, mock_command, mock_check_api, mock_token):
    from WizDefend import main

    main()

    # Check that demisto.results was called with 'ok'
    mock_results.assert_called_once_with('ok')


@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.demisto.command', return_value='unknown-command')
@patch('WizDefend.return_error')
def test_main_unknown_command(mock_return_error, mock_command, mock_token):
    from WizDefend import main

    main()

    # Check that return_error was called with the appropriate error message
    error_arg = mock_return_error.call_args[0][0]
    assert 'Unrecognized command' in error_arg


@patch('WizDefend.get_token', side_effect=Exception("Auth error"))
@patch('WizDefend.demisto.command', return_value='test-module')
@patch('WizDefend.return_error')
def test_main_auth_error(mock_return_error, mock_command, mock_token):
    from WizDefend import main

    main()

    # Check that return_error was called with the auth error
    error_arg = mock_return_error.call_args[0][0]
    assert 'Auth error' in error_arg