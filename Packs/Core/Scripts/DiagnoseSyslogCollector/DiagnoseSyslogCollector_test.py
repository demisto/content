import pytest
import demistomock as demisto
from CommonServerPython import DemistoException


def test_diagnose_syslog_collector_healthy_status(mocker):
    """
    Given: Broker with active Syslog Collector and no errors in XQL query
    When: diagnose_syslog_collector is called
    Then: Returns HEALTHY status with success message
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    # Mock core-list-brokers response
    broker_response = [
        {
            "Contents": [
                {
                    "DEVICE_NAME": "test-broker",
                    "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                }
            ]
        }
    ]

    # Mock core-xql-generic-query-platform response (no errors)
    xql_response = [{"Contents": {"status": "SUCCESS", "results": []}}]

    mock_execute = mocker.patch.object(demisto, "executeCommand")
    mock_execute.side_effect = [broker_response, xql_response]
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "HEALTHY"
    assert any("no errors" in item for item in result.outputs["diagnosis_report"])
    assert mock_execute.call_count == 2


def test_diagnose_syslog_collector_collector_not_configured(mocker):
    """
    Given: Broker without Syslog Collector app
    When: diagnose_syslog_collector is called
    Then: Returns ERROR status indicating collector not configured
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Contents": [{"DEVICE_NAME": "test-broker", "APPS": []}]}]

    mock_execute = mocker.patch.object(demisto, "executeCommand", return_value=broker_response)
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "ERROR"
    assert any("not configured" in item for item in result.outputs["diagnosis_report"])
    assert mock_execute.call_count == 1  # Only broker query, no XQL query


def test_diagnose_syslog_collector_inactive_with_errors(mocker):
    """
    Given: Broker with inactive Syslog Collector and error/warning reasons
    When: diagnose_syslog_collector is called
    Then: Returns ERROR status with detailed error messages
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [
        {
            "Contents": [
                {
                    "DEVICE_NAME": "test-broker",
                    "APPS": [
                        {
                            "display_name": "Syslog Collector",
                            "status": "inactive",
                            "reasons": {
                                "errors": ["Connection failed", "Port unavailable"],
                                "warnings": ["High latency"],
                            },
                        }
                    ],
                }
            ]
        }
    ]

    mocker.patch.object(demisto, "executeCommand", return_value=broker_response)
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "ERROR"
    assert any("[ERROR] Connection failed" in item for item in result.outputs["diagnosis_report"])
    assert any("[ERROR] Port unavailable" in item for item in result.outputs["diagnosis_report"])
    assert any("[WARNING] High latency" in item for item in result.outputs["diagnosis_report"])


def test_diagnose_syslog_collector_active_with_warnings(mocker):
    """
    Given: Active collector with errors/warnings in collection_auditing
    When: diagnose_syslog_collector is called
    Then: Returns WARNING status with deduplicated error messages including timestamps
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [
        {
            "Contents": [
                {
                    "DEVICE_NAME": "test-broker",
                    "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                }
            ]
        }
    ]

    xql_response = [
        {
            "Contents": {
                "status": "SUCCESS",
                "results": [
                    {
                        "_time": "2026-03-01 11:06:42 UTC",
                        "classification": "WARNING",
                        "description": (
                            "Failed to process the packet due to a missing length header. "
                            "The packet does not conform to the expected octet-framing format."
                        ),
                    },
                    {
                        "_time": "2026-03-01 11:07:15 UTC",
                        "classification": "WARNING",
                        "description": "Log parsing failed due to an unexpected format.",
                    },
                    {
                        "_time": "2026-03-01 11:08:30 UTC",
                        "classification": "ERROR",
                        "description": "Unable to connect to the receptor for data transmission.",
                    },
                    {
                        "_time": "2026-03-01 11:09:00 UTC",
                        "classification": "WARNING",
                        "description": (
                            "Failed to process the packet due to a missing length header. "
                            "The packet does not conform to the expected octet-framing format."
                        ),
                    },  # Duplicate
                ],
            }
        }
    ]

    mock_execute = mocker.patch.object(demisto, "executeCommand")
    mock_execute.side_effect = [broker_response, xql_response]
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "WARNING"
    diagnosis = result.outputs["diagnosis_report"]
    # Verify deduplication
    assert sum(1 for item in diagnosis if "Failed to process the packet due to a missing length header" in item) == 1
    assert any("[WARNING] Log parsing failed due to an unexpected format." in item for item in diagnosis)
    assert any("[ERROR] Unable to connect to the receptor for data transmission." in item for item in diagnosis)
    # Verify timestamps are included
    assert any("2026-03-01 11:06:42 UTC" in item or "2026-03-01 11:09:00 UTC" in item for item in diagnosis)


def test_diagnose_syslog_collector_broker_not_found(mocker):
    """
    Given: Broker name that doesn't exist
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Contents": []}]

    mocker.patch.object(demisto, "executeCommand", return_value=broker_response)
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    with pytest.raises(DemistoException, match="not found"):
        diagnose_syslog_collector("nonexistent-broker", "24 hours")


def test_diagnose_syslog_collector_xql_query_failure(mocker):
    """
    Given: Active collector but XQL query fails
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException with error details
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [
        {
            "Contents": [
                {
                    "DEVICE_NAME": "test-broker",
                    "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                }
            ]
        }
    ]

    xql_response = [{"Contents": {"status": "FAIL", "error_details": "Query syntax error"}}]

    mock_execute = mocker.patch.object(demisto, "executeCommand")
    mock_execute.side_effect = [broker_response, xql_response]
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    with pytest.raises(DemistoException, match="Internal error while trying to query collection_auditing"):
        diagnose_syslog_collector("test-broker", "24 hours")
