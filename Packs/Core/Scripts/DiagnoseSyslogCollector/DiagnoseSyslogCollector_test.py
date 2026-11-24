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

    # Mock getBrokers response
    broker_response = [
        {
            "EntryContext": {
                "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)": [
                    {
                        "DEVICE_NAME": "test-broker",
                        "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                    }
                ]
            }
        }
    ]

    # Mock runXQLQuery response (no errors)
    xql_response = [
        {
            "EntryContext": {
                "GenericXQLQuery(val.execution_id && val.execution_id == obj.execution_id)": {"status": "SUCCESS", "results": []}
            }
        }
    ]

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

    broker_response = [
        {
            "EntryContext": {
                "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)": [{"DEVICE_NAME": "test-broker", "APPS": []}]
            }
        }
    ]

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
            "EntryContext": {
                "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)": [
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
            "EntryContext": {
                "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)": [
                    {
                        "DEVICE_NAME": "test-broker",
                        "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                    }
                ]
            }
        }
    ]

    xql_response = [
        {
            "EntryContext": {
                "GenericXQLQuery(val.execution_id && val.execution_id == obj.execution_id)": {
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

    broker_response = [{"Type": 1, "EntryContext": {}}]

    mocker.patch.object(demisto, "executeCommand", return_value=broker_response)
    mocker.patch("DiagnoseSyslogCollector.is_error", return_value=False)

    with pytest.raises(DemistoException, match="not found"):
        diagnose_syslog_collector("nonexistent-broker", "24 hours")


def test_diagnose_syslog_collector_xql_query_failure(mocker):
    """
    Given: Active collector but XQL query fails
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException with the clean formatted error message
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [
        {
            "Type": 1,
            "EntryContext": {
                "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)": [
                    {
                        "DEVICE_NAME": "test-broker",
                        "APPS": [{"display_name": "Syslog Collector", "status": "active"}],
                    }
                ]
            },
        }
    ]

    error_message = "XQL query '' failed with status FAIL. Error: Query syntax error"
    xql_response = [
        {
            "Type": 4,
            "Contents": error_message,
            "EntryContext": {
                "GenericXQLQuery": {"status": "FAIL", "error_details": {"error": {"err_msg": "Query syntax error"}}}
            },
        }
    ]

    mock_execute = mocker.patch.object(demisto, "executeCommand")
    mock_execute.side_effect = [broker_response, xql_response]

    with pytest.raises(DemistoException) as e:
        diagnose_syslog_collector("test-broker", "24 hours")
    assert str(e.value) == f"Internal error while trying to query collection_auditing. {error_message}"


ACTIVE_BROKER = {"DEVICE_NAME": "test-broker", "APPS": [{"display_name": "Syslog Collector", "status": "active"}]}
BROKER_SELECTOR_KEY = "Core.Broker(val.DEVICE_NAME && val.DEVICE_NAME == obj.DEVICE_NAME)"
XQL_SELECTOR_KEY = "GenericXQLQuery(val.execution_id && val.execution_id == obj.execution_id)"


def test_diagnose_syslog_collector_builtin_commands_healthy(mocker):
    """
    Given: getBrokers and runXQLQuery built-in responses (outputs in EntryContext, empty Contents)
    When: diagnose_syslog_collector is called
    Then: The built-in commands are called with the expected args and HEALTHY status is returned
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "Contents": None, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    xql_response = [{"Type": 1, "Contents": None, "EntryContext": {XQL_SELECTOR_KEY: {"status": "SUCCESS", "results": []}}}]

    mock_execute = mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response, xql_response])

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "HEALTHY"
    assert mock_execute.call_args_list[0][0] == ("getBrokers", {"broker_vm_names": "test-broker"})
    xql_command, xql_args = mock_execute.call_args_list[1][0]
    assert xql_command == "runXQLQuery"
    assert xql_args["timeframe"] == "24 hours"
    assert xql_args["wait_for_results"] == "true"
    assert '_broker_device_name = "test-broker"' in xql_args["query"]


def test_diagnose_syslog_collector_builtin_commands_warning(mocker):
    """
    Given: runXQLQuery built-in response with collection_auditing results in EntryContext
    When: diagnose_syslog_collector is called
    Then: Returns WARNING status with the parsed results
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    results = [{"_time": "2026-03-01 11:08:30 UTC", "classification": "ERROR", "description": "Receptor unreachable."}]
    xql_response = [{"Type": 1, "EntryContext": {"GenericXQLQuery": {"status": "SUCCESS", "results": results}}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response, xql_response])

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "WARNING"
    assert result.outputs["diagnosis_report"] == ["[2026-03-01 11:08:30 UTC][ERROR] Receptor unreachable."]


def test_diagnose_syslog_collector_builtin_real_get_brokers_context_shape(mocker):
    """
    Given: The real getBrokers EntryContext shape (keys "DeviceName" and "Apps", selector on DeviceName)
    When: diagnose_syslog_collector is called
    Then: The Syslog Collector app is detected in "Apps" and HEALTHY status is returned
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker = {
        "DeviceName": "test-broker",
        "STATUS": "CONNECTED",
        "Apps": [{"app": "SYSLOG", "display_name": "Syslog Collector", "status": "Active"}],
    }
    broker_response = [{"Type": 1, "EntryContext": {"Core.Broker(val.DeviceName && val.DeviceName == obj.DeviceName)": [broker]}}]
    xql_response = [{"Type": 1, "EntryContext": {XQL_SELECTOR_KEY: {"status": "SUCCESS", "results": []}}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response, xql_response])

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs["status"] == "HEALTHY"


def test_diagnose_syslog_collector_builtin_no_brokers_found(mocker):
    """
    Given: getBrokers returns the "No brokers were found." message entry (empty EntryContext)
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException indicating the broker was not found
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "Contents": None, "HumanReadable": "No brokers were found.", "EntryContext": {}}]
    mocker.patch.object(demisto, "executeCommand", return_value=broker_response)

    with pytest.raises(DemistoException, match="Broker VM 'missing-broker' not found"):
        diagnose_syslog_collector("missing-broker", "24 hours")


def test_diagnose_syslog_collector_builtin_get_brokers_error(mocker):
    """
    Given: getBrokers returns an error entry
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException about failing to retrieve broker information
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "API Error"}])

    with pytest.raises(DemistoException, match="Failed to retrieve broker information"):
        diagnose_syslog_collector("test-broker", "24 hours")


def test_diagnose_syslog_collector_builtin_xql_fail_status(mocker):
    """
    Given: runXQLQuery returns an error entry with status FAIL, the formatted message in Contents and error_details
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException that includes the clean formatted error message
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    error_message = "XQL query '' failed with status FAIL. Error: Dataset not found"
    xql_response = [
        {
            "Type": 4,
            "Contents": error_message,
            "EntryContext": {XQL_SELECTOR_KEY: {"status": "FAIL", "error_details": {"error": {"err_msg": "Dataset not found"}}}},
        }
    ]
    mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response, xql_response])

    with pytest.raises(DemistoException) as e:
        diagnose_syslog_collector("test-broker", "24 hours")
    assert str(e.value) == f"Internal error while trying to query collection_auditing. {error_message}"


def test_diagnose_syslog_collector_builtin_xql_error_entry(mocker):
    """
    Given: runXQLQuery returns an error entry without query outputs (e.g. API error)
    When: diagnose_syslog_collector is called
    Then: Raises DemistoException about failing to execute the XQL query
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    xql_response = [{"Type": 4, "Contents": "API Error: unauthorized"}]
    mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response, xql_response])

    with pytest.raises(DemistoException, match="Failed to execute XQL query"):
        diagnose_syslog_collector("test-broker", "24 hours")


def build_xql_polling_entry(execution_id: str = "exec-1") -> dict:
    """Builds the in-progress entry runXQLQuery returns to a script (real tenant shape)."""
    polling_args = {
        "execution_id": execution_id,
        "interval_in_seconds": 2,
        "is_manual_flow": "true",
        "max_limit": "1000",
        "query": "dataset = collection_auditing",
        "timeframe": "24 hours",
        "timeout_in_seconds": 180,
        "wait_for_results": "true",
    }
    return {
        "Type": 1,
        "Contents": "",
        "HumanReadable": "Running XQL query:",
        "EntryContext": {},
        "Metadata": {"polling": True, "pollingCommand": "runXQLQuery"},
        "NextRun": "2",
        "PollingCommand": "runXQLQuery",
        "PollingItemsRemaining": 0,
        "PollingArgs": polling_args,
    }


def test_diagnose_syslog_collector_xql_polling_then_success(mocker):
    """
    Given: runXQLQuery first returns an in-progress polling entry, then SUCCESS with results
    When: diagnose_syslog_collector is called
    Then: runXQLQuery is re-called with the returned PollingArgs (execution_id) and WARNING is returned
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    results = [{"_time": "2026-03-01 11:08:30 UTC", "classification": "ERROR", "description": "Receptor unreachable."}]
    success_response = [
        {"Type": 1, "EntryContext": {XQL_SELECTOR_KEY: {"execution_id": "exec-1", "status": "SUCCESS", "results": results}}}
    ]
    mock_execute = mocker.patch.object(
        demisto, "executeCommand", side_effect=[broker_response, [build_xql_polling_entry()], success_response]
    )
    mock_sleep = mocker.patch("DiagnoseSyslogCollector.time.sleep")

    result = diagnose_syslog_collector("test-broker", "24 hours")

    assert result.outputs == {"status": "WARNING", "diagnosis_report": ["[2026-03-01 11:08:30 UTC][ERROR] Receptor unreachable."]}
    assert mock_execute.call_count == 3
    second_command, second_args = mock_execute.call_args_list[2][0]
    assert second_command == "runXQLQuery"
    assert second_args["execution_id"] == "exec-1"
    mock_sleep.assert_called_once_with(2)


def test_diagnose_syslog_collector_xql_polling_timeout(mocker):
    """
    Given: runXQLQuery keeps returning an in-progress polling entry
    When: diagnose_syslog_collector is called
    Then: Polling stops at timeout_in_seconds and a clear wrapped timeout error is raised
    """
    from DiagnoseSyslogCollector import diagnose_syslog_collector

    broker_response = [{"Type": 1, "EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER]}}]
    polling_entry = build_xql_polling_entry()
    polling_entry["PollingArgs"]["timeout_in_seconds"] = 6
    mock_execute = mocker.patch.object(demisto, "executeCommand", side_effect=[broker_response] + [[polling_entry]] * 10)
    mock_sleep = mocker.patch("DiagnoseSyslogCollector.time.sleep")

    with pytest.raises(DemistoException) as e:
        diagnose_syslog_collector("test-broker", "24 hours")

    assert str(e.value) == (
        "Internal error while trying to query collection_auditing. "
        "XQL query did not complete within 6 seconds (execution_id: exec-1)."
    )
    assert mock_sleep.call_count == 3
    assert mock_execute.call_count == 5  # getBrokers + 4 runXQLQuery calls


def test_extract_broker_list_defensive_parsing():
    """
    Given: getBrokers responses in different shapes
    When: extract_broker_list is called
    Then: Returns a list of broker dicts, or an empty list when nothing usable is found
    """
    from DiagnoseSyslogCollector import extract_broker_list

    assert extract_broker_list([{"EntryContext": {"Core.Broker": ACTIVE_BROKER}}]) == [ACTIVE_BROKER]
    assert extract_broker_list([{"EntryContext": {BROKER_SELECTOR_KEY: [ACTIVE_BROKER, "bad"]}}]) == [ACTIVE_BROKER]
    assert extract_broker_list([{"Contents": [ACTIVE_BROKER]}]) == []
    assert extract_broker_list([{"Contents": "No brokers were found.", "EntryContext": {}}]) == []
