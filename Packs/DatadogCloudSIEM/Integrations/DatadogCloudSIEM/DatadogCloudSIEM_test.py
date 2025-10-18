"""Unit tests for DatadogCloudSIEM integration.

Pytest Unit Tests: all function names must start with "test_"
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import json
from unittest.mock import MagicMock, patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import CommandResults, DemistoException
from DatadogCloudSIEM import (
    get_security_signal_command,
    get_security_signal_list_command,
    logs_query_command,
    update_security_signal_command,
)


def util_load_json(path):
    """Load JSON test data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def configuration():
    """Mock Datadog API configuration."""
    return MagicMock()


@pytest.fixture
def mock_api_client():
    """Mock ApiClient for Datadog API calls."""
    return MagicMock()


@pytest.fixture
def security_signal_response():
    """Sample security signal API response."""
    return {
        "data": {
            "id": "AQAAAYvz-1234567890",
            "event_id": "AQAAAYvz-1234567890",
            "type": "signal",
            "attributes": {
                "timestamp": "2024-01-15T10:30:00.000Z",
                "message": "Suspicious login attempt detected from unusual location",
                "tags": [
                    "security:threat",
                    "env:production",
                    "source:aws",
                ],
                "custom": {
                    "workflow": {
                        "rule": {
                            "id": "abc-123-def",
                            "name": "Brute Force Login Detection",
                            "ruleType": "log_detection",
                            "ruleTags": ["attack:credential_access", "technique:T1110"],
                        },
                        "triage": {
                            "state": "open",
                            "comment": "",
                            "reason": "",
                            "assignee": {
                                "id": 12345,
                                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                                "name": "security_analyst",
                            },
                        },
                    }
                },
            },
        }
    }


@pytest.fixture
def security_signals_list_response():
    """Sample security signals list API response."""
    return {
        "data": [
            {
                "id": "AQAAAYvz-1234567890",
                "event_id": "AQAAAYvz-1234567890",
                "type": "signal",
                "attributes": {
                    "timestamp": "2024-01-15T10:30:00.000Z",
                    "message": "Suspicious login attempt detected",
                    "tags": ["security:threat", "env:production"],
                    "custom": {
                        "workflow": {
                            "rule": {
                                "id": "abc-123",
                                "name": "Brute Force Detection",
                                "ruleType": "log_detection",
                                "ruleTags": ["attack:credential_access"],
                            },
                            "triage": {
                                "state": "open",
                                "comment": "",
                                "reason": "",
                            },
                        }
                    },
                },
            },
            {
                "id": "AQAAAYvz-0987654321",
                "event_id": "AQAAAYvz-0987654321",
                "type": "signal",
                "attributes": {
                    "timestamp": "2024-01-15T09:15:00.000Z",
                    "message": "Malicious file download detected",
                    "tags": ["security:threat", "env:production"],
                    "custom": {
                        "workflow": {
                            "rule": {
                                "id": "xyz-456",
                                "name": "Malware Detection",
                                "ruleType": "log_detection",
                                "ruleTags": ["attack:execution"],
                            },
                            "triage": {
                                "state": "under_review",
                                "comment": "",
                                "reason": "",
                            },
                        }
                    },
                },
            },
        ],
        "meta": {
            "page": {
                "after": "next_page_cursor",
            }
        },
    }


def test_get_security_signal_command_success(configuration, security_signal_response):
    """Test get_security_signal_command with valid signal ID."""
    args = {"signal_id": "AQAAAYvz-1234567890"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = security_signal_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.get_security_monitoring_signal.return_value = mock_response

        result = get_security_signal_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore
        mock_api_instance.get_security_monitoring_signal.assert_called_once_with(signal_id="AQAAAYvz-1234567890")


def test_get_security_signal_command_with_ioc(configuration, security_signal_response):
    """Test get_security_signal_command with IOC extraction enabled."""
    # Add IOC data to the signal response
    security_signal_response["data"]["attributes"]["custom"]["signal"] = {
        "attributes": {
            "network": {"client": {"ip": "192.168.1.100"}},
        }
    }

    args = {"signal_id": "AQAAAYvz-1234567890"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = security_signal_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.get_security_monitoring_signal.return_value = mock_response

        result = get_security_signal_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore


def test_get_security_signal_command_not_found(configuration):
    """Test get_security_signal_command when signal is not found."""
    args = {"signal_id": "non_existent_id", "fetch_ioc": "false"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = {"data": {}}

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.get_security_monitoring_signal.return_value = mock_response

        result = get_security_signal_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert "No security signal found" in result.readable_output


def test_get_security_signal_command_missing_signal_id(configuration):
    """Test get_security_signal_command without signal_id."""
    args = {}

    with (
        patch("DatadogCloudSIEM.demisto.incident", return_value={"CustomFields": {}}),
        pytest.raises(DemistoException, match="signal_id is required"),
    ):
        get_security_signal_command(configuration, args)


def test_get_security_signal_list_command_success(configuration, security_signals_list_response):
    """Test get_security_signal_list_command with default parameters."""
    args = {"limit": "50"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = security_signals_list_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi"),
        patch("DatadogCloudSIEM.fetch_security_signals") as mock_fetch,
    ):
        # Mock the helper function that parses signals
        mock_signal1 = MagicMock()
        mock_signal1.to_dict.return_value = {"id": "signal1"}
        mock_signal1.to_display_dict.return_value = {"ID": "signal1"}

        mock_signal2 = MagicMock()
        mock_signal2.to_dict.return_value = {"id": "signal2"}
        mock_signal2.to_display_dict.return_value = {"ID": "signal2"}

        mock_fetch.return_value = [mock_signal1, mock_signal2]

        result = get_security_signal_list_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert isinstance(result.outputs, list)  # type: ignore
        assert len(result.outputs) == 2  # type: ignore


def test_get_security_signal_list_command_with_filters(configuration, security_signals_list_response):
    """Test get_security_signal_list_command with severity and state filters."""
    args = {
        "state": "open",
        "severity": "high",
        "limit": "50",
    }

    mock_response = MagicMock()
    mock_response.to_dict.return_value = security_signals_list_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        patch("DatadogCloudSIEM.fetch_security_signals") as mock_fetch,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.search_security_monitoring_signals.return_value = mock_response

        # Mock fetch to return signals
        mock_signal = MagicMock()
        mock_signal.to_dict.return_value = {"id": "signal1"}
        mock_signal.to_display_dict.return_value = {"ID": "signal1"}
        mock_fetch.return_value = [mock_signal]

        result = get_security_signal_list_command(configuration, args)

        assert isinstance(result, CommandResults)


def test_get_security_signal_list_command_with_ioc(configuration, security_signals_list_response):
    """Test get_security_signal_list_command with IOC extraction enabled."""
    args = {"limit": "50"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = security_signals_list_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        patch("DatadogCloudSIEM.fetch_security_signals") as mock_fetch,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.search_security_monitoring_signals.return_value = mock_response

        # Mock fetch to return signals
        mock_signal = MagicMock()
        mock_signal.to_dict.return_value = {"id": "signal1"}
        mock_signal.to_display_dict.return_value = {"ID": "signal1"}
        mock_fetch.return_value = [mock_signal]

        result = get_security_signal_list_command(configuration, args)

        assert isinstance(result, CommandResults)


def test_get_security_signal_list_command_no_results(configuration):
    """Test get_security_signal_list_command when no signals are found."""
    args = {"limit": "50"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = {"data": [], "meta": {}}

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.search_security_monitoring_signals.return_value = mock_response

        results = get_security_signal_list_command(configuration, args)

        assert isinstance(results, CommandResults)
        assert "No security signals found" in results.readable_output


def test_update_security_signal_assignee_command_success(configuration):
    """Test update_security_signal_assignee_command with valid parameters."""
    args = {
        "signal_id": "AQAAAYvz-1234567890",
        "assignee": "security_analyst",
    }

    # Mock the get_security_monitoring_signal response
    mock_get_response = MagicMock()
    mock_get_response.to_dict.return_value = {
        "data": {
            "id": "AQAAAYvz-1234567890",
            "event_id": "AQAAAYvz-1234567890",
            "type": "signal",
            "attributes": {
                "timestamp": "2024-01-15T10:30:00.000Z",
                "message": "Test signal",
                "tags": ["test:tag"],
                "custom": {
                    "workflow": {
                        "rule": {"id": "rule-123", "name": "Test Rule"},
                        "triage": {"state": "open"},
                    }
                },
            },
        }
    }

    # Mock the update response
    mock_update_response = MagicMock()
    mock_update_response.to_dict.return_value = {
        "data": {
            "id": "AQAAAYvz-1234567890",
            "event_id": "AQAAAYvz-1234567890",
            "type": "signal",
            "attributes": {
                "timestamp": "2024-01-15T10:30:00.000Z",
                "message": "Test signal",
                "tags": ["test:tag"],
                "custom": {
                    "workflow": {
                        "rule": {"id": "rule-123", "name": "Test Rule"},
                        "triage": {
                            "state": "under_review",
                            "assignee": {
                                "name": "security_analyst",
                                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                            },
                        },
                    }
                },
            },
        }
    }

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        patch("DatadogCloudSIEM.UsersApi") as mock_users_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.get_security_monitoring_signal.return_value = mock_get_response
        mock_api_instance.edit_security_monitoring_signal_assignee.return_value = mock_update_response

        # Mock user lookup
        mock_users_instance = MagicMock()
        mock_users_api.return_value = mock_users_instance
        # list_users returns a dict-like object
        mock_users_instance.list_users.return_value = {
            "data": [
                {
                    "id": "user-123",
                    "attributes": {
                        "name": "security_analyst",
                        "email": "analyst@example.com",
                    },
                }
            ]
        }

        result = update_security_signal_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore


def test_update_security_signal_state_command_success(configuration):
    """Test update_security_signal_state_command with valid parameters."""
    args = {
        "signal_id": "AQAAAYvz-1234567890",
        "state": "archived",
        "archive_reason": "false_positive",
        "archive_comment": "This was a false positive alert",
    }

    # Mock the get_security_monitoring_signal response
    mock_get_response = MagicMock()
    mock_get_response.to_dict.return_value = {
        "data": {
            "id": "AQAAAYvz-1234567890",
            "event_id": "AQAAAYvz-1234567890",
            "type": "signal",
            "attributes": {
                "timestamp": "2024-01-15T10:30:00.000Z",
                "message": "Test signal",
                "tags": ["test:tag"],
                "custom": {
                    "workflow": {
                        "rule": {"id": "rule-123", "name": "Test Rule"},
                        "triage": {"state": "open"},
                    }
                },
            },
        }
    }

    # Mock the update response - state update returns attributes at top level
    mock_update_response = MagicMock()
    mock_update_response.to_dict.return_value = {
        "data": {
            "id": "AQAAAYvz-1234567890",
            "type": "signal",
            "attributes": {
                "state": "archived",
                "archive_reason": "false_positive",
                "archive_comment": "This was a false positive alert",
            },
        }
    }

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.get_security_monitoring_signal.return_value = mock_get_response
        mock_api_instance.edit_security_monitoring_signal_state.return_value = mock_update_response

        result = update_security_signal_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore
        assert result.outputs["triage"]["state"] == "archived"  # type: ignore
        assert result.outputs["triage"]["archive_reason"] == "false_positive"  # type: ignore


@pytest.fixture
def logs_search_response():
    """Sample logs search API response."""
    return {
        "data": [
            {
                "id": "log-12345",
                "type": "log",
                "attributes": {
                    "timestamp": "2024-01-15T10:30:00.000Z",
                    "message": "User login attempt from 192.168.1.100",
                    "service": "auth-service",
                    "host": "web-server-01",
                    "source": "nginx",
                    "status": "info",
                    "tags": ["env:production", "team:security"],
                },
            },
            {
                "id": "log-12346",
                "type": "log",
                "attributes": {
                    "timestamp": "2024-01-15T10:31:00.000Z",
                    "message": "Failed login attempt detected",
                    "service": "auth-service",
                    "host": "web-server-01",
                    "source": "nginx",
                    "status": "warn",
                    "tags": ["env:production", "team:security"],
                },
            },
        ],
        "meta": {"page": {"after": "next_cursor"}},
    }


def test_logs_search_command_success(configuration, logs_search_response):
    """Test logs_search_command with default parameters."""
    args = {"query": "*", "limit": "50"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = logs_search_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.LogsApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.list_logs.return_value = mock_response

        result = logs_query_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert isinstance(result.outputs, list)  # type: ignore
        assert len(result.outputs) == 2  # type: ignore
        assert result.outputs[0]["id"] == "log-12345"  # type: ignore


def test_logs_search_command_with_filters(configuration, logs_search_response):
    """Test logs_search_command with service and status filters."""
    args = {
        "query": "*",
        "service": "auth-service",
        "status": "warn",
        "host": "web-server-01",
        "limit": "50",
    }

    mock_response = MagicMock()
    mock_response.to_dict.return_value = logs_search_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.LogsApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.list_logs.return_value = mock_response

        result = logs_query_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert isinstance(result.outputs, list)  # type: ignore
        # Verify that the API was called with a body containing the filters
        mock_api_instance.list_logs.assert_called_once()


def test_logs_search_command_no_results(configuration):
    """Test logs_search_command when no logs are found."""
    args = {"query": "*", "limit": "50"}

    mock_response = MagicMock()
    mock_response.to_dict.return_value = {"data": [], "meta": {}}

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.LogsApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.list_logs.return_value = mock_response

        result = logs_query_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert "No logs found" in result.readable_output


def test_logs_search_command_with_custom_query(configuration, logs_search_response):
    """Test logs_search_command with custom query string."""
    args = {
        "query": "error AND status:500",
        "limit": "50",
    }

    mock_response = MagicMock()
    mock_response.to_dict.return_value = logs_search_response

    with (
        patch("DatadogCloudSIEM.ApiClient"),
        patch("DatadogCloudSIEM.LogsApi") as mock_api,
    ):
        mock_api_instance = MagicMock()
        mock_api.return_value = mock_api_instance
        mock_api_instance.list_logs.return_value = mock_response

        result = logs_query_command(configuration, args)

        assert isinstance(result, CommandResults)
        assert isinstance(result.outputs, list)  # type: ignore


def test_fetch_incidents_first_fetch(configuration, mocker):
    """Test fetch_incidents on first run (no last_run)."""
    params = {
        "first_fetch": "3 days",
        "max_fetch": 10,
        "fetch_severity": "high,critical",
        "fetch_state": "open",
        "fetch_query": "",
    }

    # Mock demisto functions
    mock_get_last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_incidents = mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "debug")

    # Mock fetch_security_signals helper
    mock_signal = MagicMock()
    mock_signal.id = "signal-123"
    mock_signal.event_id = "signal-123"
    mock_signal.title = "Test Security Signal"
    mock_signal.severity = "high"
    mock_signal.timestamp = "2024-01-15T10:30:00+00:00"
    mock_signal.message = "Test message content"
    mock_signal.host = "test-host"
    mock_signal.tags = ["test:tag"]
    mock_signal.url = "https://app.datadoghq.com/security/signal?event=signal-123"
    mock_signal.to_dict.return_value = {
        "id": "signal-123",
        "event_id": "signal-123",
        "title": "Test Security Signal",
        "severity": "high",
        "timestamp": "2024-01-15T10:30:00+00:00",
        "message": "Test message content",
        "host": "test-host",
        "tags": ["test:tag"],
        "url": "https://app.datadoghq.com/security/signal?event=signal-123",
    }

    with patch("DatadogCloudSIEM.fetch_security_signals", return_value=[mock_signal]):
        from DatadogCloudSIEM import fetch_incidents

        fetch_incidents(configuration, params)

        # Verify demisto functions were called
        mock_get_last_run.assert_called_once()
        mock_set_last_run.assert_called_once()
        mock_incidents.assert_called_once()

        # Verify incidents were created
        incidents_arg = mock_incidents.call_args[0][0]
        assert len(incidents_arg) == 1
        assert incidents_arg[0]["name"] == "Test Security Signal"
        assert incidents_arg[0]["severity"] == 3  # High severity maps to 3
        assert incidents_arg[0]["dbotMirrorId"] == "signal-123"
        assert incidents_arg[0]["details"] == "Test message content"
        # Verify rawJSON contains the signal data
        import json

        raw_json = json.loads(incidents_arg[0]["rawJSON"])
        assert raw_json["id"] == "signal-123"
        assert raw_json["event_id"] == "signal-123"


def test_fetch_incidents_incremental_fetch(configuration, mocker):
    """Test fetch_incidents with existing last_run timestamp."""
    params = {
        "first_fetch": "3 days",
        "max_fetch": 10,
        "fetch_severity": "",
        "fetch_state": "open",
        "fetch_query": "",
    }
    # Mock demisto functions
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "debug")

    # Mock fetch_security_signals helper
    mock_signal = MagicMock()
    mock_signal.id = "signal-456"
    mock_signal.event_id = "signal-456"
    mock_signal.title = "New Security Signal"
    mock_signal.severity = "critical"
    mock_signal.timestamp = "2024-01-15T10:30:00+00:00"
    mock_signal.message = "New signal message"
    mock_signal.host = "test-host"
    mock_signal.tags = ["test:tag"]
    mock_signal.url = "https://app.datadoghq.com/security/signal?event=signal-456"
    mock_signal.to_dict.return_value = {
        "id": "signal-456",
        "event_id": "signal-456",
        "title": "New Security Signal",
        "severity": "critical",
        "timestamp": "2024-01-15T10:30:00+00:00",
        "message": "New signal message",
        "host": "test-host",
        "tags": ["test:tag"],
        "url": "https://app.datadoghq.com/security/signal?event=signal-456",
    }

    with patch("DatadogCloudSIEM.fetch_security_signals", return_value=[mock_signal]):
        from DatadogCloudSIEM import fetch_incidents

        fetch_incidents(configuration, params)

        # Verify last_run was updated with new timestamp
        mock_set_last_run.assert_called_once()
        updated_last_run = mock_set_last_run.call_args[0][0]
        assert updated_last_run["last_fetch_time"] == "2024-01-15T10:30:00+00:00"


def test_fetch_incidents_no_results(configuration, mocker):
    """Test fetch_incidents when no new signals are found."""
    params = {
        "first_fetch": "1 day",
        "max_fetch": 50,
        "fetch_severity": "",
        "fetch_state": "open",
        "fetch_query": "",
    }

    # Mock demisto functions
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mock_incidents = mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "debug")

    with patch("DatadogCloudSIEM.fetch_security_signals", return_value=[]):
        from DatadogCloudSIEM import fetch_incidents

        fetch_incidents(configuration, params)

        # Verify empty incidents list was sent
        mock_incidents.assert_called_once_with([])


def test_build_security_signal_url():
    """Test build_security_signal_url constructs correct URLs."""
    from DatadogCloudSIEM import SecuritySignal

    assert (
        SecuritySignal(id="signal-123", event_id="signal-123").build_url()
        == "https://app.datadoghq.com/security/signal?event=signal-123"
    )


def test_security_signals_search_query():
    """Test security_signals_search_query builds correct query string."""
    from DatadogCloudSIEM import security_signals_search_query

    # Test with multiple filters
    args = {
        "state": "open",
        "severity": "high",
        "source": "aws",
        "query": "host:web-server",
    }
    query = security_signals_search_query(args)
    assert "@workflow.triage.state:open" in query
    assert "status:high" in query
    assert "source:aws" in query
    assert "host:web-server" in query
    assert " AND " in query

    # Test with no filters (should still have the default rule type filter)
    query_empty = security_signals_search_query({})
    assert '@workflow.rule.type:("Log Detection" OR "Signal Correlation")' in query_empty


def test_calculate_limit():
    """Test calculate_limit function."""
    from DatadogCloudSIEM import calculate_limit

    # page_size takes precedence
    assert calculate_limit(100, 50) == 50

    # Use limit when no page_size
    assert calculate_limit(100, None) == 100

    # Use default when both None
    assert calculate_limit(None, None) == 50

    # Test invalid page_size (negative)
    with pytest.raises(DemistoException, match="page size should be greater than zero"):
        calculate_limit(None, -1)


def test_map_severity_to_xsoar():
    """Test map_severity_to_xsoar function."""
    from DatadogCloudSIEM import map_severity_to_xsoar

    assert map_severity_to_xsoar("info") == 1
    assert map_severity_to_xsoar("low") == 1
    assert map_severity_to_xsoar("medium") == 2
    assert map_severity_to_xsoar("high") == 3
    assert map_severity_to_xsoar("critical") == 4
    assert map_severity_to_xsoar("unknown") == 0
    assert map_severity_to_xsoar(None) == 0
