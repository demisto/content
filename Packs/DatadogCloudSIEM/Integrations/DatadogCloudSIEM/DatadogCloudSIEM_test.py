"""Unit tests for DatadogCloudSIEM integration.

Pytest Unit Tests: all function names must start with "test_"
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import CommandResults, DemistoException
from DatadogCloudSIEM import (
    Assignee,
    Comment,
    Log,
    SecurityRule,
    SecuritySignal,
    Triage,
    add_security_signal_comment_command,
    add_utc_offset,
    as_list,
    calculate_limit,
    convert_datetime_to_str,
    flatten_tag_map,
    get_security_rule_command,
    get_security_signal_command,
    get_security_signal_list_command,
    list_security_signal_comments_command,
    logs_query_command,
    map_severity_to_xsoar,
    module_test,
    parse_log,
    parse_security_comment,
    parse_security_rule,
    parse_security_signal,
    remove_none_values,
    security_signals_search_query,
    suppress_rule_command,
    unsuppress_rule_command,
    update_security_signal_command,
)


@pytest.fixture
def configuration():
    """Mock Datadog API configuration."""
    config = MagicMock()
    config.api_key = {"apiKeyAuth": "test_api_key", "appKeyAuth": "test_app_key"}
    return config


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
                "status": "high",
                "host": "web-server-01",
                "service": "auth-service",
                "tags": [
                    "security:threat",
                    "env:production",
                    "source:aws",
                ],
                "custom": {
                    "title": "Brute Force Login Detection",
                    "workflow": {
                        "rule": {
                            "id": "abc-123-def",
                            "name": "Brute Force Login Detection",
                            "ruleType": "log_detection",
                            "ruleTags": ["attack:credential_access", "technique:T1110"],
                        },
                        "triage": {
                            "state": "open",
                            "archiveComment": "",
                            "archiveReason": "",
                            "assignee": {
                                "id": 12345,
                                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                                "name": "security_analyst",
                                "handle": "analyst@example.com",
                            },
                        },
                    },
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
                    "status": "high",
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
                                "archiveComment": "",
                                "archiveReason": "",
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
                    "status": "critical",
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
                                "archiveComment": "",
                                "archiveReason": "",
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


# Test classes organized by command


class TestGetSecuritySignalCommand:
    """Tests for datadog-signal-get command."""

    def test_get_security_signal_command_success(self, configuration, security_signal_response):
        """Test get_security_signal_command with valid signal ID.

        Given: A valid signal ID and mocked API response
        When: The get_security_signal_command is executed
        Then: The command should return the signal data with correct ID and attributes
        """
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
            assert result.outputs["severity"] == "high"  # type: ignore
            mock_api_instance.get_security_monitoring_signal.assert_called_once_with(signal_id="AQAAAYvz-1234567890")

    def test_get_security_signal_command_not_found(self, configuration):
        """Test get_security_signal_command when signal is not found.

        Given: A non-existent signal ID
        When: The get_security_signal_command is executed
        Then: The command should return a "not found" message with empty outputs
        """
        args = {"signal_id": "non_existent_id"}

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
            assert result.outputs == {}  # type: ignore

    def test_get_security_signal_command_missing_signal_id(self, configuration):
        """Test get_security_signal_command without signal_id in args or incident context.

        Given: No signal_id provided in args and no incident context
        When: The get_security_signal_command is executed
        Then: The command should raise a DemistoException with helpful message
        """
        args = {}

        with (
            patch("DatadogCloudSIEM.demisto.incident", return_value={"CustomFields": {}}),
            pytest.raises(DemistoException, match="signal_id is required"),
        ):
            get_security_signal_command(configuration, args)

    def test_get_security_signal_command_from_incident_context(self, configuration, security_signal_response):
        """Test get_security_signal_command retrieves signal_id from incident context.

        Given: No signal_id in args but valid signal_id in incident custom fields
        When: The get_security_signal_command is executed
        Then: The command should use the signal_id from incident and return signal data
        """
        args = {}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = security_signal_response

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
            patch(
                "DatadogCloudSIEM.demisto.incident",
                return_value={"CustomFields": {"datadogsecuritysignalid": "AQAAAYvz-1234567890"}},
            ),
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_security_monitoring_signal.return_value = mock_response

            result = get_security_signal_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore

    def test_get_security_signal_command_api_error(self, configuration):
        """Test get_security_signal_command handles API errors gracefully.

        Given: A signal_id that causes an API error
        When: The get_security_signal_command is executed
        Then: The command should raise a DemistoException with error details
        """
        args = {"signal_id": "error_signal"}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
            pytest.raises(DemistoException, match="Failed to get security signal"),
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_security_monitoring_signal.side_effect = Exception("API Error")

            get_security_signal_command(configuration, args)


class TestGetSecuritySignalListCommand:
    """Tests for datadog-signal-list command."""

    def test_get_security_signal_list_command_success(self, configuration, security_signals_list_response):
        """Test get_security_signal_list_command with default parameters.

        Given: Default limit parameter and mocked API response with 2 signals
        When: The get_security_signal_list_command is executed
        Then: The command should return a list of 2 security signals with correct IDs
        """
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

    def test_get_security_signal_list_command_with_filters(self, configuration, security_signals_list_response):
        """Test get_security_signal_list_command with severity and state filters.

        Given: State and severity filter parameters
        When: The get_security_signal_list_command is executed
        Then: The command should call fetch_security_signals with correct filter query containing state and severity
        """
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
            # Verify that fetch_security_signals was called with the correct filter query
            mock_fetch.assert_called_once()
            call_kwargs = mock_fetch.call_args[1]
            filter_query = call_kwargs.get("filter_query")
            # Verify the filter query contains the expected filters
            assert "@workflow.triage.state:open" in filter_query
            assert "status:high" in filter_query

    def test_get_security_signal_list_command_no_results(self, configuration):
        """Test get_security_signal_list_command when no signals are found.

        Given: A valid request that returns no signals
        When: The get_security_signal_list_command is executed
        Then: The command should return a "no signals found" message with empty outputs
        """
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
            assert results.outputs == []  # type: ignore

    def test_get_security_signal_list_command_with_custom_query(self, configuration):
        """Test get_security_signal_list_command with custom query parameter.

        Given: A custom query string parameter
        When: The get_security_signal_list_command is executed
        Then: The command should include the custom query in the filter
        """
        args = {"query": "host:web-server-01", "limit": "10"}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi"),
            patch("DatadogCloudSIEM.fetch_security_signals") as mock_fetch,
        ):
            mock_signal = MagicMock()
            mock_signal.to_dict.return_value = {"id": "signal1"}
            mock_signal.to_display_dict.return_value = {"ID": "signal1"}
            mock_fetch.return_value = [mock_signal]

            get_security_signal_list_command(configuration, args)

            call_kwargs = mock_fetch.call_args[1]
            filter_query = call_kwargs.get("filter_query")
            assert "host:web-server-01" in filter_query

    def test_get_security_signal_list_command_invalid_sort(self, configuration):
        """Test get_security_signal_list_command with invalid sort parameter.

        Given: An invalid sort parameter (not 'asc' or 'desc')
        When: The get_security_signal_list_command is executed
        Then: The command should raise a DemistoException
        """
        args = {"sort": "invalid", "limit": "50"}

        with pytest.raises(DemistoException, match="Sort must be either 'asc' or 'desc'"):
            get_security_signal_list_command(configuration, args)

    def test_get_security_signal_list_command_with_page_size(self, configuration):
        """Test get_security_signal_list_command using page_size instead of limit.

        Given: A page_size parameter instead of limit
        When: The get_security_signal_list_command is executed
        Then: The command should use page_size as the limit
        """
        args = {"page_size": "25"}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi"),
            patch("DatadogCloudSIEM.fetch_security_signals") as mock_fetch,
        ):
            mock_fetch.return_value = []

            get_security_signal_list_command(configuration, args)

            call_kwargs = mock_fetch.call_args[1]
            assert call_kwargs["limit"] == 25


class TestUpdateSecuritySignalCommand:
    """Tests for datadog-signal-update command."""

    def test_update_security_signal_assignee_command_success(self, configuration):
        """Test update_security_signal_command with valid assignee parameter.

        Given: A valid signal ID and assignee username
        When: The update_security_signal_command is executed
        Then: The command should call the update API with correct payload, then fetch fresh signal data
        """
        args = {
            "signal_id": "AQAAAYvz-1234567890",
            "assignee": "security_analyst",
        }

        # Mock the get_security_monitoring_signal response (called AFTER update to fetch fresh data)
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
                            "triage": {
                                "state": "under_review",
                                "assignee": {
                                    "name": "security_analyst",
                                    "handle": "analyst@example.com",
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
            # The GET call happens after the update to fetch fresh data
            mock_api_instance.get_security_monitoring_signal.return_value = mock_get_response

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

            # Verify the update API was called with correct assignee payload
            mock_api_instance.edit_security_monitoring_signal_assignee.assert_called_once()
            call_args = mock_api_instance.edit_security_monitoring_signal_assignee.call_args
            assert call_args[1]["signal_id"] == "AQAAAYvz-1234567890"
            # Verify the body contains the correct assignee UUID from user lookup
            body = call_args[1]["body"]
            assert body.data.attributes.assignee.uuid == "user-123"

            # Verify that after the update, a fresh GET was called to retrieve the updated signal
            mock_api_instance.get_security_monitoring_signal.assert_called_once_with(signal_id="AQAAAYvz-1234567890")

    def test_update_security_signal_state_command_success(self, configuration):
        """Test update_security_signal_command with valid state parameter.

        Given: A valid signal ID, state, archive reason and comment
        When: The update_security_signal_command is executed
        Then: The command should update the signal state and return the updated signal with archive details
        """
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
                            "triage": {
                                "state": "archived",
                                "archiveReason": "false_positive",
                                "archiveComment": "This was a false positive alert",
                            },
                        }
                    },
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

            result = update_security_signal_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert result.outputs["id"] == "AQAAAYvz-1234567890"  # type: ignore
            assert result.outputs["triage"]["state"] == "archived"  # type: ignore
            assert result.outputs["triage"]["archive_reason"] == "false_positive"  # type: ignore

    def test_update_security_signal_both_assignee_and_state(self, configuration):
        """Test update_security_signal_command updating both assignee and state together.

        Given: A signal ID with both assignee and state parameters
        When: The update_security_signal_command is executed
        Then: The command should update both assignee and state in sequence
        """
        args = {
            "signal_id": "AQAAAYvz-1234567890",
            "assignee": "security_analyst",
            "state": "under_review",
        }

        mock_get_response = MagicMock()
        mock_get_response.to_dict.return_value = {
            "data": {
                "id": "AQAAAYvz-1234567890",
                "event_id": "AQAAAYvz-1234567890",
                "attributes": {
                    "timestamp": "2024-01-15T10:30:00.000Z",
                    "message": "Test signal",
                    "custom": {
                        "workflow": {
                            "rule": {"id": "rule-123"},
                            "triage": {
                                "state": "under_review",
                                "assignee": {
                                    "name": "security_analyst",
                                    "handle": "analyst@example.com",
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

            mock_users_instance = MagicMock()
            mock_users_api.return_value = mock_users_instance
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
            # Verify both edit methods were called
            mock_api_instance.edit_security_monitoring_signal_assignee.assert_called_once()
            mock_api_instance.edit_security_monitoring_signal_state.assert_called_once()

    def test_update_security_signal_unassign(self, configuration):
        """Test update_security_signal_command with empty assignee to unassign.

        Given: A signal ID and empty string for assignee parameter
        When: The update_security_signal_command is executed
        Then: The command should unassign the signal (empty UUID)
        """
        args = {
            "signal_id": "AQAAAYvz-1234567890",
            "assignee": "",
        }

        mock_get_response = MagicMock()
        mock_get_response.to_dict.return_value = {
            "data": {
                "id": "AQAAAYvz-1234567890",
                "event_id": "AQAAAYvz-1234567890",
                "attributes": {
                    "timestamp": "2024-01-15T10:30:00.000Z",
                    "custom": {
                        "workflow": {
                            "rule": {"id": "rule-123"},
                            "triage": {"state": "open"},
                        }
                    },
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

            result = update_security_signal_command(configuration, args)

            assert isinstance(result, CommandResults)
            # Verify assignee update was called with empty UUID
            call_args = mock_api_instance.edit_security_monitoring_signal_assignee.call_args
            body = call_args[1]["body"]
            assert body.data.attributes.assignee.uuid == ""

    def test_update_security_signal_no_parameters(self, configuration):
        """Test update_security_signal_command with no update parameters.

        Given: A signal ID but no assignee or state parameters
        When: The update_security_signal_command is executed
        Then: The command should raise a DemistoException
        """
        args = {"signal_id": "AQAAAYvz-1234567890"}

        with pytest.raises(
            DemistoException,
            match="At least one of 'assignee' or 'state' must be provided",
        ):
            update_security_signal_command(configuration, args)

    def test_update_security_signal_invalid_state(self, configuration):
        """Test update_security_signal_command with invalid state parameter.

        Given: A signal ID and invalid state value
        When: The update_security_signal_command is executed
        Then: The command should raise a DemistoException with valid states
        """
        args = {"signal_id": "AQAAAYvz-1234567890", "state": "invalid_state"}

        with pytest.raises(DemistoException, match="Invalid state"):
            update_security_signal_command(configuration, args)

    def test_update_security_signal_multiple_users_found(self, configuration):
        """Test update_security_signal_command when user lookup returns multiple results.

        Given: A signal ID and assignee that matches multiple users
        When: The update_security_signal_command is executed
        Then: The command should raise a DemistoException indicating ambiguity
        """
        args = {"signal_id": "AQAAAYvz-1234567890", "assignee": "john"}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi"),
            patch("DatadogCloudSIEM.UsersApi") as mock_users_api,
            pytest.raises(DemistoException, match="Could not determine the user to assign"),
        ):
            mock_users_instance = MagicMock()
            mock_users_api.return_value = mock_users_instance
            mock_users_instance.list_users.return_value = {
                "data": [
                    {
                        "id": "user-1",
                        "attributes": {
                            "name": "John Doe",
                            "email": "john.doe@example.com",
                        },
                    },
                    {
                        "id": "user-2",
                        "attributes": {
                            "name": "John Smith",
                            "email": "john.smith@example.com",
                        },
                    },
                ]
            }

            update_security_signal_command(configuration, args)

    def test_update_security_signal_user_not_found(self, configuration):
        """Test update_security_signal_command when user lookup returns no results.

        Given: A signal ID and assignee that matches no users
        When: The update_security_signal_command is executed
        Then: The command should raise a DemistoException
        """
        args = {"signal_id": "AQAAAYvz-1234567890", "assignee": "nonexistent"}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi"),
            patch("DatadogCloudSIEM.UsersApi") as mock_users_api,
            pytest.raises(DemistoException, match="Could not determine any user"),
        ):
            mock_users_instance = MagicMock()
            mock_users_api.return_value = mock_users_instance
            mock_users_instance.list_users.return_value = {"data": []}

            update_security_signal_command(configuration, args)


class TestGetSecurityRuleCommand:
    """Tests for datadog-rule-get command."""

    def test_get_security_rule_command_success(self, configuration):
        """Test get_security_rule_command with valid rule ID.

        Given: A valid rule ID and mocked API response
        When: The get_security_rule_command is executed
        Then: The command should return the rule data with correct ID and details
        """
        args = {"rule_id": "rule-abc-123"}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "id": "rule-abc-123",
            "name": "Brute Force Login Detection",
            "type": "log_detection",
            "isEnabled": True,
            "createdAt": "2024-01-01T00:00:00+00:00",
            "message": "Detects brute force login attempts",
            "queries": [{"query": "source:auth status:error"}],
            "tags": ["security", "authentication"],
        }

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_security_monitoring_rule.return_value = mock_response

            result = get_security_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert result.outputs["id"] == "rule-abc-123"  # type: ignore
            assert result.outputs["name"] == "Brute Force Login Detection"  # type: ignore
            assert result.outputs["type"] == "log_detection"  # type: ignore
            mock_api_instance.get_security_monitoring_rule.assert_called_once_with(rule_id="rule-abc-123")

    def test_get_security_rule_command_from_incident(self, configuration):
        """Test get_security_rule_command retrieves rule_id from incident context.

        Given: No rule_id in args but valid rule_id in incident custom fields
        When: The get_security_rule_command is executed
        Then: The command should use the rule_id from incident and return rule data
        """
        args = {}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "id": "rule-from-incident",
            "name": "Test Rule",
            "type": "log_detection",
            "isEnabled": True,
        }

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
            patch(
                "DatadogCloudSIEM.demisto.incident",
                return_value={"CustomFields": {"datadogsecuritysignalruleid": "rule-from-incident"}},
            ),
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_security_monitoring_rule.return_value = mock_response

            result = get_security_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert result.outputs["id"] == "rule-from-incident"  # type: ignore

    def test_get_security_rule_command_not_found(self, configuration):
        """Test get_security_rule_command when rule is not found.

        Given: A non-existent rule ID
        When: The get_security_rule_command is executed
        Then: The command should return a "not found" message
        """
        args = {"rule_id": "non-existent-rule"}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = {}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_security_monitoring_rule.return_value = mock_response

            result = get_security_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert "No security rule found" in result.readable_output


class TestSuppressRuleCommand:
    """Tests for datadog-rule-suppress command."""

    def test_suppress_rule_command_success(self, configuration):
        """Test suppress_rule_command with valid rule ID.

        Given: A valid rule ID and mocked API response
        When: The suppress_rule_command is executed
        Then: The command should create a suppression and return success message with URL
        """
        args = {"rule_id": "rule-abc-123"}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "data": {
                "id": "suppression-xyz-789",
                "type": "suppressions",
                "attributes": {
                    "name": "[XSOAR suppression] rule-abc-123",
                    "enabled": True,
                    "rule_query": "type:(log_detection OR signal_correlation) ruleId:rule-abc-123",
                },
            }
        }

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.create_security_monitoring_suppression.return_value = mock_response

            result = suppress_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert "Successfully created suppression for rule rule-abc-123" in result.readable_output
            assert "suppression-xyz-789" in result.readable_output
            mock_api_instance.create_security_monitoring_suppression.assert_called_once()

    def test_suppress_rule_command_with_custom_query(self, configuration):
        """Test suppress_rule_command with custom data exclusion query.

        Given: A rule ID and custom data_exclusion_query parameter
        When: The suppress_rule_command is executed
        Then: The command should create a suppression with the custom query
        """
        args = {"rule_id": "rule-abc-123", "data_exclusion_query": "host:test-server"}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "data": {
                "id": "suppression-xyz-789",
                "type": "suppressions",
                "attributes": {"enabled": True},
            }
        }

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.create_security_monitoring_suppression.return_value = mock_response

            result = suppress_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            # Verify the data_exclusion_query was passed
            call_args = mock_api_instance.create_security_monitoring_suppression.call_args
            body = call_args[1]["body"]
            assert body.data.attributes.data_exclusion_query == "host:test-server"


class TestUnsuppressRuleCommand:
    """Tests for datadog-rule-unsuppress command."""

    def test_unsuppress_rule_command_success(self, configuration):
        """Test unsuppress_rule_command with valid rule ID.

        Given: A valid rule ID with existing suppressions and mocked API responses
        When: The unsuppress_rule_command is executed
        Then: The command should disable all suppressions and return success message
        """
        args = {"rule_id": "rule-abc-123"}

        # Mock get_suppressions_affecting_rule response
        mock_get_response = MagicMock()
        mock_get_response.to_dict.return_value = {
            "data": [
                {"id": "suppression-1", "type": "suppressions"},
                {"id": "suppression-2", "type": "suppressions"},
            ]
        }

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_suppressions_affecting_rule.return_value = mock_get_response

            result = unsuppress_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert "Succesfully disabled suppressions" in result.readable_output
            assert "suppression-1" in result.readable_output
            assert "suppression-2" in result.readable_output
            # Verify update was called twice (once for each suppression)
            assert mock_api_instance.update_security_monitoring_suppression.call_count == 2

    def test_unsuppress_rule_command_no_suppressions(self, configuration):
        """Test unsuppress_rule_command when no suppressions exist.

        Given: A valid rule ID with no existing suppressions
        When: The unsuppress_rule_command is executed
        Then: The command should complete successfully with message about zero suppressions
        """
        args = {"rule_id": "rule-abc-123"}

        mock_get_response = MagicMock()
        mock_get_response.to_dict.return_value = {"data": []}

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_api,
        ):
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance
            mock_api_instance.get_suppressions_affecting_rule.return_value = mock_get_response

            result = unsuppress_rule_command(configuration, args)

            assert isinstance(result, CommandResults)
            # Verify update was never called (no suppressions to disable)
            mock_api_instance.update_security_monitoring_suppression.assert_not_called()


class TestSecuritySignalCommentCommands:
    """Tests for datadog-signal-comment-add and datadog-signal-comment-list commands."""

    def test_add_security_signal_comment_command_success(self, configuration):
        """Test add_security_signal_comment_command with valid parameters.

        Given: A valid event ID and comment text with mocked API response
        When: The add_security_signal_comment_command is executed
        Then: The command should add the comment and return the comment data with user information
        """
        args = {
            "event_id": "AQAAAYvz-1234567890",
            "comment": "Investigating this security signal",
        }

        # Mock requests.post response
        mock_requests_response = MagicMock()
        mock_requests_response.ok = True
        mock_requests_response.json.return_value = {
            "data": {
                "id": "comment-123",
                "attributes": {
                    "comment_id": "comment-123",
                    "created_at": "2024-01-15T10:30:00+00:00",
                    "user_uuid": "user-uuid-123",
                    "text": "Investigating this security signal",
                },
            }
        }

        # Mock UsersApi response for user lookup
        mock_user_response = MagicMock()
        mock_user_response.to_dict.return_value = {
            "data": {
                "id": "user-uuid-123",
                "attributes": {
                    "name": "John Doe",
                    "handle": "john.doe@example.com",
                },
            }
        }

        with (
            patch("DatadogCloudSIEM.requests.post", return_value=mock_requests_response),
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.UsersApi") as mock_users_api,
        ):
            mock_users_instance = MagicMock()
            mock_users_api.return_value = mock_users_instance
            mock_users_instance.get_user.return_value = mock_user_response

            result = add_security_signal_comment_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert result.outputs["id"] == "comment-123"  # type: ignore
            assert result.outputs["text"] == "Investigating this security signal"  # type: ignore
            assert result.outputs["user"]["name"] == "John Doe"  # type: ignore

    def test_add_security_signal_comment_command_missing_comment(self, configuration):
        """Test add_security_signal_comment_command without comment text.

        Given: An event ID but no comment text
        When: The add_security_signal_comment_command is executed
        Then: The command should raise a DemistoException
        """
        args = {"event_id": "AQAAAYvz-1234567890"}

        with pytest.raises(DemistoException, match="comment is required"):
            add_security_signal_comment_command(configuration, args)

    def test_add_security_signal_comment_command_api_error(self, configuration):
        """Test add_security_signal_comment_command when API request fails.

        Given: Valid parameters but API request fails
        When: The add_security_signal_comment_command is executed
        Then: The command should raise a DemistoException with API error details
        """
        args = {"event_id": "AQAAAYvz-1234567890", "comment": "Test comment"}

        mock_requests_response = MagicMock()
        mock_requests_response.ok = False
        mock_requests_response.status_code = 403
        mock_requests_response.text = "Forbidden"

        with (
            patch("DatadogCloudSIEM.requests.post", return_value=mock_requests_response),
            pytest.raises(DemistoException, match="API request failed with status 403"),
        ):
            add_security_signal_comment_command(configuration, args)

    def test_list_security_signal_comments_command_success(self, configuration):
        """Test list_security_signal_comments_command with valid event ID.

        Given: A valid event ID and mocked API response with 2 comments
        When: The list_security_signal_comments_command is executed
        Then: The command should return a list of 2 comments with user information resolved
        """
        args = {"event_id": "AQAAAYvz-1234567890"}

        # Mock requests.get response
        mock_requests_response = MagicMock()
        mock_requests_response.json.return_value = {
            "data": [
                {
                    "id": "comment-123",
                    "attributes": {
                        "comment_id": "comment-123",
                        "created_at": "2024-01-15T10:30:00+00:00",
                        "user_uuid": "user-uuid-123",
                        "text": "First comment",
                    },
                },
                {
                    "id": "comment-456",
                    "attributes": {
                        "comment_id": "comment-456",
                        "created_at": "2024-01-15T11:00:00+00:00",
                        "user_uuid": "user-uuid-456",
                        "text": "Second comment",
                    },
                },
            ]
        }

        # Mock UsersApi responses for user lookups
        mock_user1_response = MagicMock()
        mock_user1_response.to_dict.return_value = {
            "data": {
                "id": "user-uuid-123",
                "attributes": {
                    "name": "John Doe",
                    "handle": "john.doe@example.com",
                },
            }
        }

        mock_user2_response = MagicMock()
        mock_user2_response.to_dict.return_value = {
            "data": {
                "id": "user-uuid-456",
                "attributes": {
                    "name": "Jane Smith",
                    "handle": "jane.smith@example.com",
                },
            }
        }

        with (
            patch("DatadogCloudSIEM.requests.get", return_value=mock_requests_response),
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.UsersApi") as mock_users_api,
        ):
            mock_users_instance = MagicMock()
            mock_users_api.return_value = mock_users_instance
            # Return different user data based on which UUID is requested
            mock_users_instance.get_user.side_effect = [
                mock_user1_response,
                mock_user2_response,
            ]

            result = list_security_signal_comments_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert isinstance(result.outputs, list)  # type: ignore
            assert len(result.outputs) == 2  # type: ignore
            assert result.outputs[0]["id"] == "comment-123"  # type: ignore
            assert result.outputs[0]["text"] == "First comment"  # type: ignore
            assert result.outputs[1]["id"] == "comment-456"  # type: ignore

    def test_list_security_signal_comments_command_no_comments(self, configuration):
        """Test list_security_signal_comments_command when no comments exist.

        Given: A valid event ID with no comments
        When: The list_security_signal_comments_command is executed
        Then: The command should return a "no comments found" message
        """
        args = {"event_id": "AQAAAYvz-1234567890"}

        mock_requests_response = MagicMock()
        mock_requests_response.json.return_value = {"data": []}

        with (
            patch("DatadogCloudSIEM.requests.get", return_value=mock_requests_response),
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.UsersApi"),
        ):
            result = list_security_signal_comments_command(configuration, args)

            assert isinstance(result, CommandResults)
            assert "No comments found" in result.readable_output
            assert result.outputs == []  # type: ignore


class TestLogsQueryCommand:
    """Tests for datadog-logs-query command."""

    @pytest.fixture
    def logs_query_response(self):
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

    def test_logs_query_command_success(self, configuration, logs_query_response):
        """Test logs_query_command with default parameters.

        Given: A basic query and limit parameter with mocked API response containing 2 logs
        When: The logs_query_command is executed
        Then: The command should return a list of 2 logs with correct IDs and verify query is passed to API
        """
        args = {"query": "*", "limit": "50"}

        mock_response = MagicMock()
        mock_response.to_dict.return_value = logs_query_response

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

            # Verify that the API was called with the correct query in the body
            mock_api_instance.list_logs.assert_called_once()
            call_args = mock_api_instance.list_logs.call_args
            body = call_args[1]["body"]
            assert body.filter.query == "*"

    def test_logs_query_command_with_filters(self, configuration, logs_query_response):
        """Test logs_query_command with complex query filters.

        Given: A complex query string with service and status filters
        When: The logs_query_command is executed
        Then: The command should call list_logs API with the exact query string in the body
        """
        args = {
            "query": "service:auth-service status:warn host:web-server-01",
            "limit": "50",
        }

        mock_response = MagicMock()
        mock_response.to_dict.return_value = logs_query_response

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
            # Verify that the API was called with the correct query in the body
            mock_api_instance.list_logs.assert_called_once()
            call_args = mock_api_instance.list_logs.call_args
            body = call_args[1]["body"]
            assert body.filter.query == "service:auth-service status:warn host:web-server-01"

    def test_logs_query_command_no_results(self, configuration):
        """Test logs_query_command when no logs are found.

        Given: A valid query that returns no logs
        When: The logs_query_command is executed
        Then: The command should return a "no logs found" message
        """
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

    def test_logs_query_command_from_incident_rule(self, configuration, logs_query_response):
        """Test logs_query_command without query parameter, using rule from incident.

        Given: No query parameter but valid rule_id in incident context
        When: The logs_query_command is executed
        Then: The command should extract query from the rule and use it for log search
        """
        args = {}

        mock_rule_response = MagicMock()
        mock_rule_response.to_dict.return_value = {
            "id": "rule-123",
            "name": "Test Rule",
            "type": "log_detection",
            "isEnabled": True,
            "queries": [{"query": "source:nginx status:error"}],
        }

        mock_logs_response = MagicMock()
        mock_logs_response.to_dict.return_value = logs_query_response

        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.SecurityMonitoringApi") as mock_security_api,
            patch("DatadogCloudSIEM.LogsApi") as mock_logs_api,
            patch(
                "DatadogCloudSIEM.demisto.incident",
                return_value={"CustomFields": {"datadogsecuritysignalruleid": "rule-123"}},
            ),
        ):
            mock_security_instance = MagicMock()
            mock_security_api.return_value = mock_security_instance
            mock_security_instance.get_security_monitoring_rule.return_value = mock_rule_response

            mock_logs_instance = MagicMock()
            mock_logs_api.return_value = mock_logs_instance
            mock_logs_instance.list_logs.return_value = mock_logs_response

            result = logs_query_command(configuration, args)

            assert isinstance(result, CommandResults)
            # Verify rule was fetched and query was extracted
            mock_security_instance.get_security_monitoring_rule.assert_called_once_with(rule_id="rule-123")
            # Verify logs were queried with extracted query
            call_args = mock_logs_instance.list_logs.call_args
            body = call_args[1]["body"]
            assert body.filter.query == "source:nginx status:error"

    def test_logs_query_command_no_query_no_incident(self, configuration):
        """Test logs_query_command without query and without incident context.

        Given: No query parameter and no incident context
        When: The logs_query_command is executed
        Then: The command should raise a DemistoException
        """
        args = {}

        with (
            patch("DatadogCloudSIEM.demisto.incident", return_value={"CustomFields": {}}),
            pytest.raises(DemistoException, match="query is required"),
        ):
            logs_query_command(configuration, args)


class TestFetchIncidents:
    """Tests for fetch-incidents functionality."""

    def test_fetch_incidents_first_fetch(self, configuration, mocker):
        """Test fetch_incidents on first run (no last_run).

        Given: First fetch with no previous last_run timestamp
        When: fetch_incidents is executed
        Then: Incidents should be created and last_run should be updated with signal timestamp
        """
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

    def test_fetch_incidents_incremental_fetch(self, configuration, mocker):
        """Test fetch_incidents with existing last_run timestamp.

        Given: Existing last_run with previous fetch timestamp
        When: fetch_incidents is executed
        Then: New incidents should be fetched from the last timestamp and last_run should be updated
        """
        params = {
            "first_fetch": "3 days",
            "max_fetch": 10,
            "fetch_severity": "",
            "fetch_state": "open",
            "fetch_query": "",
        }
        # Mock demisto functions - simulate incremental fetch with previous timestamp
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={"last_fetch_time": "2024-01-14T10:00:00+00:00"},
        )
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

    def test_fetch_incidents_no_results(self, configuration, mocker):
        """Test fetch_incidents when no new signals are found during incremental fetch.

        Given: An incremental fetch request with existing last_run that returns no new signals
        When: fetch_incidents is executed
        Then: An empty incidents list should be sent to XSOAR and last_run should not change
        """
        params = {
            "first_fetch": "1 day",
            "max_fetch": 50,
            "fetch_severity": "",
            "fetch_state": "open",
            "fetch_query": "",
        }

        # Mock demisto functions - simulate incremental fetch with previous timestamp
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={"last_fetch_time": "2024-01-14T10:00:00+00:00"},
        )
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_incidents = mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "debug")

        with patch("DatadogCloudSIEM.fetch_security_signals", return_value=[]):
            from DatadogCloudSIEM import fetch_incidents

            fetch_incidents(configuration, params)

            # Verify empty incidents list was sent
            mock_incidents.assert_called_once_with([])
            # Verify last_run was not updated (no new incidents)
            mock_set_last_run.assert_not_called()

    def test_fetch_incidents_first_fetch_no_results(self, configuration, mocker):
        """Test fetch_incidents on first run with no results.

        Given: First fetch with no previous last_run timestamp and no signals returned
        When: fetch_incidents is executed
        Then: Empty incidents list should be sent and last_run should be set to from_datetime
        """
        params = {
            "first_fetch": "1 day",
            "max_fetch": 50,
            "fetch_severity": "",
            "fetch_state": "open",
            "fetch_query": "",
        }

        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_incidents = mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "debug")

        with patch("DatadogCloudSIEM.fetch_security_signals", return_value=[]):
            from DatadogCloudSIEM import fetch_incidents

            fetch_incidents(configuration, params)

            # Verify empty incidents list was sent
            mock_incidents.assert_called_once_with([])
            # Verify last_run was set even with no incidents (first run)
            mock_set_last_run.assert_called_once()


# Helper functions and dataclass tests


class TestHelperFunctions:
    """Tests for helper utility functions."""

    def test_remove_none_values(self):
        """Test remove_none_values recursively removes None values.

        Given: A nested dictionary with None values at various levels
        When: remove_none_values is called
        Then: All None values should be removed while preserving non-None values
        """
        data = {
            "key1": "value1",
            "key2": None,
            "key3": {
                "nested1": "value",
                "nested2": None,
                "nested3": {"deep": None, "keep": "value"},
            },
            "key4": [{"item1": "value", "item2": None}, None, "string"],
        }

        result = remove_none_values(data)

        assert "key1" in result
        assert "key2" not in result
        assert "nested2" not in result["key3"]
        assert "deep" not in result["key3"]["nested3"]
        assert "keep" in result["key3"]["nested3"]
        assert len(result["key4"]) == 2
        assert "item2" not in result["key4"][0]

    def test_add_utc_offset(self):
        """Test add_utc_offset adds UTC timezone to datetime string.

        Given: An ISO format datetime string without timezone
        When: add_utc_offset is called
        Then: The datetime string should have +00:00 UTC offset appended
        """
        dt_str = "2024-01-15T10:30:00"
        result = add_utc_offset(dt_str)

        assert "+00:00" in result or "Z" in result
        assert "2024-01-15" in result
        assert "10:30:00" in result

    def test_convert_datetime_to_str(self):
        """Test convert_datetime_to_str converts datetime objects to ISO strings.

        Given: A dictionary containing datetime objects
        When: convert_datetime_to_str is called
        Then: All datetime objects should be converted to ISO format strings
        """
        dt = datetime(2024, 1, 15, 10, 30, 0)
        data = {"timestamp": dt, "nested": {"date": dt}, "string": "keep me"}

        result = convert_datetime_to_str(data)

        assert isinstance(result["timestamp"], str)
        assert "2024-01-15" in result["timestamp"]
        assert isinstance(result["nested"]["date"], str)
        assert result["string"] == "keep me"

    def test_as_list(self):
        """Test as_list converts various inputs to list format.

        Given: Various input types (None, single value, list)
        When: as_list is called
        Then: Correct list representation should be returned
        """
        assert as_list(None) == []
        assert as_list("single") == ["single"]
        assert as_list([1, 2, 3]) == [1, 2, 3]
        assert as_list(42) == [42]

    def test_flatten_tag_map(self):
        """Test flatten_tag_map converts tag dictionary to key:value strings.

        Given: A dictionary with various value types (string, list)
        When: flatten_tag_map is called
        Then: A flat list of "key:value" strings should be returned
        """
        tag_map = {"env": "prod", "team": ["security", "ops"], "version": 1}

        result = flatten_tag_map(tag_map)

        assert "env:prod" in result
        assert "team:security" in result
        assert "team:ops" in result
        assert "version:1" in result
        assert len(result) == 4

    def test_security_signals_search_query(self):
        """Test security_signals_search_query builds correct query string.

        Given: Arguments with various filter parameters (state, severity, source, query)
        When: security_signals_search_query is called
        Then: A properly formatted Datadog search query string should be returned with all filters
        """
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

    def test_calculate_limit(self):
        """Test calculate_limit function.

        Given: Various combinations of limit and page_size parameters
        When: calculate_limit is called
        Then: The correct limit value should be returned with proper precedence rules
        """
        # page_size takes precedence
        assert calculate_limit(100, 50) == 50

        # Use limit when no page_size
        assert calculate_limit(100, None) == 100

        # Use default when both None
        assert calculate_limit(None, None) == 50

        # Test page_size of zero falls through to default (0 is falsy in Python)
        assert calculate_limit(None, 0) == 50

        # Test invalid page_size (negative)
        with pytest.raises(DemistoException, match="page size should be greater than zero"):
            calculate_limit(None, -1)

    def test_map_severity_to_xsoar(self):
        """Test map_severity_to_xsoar function.

        Given: Various Datadog severity levels (info, low, medium, high, critical, unknown, None)
        When: map_severity_to_xsoar is called
        Then: The correct XSOAR severity number should be returned for each level
        """
        assert map_severity_to_xsoar("info") == 1
        assert map_severity_to_xsoar("low") == 1
        assert map_severity_to_xsoar("medium") == 2
        assert map_severity_to_xsoar("high") == 3
        assert map_severity_to_xsoar("critical") == 4
        assert map_severity_to_xsoar("unknown") == 0
        assert map_severity_to_xsoar(None) == 0
        assert map_severity_to_xsoar("") == 0


class TestParsingFunctions:
    """Tests for parsing functions."""

    def test_parse_security_comment(self):
        """Test parse_security_comment extracts comment data correctly.

        Given: Raw comment data from Datadog API
        When: parse_security_comment is called
        Then: A Comment object with correct attributes should be returned
        """
        data = {
            "id": "comment-123",
            "attributes": {
                "comment_id": "comment-456",
                "created_at": "2024-01-15T10:30:00+00:00",
                "user_uuid": "user-uuid-123",
                "text": "Test comment",
            },
        }

        comment = parse_security_comment(data)

        assert isinstance(comment, Comment)
        assert comment.id == "comment-123"
        assert comment.created_at == "2024-01-15T10:30:00+00:00"
        assert comment.user_uuid == "user-uuid-123"
        assert comment.text == "Test comment"

    def test_parse_security_rule(self):
        """Test parse_security_rule extracts rule data correctly.

        Given: Raw rule data from Datadog API
        When: parse_security_rule is called
        Then: A SecurityRule object with correct attributes should be returned
        """
        data = {
            "id": "rule-123",
            "name": "Test Rule",
            "type": "log_detection",
            "isEnabled": True,
            "createdAt": "2024-01-01T00:00:00+00:00",
            "queries": [{"query": "source:nginx"}],
            "tags": ["security", "auth"],
        }

        rule = parse_security_rule(data)

        assert isinstance(rule, SecurityRule)
        assert rule.id == "rule-123"
        assert rule.name == "Test Rule"
        assert rule.type == "log_detection"
        assert rule.is_enabled is True
        assert len(rule.tags) == 2  # type: ignore

    def test_parse_security_signal(self, security_signal_response):
        """Test parse_security_signal extracts signal data correctly.

        Given: Raw signal data from Datadog API with nested workflow and triage
        When: parse_security_signal is called
        Then: A SecuritySignal object with correct nested attributes should be returned
        """
        signal = parse_security_signal(security_signal_response["data"])

        assert isinstance(signal, SecuritySignal)
        assert signal.id == "AQAAAYvz-1234567890"
        assert signal.event_id == "AQAAAYvz-1234567890"
        assert signal.severity == "high"
        assert signal.title == "Brute Force Login Detection"
        assert signal.triage is not None
        assert signal.triage.state == "open"
        assert signal.triage.assignee is not None
        assert signal.triage.assignee.name == "security_analyst"
        assert signal.rule_id == "abc-123-def"

    def test_parse_log(self):
        """Test parse_log extracts log data correctly.

        Given: Raw log data from Datadog API
        When: parse_log is called
        Then: A Log object with correct attributes should be returned
        """
        data = {
            "id": "log-123",
            "attributes": {
                "timestamp": "2024-01-15T10:30:00.000Z",
                "message": "Test log message",
                "service": "web-service",
                "host": "server-01",
                "source": "nginx",
                "status": "info",
                "tags": ["env:prod", "team:ops"],
            },
        }

        log = parse_log(data)

        assert isinstance(log, Log)
        assert log.id == "log-123"
        assert log.message == "Test log message"
        assert log.service == "web-service"
        assert log.host == "server-01"
        assert len(log.tags) == 2  # type: ignore


class TestDataclassMethods:
    """Tests for dataclass methods (to_dict, to_display_dict, build_url)."""

    def test_security_signal_build_url(self):
        """Test SecuritySignal.build_url constructs correct URLs.

        Given: A SecuritySignal object with a signal ID
        When: build_url method is called
        Then: A properly formatted Datadog security signal URL should be returned
        """
        signal = SecuritySignal(id="signal-123", event_id="signal-123")
        url = signal.build_url()

        assert url == "https://app.datadoghq.com/security/signal?event=signal-123"

    def test_security_signal_to_dict(self):
        """Test SecuritySignal.to_dict converts signal to dictionary.

        Given: A SecuritySignal object with nested triage and assignee
        When: to_dict method is called
        Then: A properly formatted dictionary with all fields should be returned
        """
        triage = Triage(
            state="open",
            archive_comment="",
            archive_reason="",
            assignee=Assignee("John", "john@example.com"),
        )
        signal = SecuritySignal(
            id="signal-123",
            event_id="event-123",
            severity="high",
            title="Test Signal",
            rule_id="rule-123",
            triage=triage,
        )

        result = signal.to_dict()

        assert result["id"] == "signal-123"
        assert result["severity"] == "high"
        assert result["triage"]["state"] == "open"
        assert result["triage"]["assignee"]["name"] == "John"
        assert result["rule"]["id"] == "rule-123"

    def test_security_rule_extract_query(self):
        """Test SecurityRule.extract_query combines multiple queries with OR.

        Given: A SecurityRule with multiple query objects
        When: extract_query method is called
        Then: Queries should be combined with OR operator
        """
        rule = SecurityRule(
            id="rule-123",
            name="Test",
            type="log_detection",
            is_enabled=True,
            queries=[{"query": "source:nginx"}, {"query": "source:apache"}],
        )

        query = rule.extract_query()

        assert query == "(source:nginx) OR (source:apache)"

    def test_security_rule_extract_query_single(self):
        """Test SecurityRule.extract_query with single query returns query directly.

        Given: A SecurityRule with one query object
        When: extract_query method is called
        Then: The single query string should be returned without OR
        """
        rule = SecurityRule(
            id="rule-123",
            name="Test",
            type="log_detection",
            is_enabled=True,
            queries=[{"query": "source:nginx"}],
        )

        query = rule.extract_query()

        assert query == "source:nginx"

    def test_security_rule_extract_query_no_queries(self):
        """Test SecurityRule.extract_query with no queries returns wildcard.

        Given: A SecurityRule with no queries
        When: extract_query method is called
        Then: A wildcard "*" should be returned
        """
        rule = SecurityRule(
            id="rule-123",
            name="Test",
            type="log_detection",
            is_enabled=True,
            queries=[],
        )

        query = rule.extract_query()

        assert query == "*"

    def test_log_to_dict(self):
        """Test Log.to_dict converts log to dictionary.

        Given: A Log object with timestamp and tags
        When: to_dict method is called
        Then: A properly formatted dictionary should be returned
        """
        log = Log(
            id="log-123",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            message="Test message",
            service="web-service",
            tags=["env:prod"],
        )

        result = log.to_dict()

        assert result["id"] == "log-123"
        assert "2024-01-15" in result["timestamp"]
        assert result["message"] == "Test message"
        assert result["service"] == "web-service"
        assert len(result["tags"]) == 1

    def test_log_build_url(self):
        """Test Log.build_url constructs correct log URLs.

        Given: A Log object with log ID
        When: build_url method is called
        Then: A properly formatted Datadog log URL should be returned
        """
        log = Log(id="log-123")
        url = log.build_url()

        assert url == "https://app.datadoghq.com/logs?event=log-123"

    def test_comment_to_dict(self):
        """Test Comment.to_dict converts comment to dictionary.

        Given: A Comment object with user information
        When: to_dict method is called
        Then: A properly formatted dictionary with user sub-object should be returned
        """
        comment = Comment(
            id="comment-123",
            created_at="2024-01-15T10:30:00+00:00",
            user_uuid="user-123",
            text="Test comment",
            user_name="John Doe",
            user_handle="john@example.com",
        )

        result = comment.to_dict()

        assert result["id"] == "comment-123"
        assert result["text"] == "Test comment"
        assert result["user"]["name"] == "John Doe"
        assert result["user"]["handle"] == "john@example.com"


class TestModuleTest:
    """Tests for test-module command."""

    def test_module_test_success(self, configuration):
        """Test module_test with valid authentication.

        Given: Valid API configuration
        When: module_test is executed
        Then: Should return "ok" indicating successful authentication
        """
        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.AuthenticationApi") as mock_auth_api,
        ):
            mock_auth_instance = MagicMock()
            mock_auth_api.return_value = mock_auth_instance
            mock_auth_instance.validate.return_value = None

            result = module_test(configuration)

            assert result == "ok"
            mock_auth_instance.validate.assert_called_once()

    def test_module_test_authentication_error(self, configuration):
        """Test module_test with invalid authentication.

        Given: Invalid API configuration
        When: module_test is executed
        Then: Should return authentication error message
        """
        with (
            patch("DatadogCloudSIEM.ApiClient"),
            patch("DatadogCloudSIEM.AuthenticationApi") as mock_auth_api,
        ):
            mock_auth_instance = MagicMock()
            mock_auth_api.return_value = mock_auth_instance
            mock_auth_instance.validate.side_effect = Exception("Invalid API Key")

            result = module_test(configuration)

            assert "Authentication Error" in result
