import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import DemistoException
from RemedioEventCollectorEventCollector import (
    Client,
    fetch_events,
    get_events_command,
    main,
    test_module as module_test,
)


class TestClient:
    def test_get_misconfigurations_single_page(self, requests_mock):
        """Single page of results — no nextCursor."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {
                        "misconfigurationId": "abc123",
                        "title": "Test Misconfig",
                        "description": "A test",
                        "severity": "high",
                        "alertsCount": 10,
                        "devicesCount": 5,
                        "instancesCount": 2,
                        "instanceValueCategory": "version",
                        "scores": {"cvss": 7.5},
                    }
                ],
                "nextCursor": "",
            },
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = client.get_misconfigurations()
        assert len(result) == 1
        assert result[0]["misconfigurationId"] == "abc123"

    def test_get_misconfigurations_pagination(self, requests_mock):
        """Two pages of results — follows nextCursor."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            [
                {
                    "json": {
                        "data": [{"misconfigurationId": "page1"}],
                        "nextCursor": "cursor_abc",
                    }
                },
                {
                    "json": {
                        "data": [{"misconfigurationId": "page2"}],
                        "nextCursor": "",
                    }
                },
            ],
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = client.get_misconfigurations()
        assert len(result) == 2
        assert result[0]["misconfigurationId"] == "page1"
        assert result[1]["misconfigurationId"] == "page2"

    def test_get_misconfigurations_max_fetch(self, requests_mock):
        """Stops fetching when max_fetch is reached."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {"misconfigurationId": "a"},
                    {"misconfigurationId": "b"},
                    {"misconfigurationId": "c"},
                ],
                "nextCursor": "more_data",
            },
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = client.get_misconfigurations(max_fetch=2)
        assert len(result) == 2


class TestFetchEvents:
    def test_fetch_events_sends_all(self, requests_mock, mocker):
        """Full dump — all misconfigs sent to XSIAM and setLastRun called."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {
                        "misconfigurationId": "first1",
                        "title": "First Issue",
                        "description": "desc",
                        "severity": "high",
                        "alertsCount": 10,
                        "devicesCount": 5,
                        "instancesCount": 2,
                        "instanceValueCategory": "version",
                        "scores": {"cvss": 7.5},
                    },
                    {
                        "misconfigurationId": "second1",
                        "title": "Second Issue",
                        "description": "desc2",
                        "severity": "medium",
                        "alertsCount": 3,
                        "devicesCount": 2,
                        "instancesCount": 1,
                        "instanceValueCategory": "type",
                        "scores": {"cvss": 4.0},
                    },
                ],
                "nextCursor": "",
            },
        )
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")

        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        fetch_events(client, params={})

        mock_send.assert_called_once()
        assert mock_send.call_args[1]["events"] is not None
        events = mock_send.call_args[1]["events"]
        assert len(events) == 2
        assert events[0]["event_type"] == "misconfiguration"
        assert events[0]["misconfigurationId"] == "first1"
        assert events[1]["misconfigurationId"] == "second1"
        assert mock_send.call_args[1]["vendor"] == "remedio"
        assert mock_send.call_args[1]["product"] == "misconfigurations"

        mock_set_last_run.assert_called_once()
        last_run = mock_set_last_run.call_args[0][0]
        assert "last_fetch" in last_run

    def test_fetch_events_empty(self, requests_mock, mocker):
        """No misconfigs — send_events_to_xsiam not called."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={"data": [], "nextCursor": ""},
        )
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")

        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        fetch_events(client, params={})

        mock_send.assert_not_called()

    def test_fetch_events_with_max_fetch(self, requests_mock, mocker):
        """max_fetch limits results sent to XSIAM."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {
                        "misconfigurationId": "a",
                        "title": "A",
                        "description": "",
                        "severity": "low",
                        "alertsCount": 1,
                        "devicesCount": 1,
                        "instancesCount": 1,
                        "instanceValueCategory": "",
                        "scores": {"cvss": 1.0},
                    },
                    {
                        "misconfigurationId": "b",
                        "title": "B",
                        "description": "",
                        "severity": "low",
                        "alertsCount": 1,
                        "devicesCount": 1,
                        "instancesCount": 1,
                        "instanceValueCategory": "",
                        "scores": {"cvss": 1.0},
                    },
                    {
                        "misconfigurationId": "c",
                        "title": "C",
                        "description": "",
                        "severity": "low",
                        "alertsCount": 1,
                        "devicesCount": 1,
                        "instancesCount": 1,
                        "instanceValueCategory": "",
                        "scores": {"cvss": 1.0},
                    },
                ],
                "nextCursor": "more",
            },
        )
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")

        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        fetch_events(client, params={"max_fetch": "2"})

        mock_send.assert_called_once()
        events = mock_send.call_args[1]["events"]
        assert len(events) == 2

    def test_fetch_events_send_failure_reraises(self, requests_mock, mocker):
        """A send_events_to_xsiam failure is logged and re-raised."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [{"misconfigurationId": "boom", "scores": {"cvss": 1.0}}],
                "nextCursor": "",
            },
        )
        mocker.patch(
            "RemedioEventCollectorEventCollector.send_events_to_xsiam",
            side_effect=Exception("XSIAM unreachable"),
        )
        mock_debug = mocker.patch.object(demisto, "debug")

        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        with pytest.raises(Exception, match="XSIAM unreachable"):
            fetch_events(client, params={})
        mock_debug.assert_called()


class TestGetEventsCommand:
    def test_get_events_returns_command_results(self, requests_mock, mocker):
        """get-events returns CommandResults, does NOT push by default."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {
                        "misconfigurationId": "debug1",
                        "title": "Debug Issue",
                        "description": "for debugging",
                        "severity": "medium",
                        "alertsCount": 3,
                        "devicesCount": 2,
                        "instancesCount": 1,
                        "instanceValueCategory": "type",
                        "scores": {"cvss": 4.0},
                    }
                ],
                "nextCursor": "",
            },
        )
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = get_events_command(client, {"limit": "10"})
        assert hasattr(result, "readable_output")
        assert "debug1" in str(result.outputs)
        mock_send.assert_not_called()

    def test_get_events_with_push(self, requests_mock, mocker):
        """get-events pushes to XSIAM when should_push_events=true."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [
                    {
                        "misconfigurationId": "push1",
                        "title": "Push Issue",
                        "description": "test push",
                        "severity": "high",
                        "alertsCount": 5,
                        "devicesCount": 3,
                        "instancesCount": 1,
                        "instanceValueCategory": "version",
                        "scores": {"cvss": 6.0},
                    }
                ],
                "nextCursor": "",
            },
        )
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = get_events_command(client, {"limit": "10", "should_push_events": "true"})
        mock_send.assert_called_once()
        assert "push1" in str(result.outputs)


class TestTestModule:
    def test_module_success(self, requests_mock):
        """Remedio API connection succeeds."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={"data": [], "nextCursor": ""},
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        result = module_test(client)
        assert result == "ok"

    def test_module_auth_failure(self, requests_mock):
        """Remedio API returns 401."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            status_code=401,
            json={"error": "Unauthorized"},
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="bad-key",
            verify=False,
            proxy=False,
        )
        result = module_test(client)
        assert "Authorization failed" in result

    def test_module_forbidden(self, requests_mock):
        """Remedio API returns 403."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            status_code=403,
            json={"error": "Forbidden"},
        )
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="limited-key",
            verify=False,
            proxy=False,
        )
        result = module_test(client)
        assert "Forbidden" in result

    def test_module_connection_failure(self, mocker):
        """A connection-level DemistoException reports a friendly message."""
        client = Client(
            base_url="https://acme.gytpol.com/customer_api/v1",
            api_key="test-key",
            verify=False,
            proxy=False,
        )
        mocker.patch.object(
            client, "test_connection", side_effect=DemistoException("Connection error")
        )
        result = module_test(client)
        assert "Connection failed" in result


class TestMain:
    def test_main_fetch_events(self, requests_mock, mocker):
        """main() wires params into a Client and dispatches fetch-events."""
        requests_mock.post(
            "https://acme.gytpol.com/customer_api/v1/misconfigurations",
            json={
                "data": [{"misconfigurationId": "m1", "scores": {"cvss": 2.0}}],
                "nextCursor": "",
            },
        )
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://acme.gytpol.com/",
                "api_key": {"password": "test-key"},
                "insecure": True,
            },
        )
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("RemedioEventCollectorEventCollector.send_events_to_xsiam")

        main()

        mock_send.assert_called_once()
        assert mock_send.call_args[1]["events"][0]["misconfigurationId"] == "m1"

    def test_main_handles_error(self, mocker):
        """main() routes unexpected exceptions through return_error."""
        mocker.patch.object(demisto, "params", return_value={"url": "https://acme.gytpol.com"})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch("RemedioEventCollectorEventCollector.return_error")

        main()

        mock_return_error.assert_called_once()
