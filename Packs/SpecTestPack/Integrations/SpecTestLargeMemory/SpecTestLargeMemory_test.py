import pytest
from SpecTestLargeMemory import Client, test_module, list_resources_command, process_resource_command

from CommonServerPython import DemistoException, urljoin

BASE_URL = "https://example.com/"


@pytest.fixture
def client():
    return Client(base_url=BASE_URL, verify=False, proxy=False)


class TestTestModule:
    def test_always_returns_ok(self, client):
        """test-module always returns ok for this test-only integration."""
        assert test_module(client) == "ok"


class TestListResources:
    MOCK_RESPONSE = [
        {"id": "res-1", "name": "Resource One"},
        {"id": "res-2", "name": "Resource Two"},
    ]

    def test_list_resources(self, requests_mock, client):
        requests_mock.get(urljoin(BASE_URL, "resources"), json=self.MOCK_RESPONSE)
        result = list_resources_command(client, {"limit": "10"})

        assert result.outputs_prefix == "SpecTestLargeMemory.Resource"
        assert len(result.outputs) == 2
        assert result.outputs[0]["ID"] == "res-1"
        assert result.outputs[1]["Name"] == "Resource Two"

    def test_list_resources_default_limit(self, requests_mock, client):
        requests_mock.get(urljoin(BASE_URL, "resources"), json=[])
        result = list_resources_command(client, {})

        assert result.outputs == []


class TestProcessResource:
    MOCK_RESPONSE = {
        "id": "res-1",
        "status": "completed",
        "size_bytes": 1048576,
    }

    def test_process_resource(self, requests_mock, client):
        requests_mock.post(
            urljoin(BASE_URL, "resources/res-1/process"),
            json=self.MOCK_RESPONSE,
        )
        result = process_resource_command(client, {"resource_id": "res-1"})

        assert result.outputs_prefix == "SpecTestLargeMemory.Resource"
        assert result.outputs["ID"] == "res-1"
        assert result.outputs["Status"] == "completed"
        assert result.outputs["SizeBytes"] == 1048576

    def test_process_resource_missing_id(self, client):
        with pytest.raises(DemistoException, match="resource_id is required"):
            process_resource_command(client, {})
