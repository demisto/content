import pytest
from SpecTestDefault import Client, test_module, list_items_command, get_item_command

from CommonServerPython import DemistoException, urljoin

BASE_URL = "https://example.com/"


@pytest.fixture
def client():
    return Client(base_url=BASE_URL, verify=False, proxy=False)


class TestTestModule:
    def test_always_returns_ok(self, client):
        """test-module always returns ok for this test-only integration."""
        assert test_module(client) == "ok"


class TestListItems:
    MOCK_RESPONSE = [
        {"id": "item-1", "name": "Item One"},
        {"id": "item-2", "name": "Item Two"},
    ]

    def test_list_items(self, requests_mock, client):
        requests_mock.get(urljoin(BASE_URL, "items"), json=self.MOCK_RESPONSE)
        result = list_items_command(client, {"limit": "10"})

        assert result.outputs_prefix == "SpecTestDefault.Item"
        assert len(result.outputs) == 2
        assert result.outputs[0]["ID"] == "item-1"
        assert result.outputs[1]["Name"] == "Item Two"

    def test_list_items_default_limit(self, requests_mock, client):
        requests_mock.get(urljoin(BASE_URL, "items"), json=[])
        result = list_items_command(client, {})

        assert result.outputs == []


class TestGetItem:
    MOCK_RESPONSE = {
        "id": "item-1",
        "name": "Item One",
        "created_at": "2026-01-01T00:00:00Z",
    }

    def test_get_item(self, requests_mock, client):
        requests_mock.get(
            urljoin(BASE_URL, "items/item-1"),
            json=self.MOCK_RESPONSE,
        )
        result = get_item_command(client, {"item_id": "item-1"})

        assert result.outputs_prefix == "SpecTestDefault.Item"
        assert result.outputs["ID"] == "item-1"
        assert result.outputs["Name"] == "Item One"
        assert result.outputs["CreatedAt"] == "2026-01-01T00:00:00Z"

    def test_get_item_missing_id(self, client):
        with pytest.raises(DemistoException, match="item_id is required"):
            get_item_command(client, {})
