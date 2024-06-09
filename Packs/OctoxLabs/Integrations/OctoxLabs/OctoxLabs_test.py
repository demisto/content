"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import io
import json
import pytest
import requests_mock as rm

from octoxlabs import OctoxLabs
from octoxlabs.exceptions import NotFound
from octoxlabs.models.adapter import Adapter
from OctoxLabs import convert_to_json, run_command


@pytest.fixture()
def octox_client() -> OctoxLabs:
    return OctoxLabs(ip="octoxlabs.test", token="xsoar")


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_convert_to_json():
    adapter = Adapter(
        id=1,
        name="Active Directory",
        slug="active-directory",
        description="Active directory description",
        groups=["ad"],
        beta=False,
        status=1,
    )
    data = convert_to_json(
        obj=adapter,
        keys=[
            "id",
            "name",
            "slug",
            "description",
            "groups",
            "beta",
            "status",
            "hr_status",
        ],
    )

    assert data["id"] == 1
    assert data["name"] == "Active Directory"
    assert data["slug"] == "active-directory"
    assert data["description"] == "Active directory description"
    assert data["groups"] == ["ad"]
    assert data["beta"] is False
    assert data["status"] == 1
    assert data["hr_status"] == "Done"


def test_run_command_exception(octox_client):
    with pytest.raises(Exception):
        run_command(octox=octox_client, command_name="no-command", args={})


def test_test_module(requests_mock, octox_client):
    requests_mock.get("/api/ping", json={"pong": "ok"})
    assert run_command(octox=octox_client, command_name="test-module", args={}) == "ok"


def test_get_adapters(requests_mock, octox_client):
    adapter_data = util_load_json(path="test_data/get_adapters.json")
    requests_mock.get("/adapters/adapters", json=adapter_data)

    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-adapters", args={}
    )
    data = result.outputs

    assert data["count"] == 2
    assert data["results"][0]["name"] == "Netskope"


def test_get_connections(requests_mock, octox_client):
    connections_data = util_load_json(path="test_data/get_connections.json")
    requests_mock.get("/adapters/connections", json=connections_data)

    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-connections", args={}
    )
    data = result.outputs

    assert data["count"] == 2
    assert data["results"][0]["adapter_name"] == "Active Directory"
    assert data["results"][0]["name"] == "Insecure AD"


def test_search_devices_parameters(octox_client):
    with rm.mock() as m:
        m.post("/devices/devices", json={"count": 0, "results": []})
        run_command(
            octox=octox_client,
            command_name="octoxlabs-search-devices",
            args={"fields": "Adapters, Hostname"},
        )
        run_command(
            octox=octox_client, command_name="octoxlabs-search-devices", args={}
        )

    first_request = m.request_history[0]
    first_data = first_request.json()
    assert first_data["fields"] == ["Adapters", "Hostname"]

    last_request = m.request_history[1]
    last_data = last_request.json()
    assert last_data["fields"] is None


def test_get_queries(requests_mock, octox_client):
    queries_data = util_load_json(path="test_data/get_queries.json")
    requests_mock.get("/queries/queries", json=queries_data)

    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-queries", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 1
    assert first_data["results"][0]["id"] == 142


def test_get_query_by_id(requests_mock, octox_client):
    query_data = util_load_json(path="test_data/get_query.json")
    requests_mock.get("/queries/queries/142", json=query_data)

    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-query-by-id",
        args={"query_id": 142},
    )
    data = result.outputs

    assert data["id"] == 142
    assert data["tags"] == ["cisco"]


def test_get_query_by_name(requests_mock, octox_client):
    queries_data = util_load_json(path="test_data/get_queries.json")
    requests_mock.get(
        "/queries/queries?search=error",
        json={"count": 1, "results": [{"name": "not cisco"}]},
    )
    with pytest.raises(NotFound):
        run_command(
            octox=octox_client,
            command_name="octoxlabs-get-query-by-name",
            args={"query_name": "error"},
        )

    requests_mock.get("/queries/queries?search=cisco ise machines", json=queries_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-query-by-name",
        args={"query_name": "cisco ise machines"},
    )
    data = result.outputs

    assert data["name"] == "cisco ise machines"
