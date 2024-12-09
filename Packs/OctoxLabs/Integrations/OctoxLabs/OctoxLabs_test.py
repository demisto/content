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
from OctoxLabs import convert_to_json, run_command
from octoxlabs.exceptions import NotFound
from octoxlabs.models.adapter import Adapter


@pytest.fixture()
def octox_client(requests_mock) -> OctoxLabs:
    requests_mock.post("/api/token/token", json={"access": "token"})
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


def test_get_companies(requests_mock, octox_client):
    companies_data = util_load_json(path="test_data/get_companies.json")
    requests_mock.get("/companies/companies", json=companies_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-companies", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 1
    assert first_data["results"][0]["name"] == "Octoxlabs"


def test_get_company_by_id(requests_mock, octox_client):
    company_data = util_load_json(path="test_data/get_company.json")
    requests_mock.get("/companies/companies/1", json=company_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-company-by-id",
        args={"company_id": 1},
    )
    first_data = result.outputs
    assert first_data["name"] == "Octoxlabs"


def test_get_company_by_name(requests_mock, octox_client):
    company_data = util_load_json(path="test_data/get_companies.json")
    requests_mock.get("/companies/companies", json=company_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-company-by-name",
        args={"company_name": "Octoxlabs"},
    )
    first_data = result.outputs
    assert first_data["name"] == "Octoxlabs"


def test_get_domains(requests_mock, octox_client):
    domains_data = util_load_json(path="test_data/get_domains.json")
    requests_mock.get("/companies/domains", json=domains_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-domains", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 1
    assert first_data["results"][0]["tenant_name"] == "Octoxlabs"


def test_get_domain_by_id(requests_mock, octox_client):
    domain_data = util_load_json(path="test_data/get_domain.json")
    requests_mock.get("/companies/domains/1", json=domain_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-domain-by-id",
        args={"domain_id": 1},
    )
    first_data = result.outputs
    assert first_data["tenant_name"] == "Octoxlabs"


def test_get_domain_by_domain_name(requests_mock, octox_client):
    domain_data = util_load_json(path="test_data/get_domains.json")
    requests_mock.get("/companies/domains", json=domain_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-domain-by-domain-name",
        args={"domain_name": "localhost"},
    )
    first_data = result.outputs
    assert first_data["domain"] == "localhost"


def test_get_users(requests_mock, octox_client):
    users_data = util_load_json(path="test_data/get_users.json")
    requests_mock.get("/users/users", json=users_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-users", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 1
    assert first_data["results"][0]["name"] == "XSOAR OctoxLabs"


def test_get_user_by_id(requests_mock, octox_client):
    user_data = util_load_json(path="test_data/get_user.json")
    requests_mock.get("/users/users/1", json=user_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-user-by-id", args={"user_id": 1}
    )
    first_data = result.outputs
    assert first_data["name"] == "XSOAR OctoxLabs"


def test_get_user_by_username(requests_mock, octox_client):
    users_data = util_load_json(path="test_data/get_users.json")
    requests_mock.get("/users/users", json=users_data)
    result = run_command(
        octox=octox_client,
        command_name="octoxlabs-get-user-by-username",
        args={"username": "xsoar"},
    )
    first_data = result.outputs
    assert first_data["username"] == "xsoar"


def test_get_groups(requests_mock, octox_client):
    groups_data = util_load_json(path="test_data/get_groups.json")
    requests_mock.get("/users/groups", json=groups_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-groups", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 2
    assert first_data["results"][0]["name"] == "Auditors"


def test_get_permissions(requests_mock, octox_client):
    permissions_data = util_load_json(path="test_data/get_permissions.json")
    requests_mock.get("/users/permissions", json=permissions_data)
    result = run_command(
        octox=octox_client, command_name="octoxlabs-get-permissions", args={}
    )
    first_data = result.outputs
    assert first_data["count"] == 1
    assert first_data["results"][0]["app"] == "activities"
