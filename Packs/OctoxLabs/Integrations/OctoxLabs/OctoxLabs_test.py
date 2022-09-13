"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import io
import json
import pytest

from octoxlabs import OctoxLabs
from octoxlabs.models.adapter import Adapter
from OctoxLabs import convert_to_json, run_command


@pytest.fixture()
def octox_client() -> OctoxLabs:
    return OctoxLabs(ip="octoxlabs.test", token="xsoar")


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_convert_to_json():
    adapter = Adapter(
        id=1,
        name="Active Directory",
        slug="active-directory",
        description="Active directory description",
        groups=["ad"],
        beta=False,
        status=1
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


def test_get_adapters(requests_mock, octox_client):
    adapter_data = util_load_json(path="test_data/get_adapters.json")
    requests_mock.get("/adapters/adapters", json=adapter_data)

    result = run_command(octox=octox_client, command_name="get-adapters", args={})
    data = result.outputs["OctoxLabs"]["Adapters"]

    assert data["count"] == 2
    assert data["results"][0]["name"] == "Netskope"


def test_run_command_exception(octox_client):
    with pytest.raises(Exception):
        run_command(octox=octox_client, command_name="no-command", args={})

