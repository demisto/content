"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

from OctoxLabs import convert_to_json
from octoxlabs.models.adapter import Adapter


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
