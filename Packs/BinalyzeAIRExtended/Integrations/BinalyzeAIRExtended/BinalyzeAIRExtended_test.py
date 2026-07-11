import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

CONTENT_ROOT = Path(__file__).resolve().parents[4]
INTEGRATION_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(CONTENT_ROOT))
sys.path.insert(0, str(INTEGRATION_DIR))
sys.path.insert(0, str(CONTENT_ROOT / "Tests" / "demistomock"))
sys.path.insert(0, str(CONTENT_ROOT / "Tests" / "scripts"))

for scripts_root in (
    CONTENT_ROOT / "Packs" / "Base" / "Scripts",
    CONTENT_ROOT / "Packs" / "ApiModules" / "Scripts",
):
    if scripts_root.exists():
        for script_dir in scripts_root.iterdir():
            if script_dir.is_dir():
                sys.path.insert(0, str(script_dir))

import CommonServerPython as csp  # noqa: E402

if not hasattr(csp, "ContentClient"):
    csp.ContentClient = csp.BaseClient

from CommonServerPython import DemistoException  # noqa: E402
from BinalyzeAIRExtended import (  # noqa: E402
    Client,
    clean_params,
    remove_empty_values,
    required_int_arg,
    status_from_task,
    visibility_value,
)


def test_clean_params_removes_empty_values():
    assert clean_params({"a": "x", "b": "", "c": None, "d": [], "e": [1, 2]}) == {
        "a": "x",
        "e": "1,2",
    }


def test_remove_empty_values_recursive():
    payload = {
        "caseId": "C-1",
        "filter": {
            "name": "HOST1",
            "groupId": "",
            "tags": [],
            "organizationIds": [0],
        },
        "empty": "",
    }

    assert remove_empty_values(payload) == {
        "caseId": "C-1",
        "filter": {
            "name": "HOST1",
            "organizationIds": [0],
        },
    }


def test_required_int_arg_invalid():
    with pytest.raises(DemistoException):
        required_int_arg({"organization_id": "invalid"}, "organization_id")


def test_required_int_arg_valid():
    assert required_int_arg({"organization_id": "0"}, "organization_id") == 0
    assert required_int_arg({"organization_id": 1}, "organization_id") == 1


def test_visibility_value_normalizes_human_readable_values():
    assert visibility_value("Public to Organization") == "public-to-organization"
    assert visibility_value("Private to Users") == "private-to-users"
    assert visibility_value("public-to-organization") == "public-to-organization"
    assert visibility_value("private-to-users") == "private-to-users"


def test_status_from_task_normalizes_terminal_status():
    assert status_from_task({"status": "Completed"}) == "completed"
    assert status_from_task({"state": {"name": "Failed"}}) == "failed"
    assert status_from_task({}) == "unknown"


def test_get_asset_by_hostname_uses_params():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.get_asset_by_hostname("HOST123", 0)

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/endpoints",
        params={"filter[name]": "HOST123", "filter[organizationIds]": 0},
    )


def test_get_profile_id_with_preset_profile_does_not_call_api():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock()

    assert client.get_profile_id("quick", 0) == "quick"
    client._http_request.assert_not_called()


def test_get_profile_id_custom_profile_found():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(
        return_value={
            "result": {
                "entities": [
                    {
                        "name": "custom",
                        "_id": "profile-id",
                    }
                ]
            }
        }
    )

    assert client.get_profile_id("custom", 0) == "profile-id"


def test_get_profile_id_custom_profile_uses_params():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(
        return_value={
            "result": {
                "entities": [
                    {
                        "name": "custom",
                        "_id": "profile-id",
                    }
                ]
            }
        }
    )

    client.get_profile_id("custom", 0)

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/acquisitions/profiles",
        params={"filter[name]": "custom", "filter[organizationIds]": 0},
    )


def test_get_profile_id_custom_profile_not_found():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    with pytest.raises(DemistoException):
        client.get_profile_id("missing-profile", 0)


def test_assign_triage_task_payload_is_cleaned():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"success": True})

    client.assign_triage_task(
        {
            "case_id": "CASE-1",
            "triage_rule_ids": "RULE-1",
            "organization_id": "0",
            "hostname": "HOST123",
            "group_id": "",
            "mitre_attack": "False",
        }
    )

    sent_payload = client._http_request.call_args.kwargs["json_data"]

    assert sent_payload["caseId"] == "CASE-1"
    assert sent_payload["triageRuleIds"] == ["RULE-1"]
    assert sent_payload["filter"]["organizationIds"] == [0]
    assert sent_payload["filter"]["name"] == "HOST123"
    assert "groupId" not in sent_payload["filter"]

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/api/public/triages/triage",
        json_data=sent_payload,
    )


def test_list_cases_uses_params():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.list_cases(
        {
            "name": "Case",
            "organization_ids": "0,1",
            "page": "1",
            "limit": "50",
        }
    )

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/cases",
        params={
            "filter[name]": "Case",
            "filter[organizationIds]": "0,1",
            "page": "1",
            "limit": "50",
        },
    )


def test_download_file_uses_params():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"content": b"test"})

    client.download_file("evidence.zip")

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/interact/library/download",
        params={"filename": "evidence.zip"},
        resp_type="response",
    )
