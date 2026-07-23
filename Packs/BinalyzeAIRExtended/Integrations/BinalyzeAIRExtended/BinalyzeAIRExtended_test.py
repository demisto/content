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
            "page": 1,
            "limit": 50,
        }
    )

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/cases",
        params={
            "filter[name]": "Case",
            "filter[organizationIds]": "0,1",
            "page": 1,
            "limit": 50,
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


def test_air_isolate_sets_enabled_payload():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"success": True})

    client.air_isolate("HOST123", 0, "enable")

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/api/public/endpoints/tasks/isolation",
        json_data={"enabled": True, "filter": {"name": "HOST123", "organizationIds": [0]}},
    )


def test_get_case_uses_case_id_path():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"_id": "CASE-1"})

    client.get_case("CASE-1")

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/cases/CASE-1",
    )


def test_close_case_posts_reason():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"success": True})

    client.close_case("CASE-1", "Resolved")

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/api/public/cases/CASE-1/close",
        json_data={"reason": "Resolved"},
    )


@pytest.mark.parametrize(
    "relation",
    [
        "tasks",
        "endpoints",
        "activities",
    ],
)
def test_get_case_related_uses_standard_pagination(relation):
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.get_case_related("CASE-1", relation, {"page": "2", "limit": "25"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix=f"/api/public/cases/CASE-1/{relation}",
        params={"page": 2, "limit": 25},
    )


def test_get_case_tasks_can_filter_by_task_id():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.get_case_related("CASE-1", "tasks", {"task_id": "TASK-1"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/cases/CASE-1/tasks",
        params={"taskId": "TASK-1", "page": 1, "limit": 50},
    )


def test_list_assets_uses_standard_pagination_and_filters():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.list_assets(
        {
            "hostname": "HOST123",
            "organization_id": "0",
            "online_status": "online",
            "page": "2",
            "limit": "25",
        }
    )

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/endpoints",
        params={
            "filter[name]": "HOST123",
            "filter[organizationIds]": "0",
            "filter[onlineStatus]": "online",
            "page": 2,
            "limit": 25,
        },
    )


def test_get_asset_uses_asset_id_path():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"_id": "ASSET-1"})

    client.get_asset("ASSET-1")

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/endpoints/ASSET-1",
    )


def test_get_asset_tasks_uses_standard_pagination():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.get_asset_tasks("ASSET-1", {"page": "2", "limit": "25"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/endpoints/ASSET-1/tasks",
        params={"page": 2, "limit": 25},
    )


def test_list_tasks_uses_standard_pagination_and_filters():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.list_tasks(
        {
            "case_id": "CASE-1",
            "organization_id": "0",
            "status": "completed",
            "task_type": "acquisition",
            "page": "3",
            "limit": "10",
        }
    )

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/tasks",
        params={
            "filter[caseIds]": "CASE-1",
            "filter[organizationIds]": "0",
            "filter[status]": "completed",
            "filter[type]": "acquisition",
            "page": 3,
            "limit": 10,
        },
    )


def test_get_task_assignments_uses_standard_pagination():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.get_task_assignments("TASK-1", {"page": "2", "limit": "25"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/tasks/TASK-1/assignments",
        params={"page": 2, "limit": 25},
    )


def test_update_triage_rule_payload_is_cleaned():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"success": True})

    client.update_triage_rule(
        description="Suspicious PowerShell",
        rule="rule content",
        search_in="system",
        rule_id="RULE-1",
        organization_ids=[],
    )

    client._http_request.assert_called_once_with(
        method="PUT",
        url_suffix="/api/public/triages/rules/RULE-1",
        json_data={
            "description": "Suspicious PowerShell",
            "rule": "rule content",
            "searchIn": "system",
        },
    )


def test_delete_triage_rule_uses_delete_method():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"success": True})

    client.delete_triage_rule("RULE-1")

    client._http_request.assert_called_once_with(
        method="DELETE",
        url_suffix="/api/public/triages/rules/RULE-1",
    )


def test_get_acquisition_profile_uses_profile_id_path():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"_id": "PROFILE-1"})

    client.get_acquisition_profile("PROFILE-1")

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/acquisitions/profiles/PROFILE-1",
    )


def test_list_acquisition_profiles_uses_standard_pagination_and_filters():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.list_acquisition_profiles({"name": "Quick", "organization_id": "0", "page": "2", "limit": "25"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/acquisitions/profiles",
        params={
            "filter[name]": "Quick",
            "filter[organizationIds]": "0",
            "page": 2,
            "limit": 25,
        },
    )


def test_get_repository_uses_repository_id_path():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"_id": "REPO-1"})

    client.get_repository("REPO-1")

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/repositories/REPO-1",
    )


def test_list_repositories_uses_standard_pagination():
    client = Client(base_url="https://air.example.com", verify=False, headers={}, proxy=False)
    client._http_request = MagicMock(return_value={"result": {"entities": []}})

    client.list_repositories({"page": "2", "limit": "25"})

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/public/repositories",
        params={"page": 2, "limit": 25},
    )
