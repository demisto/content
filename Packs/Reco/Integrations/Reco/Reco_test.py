import json
import uuid

from typing import Any

import base64

import demistomock as demisto
import pytest
import datetime
import os
import re
import yaml
import Reco
from urllib.parse import parse_qs, urlparse

from Reco import (
    RecoClient,
    fetch_incidents,
    map_reco_score_to_demisto_score,
    get_max_fetch,
    get_risky_users_from_reco,
    add_risky_user_label,
    get_assets_user_has_access,
    get_sensitive_assets_by_name,
    get_sensitive_assets_by_id,
    get_link_to_user_overview_page,
    get_sensitive_assets_shared_with_public_link,
    get_3rd_parties_list,
    get_files_shared_with_3rd_parties,
    map_reco_alert_score_to_demisto_score,
    get_user_context_by_email_address,
    get_assets_shared_externally_command,
    get_files_exposed_to_email_command,
    get_private_email_list_with_access,
    get_apps_command,
    set_app_authorization_status_command,
    parse_alerts_to_incidents,
    parse_minimum_risk_level,
    list_events_command,
    list_posture_issues_command,
    list_accounts_command,
    list_devices_command,
    list_ai_agents_command,
    list_groups_command,
    list_saas_to_saas_command,
    list_ip_addresses_command,
    list_business_units_command,
    list_audit_logs_command,
    list_posture_checks_command,
    list_threat_detection_policies_command,
    list_exclusions_command,
    list_app_instances_command,
    add_legacy_output_aliases,
    AlertFilterOptions,
    build_alerts_scim_filter,
    parse_risk_levels,
    parse_alert_statuses,
    parse_date_param,
    get_fetch_filters,
    list_alerts_command,
    fetch_alerts_command,
    get_alert_command,
    update_alert_severity_command,
    add_entity_label_command,
    remove_entity_label_command,
)

from test_data.structs import (
    TableData,
    RowData,
    KeyValuePair,
    GetTableResponse,
    GetIncidentTableResponse,
)

DUMMY_RECO_API_DNS_NAME = "https://dummy.reco.ai/api"
ALERT_ID = "ee593dc2-a50e-415e-bed0-8403c18b26ca"
INCIDENT_DESCRIPTION = "Sensitive files are accessible to anyone who has their link"
ENCODING = "utf-8"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def build_alert_detail(alert_id: str, description: str, risk_level: int, created_at: str) -> dict[str, Any]:
    """Build an alert-details response (external API `GET /external-api/alert-details/{id}`)."""
    return {
        "alert": {
            "id": alert_id,
            "description": description,
            "riskLevel": risk_level,
            "createdAt": created_at,
            "policyViolations": [
                {
                    "id": "75123c18-5ea2-4511-b9c0-1aad67e8b2ff",
                    "jsonData": json.dumps({"violation": True, "id": "91bef1de"}),
                }
            ],
        }
    }


def build_alerts_list_response(alert_ids: list[str]) -> dict[str, Any]:
    """Build an alerts/list response (external API `GET /external-api/alerts/list`)."""
    return {"alerts": [{"id": alert_id} for alert_id in alert_ids], "totalResults": len(alert_ids)}


def get_random_assets_user_has_access_to_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="source",
                                value=base64.b64encode("GDRIVE_ACCESS_LOG_AP".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_type",
                                value=base64.b64encode("document".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="currently_permitted_users",
                                value=base64.b64encode(json.dumps(["a", "b", "c", "d", "e"]).encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="labels",
                                value=base64.b64encode(json.dumps(["a", "b", "c", "d", "e"]).encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="delete_state",
                                value=base64.b64encode("active".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_size",
                                value=base64.b64encode("0".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_name",
                                value=base64.b64encode("User Activity Report".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="visibility",
                                value=base64.b64encode("shared_internally".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="asset_id",
                                value=base64.b64encode("1".encode(ENCODING)).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_owner",
                                value=base64.b64encode("a".encode(ENCODING)).decode(ENCODING),
                            ),
                        ],
                    )
                ],
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_mock_assets() -> list[dict[str, Any]]:
    return {
        "assets": [
            {
                "entityId": "1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1",
                "name": "Untitled document",
                "link": "https://drive.google.com/file/d/1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1",
                "dataSource": "GSUITE_GDRIVE_AUDIT_LOG_API",
                "type": "ASSET_TYPE_FILE",
                "attributes": {},
                "owner": "test@acme.com",
            }
        ]
    }


def test_test_module_success(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json={"alerts": [], "totalResults": 0})

    res = reco_client.validate_api_key()
    assert res == "ok"


@pytest.fixture
def reco_client() -> RecoClient:
    api_token = "dummy api key"
    return RecoClient(api_token=api_token, base_url=DUMMY_RECO_API_DNS_NAME, verify=True, proxy=True)


def test_fetch_incidents_should_succeed(requests_mock, reco_client: RecoClient) -> None:
    created_at = datetime.datetime.now().strftime(TIME_FORMAT)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, created_at),
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_levels=["CRITICAL"],
        source="test",
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )

    assert len(fetched_incidents) == 1
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == ALERT_ID
    assert fetched_incidents[0].get("severity") == 3  # risk_level 30 -> Demisto high
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert "id" in res_json


def test_fetch_same_incidents(requests_mock, reco_client: RecoClient) -> None:
    created_at = datetime.datetime.now().strftime(TIME_FORMAT)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, created_at),
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_levels=["CRITICAL"],
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )

    assert len(fetched_incidents) == 1
    last_run, incidents = fetch_incidents(
        reco_client=reco_client,
        risk_levels=["CRITICAL"],
        before=datetime.datetime.now(),
        last_run=last_run,
        max_fetch=1,
    )
    assert len(incidents) == 0


def test_fetch_incidents_paginates_a_burst_without_skipping(requests_mock, reco_client: RecoClient) -> None:
    """A page as large as max_fetch must not advance lastRun; the next cycle resumes via
    startIndex instead, so a burst larger than max_fetch is drained over multiple cycles
    rather than the excess being permanently skipped."""
    created_at = datetime.datetime.now().strftime(TIME_FORMAT)
    page_1_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    page_2_ids = [str(uuid.uuid4())]

    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list",
        [
            {"json": build_alerts_list_response(page_1_ids)},
            {"json": build_alerts_list_response(page_2_ids)},
        ],
    )
    for alert_id in page_1_ids + page_2_ids:
        requests_mock.get(
            f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{alert_id}",
            json=build_alert_detail(alert_id, INCIDENT_DESCRIPTION, 30, created_at),
        )

    last_run, incidents = fetch_incidents(reco_client=reco_client, last_run={}, max_fetch=2)

    assert len(incidents) == 2
    assert last_run["startIndex"] == 2
    assert last_run["lastRun"] is None

    last_run, incidents = fetch_incidents(reco_client=reco_client, last_run=last_run, max_fetch=2)

    assert len(incidents) == 1
    assert last_run["startIndex"] == 0
    assert last_run["lastRun"] is not None


def test_get_alerts_sorts_ascending_and_forwards_pagination(requests_mock, reco_client: RecoClient) -> None:
    """get_alerts must request ascending createdAt order and forward start_index/count, so
    resuming a burst mid-window never skips or re-jumps past unfetched alerts."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([]))

    reco_client.get_alerts(limit=50, start_index=100)

    sent_qs = requests_mock.last_request.qs
    assert sent_qs["sortby"] == ["createdat"]
    assert sent_qs["sortorder"] == ["ascending"]
    assert sent_qs["startindex"] == ["100"]
    assert sent_qs["count"] == ["50"]


def test_get_alerts_excludes_preview_status(requests_mock, reco_client: RecoClient) -> None:
    """get_alerts must always filter out ALERT_STATUS_PREVIEW alerts - Preview-state
    Policies are meant to stay out of the customer's SOAR, matching the guard already
    enforced on the webhook and share-service paths."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([]))

    reco_client.get_alerts(risk_levels=["HIGH"])

    sent_filter = requests_mock.last_request.qs["filters"][0]
    assert 'status ne "alert_status_preview"' in sent_filter
    assert 'severity eq "high"' in sent_filter


def test_get_alerts_expands_multiple_severities_with_or_not_in(requests_mock, reco_client: RecoClient) -> None:
    """The External API returns HTTP 500 on the SCIM `in` operator, so multiple severities
    must be sent as parenthesised `eq` clauses joined with `or`."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([]))

    reco_client.get_alerts(risk_levels=["MEDIUM", "HIGH", "CRITICAL"])

    sent_filter = requests_mock.last_request.qs["filters"][0]
    assert " in [" not in sent_filter
    assert '(severity eq "medium" or severity eq "high" or severity eq "critical")' in sent_filter


def test_get_alerts_raises_on_api_error(requests_mock, reco_client: RecoClient) -> None:
    """A failed alerts/list call must raise instead of looking like 'no new alerts'."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", status_code=500, json={"code": 13})

    with pytest.raises(Exception):
        reco_client.get_alerts(risk_levels=["HIGH", "CRITICAL"])


def test_fetch_incidents_propagates_api_error(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", status_code=500, json={"code": 13})

    with pytest.raises(Exception):
        fetch_incidents(reco_client=reco_client, last_run={}, max_fetch=10, risk_levels=["HIGH", "CRITICAL"])


def test_test_module_uses_fetch_filter(requests_mock, reco_client: RecoClient) -> None:
    """Test button must send the same severity/Preview filter as fetch-incidents."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json={"alerts": [], "totalResults": 0})

    assert reco_client.validate_api_key(risk_levels=["HIGH", "CRITICAL"]) == "ok"

    sent_filter = requests_mock.last_request.qs["filters"][0]
    assert 'status ne "alert_status_preview"' in sent_filter
    assert '(severity eq "high" or severity eq "critical")' in sent_filter


def test_test_module_fails_when_filtered_query_rejected(requests_mock, mocker, reco_client: RecoClient) -> None:
    mocker.patch.object(demisto, "error")
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", status_code=500, json={"code": 13})

    with pytest.raises(Exception):
        reco_client.validate_api_key(risk_levels=["HIGH", "CRITICAL"])


def test_fetch_incidents_without_assets_info(requests_mock, reco_client: RecoClient) -> None:
    created_at = datetime.datetime.now().strftime(TIME_FORMAT)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, created_at),
    )
    last_run, fetched_incidents = fetch_incidents(reco_client=reco_client, last_run={}, source="GOOGLE_DRIVE", max_fetch=1)

    assert len(fetched_incidents) == 1
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == ALERT_ID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert "id" in res_json


def test_empty_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json={"alerts": [], "totalResults": 0})
    last_run, fetched_incidents = fetch_incidents(reco_client=reco_client, last_run={}, max_fetch=1)

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_empty_valid_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json={"alerts": [], "totalResults": 0})
    last_run, fetched_incidents = fetch_incidents(reco_client=reco_client, last_run={}, max_fetch=1)

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_invalid_response(requests_mock, reco_client: RecoClient) -> None:
    """A malformed alerts/list response (missing the 'alerts' key) yields zero incidents, no exception."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list", json={})
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        last_run={},
        max_fetch=1,
        risk_levels=["HIGH", "CRITICAL"],
        source="GSUITE_GDRIVE_AUDIT_LOG_API",
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_risk_level_mapper():
    """Map Reco numeric risk score (10-40) to Demisto severity."""
    assert map_reco_score_to_demisto_score(40) == 4
    assert map_reco_score_to_demisto_score(30) == 3
    assert map_reco_score_to_demisto_score(20) == 2
    assert map_reco_score_to_demisto_score(10) == 0.5
    assert map_reco_score_to_demisto_score(0) == 0.5


def test_risk_level_mapper_mid_range():
    """Mid-range scores (10-40) normalize to tier: 10->0.5, 20->2, 30->3, 40->4."""
    assert map_reco_score_to_demisto_score(15) == 0.5
    assert map_reco_score_to_demisto_score(25) == 2
    assert map_reco_score_to_demisto_score(35) == 3
    assert map_reco_score_to_demisto_score(37) == 3


def test_alert_mapper():
    assert map_reco_alert_score_to_demisto_score("CRITICAL") == 4


def test_parse_minimum_risk_level_expands_to_higher_severities():
    """A single risk_level value expands to itself and every severity above it."""
    assert parse_minimum_risk_level("MEDIUM") == ["MEDIUM", "HIGH", "CRITICAL"]
    assert parse_minimum_risk_level("LOW") == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert parse_minimum_risk_level("CRITICAL") == ["CRITICAL"]


def test_parse_minimum_risk_level_accepts_numeric_and_lowercase():
    assert parse_minimum_risk_level("30") == ["HIGH", "CRITICAL"]
    assert parse_minimum_risk_level("medium") == ["MEDIUM", "HIGH", "CRITICAL"]


def test_parse_minimum_risk_level_empty_returns_none():
    assert parse_minimum_risk_level(None) is None
    assert parse_minimum_risk_level("") is None


def test_add_legacy_output_aliases_copies_new_field_to_old_key():
    items = [{"id": "1", "name": "foo"}, {"id": "2", "name": "bar"}]
    add_legacy_output_aliases(items, {"app_name": "name"})
    assert items[0]["app_name"] == "foo"
    assert items[1]["app_name"] == "bar"


def test_add_legacy_output_aliases_skips_missing_new_key():
    items = [{"id": "1"}]
    add_legacy_output_aliases(items, {"app_name": "name"})
    assert "app_name" not in items[0]


def test_parse_alerts_to_incidents_numeric_risk():
    """parse_alerts_to_incidents maps numeric risk_level (10-40) to severity."""
    alerts = [
        {"riskLevel": 40, "description": "Critical", "id": "1", "createdAt": "2023-01-01T00:00:00Z"},
        {"risk_level": 20, "description": "Medium", "id": "2", "created_at": "2023-01-01T00:00:00Z"},
        {"riskLevel": 15, "description": "Low tier", "id": "3", "createdAt": "2023-01-01T00:00:00Z"},
    ]
    incidents = parse_alerts_to_incidents(alerts)
    assert len(incidents) == 3
    assert incidents[0]["severity"] == 4
    assert incidents[1]["severity"] == 2
    assert incidents[2]["severity"] == 0.5


def test_parse_alerts_to_incidents_missing_risk_defaults_to_low():
    """When risk_level is missing or invalid, severity defaults to 0.5 (LOW)."""
    alerts = [{"description": "No risk", "id": "1", "createdAt": "2023-01-01T00:00:00Z"}]
    incidents = parse_alerts_to_incidents(alerts)
    assert len(incidents) == 1
    assert incidents[0]["severity"] == 0.5


def test_parse_alerts_to_incidents_risk_level_string_and_int():
    """risk_level works as string labels ('HIGH'), string numbers ('10'), and ints (40)."""
    alerts = [
        {"riskLevel": "HIGH", "description": "High", "id": "1", "createdAt": "2023-01-01T00:00:00Z"},
        {"risk_level": "10", "description": "Low str", "id": "2", "created_at": "2023-01-01T00:00:00Z"},
        {"riskLevel": 40, "description": "Critical int", "id": "3", "createdAt": "2023-01-01T00:00:00Z"},
        {"riskLevel": "30", "description": "High str num", "id": "4", "createdAt": "2023-01-01T00:00:00Z"},
        {"risk_level": "MEDIUM", "description": "Medium", "id": "5", "created_at": "2023-01-01T00:00:00Z"},
    ]
    incidents = parse_alerts_to_incidents(alerts)
    assert len(incidents) == 5
    assert incidents[0]["severity"] == 3  # "HIGH" -> high
    assert incidents[1]["severity"] == 0.5  # "10" -> low
    assert incidents[2]["severity"] == 4  # 40 -> critical
    assert incidents[3]["severity"] == 3  # "30" -> high
    assert incidents[4]["severity"] == 2  # "MEDIUM" -> medium


def test_get_max_fetch_bigger():
    big_number_max_fetch = 600
    result = get_max_fetch(big_number_max_fetch)
    assert result == 500


def test_max_fetch():
    max_fetch = 200
    result = get_max_fetch(max_fetch)
    assert result == max_fetch


def test_update_reco_incident_timeline(requests_mock, reco_client: RecoClient) -> None:
    incident_id = uuid.uuid1()
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/comments/create",
        json={},
        status_code=200,
    )
    res = reco_client.update_reco_incident_timeline(incident_id=str(incident_id), comment="test")
    assert res == {}


def test_update_reco_incident_timeline_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    incident_id = uuid.uuid1()
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/comments/create",
        json={},
        status_code=404,
    )
    with capfd.disabled(), pytest.raises(Exception):
        reco_client.update_reco_incident_timeline(incident_id=str(incident_id), comment="test")


def test_resolve_visibility_event(requests_mock, reco_client: RecoClient) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=200)
    res = reco_client.resolve_visibility_event(entity_id=str(entry_id), label_name="Accessible by all")
    assert res == {}


def test_resolve_visibility_event_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=404)
    with capfd.disabled(), pytest.raises(Exception):
        reco_client.resolve_visibility_event(entity_id=str(entry_id), label_name="Accessible by all")


def test_get_risky_users(requests_mock, reco_client: RecoClient) -> None:
    accounts = [
        {
            "id": str(uuid.uuid4()),
            "name": "John Doe",
            "accountEmail": f"{uuid.uuid4()}@acme.com",
            "isAdmin": False,
            "isRiskyUser": True,
        }
    ]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/accounts/list",
        json={"accounts": accounts, "totalResults": len(accounts)},
        status_code=200,
    )
    actual_result = get_risky_users_from_reco(reco_client=reco_client)
    assert len(actual_result.outputs) == len(accounts)
    assert "@" in actual_result.outputs[0].get("accountEmail")


def test_get_risky_users_bad_response(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/accounts/list",
        json={},
        status_code=500,
    )
    with capfd.disabled(), pytest.raises(Exception):
        get_risky_users_from_reco(reco_client=reco_client)


def test_add_risky_user_label(requests_mock, reco_client: RecoClient) -> None:
    label_id = f"{uuid.uuid1()}@gmail.com"
    identity_id = str(uuid.uuid4())
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/users/list",
        json={"users": [{"id": identity_id, "email": label_id}], "totalResults": 1},
        status_code=200,
    )
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/labels/add", json={}, status_code=200)
    res = add_risky_user_label(reco_client=reco_client, email_address=label_id)
    assert "labeled as risky" in res.readable_output


def test_get_assets_user_has_access_to(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200)
    actual_result = get_assets_user_has_access(
        reco_client=reco_client,
        email_address=f"{uuid.uuid1()}@gmail.com",
        only_sensitive=False,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_assets_user_bad_response(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json={}, status_code=200)
    with capfd.disabled(), pytest.raises(Exception):
        get_assets_user_has_access(reco_client=reco_client, email_address="test", only_sensitive=False)


def test_get_sensitive_assets_by_name(requests_mock, reco_client: RecoClient) -> None:
    files = [{"id": "asset-1", "name": "sensitive.txt", "owner": "test@acme.com", "sensitivityLevel": "40"}]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/files/list", json={"files": files, "totalResults": len(files)})
    actual_result = get_sensitive_assets_by_name(reco_client=reco_client, asset_name="test", regex_search=True)
    assert len(actual_result.outputs) == len(files)
    assert actual_result.outputs[0].get("id") is not None


def test_get_sensitive_assets_by_id(requests_mock, reco_client: RecoClient) -> None:
    files = [
        {
            "id": "asset-id",
            "name": "sensitive.txt",
            "owner": "test@acme.com",
            "url": "https://drive.example.com/sensitive.txt",
            "sensitivityLevel": "40",
            "permissionVisibility": "PUBLIC",
        }
    ]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/files/list", json={"files": files, "totalResults": len(files)})
    actual_result = get_sensitive_assets_by_id(reco_client=reco_client, asset_id="asset-id")
    assert len(actual_result.outputs) == len(files)
    output = actual_result.outputs[0]
    assert output.get("id") is not None
    # legacy pre-migration field names must still be populated for backward compatibility
    assert output.get("file_name") == "sensitive.txt"
    assert output.get("file_owner") == "test@acme.com"
    assert output.get("file_url") == "https://drive.example.com/sensitive.txt"
    assert output.get("sensitivity_level") == "40"
    assert output.get("visibility") == "PUBLIC"


def test_get_link_to_user_overview_page(requests_mock, reco_client: RecoClient) -> None:
    entity_id = f"{uuid.uuid1()}@gmail.com"
    link_type = "RM_LINK_TYPE_USER"
    link_res = str(uuid.uuid1())
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
        json={"link": link_res},
        status_code=200,
    )
    actual_result = get_link_to_user_overview_page(reco_client=reco_client, entity=entity_id, link_type=link_type)
    assert actual_result.outputs_prefix == "Reco.Link"
    assert actual_result.outputs.get("link") == link_res


def test_get_link_to_user_overview_page_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    entity_id = f"{uuid.uuid1()}@gmail.com"
    link_type = "RM_LINK_TYPE_USER"
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
        json={},
        status_code=404,
    )
    with capfd.disabled(), pytest.raises(Exception):
        get_link_to_user_overview_page(reco_client=reco_client, entity=entity_id, link_type=link_type)


def test_get_exposed_publicly(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_sensitive_assets_shared_with_public_link(reco_client=reco_client)
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_private_email_list_with_access(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table",
        json={"getTableResponse": {}},
        status_code=200,
    )
    actual_result = get_private_email_list_with_access(reco_client=reco_client)
    assert len(actual_result.outputs) == 0


def test_get_assets_shared_externally_command(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/asset-management/query", json=raw_result, status_code=200)
    actual_result = get_assets_shared_externally_command(reco_client=reco_client, email_address="g@example.com")
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_get_files_exposed_to_email_command(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_files_exposed_to_email_command(reco_client=reco_client, email_account="g@example.com")
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_exposed_publicly_page_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json={}, status_code=200)
    with capfd.disabled(), pytest.raises(Exception):
        get_sensitive_assets_shared_with_public_link(reco_client=reco_client)


def test_get_3rd_parties_list_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json={}, status_code=200)
    with capfd.disabled(), pytest.raises(Exception):
        get_3rd_parties_list(
            reco_client=reco_client,
            last_interaction_time_in_days=30,
        )


def test_get_3rd_parties_list(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_3rd_parties_list(
        reco_client=reco_client,
        last_interaction_time_in_days=30,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_get_files_shared_with_3rd_parties(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-data-risk-management-table", json=raw_result, status_code=200
    )
    actual_result = get_files_shared_with_3rd_parties(
        reco_client=reco_client,
        domain="data",
        last_interaction_time_before_in_days=30,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)


def test_date_formatting(reco_client: RecoClient) -> None:
    date = reco_client.get_date_time_before_days_formatted(30)
    assert ".999Z" in date


def test_add_exclusion_filter(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/algo/add_values_to_data_type_exclude_analyzer", json={}, status_code=200)
    reco_client.add_exclusion_filter("key", ["val1", "val2"])


def test_change_alert_status(requests_mock, reco_client: RecoClient) -> None:
    """Threat-alert statuses use the External API endpoint."""
    alert_id = str(uuid.uuid1())
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{alert_id}/status", json={"alert": {"id": alert_id}})

    res = reco_client.change_alert_status(alert_id=alert_id, status="ALERT_STATUS_CLOSED")

    assert res == {"alert": {"id": alert_id}}
    assert json.loads(requests_mock.last_request.text) == {"status": "ALERT_STATUS_CLOSED"}
    assert len(requests_mock.request_history) == 1  # the internal endpoint was not called


@pytest.mark.parametrize("external_status_code", [403, 404])
def test_change_alert_status_falls_back_to_internal(capfd, requests_mock, reco_client: RecoClient, external_status_code) -> None:
    """404: posture issue IDs. 403: a token with PERM_POSTURES_UPDATE but not PERM_ALERTS_WRITE, which the
    internal endpoint still accepts."""
    alert_id = str(uuid.uuid1())
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{alert_id}/status", status_code=external_status_code, json={}
    )
    internal = requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{alert_id}/status/ALERT_STATUS_CLOSED", json={}
    )

    assert reco_client.change_alert_status(alert_id=alert_id, status="ALERT_STATUS_CLOSED") == {}
    assert internal.called


def test_change_alert_status_surfaces_the_error_when_both_endpoints_refuse(capfd, requests_mock, reco_client: RecoClient) -> None:
    alert_id = str(uuid.uuid1())
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{alert_id}/status", status_code=403, json={})
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{alert_id}/status/ALERT_STATUS_CLOSED", status_code=403, json={}
    )

    with capfd.disabled(), pytest.raises(Exception):
        reco_client.change_alert_status(alert_id=alert_id, status="ALERT_STATUS_CLOSED")


def test_change_alert_status_does_not_swallow_other_external_errors(capfd, requests_mock, reco_client: RecoClient) -> None:
    alert_id = str(uuid.uuid1())
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{alert_id}/status", status_code=400, json={})

    with capfd.disabled(), pytest.raises(Exception):
        reco_client.change_alert_status(alert_id=alert_id, status="ALERT_STATUS_NEW")
    assert len(requests_mock.request_history) == 1


def test_change_alert_status_posture_status(requests_mock, reco_client: RecoClient) -> None:
    """The status enum also covers posture-check statuses like ALERT_STATUS_RISK_MITIGATED."""
    alert_id = uuid.uuid1()
    status = "ALERT_STATUS_RISK_MITIGATED"
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/policy-subsystem/alert-inbox/{str(alert_id)}/status/{status}",
        json={},
        status_code=200,
    )
    res = reco_client.change_alert_status(alert_id=str(alert_id), status=status)
    assert res == {}


def test_get_alert_summary(requests_mock, reco_client: RecoClient) -> None:
    alert_id = uuid.uuid1()
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/alert/summarize/{alert_id}",
        json={"content": "test"},
        status_code=200,
    )
    res = reco_client.get_alert_ai_summary(alert_id=str(alert_id))
    assert res.get("content") == "test"


def test_get_alert_summary_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    alert_id = uuid.uuid1()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/alert/summarize/{alert_id}", json={}, status_code=404)
    with capfd.disabled(), pytest.raises(Exception):
        reco_client.get_alert_ai_summary(str(alert_id))


def test_get_user_context_by_email(requests_mock, reco_client: RecoClient) -> None:
    users = [
        {
            "email": "charles@corp.com",
            "name": "Yossi",
            "departments": ["Pro"],
            "jobTitles": ["VP Product"],
            "isInternal": False,
        }
    ]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/users/list", json={"users": users, "totalResults": len(users)})
    res = get_user_context_by_email_address(reco_client, "charles@corp.com")
    assert res.outputs_prefix == "Reco.User"
    assert res.outputs.get("email") != ""
    assert res.outputs.get("email") == "charles@corp.com"
    # legacy pre-migration field names must still be populated for backward compatibility
    assert res.outputs.get("email_account") == "charles@corp.com"
    assert res.outputs.get("full_name") == "Yossi"
    assert res.outputs.get("job_titles") == ["VP Product"]
    assert res.outputs.get("category") == "external"


def test_get_app_discovery_with_filters(requests_mock, reco_client: RecoClient) -> None:
    """Test the get_app_discovery method with date filters."""
    apps = [{"id": "slack.com", "name": "Slack", "category": "Communication"}]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/list", json={"apps": apps, "totalResults": len(apps)})

    # Test with date filters
    from datetime import datetime, timedelta

    before = datetime.now()
    after = datetime.now() - timedelta(days=30)

    result = reco_client.get_app_discovery(before=before, after=after, limit=100)

    # Verify the response
    assert isinstance(result, list)


def test_get_app_discovery_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    """Test error handling in get_app_discovery."""
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/list", json={}, status_code=500)

    with capfd.disabled(), pytest.raises(Exception):
        reco_client.get_app_discovery()


def test_set_app_authorization_status(requests_mock, reco_client: RecoClient) -> None:
    """Test setting app authorization status."""
    app_id = "microsoft.com"
    authorization_status = "AUTH_STATUS_SANCTIONED"

    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/{app_id}/auth-status",
        json={"authorizationStatus": authorization_status},
        status_code=200,
    )

    response = reco_client.set_app_authorization_status(app_id, authorization_status)
    assert response == {"authorizationStatus": authorization_status}


def test_set_app_authorization_status_sends_app_type_only_when_given(requests_mock, reco_client: RecoClient) -> None:
    url = f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/app-1/auth-status"
    requests_mock.put(url, json={})

    reco_client.set_app_authorization_status("app-1", "AUTH_STATUS_SANCTIONED")
    assert json.loads(requests_mock.last_request.text) == {"authorizationStatus": "AUTH_STATUS_SANCTIONED"}

    reco_client.set_app_authorization_status("app-1", "AUTH_STATUS_SANCTIONED", "APP_ENTITY_TYPE_APP_PORTFOLIO")
    assert json.loads(requests_mock.last_request.text) == {
        "authorizationStatus": "AUTH_STATUS_SANCTIONED",
        "appType": "APP_ENTITY_TYPE_APP_PORTFOLIO",
    }


def test_set_app_authorization_status_command(requests_mock, reco_client: RecoClient) -> None:
    """Test the set_app_authorization_status_command function."""
    app_id = "slack.com"
    authorization_status = "AUTH_STATUS_UNSANCTIONED"

    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/{app_id}/auth-status",
        json={"authorizationStatus": authorization_status},
        status_code=200,
    )

    result = set_app_authorization_status_command(reco_client, app_id, authorization_status)

    assert result.outputs_prefix == "Reco.AppAuthorization"
    assert result.outputs["app_id"] == app_id
    assert result.outputs["authorization_status"] == authorization_status
    assert result.outputs["updated"] is True
    assert "updated to" in result.readable_output


def test_get_apps_command(requests_mock, reco_client: RecoClient) -> None:
    """Test the get_apps_command function."""
    mock_apps = [
        {
            "id": "slack.com",
            "name": "Slack",
            "category": "Communication",
            "usersCount": 10,
            "authorization": "AUTH_STATUS_SANCTIONED",
            "isUsingAi": False,
            "vendorGrade": "A",
            "aiCapability": True,
            "lastSeen": "2024-01-01T00:00:00Z",
        }
    ]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/list",
        json={"apps": mock_apps, "totalResults": len(mock_apps)},
        status_code=200,
    )

    result = get_apps_command(reco_client)

    assert result.outputs_prefix == "Reco.Apps"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert "App Discovery" in result.readable_output
    # legacy pre-migration field names must still be populated for backward compatibility
    output = result.outputs[0]
    assert output.get("app_id") == "slack.com"
    assert output.get("app_name") == "Slack"
    assert output.get("users_count") == 10


def test_set_app_authorization_status_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    """Test error handling in set_app_authorization_status."""
    app_id = "test.com"
    authorization_status = "AUTH_STATUS_SANCTIONED"

    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/{app_id}/auth-status",
        json={},
        status_code=500,
    )

    with capfd.disabled(), pytest.raises(Exception):
        reco_client.set_app_authorization_status(app_id, authorization_status)


def test_set_app_authorization_status_error_2(capfd, requests_mock, reco_client: RecoClient) -> None:
    """Test error handling in set_app_authorization_status with a different failure status code."""
    app_id = "test.com"
    authorization_status = "AUTH_STATUS_SANCTIONED"

    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/{app_id}/auth-status",
        json={},
        status_code=404,
    )

    with capfd.disabled(), pytest.raises(Exception):
        reco_client.set_app_authorization_status(app_id, authorization_status)


def test_list_events_command(requests_mock, reco_client: RecoClient) -> None:
    events = [
        {
            "id": "event-1",
            "eventType": "login",
            "formattedEventType": "Login",
            "application": "Slack",
            "eventTime": "2024-01-01T00:00:00Z",
            "outcomeString": "success",
            "actor": {"email": "test@acme.com", "name": "User"},
        }
    ]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/events/list", json={"events": events, "totalResults": len(events)})
    result = list_events_command(reco_client)
    assert result.outputs_prefix == "Reco.Events"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Events" in result.readable_output


def test_list_posture_issues_command(requests_mock, reco_client: RecoClient) -> None:
    issues = [{"id": "issue-1", "name": "MFA not enforced", "severity": "HIGH", "checkStatus": "ALERT_STATUS_TO_REVIEW"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/posture-issues/list",
        json={"issues": issues, "totalResults": len(issues)},
    )
    result = list_posture_issues_command(reco_client)
    assert result.outputs_prefix == "Reco.PostureIssues"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Posture Issues" in result.readable_output


def test_list_accounts_command(requests_mock, reco_client: RecoClient) -> None:
    accounts = [{"id": "acc-1", "name": "John Doe", "accountEmail": "john@acme.com", "isAdmin": False}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/accounts/list",
        json={"accounts": accounts, "totalResults": len(accounts)},
    )
    result = list_accounts_command(reco_client)
    assert result.outputs_prefix == "Reco.Accounts"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Accounts" in result.readable_output


def test_list_devices_command(requests_mock, reco_client: RecoClient) -> None:
    devices = [{"id": "dev-1", "name": "MacBook Pro", "devicePlatform": "macOS", "isUnmanaged": False}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/devices/list", json={"devices": devices, "totalResults": len(devices)}
    )
    result = list_devices_command(reco_client)
    assert result.outputs_prefix == "Reco.Devices"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Devices" in result.readable_output


def test_list_ai_agents_command(requests_mock, reco_client: RecoClient) -> None:
    agents = [{"id": "agent-1", "name": "Copilot", "vendor": "Microsoft", "authorization": "AUTH_STATUS_SANCTIONED"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/ai-agents/list", json={"aiAgents": agents, "totalResults": len(agents)}
    )
    result = list_ai_agents_command(reco_client)
    assert result.outputs_prefix == "Reco.AiAgents"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "AI Agents" in result.readable_output


def test_list_groups_command(requests_mock, reco_client: RecoClient) -> None:
    groups = [{"id": "group-1", "name": "Engineering", "email": "test@acme.com", "membersCount": 10}]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/groups/list", json={"groups": groups, "totalResults": len(groups)})
    result = list_groups_command(reco_client)
    assert result.outputs_prefix == "Reco.Groups"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Groups" in result.readable_output


def test_list_saas_to_saas_command(requests_mock, reco_client: RecoClient) -> None:
    grants = [{"id": "grant-1", "plugin": "Zoom for Slack", "authorization": "AUTH_STATUS_TO_REVIEW"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/saas-to-saas/list",
        json={"saasToSaas": grants, "totalResults": len(grants)},
    )
    result = list_saas_to_saas_command(reco_client)
    assert result.outputs_prefix == "Reco.SaasToSaas"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "SaaS-to-SaaS Grants" in result.readable_output


def test_list_ip_addresses_command(requests_mock, reco_client: RecoClient) -> None:
    ips = [{"ipAddress": "1.2.3.4", "country": "US", "hasVpn": False, "hasProxy": False}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/ip-addresses/list", json={"ipAddresses": ips, "totalResults": len(ips)}
    )
    result = list_ip_addresses_command(reco_client)
    assert result.outputs_prefix == "Reco.IpAddresses"
    assert result.outputs_key_field == "ipAddress"
    assert len(result.outputs) == 1
    assert "IP Addresses" in result.readable_output


def test_list_business_units_command(requests_mock, reco_client: RecoClient) -> None:
    bus = [{"id": "bu-1", "name": "R&D", "manager": "jane@acme.com"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/business-units/list", json={"businessUnits": bus, "totalResults": len(bus)}
    )
    result = list_business_units_command(reco_client)
    assert result.outputs_prefix == "Reco.BusinessUnits"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Business Units" in result.readable_output


def test_list_audit_logs_command(requests_mock, reco_client: RecoClient) -> None:
    logs = [{"id": "log-1", "userEmail": "admin@acme.com", "module": "auth", "action": "login"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/audit-logs/list", json={"auditLogs": logs, "totalResults": len(logs)}
    )
    result = list_audit_logs_command(reco_client)
    assert result.outputs_prefix == "Reco.AuditLogs"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Audit Logs" in result.readable_output


def test_list_posture_checks_command(requests_mock, reco_client: RecoClient) -> None:
    checks = [{"id": "check-1", "name": "MFA Enforced", "severity": "HIGH", "policyType": "SECURITY"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/posture-checks/list",
        json={"postureChecks": checks, "totalResults": len(checks)},
    )
    result = list_posture_checks_command(reco_client)
    assert result.outputs_prefix == "Reco.PostureChecks"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Posture Checks" in result.readable_output


def test_list_threat_detection_policies_command(requests_mock, reco_client: RecoClient) -> None:
    policies = [{"id": "policy-1", "name": "Impossible Travel", "severity": "CRITICAL", "status": "ALERT_STATUS_ACTIVE"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/policies/list", json={"policies": policies, "totalResults": len(policies)}
    )
    result = list_threat_detection_policies_command(reco_client)
    assert result.outputs_prefix == "Reco.ThreatDetectionPolicies"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Threat Detection Policies" in result.readable_output


def test_list_exclusions_command(requests_mock, reco_client: RecoClient) -> None:
    exclusions = [{"id": "excl-1", "name": "Trusted IP range", "policyName": "Impossible Travel"}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/exclusions/list",
        json={"exclusions": exclusions, "totalResults": len(exclusions)},
    )
    result = list_exclusions_command(reco_client)
    assert result.outputs_prefix == "Reco.Exclusions"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "Exclusions" in result.readable_output


def test_list_app_instances_command(requests_mock, reco_client: RecoClient) -> None:
    instances = [{"id": "instance-1", "name": "Slack (Prod)", "instanceType": "PRODUCTION", "isUsingAi": False}]
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/app-instances/list",
        json={"appInstances": instances, "totalResults": len(instances)},
    )
    result = list_app_instances_command(reco_client)
    assert result.outputs_prefix == "Reco.AppInstances"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "App Instances" in result.readable_output


# --- PRO-410: source-side alert filters and on-demand alert commands ---

ALERTS_LIST_URL = f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/list"


def sent_filter(requests_mock, request_index: int = -1) -> str:
    """The raw `filters` query value of a recorded request (requests_mock lower-cases `.qs`, so parse the URL)."""
    request = requests_mock.request_history[request_index]
    return parse_qs(urlparse(request.url).query)["filters"][0]


def test_build_alerts_scim_filter_default_only_excludes_preview() -> None:
    assert build_alerts_scim_filter() == 'status ne "ALERT_STATUS_PREVIEW"'


def test_build_alerts_scim_filter_combines_every_filter_with_parenthesised_groups() -> None:
    options = AlertFilterOptions(
        saas_platforms=["Microsoft 365", "Okta"],
        statuses=["ALERT_STATUS_NEW", "ALERT_STATUS_IN_PROGRESS"],
        include_labels=["Identity", "Privileged Access"],
        exclude_labels=["Noise"],
        custom_filter='description co "x" or description co "y"',
    )
    result = build_alerts_scim_filter(
        risk_levels=["HIGH", "CRITICAL"],
        source="GOOGLE_DRIVE",
        after=datetime.datetime(2026, 11, 1, 0, 0, 0),
        before=datetime.datetime(2026, 11, 8, 23, 59, 59),
        filter_options=options,
    )
    assert result == (
        'status ne "ALERT_STATUS_PREVIEW"'
        ' and (severity eq "HIGH" or severity eq "CRITICAL")'
        ' and (status eq "ALERT_STATUS_NEW" or status eq "ALERT_STATUS_IN_PROGRESS")'
        ' and apps co "GOOGLE_DRIVE"'
        ' and (instance.appName co "Microsoft 365" or instance.appName co "Okta")'
        ' and (customLabels eq "Identity" or customLabels eq "Privileged Access")'
        ' and not (customLabels eq "Noise")'
        ' and createdAt gt "2026-11-01T00:00:00Z"'
        ' and createdAt lt "2026-11-08T23:59:59Z"'
        ' and (description co "x" or description co "y")'
    )


def test_build_alerts_scim_filter_exclude_multiple_labels_is_a_single_not_group() -> None:
    result = build_alerts_scim_filter(filter_options=AlertFilterOptions(exclude_labels=["A", "B"]))
    assert result.endswith('and not (customLabels eq "A" or customLabels eq "B")')


def test_build_alerts_scim_filter_escapes_quotes_and_backslashes() -> None:
    options = AlertFilterOptions(include_labels=['evil" or severity eq "LOW', "back\\slash"])
    result = build_alerts_scim_filter(filter_options=options)
    assert 'customLabels eq "evil\\" or severity eq \\"LOW"' in result
    assert 'customLabels eq "back\\\\slash"' in result


def test_parse_risk_levels_is_an_explicit_list_not_a_minimum() -> None:
    assert parse_risk_levels("HIGH,critical, 40") == ["HIGH", "CRITICAL"]
    assert parse_risk_levels(None) is None
    with pytest.raises(ValueError, match="Unknown risk level"):
        parse_risk_levels("HIGH,SEVERE")


def test_parse_alert_statuses_accepts_short_and_full_names() -> None:
    assert parse_alert_statuses("new, In Progress,ALERT_STATUS_CLOSED, new") == [
        "ALERT_STATUS_NEW",
        "ALERT_STATUS_IN_PROGRESS",
        "ALERT_STATUS_CLOSED",
    ]
    assert parse_alert_statuses(None) == []


def test_parse_alert_statuses_rejects_preview_and_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown alert status"):
        parse_alert_statuses("PREVIEW")


def test_parse_date_param_utc_and_invalid() -> None:
    parsed = parse_date_param("2026-11-01T00:00:00Z", "after")
    assert parsed is not None
    assert parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-11-01T00:00:00Z"
    assert parse_date_param("", "after") is None
    with pytest.raises(ValueError, match="Could not parse 'before'"):
        parse_date_param("not a date", "before")


def test_parse_date_param_converts_utc_offsets() -> None:
    """A value with an offset must be converted to UTC, not have its wall time stamped with a 'Z'."""
    parsed = parse_date_param("2026-11-01T02:00:00+02:00", "after")
    assert parsed is not None
    assert parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-11-01T00:00:00Z"


def test_parse_date_param_date_only_before_includes_the_whole_day() -> None:
    before = parse_date_param("2026-10-31", "before", include_whole_day=True)
    after = parse_date_param("2026-10-01", "after")
    assert before is not None
    assert after is not None
    assert before.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-11-01T00:00:00Z"  # exclusive bound = all of Oct 31
    assert after.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-10-01T00:00:00Z"
    # an explicit time is never shifted
    explicit = parse_date_param("2026-10-31T23:59:59Z", "before", include_whole_day=True)
    assert explicit is not None
    assert explicit.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-10-31T23:59:59Z"


def test_fetch_alerts_command_date_only_range_covers_both_days(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([]))

    fetch_alerts_command(reco_client, {"after": "2026-10-01", "before": "2026-10-31"})

    result = sent_filter(requests_mock)
    assert 'createdAt gt "2026-10-01T00:00:00Z"' in result
    assert 'createdAt lt "2026-11-01T00:00:00Z"' in result


def test_get_alerts_sends_filter_options_to_the_api(requests_mock, reco_client: RecoClient) -> None:
    """Filters are applied by the Reco API (sent in the query), not after retrieval."""
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([]))

    reco_client.get_alerts(filter_options=AlertFilterOptions(saas_platforms=["Microsoft 365"], include_labels=["Identity"]))

    result = sent_filter(requests_mock)
    assert 'instance.appName co "Microsoft 365"' in result
    assert 'customLabels eq "Identity"' in result


def test_fetch_incidents_forwards_filter_options(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([]))

    fetch_incidents(
        reco_client=reco_client,
        last_run={},
        max_fetch=10,
        filter_options=AlertFilterOptions(exclude_labels=["Noise"], statuses=["ALERT_STATUS_NEW"]),
    )

    result = sent_filter(requests_mock)
    assert 'not (customLabels eq "Noise")' in result
    assert 'status eq "ALERT_STATUS_NEW"' in result


FETCH_PARAMS = {
    "risk_level": "HIGH",
    "source": "GOOGLE_DRIVE",
    "first_fetch": "7 days",
    "saas_platform": "Microsoft 365, Okta",
    "alert_status": ["New", "In Progress"],
    "include_labels": "Identity",
    "exclude_labels": "Noise",
    "custom_filter": 'actors co "@example.com"',
}


def test_get_fetch_filters_maps_every_integration_parameter() -> None:
    filters = get_fetch_filters(FETCH_PARAMS)

    assert filters["risk_levels"] == ["HIGH", "CRITICAL"]
    assert filters["source"] == "GOOGLE_DRIVE"
    assert filters["after"] is not None
    assert filters["before"] is None
    options = filters["filter_options"]
    assert options.saas_platforms == ["Microsoft 365", "Okta"]
    assert options.statuses == ["ALERT_STATUS_NEW", "ALERT_STATUS_IN_PROGRESS"]
    assert options.include_labels == ["Identity"]
    assert options.exclude_labels == ["Noise"]
    assert options.custom_filter == 'actors co "@example.com"'


def test_get_fetch_filters_parses_before_and_after_parameters() -> None:
    """`before` used to be passed as a raw string (crashing fetch on strftime) and `after` was ignored."""
    filters = get_fetch_filters({"before": "2026-11-08T00:00:00Z", "after": "2026-11-01T00:00:00Z", "first_fetch": "7 days"})

    assert filters["before"].strftime("%Y-%m-%d") == "2026-11-08"
    assert get_fetch_filters({"before": "2026-11-08"})["before"].strftime("%Y-%m-%d") == "2026-11-09"  # date-only = whole day
    assert filters["after"].strftime("%Y-%m-%d") == "2026-11-01"  # explicit `after` wins over first_fetch


def test_get_fetch_filters_parses_first_fetch_as_utc() -> None:
    after = get_fetch_filters({"first_fetch": "3 days"})["after"]

    assert after.tzinfo is not None
    assert after.utcoffset() == datetime.timedelta(0)
    assert (
        datetime.timedelta(days=2, hours=23) < datetime.datetime.now(datetime.UTC) - after < datetime.timedelta(days=3, hours=1)
    )


def test_get_fetch_filters_rejects_an_unparsable_first_fetch() -> None:
    with pytest.raises(ValueError, match="Could not parse 'first_fetch'"):
        get_fetch_filters({"first_fetch": "garbage"})


def test_get_fetch_filters_rejects_unparsable_dates() -> None:
    with pytest.raises(ValueError, match="Could not parse 'before'"):
        get_fetch_filters({"before": "garbage"})


def test_test_module_and_fetch_send_identical_filters(requests_mock, reco_client: RecoClient) -> None:
    """The Test button must exercise exactly the query fetch-incidents sends."""
    requests_mock.get(ALERTS_LIST_URL, json={"alerts": [], "totalResults": 0})
    filters = get_fetch_filters({k: v for k, v in FETCH_PARAMS.items() if k != "first_fetch"})

    assert reco_client.validate_api_key(**filters) == "ok"
    fetch_incidents(reco_client, last_run={}, max_fetch=10, **filters)

    assert sent_filter(requests_mock, 0) == sent_filter(requests_mock, 1)


def test_list_alerts_command_sends_filters_and_does_not_enrich(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(
        ALERTS_LIST_URL,
        json={
            "alerts": [
                {
                    "id": ALERT_ID,
                    "description": INCIDENT_DESCRIPTION,
                    "severity": "HIGH",
                    "status": "ALERT_STATUS_NEW",
                    "createdAt": "2026-11-02T10:00:00Z",
                    "apps": ["OKTA"],
                    "instance": {"appName": "Okta Prod", "id": "i1"},
                    "customLabels": ["Identity"],
                }
            ],
            "totalResults": 1,
        },
    )

    result = list_alerts_command(
        reco_client,
        {
            "after": "2026-11-01T00:00:00Z",
            "before": "2026-11-08T23:59:59Z",
            "saas_platform": "Okta",
            "risk_level": "HIGH,CRITICAL",
            "labels": "Identity,Privileged Access",
            "exclude_labels": "Noise",
            "status": "new",
            "filters": 'actors co "@example.com"',
            "limit": "500",
        },
    )

    assert len(requests_mock.request_history) == 1  # a single list call, no alert-details calls
    assert sent_filter(requests_mock) == (
        'status ne "ALERT_STATUS_PREVIEW"'
        ' and (severity eq "HIGH" or severity eq "CRITICAL")'
        ' and status eq "ALERT_STATUS_NEW"'
        ' and instance.appName co "Okta"'
        ' and (customLabels eq "Identity" or customLabels eq "Privileged Access")'
        ' and not (customLabels eq "Noise")'
        ' and createdAt gt "2026-11-01T00:00:00Z"'
        ' and createdAt lt "2026-11-08T23:59:59Z"'
        ' and (actors co "@example.com")'
    )
    assert requests_mock.last_request.qs["sortorder"] == ["descending"]
    assert requests_mock.last_request.qs["count"] == ["500"]
    assert result.outputs_prefix == "Reco.Alerts"
    assert result.outputs[0]["id"] == ALERT_ID
    assert "Okta Prod" in result.readable_output


def test_list_alerts_command_paginates_up_to_limit(requests_mock, reco_client: RecoClient) -> None:
    page_1 = build_alerts_list_response([f"a{i}" for i in range(1000)])
    page_2 = build_alerts_list_response([f"b{i}" for i in range(500)])
    requests_mock.get(ALERTS_LIST_URL, [{"json": page_1}, {"json": page_2}])

    result = list_alerts_command(reco_client, {"limit": "1500"})

    assert len(result.outputs) == 1500
    first, second = (r.qs for r in requests_mock.request_history)
    assert (first["startindex"], first["count"]) == (["0"], ["1000"])
    assert (second["startindex"], second["count"]) == (["1000"], ["500"])


def test_list_alerts_command_drops_duplicates_when_pages_shift(requests_mock, reco_client: RecoClient) -> None:
    """If a new alert arrives between page calls, the boundary alert shows up on both pages."""
    page_1 = build_alerts_list_response([f"a{i}" for i in range(1000)])
    page_2 = build_alerts_list_response(["a999", "b1", "b2"])
    requests_mock.get(ALERTS_LIST_URL, [{"json": page_1}, {"json": page_2}])

    result = list_alerts_command(reco_client, {"limit": "1003"})

    ids = [alert["id"] for alert in result.outputs]
    assert len(ids) == len(set(ids)) == 1002
    assert requests_mock.request_history[1].qs["startindex"] == ["1000"]


def test_list_alerts_command_has_no_upper_limit(requests_mock, reco_client: RecoClient) -> None:
    pages = [build_alerts_list_response([f"p{n}-{i}" for i in range(1000)]) for n in range(6)]
    requests_mock.get(ALERTS_LIST_URL, [{"json": page} for page in pages] + [{"json": build_alerts_list_response(["last"])}])

    result = list_alerts_command(reco_client, {"limit": "6001"})

    assert len(result.outputs) == 6001
    assert len(requests_mock.request_history) == 7


def test_list_alerts_command_stops_on_a_short_page(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response(["a", "b"]))

    result = list_alerts_command(reco_client, {"limit": "100"})

    assert len(result.outputs) == 2
    assert len(requests_mock.request_history) == 1


@pytest.mark.parametrize(
    "args, message",
    [
        ({"limit": "0"}, "limit must be a positive number"),
        ({"risk_level": "SEVERE"}, "Unknown risk level"),
        ({"status": "preview"}, "Unknown alert status"),
        ({"after": "garbage"}, "Could not parse 'after'"),
        ({"sort_order": "sideways"}, "sort_order must be"),
    ],
)
def test_list_alerts_command_validates_arguments(requests_mock, reco_client: RecoClient, args, message) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([]))

    with pytest.raises(ValueError, match=message):
        list_alerts_command(reco_client, args)
    assert not requests_mock.request_history


def test_fetch_alerts_command_returns_enriched_alerts(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, "2026-10-05T00:00:00Z"),
    )

    result = fetch_alerts_command(
        reco_client, {"after": "2026-10-01", "before": "2026-10-31", "labels": "Privileged", "limit": "10"}
    )

    assert 'customLabels eq "Privileged"' in sent_filter(requests_mock, 0)
    assert requests_mock.request_history[0].qs["sortorder"] == ["ascending"]
    assert result.outputs_prefix == "Reco.Alerts"
    assert result.outputs[0]["id"] == ALERT_ID
    # policy violation jsonData is parsed, as in fetch-incidents
    assert result.outputs[0]["policyViolations"][0]["jsonData"] == {"id": "91bef1de"}


def test_fetch_alerts_command_has_no_upper_limit_and_enriches_in_pages(requests_mock, reco_client: RecoClient) -> None:
    """A limit above one page is served by paging (500 alerts per list call), not rejected."""
    page_1 = build_alerts_list_response([f"a{i}" for i in range(500)])
    page_2 = build_alerts_list_response(["b0", "b1"])
    requests_mock.get(ALERTS_LIST_URL, [{"json": page_1}, {"json": page_2}])
    requests_mock.get(
        re.compile(r".*/external-api/alert-details/.*"),
        json=lambda request, context: build_alert_detail(request.path.rsplit("/", 1)[1], "d", 30, "2026-10-05T00:00:00Z"),
    )

    result = fetch_alerts_command(reco_client, {"limit": "502"})

    list_calls = [r for r in requests_mock.request_history if r.path.endswith("/alerts/list")]
    assert [(c.qs["startindex"], c.qs["count"]) for c in list_calls] == [(["0"], ["500"]), (["500"], ["2"])]
    assert len(result.outputs) == 502


def test_get_alert_command_returns_alert_with_parsed_violations(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, "2026-10-05T00:00:00Z"),
    )

    result = get_alert_command(reco_client, ALERT_ID)

    assert result.outputs[0]["id"] == ALERT_ID
    assert result.outputs[0]["policyViolations"][0]["jsonData"] == {"id": "91bef1de"}


def test_get_alert_command_not_found_raises(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/missing", json={})

    with pytest.raises(Exception, match="was not found"):
        get_alert_command(reco_client, "missing")


def test_on_demand_alert_commands_never_touch_the_fetch_cursor(requests_mock, mocker, reco_client: RecoClient) -> None:
    """reco-list-alerts / reco-fetch-alerts / reco-get-alert must not read or write last-run."""
    get_last_run = mocker.patch.object(demisto, "getLastRun")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, "2026-10-05T00:00:00Z"),
    )

    list_alerts_command(reco_client, {"after": "2026-10-01", "before": "2026-10-31"})
    fetch_alerts_command(reco_client, {"after": "2026-10-01", "before": "2026-10-31"})
    get_alert_command(reco_client, ALERT_ID)

    get_last_run.assert_not_called()
    set_last_run.assert_not_called()


# --- alert severity and entity labels ---


def test_update_alert_severity_sends_severity_and_returns_alert(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{ALERT_ID}/severity",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 40, "2026-10-05T00:00:00Z"),
    )

    result = update_alert_severity_command(reco_client, ALERT_ID, "critical")

    assert json.loads(requests_mock.last_request.text) == {"severity": "CRITICAL"}
    assert result.outputs_prefix == "Reco.Alerts"
    assert result.outputs["id"] == ALERT_ID
    assert result.outputs["policyViolations"][0]["jsonData"] == {"id": "91bef1de"}
    assert "CRITICAL" in result.readable_output


def test_update_alert_severity_accepts_numeric_level(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{ALERT_ID}/severity", json={"alert": {"id": ALERT_ID}})

    update_alert_severity_command(reco_client, ALERT_ID, "20")

    assert json.loads(requests_mock.last_request.text) == {"severity": "MEDIUM"}


@pytest.mark.parametrize("severity", ["", "HIGH,CRITICAL", "SEVERE"])
def test_update_alert_severity_rejects_invalid_values(requests_mock, reco_client: RecoClient, severity: str) -> None:
    with pytest.raises(ValueError):
        update_alert_severity_command(reco_client, ALERT_ID, severity)
    assert not requests_mock.request_history


def test_update_alert_severity_propagates_api_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{ALERT_ID}/severity", status_code=404, json={})

    with capfd.disabled(), pytest.raises(Exception):
        update_alert_severity_command(reco_client, ALERT_ID, "HIGH")


def test_add_entity_label_command(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/labels/add", json={})

    result = add_entity_label_command(
        reco_client,
        {"entity_id": "e1", "entity_type": "Account", "label_name": "Privileged Access", "instance_id": "i1"},
    )

    assert json.loads(requests_mock.last_request.text) == {
        "entityId": "e1",
        "entityType": "account",
        "labelName": "Privileged Access",
        "instanceId": "i1",
    }
    assert "added" in result.readable_output
    assert result.raw_response == {}


def test_remove_entity_label_command(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/labels/remove", json={})

    result = remove_entity_label_command(reco_client, {"entity_id": "e1", "entity_type": "identity", "label_name": "VIP"})

    assert json.loads(requests_mock.last_request.text) == {"entityId": "e1", "entityType": "identity", "labelName": "VIP"}
    assert "removed" in result.readable_output
    assert result.raw_response == {}


@pytest.mark.parametrize("command", [add_entity_label_command, remove_entity_label_command])
def test_entity_label_commands_reject_unknown_entity_type(requests_mock, reco_client: RecoClient, command) -> None:
    with pytest.raises(ValueError, match="Unknown entity_type"):
        command(reco_client, {"entity_id": "e1", "entity_type": "event", "label_name": "VIP"})
    assert not requests_mock.request_history


def test_remove_entity_label_propagates_api_error(capfd, requests_mock, reco_client: RecoClient) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/labels/remove", status_code=400, json={})

    with capfd.disabled(), pytest.raises(Exception):
        remove_entity_label_command(reco_client, {"entity_id": "e1", "entity_type": "app", "label_name": "VIP"})


# --- main() dispatch: every changed or new command, wired through demisto.params()/args() ---

BASE_PARAMS = {"url": DUMMY_RECO_API_DNS_NAME, "api_token": "token", "max_fetch": "10"}


def run_main(mocker, command: str, params: dict | None = None, args: dict | None = None) -> dict[str, Any]:
    """Run Reco.main() for one command; returns the demisto calls it made."""
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "params", return_value={**BASE_PARAMS, **(params or {})})
    mocker.patch.object(demisto, "args", return_value=args or {})
    calls = {
        "getLastRun": mocker.patch.object(demisto, "getLastRun", return_value={}),
        "setLastRun": mocker.patch.object(demisto, "setLastRun"),
        "incidents": mocker.patch.object(demisto, "incidents"),
        "results": mocker.patch.object(demisto, "results"),
    }
    try:
        Reco.main()
        calls["exited"] = False
    except SystemExit:  # return_error() exits after reporting the error entry
        calls["exited"] = True
    return calls


def test_main_fetch_incidents_applies_every_filter_parameter(requests_mock, mocker) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, datetime.datetime.now().strftime(TIME_FORMAT)),
    )

    calls = run_main(
        mocker,
        "fetch-incidents",
        params={**FETCH_PARAMS, "before": "2099-01-01", "after": "2026-01-01"},
    )

    result = sent_filter(requests_mock, 0)
    assert 'status ne "ALERT_STATUS_PREVIEW"' in result
    assert '(severity eq "HIGH" or severity eq "CRITICAL")' in result
    assert 'apps co "GOOGLE_DRIVE"' in result
    assert '(instance.appName co "Microsoft 365" or instance.appName co "Okta")' in result
    assert '(status eq "ALERT_STATUS_NEW" or status eq "ALERT_STATUS_IN_PROGRESS")' in result
    assert 'customLabels eq "Identity"' in result
    assert 'not (customLabels eq "Noise")' in result
    assert 'createdAt gt "2026-01-01T00:00:00Z"' in result
    assert 'createdAt lt "2099-01-02T00:00:00Z"' in result  # date-only `before` includes the whole day
    assert '(actors co "@example.com")' in result
    calls["setLastRun"].assert_called_once()
    incidents = calls["incidents"].call_args.args[0]
    assert [i["dbotMirrorId"] for i in incidents] == [ALERT_ID]


def test_main_fetch_incidents_with_only_the_defaults_is_unchanged(requests_mock, mocker) -> None:
    """A pre-existing configuration (no new parameters) must send the same query as before."""
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([]))

    run_main(mocker, "fetch-incidents", params={"first_fetch": "7 days"})

    result = sent_filter(requests_mock, 0)
    assert result.startswith('status ne "ALERT_STATUS_PREVIEW" and createdAt gt "')
    for clause in ("severity", "instance.appName", "customLabels", "apps co", "createdAt lt"):
        assert clause not in result


def test_main_test_module_sends_the_fetch_query(requests_mock, mocker) -> None:
    requests_mock.get(ALERTS_LIST_URL, json={"alerts": [], "totalResults": 0})
    params = {k: v for k, v in FETCH_PARAMS.items() if k != "first_fetch"}

    calls = run_main(mocker, "test-module", params=params)
    run_main(mocker, "fetch-incidents", params=params)

    assert calls["results"].call_args.args[0] == "ok"
    assert sent_filter(requests_mock, 0) == sent_filter(requests_mock, 1)
    assert requests_mock.request_history[0].qs["count"] == ["1"]


def test_main_test_module_fails_on_an_invalid_filter_parameter(capfd, mocker) -> None:
    with capfd.disabled():
        calls = run_main(mocker, "test-module", params={"alert_status": "bogus"})

    assert calls["exited"]
    entry = calls["results"].call_args.args[0]
    assert entry["Type"] == 4  # an error entry
    assert "Unknown alert status" in entry["Contents"]


def test_main_on_demand_alert_commands_never_touch_last_run(requests_mock, mocker) -> None:
    requests_mock.get(ALERTS_LIST_URL, json=build_alerts_list_response([ALERT_ID]))
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alert-details/{ALERT_ID}",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 30, "2026-10-05T00:00:00Z"),
    )
    window = {"after": "2026-10-01", "before": "2026-10-31", "labels": "Privileged", "limit": "5"}

    for command, args in [
        ("reco-list-alerts", window),
        ("reco-fetch-alerts", window),
        ("reco-get-alert", {"alert_id": ALERT_ID}),
    ]:
        calls = run_main(mocker, command, args=args)
        calls["getLastRun"].assert_not_called()
        calls["setLastRun"].assert_not_called()
        calls["incidents"].assert_not_called()
        entry = calls["results"].call_args.args[0]
        assert entry["EntryContext"]["Reco.Alerts(val.id && val.id == obj.id)"][0]["id"] == ALERT_ID


def test_main_reco_update_alert_severity(requests_mock, mocker) -> None:
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{ALERT_ID}/severity",
        json=build_alert_detail(ALERT_ID, INCIDENT_DESCRIPTION, 40, "2026-10-05T00:00:00Z"),
    )

    calls = run_main(mocker, "reco-update-alert-severity", args={"alert_id": ALERT_ID, "severity": "CRITICAL"})

    assert json.loads(requests_mock.last_request.text) == {"severity": "CRITICAL"}
    assert "severity updated to CRITICAL" in calls["results"].call_args.args[0]["HumanReadable"]


@pytest.mark.parametrize(
    "command, endpoint, verb",
    [("reco-add-entity-label", "labels/add", "added"), ("reco-remove-entity-label", "labels/remove", "removed")],
)
def test_main_entity_label_commands(requests_mock, mocker, command, endpoint, verb) -> None:
    requests_mock.post(f"{DUMMY_RECO_API_DNS_NAME}/external-api/{endpoint}", json={})

    calls = run_main(
        mocker,
        command,
        args={"entity_id": "e1", "entity_type": "account", "label_name": "VIP", "instance_id": "i1"},
    )

    assert json.loads(requests_mock.last_request.text) == {
        "entityId": "e1",
        "entityType": "account",
        "labelName": "VIP",
        "instanceId": "i1",
    }
    assert verb in calls["results"].call_args.args[0]["HumanReadable"]


def test_main_change_alert_status_and_app_type(requests_mock, mocker) -> None:
    status_url = f"{DUMMY_RECO_API_DNS_NAME}/external-api/alerts/{ALERT_ID}/status"
    requests_mock.post(status_url, json={"alert": {"id": ALERT_ID}})
    auth_url = f"{DUMMY_RECO_API_DNS_NAME}/external-api/apps/app-1/auth-status"
    requests_mock.put(auth_url, json={})

    run_main(mocker, "reco-change-alert-status", args={"alert_id": ALERT_ID, "status": "ALERT_STATUS_IN_PROGRESS"})
    assert json.loads(requests_mock.last_request.text) == {"status": "ALERT_STATUS_IN_PROGRESS"}

    run_main(
        mocker,
        "reco-set-app-authorization-status",
        args={"app_id": "app-1", "authorization_status": "AUTH_STATUS_SANCTIONED", "app_type": "APP_ENTITY_TYPE_SAAS_TO_SAAS"},
    )
    assert json.loads(requests_mock.last_request.text)["appType"] == "APP_ENTITY_TYPE_SAAS_TO_SAAS"

    run_main(
        mocker, "reco-set-app-authorization-status", args={"app_id": "app-1", "authorization_status": "AUTH_STATUS_SANCTIONED"}
    )
    assert "appType" not in json.loads(requests_mock.last_request.text)


def test_main_reports_invalid_arguments_as_errors(capfd, mocker) -> None:
    with capfd.disabled():
        calls = run_main(mocker, "reco-list-alerts", args={"risk_level": "SEVERE"})

    assert calls["exited"]
    entry = calls["results"].call_args.args[0]
    assert entry["Type"] == 4
    assert "Unknown risk level" in entry["Contents"]


def test_integration_yml_has_no_duplicate_configuration_parameters() -> None:
    """A duplicated parameter (e.g. a second "Fetch incidents" checkbox) shows up twice in the XSOAR UI."""
    yml_path = os.path.join(os.path.dirname(__file__), "Reco.yml")
    with open(yml_path) as yml_file:
        names = [param["name"] for param in yaml.safe_load(yml_file)["configuration"]]

    assert len(names) == len(
        set(names)
    ), f"duplicate configuration parameters: {sorted({n for n in names if names.count(n) > 1})}"
    assert names.count("isFetch") == 1
    assert names.count("incidentType") == 1
