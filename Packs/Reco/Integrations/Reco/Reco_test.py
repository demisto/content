import json
import uuid

from typing import Any

import base64

import pytest
import datetime

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
    files = [{"id": "asset-id", "name": "sensitive.txt", "owner": "test@acme.com", "sensitivityLevel": "40"}]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/files/list", json={"files": files, "totalResults": len(files)})
    actual_result = get_sensitive_assets_by_id(reco_client=reco_client, asset_id="asset-id")
    assert len(actual_result.outputs) == len(files)
    assert actual_result.outputs[0].get("id") is not None


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
    alert_id = uuid.uuid1()
    status = "ALERT_STATUS_CLOSED"
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
    users = [{"email": "charles@corp.com", "fullName": "Yossi", "departments": ["Pro"], "category": "external"}]
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/external-api/users/list", json={"users": users, "totalResults": len(users)})
    res = get_user_context_by_email_address(reco_client, "charles@corp.com")
    assert res.outputs_prefix == "Reco.User"
    assert res.outputs.get("email") != ""
    assert res.outputs.get("email") == "charles@corp.com"


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
