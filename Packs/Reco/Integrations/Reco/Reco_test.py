import json
import uuid

from typing import List, Dict, Any

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
)

from test_data.structs import (
    TableData,
    RowData,
    KeyValuePair,
    RiskLevel,
    GetTableResponse,
    GetIncidentTableResponse,
)

DUMMY_RECO_API_DNS_NAME = "https://dummy.reco.ai/api"
INCIDET_ID_UUID = "87799f2f-c012-43b6-ace2-78ec984427f3"
INCIDENT_DESCRIPTION = "Sensitive files are accessible to anyone who has their link"
ENCODING = "utf-8"
INCIDENT_STATUS = "INCIDENT_STATE_UNMARKED"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def get_random_table_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="incident_id",
                                value=base64.b64encode(
                                    INCIDET_ID_UUID.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="incident_description",
                                value=base64.b64encode(
                                    INCIDENT_DESCRIPTION.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="risk_level",
                                value=base64.b64encode(
                                    str(RiskLevel.HIGH.value).encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="event_time",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="updated_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="status",
                                value=base64.b64encode(
                                    INCIDENT_STATUS.encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_random_assets_user_has_access_to_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="source",
                                value=base64.b64encode(
                                    "GDRIVE_ACCESS_LOG_AP".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_type",
                                value=base64.b64encode(
                                    "document".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="currently_permitted_users",
                                value=base64.b64encode(
                                    json.dumps(["a", "b", "c", "d", "e"]).encode(
                                        ENCODING
                                    )
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="labels",
                                value=base64.b64encode(
                                    json.dumps(["a", "b", "c", "d", "e"]).encode(
                                        ENCODING
                                    )
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="delete_state",
                                value=base64.b64encode(
                                    "active".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_size",
                                value=base64.b64encode("0".encode(ENCODING)).decode(
                                    ENCODING
                                ),
                            ),
                            KeyValuePair(
                                key="file_name",
                                value=base64.b64encode(
                                    "User Activity Report".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="visibility",
                                value=base64.b64encode(
                                    "shared_internally".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="file_id",
                                value=base64.b64encode("1".encode(ENCODING)).decode(
                                    ENCODING
                                ),
                            ),
                            KeyValuePair(
                                key="file_owner",
                                value=base64.b64encode("a".encode(ENCODING)).decode(
                                    ENCODING
                                ),
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


def get_random_risky_users_response() -> GetIncidentTableResponse:
    return GetIncidentTableResponse(
        get_table_response=GetTableResponse(
            data=TableData(
                rows=[
                    RowData(
                        cells=[
                            KeyValuePair(
                                key="full_name",
                                value=base64.b64encode(
                                    "John Doe".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="email_account",
                                value=base64.b64encode(
                                    f"{uuid.uuid4()}@acme.com".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="risk_level",
                                value=base64.b64encode(
                                    str(RiskLevel.HIGH.value).encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="added_by",
                                value=base64.b64encode(
                                    "system".encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                            KeyValuePair(
                                key="created_at",
                                value=base64.b64encode(
                                    datetime.datetime.now()
                                    .strftime(TIME_FORMAT)
                                    .encode(ENCODING)
                                ).decode(ENCODING),
                            ),
                        ]
                    )
                ]
            ),
            total_number_of_results=1,
            table_definition="",
            dynamic_table_definition="",
            token="",
        ),
    )


def get_mock_assets() -> List[Dict[str, Any]]:
    return dict(
        assets=[
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
    )


def test_test_module_success(requests_mock, reco_client: RecoClient) -> None:
    mock_response = {"listTablesResponse": {"tablesMetadata": [{"name": "table1"}]}}
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/incident-tables/tables", json=mock_response
    )

    res = reco_client.validate_api_key()
    assert res == "ok"


@pytest.fixture
def reco_client() -> RecoClient:
    api_token = "dummy api key"
    return RecoClient(
        api_token=api_token, base_url=DUMMY_RECO_API_DNS_NAME, verify=True, proxy=True
    )


def test_fetch_incidents_should_succeed(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )
    assert (
        len(fetched_incidents)
        == random_incidents.getTableResponse.total_number_of_results
    )
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == assets.get("assets")


def test_fetch_same_incidents(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        before=datetime.datetime.now(),
        last_run={},
        max_fetch=1,
    )
    assert (
        len(fetched_incidents)
        == random_incidents.getTableResponse.total_number_of_results
    )
    last_run, incidents = fetch_incidents(
        reco_client=reco_client,
        risk_level=40,
        before=datetime.datetime.now(),
        last_run=last_run,
        max_fetch=1,
    )
    assert len(incidents) == 0


def test_fetch_incidents_without_assets_info(
    requests_mock, reco_client: RecoClient
) -> None:
    random_incidents = get_random_table_response()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json={}
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, source="GOOGLE_DRIVE", max_fetch=1
    )
    assert (
        len(fetched_incidents)
        == random_incidents.getTableResponse.total_number_of_results
    )
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == []


def test_fetch_assets_with_empty_response(
    requests_mock, reco_client: RecoClient
) -> None:
    incident_id = uuid.uuid1()
    requests_mock.get(
        f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{incident_id}", json={}
    )
    assets = reco_client.get_incidents_assets(incident_id=incident_id)
    assert assets == []


def test_empty_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident",
        json=GetIncidentTableResponse(
            get_table_response=GetTableResponse(
                data=TableData(rows=[]),
                total_number_of_results=0,
                table_definition="",
                dynamic_table_definition="",
                token="",
            )
        ),
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_empty_valid_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident",
        json=GetIncidentTableResponse(
            get_table_response=GetTableResponse(
                data=TableData(rows=[]),
                total_number_of_results=0,
                table_definition="",
                dynamic_table_definition="",
                token="",
            )
        ),
    )
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_invalid_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json={})
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client,
        last_run={},
        max_fetch=1,
        risk_level=str(RiskLevel.HIGH),
        source="GSUITE_GDRIVE_AUDIT_LOG_API",
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_risk_level_mapper():
    risk_level_high = 40
    assert map_reco_score_to_demisto_score(risk_level_high) == 4


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
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident-timeline/{str(incident_id)}",
        json={},
        status_code=200,
    )
    res = reco_client.update_reco_incident_timeline(
        incident_id=str(incident_id), comment="test"
    )
    assert res == {}


def test_update_reco_incident_timeline_error(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    incident_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/incident-timeline/{str(incident_id)}",
        json={},
        status_code=404,
    )
    with capfd.disabled():
        with pytest.raises(Exception):
            reco_client.update_reco_incident_timeline(
                incident_id=str(incident_id), comment="test"
            )


def test_resolve_visibility_event(requests_mock, reco_client: RecoClient) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=200
    )
    res = reco_client.resolve_visibility_event(
        entity_id=str(entry_id), label_name="Accessible by all"
    )
    assert res == {}


def test_resolve_visibility_event_error(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    entry_id = uuid.uuid1()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/set-label-status", json={}, status_code=404
    )
    with capfd.disabled():
        with pytest.raises(Exception):
            reco_client.resolve_visibility_event(
                entity_id=str(entry_id), label_name="Accessible by all"
            )


def test_get_risky_users(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_risky_users_response()
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json=raw_result,
        status_code=200,
    )
    actual_result = get_risky_users_from_reco(reco_client=reco_client)
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert "@" in actual_result.outputs[0].get("email_account")


def test_get_risky_users_bad_response(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/risk-management/get-risk-management-table",
        json={},
        status_code=200,
    )
    with capfd.disabled():
        with pytest.raises(Exception):
            get_risky_users_from_reco(reco_client=reco_client)


def test_add_risky_user_label(requests_mock, reco_client: RecoClient) -> None:
    label_id = f"{uuid.uuid1()}@gmail.com"
    requests_mock.put(
        f"{DUMMY_RECO_API_DNS_NAME}/entry-labels/{label_id}", json={}, status_code=200
    )
    res = add_risky_user_label(reco_client=reco_client, email_address=label_id)
    assert "labeled as risky" in res.readable_output


def test_get_assets_user_has_access_to(requests_mock, reco_client: RecoClient) -> None:
    raw_result = get_random_assets_user_has_access_to_response()
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management", json=raw_result, status_code=200
    )
    actual_result = get_assets_user_has_access(
        reco_client=reco_client,
        email_address=f"{uuid.uuid1()}@gmail.com",
        only_sensitive=False,
    )
    assert len(actual_result.outputs) == len(raw_result.getTableResponse.data.rows)
    assert actual_result.outputs[0].get("source") is not None


def test_get_assets_user_bad_response(
    capfd, requests_mock, reco_client: RecoClient
) -> None:
    requests_mock.post(
        f"{DUMMY_RECO_API_DNS_NAME}/asset-management", json={}, status_code=200
    )
    with capfd.disabled():
        with pytest.raises(Exception):
            get_assets_user_has_access(reco_client=reco_client)
