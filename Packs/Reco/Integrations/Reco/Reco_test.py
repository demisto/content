import json
import uuid

from typing import List, Dict, Any

import base64

import pytest
import datetime
from Reco import RecoClient, fetch_incidents, map_reco_score_to_demisto_score, get_max_fetch

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


def get_mock_assets() -> List[Dict[str, Any]]:
    return dict(assets=[{"entityId": "1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1", "name": "Untitled document",
                         "link": "https://drive.google.com/file/d/1Fk-_IB4nAWh5TRkG7bV7LKj15ZQP0DimklY2fr5fKX1",
                         "dataSource": "GSUITE_GDRIVE_AUDIT_LOG_API", "type": "ASSET_TYPE_FILE", "attributes": {},
                         "owner": "test@acme.com"}])


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
    return RecoClient(api_token=api_token, base_url=DUMMY_RECO_API_DNS_NAME, verify=True, proxy=True)


def test_fetch_incidents_should_succeed(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, risk_level=40, before=datetime.datetime.now(), last_run={}, max_fetch=1
    )
    assert len(fetched_incidents) == random_incidents.getTableResponse.total_number_of_results
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == assets.get("assets")


def test_fetch_same_incidents(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, risk_level=40, before=datetime.datetime.now(), last_run={}, max_fetch=1
    )
    assert len(fetched_incidents) == random_incidents.getTableResponse.total_number_of_results
    last_run, incidents = fetch_incidents(
        reco_client=reco_client, risk_level=40, before=datetime.datetime.now(), last_run=last_run, max_fetch=1
    )
    assert len(incidents) == 0


def test_fetch_incidents_without_assets_info(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json={})
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, source="GOOGLE_DRIVE", max_fetch=1
    )
    assert len(fetched_incidents) == random_incidents.getTableResponse.total_number_of_results
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == []


def test_fetch_assets_with_empty_response(requests_mock, reco_client: RecoClient) -> None:
    incident_id = uuid.uuid1()
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{incident_id}", json={})
    assets = reco_client.get_incidents_assets(incident_id=incident_id)
    assert assets == []


def test_empty_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=GetIncidentTableResponse(
        get_table_response=GetTableResponse(data=TableData(rows=[]), total_number_of_results=0, table_definition="",
                                            dynamic_table_definition="", token="")))
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )

    assert len(fetched_incidents) == 0
    assert last_run is not None


def test_empty_valid_response(requests_mock, reco_client: RecoClient) -> None:
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=GetIncidentTableResponse(
        get_table_response=GetTableResponse(data=TableData(rows=[]), total_number_of_results=0, table_definition="",
                                            dynamic_table_definition="", token="")))
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
        source="GSUITE_GDRIVE_AUDIT_LOG_API"
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
