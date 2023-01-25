import json

from typing import List, Dict, Any

import base64

import pytest
import datetime
from Reco import RecoClient, BaseClient, fetch_incidents

from structs import (
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
    assert res is "ok"


@pytest.fixture
def reco_client() -> RecoClient:
    api_token = "dummy api key"
    client = BaseClient(
        base_url=DUMMY_RECO_API_DNS_NAME,
        verify=True,
        headers={"Authorization": f"Token {api_token}"},
        proxy=True,
    )
    return RecoClient(client=client)


def test_fetch_incidents_should_succeed(requests_mock, reco_client: RecoClient) -> None:
    random_incidents = get_random_table_response()
    assets = get_mock_assets()
    requests_mock.put(f"{DUMMY_RECO_API_DNS_NAME}/incident", json=random_incidents)
    requests_mock.get(f"{DUMMY_RECO_API_DNS_NAME}/incident/assets/{INCIDET_ID_UUID}", json=assets)
    last_run, fetched_incidents = fetch_incidents(
        reco_client=reco_client, last_run={}, max_fetch=1
    )
    assert (
        len(fetched_incidents)
        == random_incidents.getTableResponse.total_number_of_results
    )
    assert fetched_incidents[0].get("name") == INCIDENT_DESCRIPTION
    assert fetched_incidents[0].get("dbotMirrorId") == INCIDET_ID_UUID
    res_json = json.loads(fetched_incidents[0].get("rawJSON"))
    assert res_json.get("assets", {}) == assets.get("assets")
