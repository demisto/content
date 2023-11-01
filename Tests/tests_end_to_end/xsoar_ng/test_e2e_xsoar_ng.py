import time
from datetime import timedelta
from datetime import datetime
from contextlib import contextmanager

import pytest
import requests
from typing import Tuple, List, Dict, Set
from demisto_client.demisto_api import IncidentWrapper
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.utils.utils import retry_http_request
from Tests.tools import get_integration_params


@contextmanager
def create_indicators(xsoar_ng_client: XsoarNGApiClient, indicators: List[Tuple[str, str, int]]):
    indicators_to_remove = []
    try:
        for indicator, indicator_type, score in indicators:
            try:
                response = xsoar_ng_client.create_indicator(indicator, indicator_type=indicator_type, score=score)
                if created_indicator_id := response.get("id"):
                    indicators_to_remove.append(created_indicator_id)
            except ApiException as e:
                if "it is in the exclusion list" not in e.reason:
                    raise
        yield
    finally:
        _response = xsoar_ng_client.delete_indicators(indicators_to_remove)
        successful_removed_ids = set(_response.get("updatedIds") or [])
        assert set(indicators_to_remove).issubset(successful_removed_ids)


@pytest.fixture()
def available_indicators(xsoar_ng_client: XsoarNGApiClient) -> List[str]:
    return [indicator.get("value") for indicator in xsoar_ng_client.list_indicators().get("iocObjects")]


@contextmanager
def create_integration_instance(xsoar_ng_client: XsoarNGApiClient, integration_params: Dict, integration_id: str, is_long_running: bool = False, instance_name: str | None = None):
    created_instance_uuid = ""
    try:
        response = xsoar_ng_client.create_integration_instance(
            _id=integration_id,
            name=instance_name,
            integration_instance_config=integration_params,
            integration_log_level="Verbose",
            is_long_running=is_long_running
        )
        created_instance_uuid = response.get("id")
        yield response
    finally:
        if created_instance_uuid:
            xsoar_ng_client.delete_integration_instance(created_instance_uuid)


@contextmanager
def create_incident(
    xsoar_ng_client: XsoarNGApiClient, name: str | None = None, playbook_id: str | None = None
) -> IncidentWrapper:
    incident_id = None
    try:
        response = xsoar_ng_client.create_incident(
            name or f'end-to-end-{playbook_id}-incident', should_create_investigation=True, attached_playbook_id=playbook_id
        )
        incident_id = response.id
        yield response
    finally:
        if incident_id:
            xsoar_ng_client.delete_incidents(incident_id)


@contextmanager
def create_playbook(xsoar_ng_client: XsoarNGApiClient, playbook_path: str, playbook_id: str, playbook_name: str):
    try:
        xsoar_ng_client.client.import_playbook(playbook_path)
        yield
    finally:
        xsoar_ng_client.delete_playbook(playbook_name, playbook_id)


@retry_http_request(times=30, delay=5)
def is_playbook_state_as_expected(xsoar_ng_client: XsoarNGApiClient, incident_id: str, expected_states: Set[str]):
    playbook_status_raw_response = xsoar_ng_client.get_playbook_state(incident_id)
    _playbook_status = playbook_status_raw_response.get("state", "").lower()
    if _playbook_status in expected_states:
        return True
    raise Exception(f'the status of the playbook {playbook_status_raw_response} is {_playbook_status}')


@retry_http_request(times=30, delay=5)
def is_incident_state_as_expected(xsoar_ng_client: XsoarNGApiClient, incident_id: str, expected_state: str = "closed"):

    incident_status = {
        0: "new",  # pending
        1: "in_progress",  # active
        2: "closed",  # done
        3: "acknowledged"  # archived
    }

    incident_response = xsoar_ng_client.search_incidents(incident_ids=incident_id)
    # status 2 means the incident is closed.
    incident_status = incident_status.get(incident_response["data"][0].get("status"))
    if incident_status == expected_state:
        return True
    raise Exception(f'incident {incident_response} status is {incident_status} and is not in state {expected_state}')


@contextmanager
def get_fetched_incident(
    xsoar_ng_client: XsoarNGApiClient,
    incident_ids: List | str | None = None,
    from_date: str | None = None,
    incident_types: List | str | None = None,
    should_start_investigation: bool = True,
    should_remove_fetched_incidents: bool = True
):
    @retry_http_request(times=30, delay=3)
    def _get_fetched_incident():
        _found_incidents = xsoar_ng_client.search_incidents(
            incident_ids, from_date=from_date, incident_types=incident_types, size=1
        )
        if data := _found_incidents.get("data"):
            return data
        raise Exception(
            f'Could not get incident with filters: {incident_ids=}, {from_date=}, {incident_types=}'
        )

    try:
        found_incidents = _get_fetched_incident()
        amount_of_found_incidents = len(found_incidents)

        assert amount_of_found_incidents == 1, f'Found {amount_of_found_incidents} incidents'
        incident = found_incidents[0]
        if incident_types:
            assert incident["type"] == incident_types, f'Found wrong incident {incident} type'

        if should_start_investigation:
            start_investigation_response = xsoar_ng_client.start_incident_investigation(incident.get("id") or "")
            incident["investigationId"] = start_investigation_response.get("response", {}).get("id")

        yield incident

    finally:
        if should_remove_fetched_incidents:
            incidents_to_remove = xsoar_ng_client.search_incidents(
                incident_ids, from_date=from_date, incident_types=incident_types
            )
            if incident_ids_to_remove := [_incident.get("id") for _incident in incidents_to_remove.get("data", [])]:
                xsoar_ng_client.delete_incidents(incident_ids_to_remove)


def test_edl(request, xsoar_ng_client: XsoarNGApiClient, available_indicators: List[str]):
    """
    Given:
        - indicators in xsoar-ng
        - long-running EDL instance
    When:
        - Trying to query the URL of edl
    Then:
        - make sure that indicators are returned in the response of edl instance
    """
    integration_params = get_integration_params(
        request.config.option.integration_secrets_path, instance_name="edl_e2e_instance"
    )
    username = integration_params["credentials"]["identifier"]
    password = integration_params["credentials"]["password"]

    with create_indicators(xsoar_ng_client, [("1.1.1.1", "IP", 0), ("2.2.2.2", "IP", 0), ("3.3.3.3", "IP", 0)]):
        with create_integration_instance(
            xsoar_ng_client,
            integration_params=integration_params,
            integration_id="EDL",
            is_long_running=True,
            instance_name=integration_params.pop(
                "integrationInstanceName", f'e2e-test-{integration_params.get("name", "EDL")}'
            )
        ) as edl_instance_response:
            instance_name = edl_instance_response.get("name")

            edl_response = xsoar_ng_client.do_long_running_instance_request(
                instance_name, username=username, password=password
            )
            assert edl_response.text, f'could not get indicators from url={edl_response.request.url} from ' \
                                      f'instance {instance_name} with available indicators={available_indicators},' \
                                      f' status code={edl_response.status_code}, response={edl_response.text}'


def test_taxii2_server(
    request, xsoar_ng_client: XsoarNGApiClient, available_indicators: List[str]
):
    """
    Given:
        - indicators in xsoar-ng
        - long-running taxii2 server instance
    When:
        - Trying to query the URL(s) of taxii2 server
    Then:
        - make sure that indicators are returned in the response of taxii2 server instance
    """

    def get_json_response(_response: requests.Response) -> dict:
        try:
            return _response.json()
        except ValueError as e:
            raise ValueError(f'Could not parse {_response.text}, error: {e}')

    integration_params = get_integration_params(
        request.config.option.integration_secrets_path, instance_name="taxii2server-e2e"
    )
    username = integration_params["credentials"]["identifier"]
    password = integration_params["credentials"]["password"]
    headers = {"Accept": "application/taxii+json;version=2.1"}

    with create_indicators(xsoar_ng_client, [("1.1.1.1", "IP", 0), ("2.2.2.2", "IP", 0), ("3.3.3.3", "IP", 0)]):
        with create_integration_instance(
            xsoar_ng_client,
            integration_params=integration_params,
            integration_id="TAXII2 Server",
            is_long_running=True,
            instance_name=integration_params.pop(
                "integrationInstanceName", f'e2e-test-{integration_params.get("name", "TAXII2-Server")}'
            )
        ) as taxii2_instance_response:
            instance_name = taxii2_instance_response.get("name")
            response = xsoar_ng_client.do_long_running_instance_request(
                instance_name,
                url_suffix="/threatintel/collections",
                headers=headers,
                username=username,
                password=password
            )

            # get the collections available
            collections = get_json_response(response).get("collections")
            assert collections, f'could not get collections from url={response.request.url}, ' \
                                f'status_code={response.status_code}, response={collections}'

            collection_id = collections[0]["id"]

            # get the actual indicators from the collection
            response = xsoar_ng_client.do_long_running_instance_request(
                instance_name,
                url_suffix=f"/threatintel/collections/{collection_id}/objects",
                headers=headers,
                username=username,
                password=password
            )

            indicators = get_json_response(response).get("objects")
            assert indicators, f'could not get indicators from url={response.request.url} with available ' \
                               f'indicators={[indicator.get("value") for indicator in xsoar_ng_client.list_indicators()]}, ' \
                               f'status code={response.status_code}, response={indicators}'


def test_slack_ask(request, xsoar_ng_client: XsoarNGApiClient):
    """
    Given:
        - playbook that runs slack-ask (runs SlackAskV2 and then answers the slack ask with the slack V3 integration)
        - slack V3 integration
    When:
        - running slack ask flow with slack V3
    Then:
        - make sure that the slack ask flow worked properly
        - make sure that the playbook finishes.
        - make sure that the context is populated with thread ID(s) from the slack-ask and slack-response.
    """
    integration_params = get_integration_params(
        request.config.option.integration_secrets_path, instance_name="slack-e2e-instance"
    )

    with create_integration_instance(
        xsoar_ng_client,
        integration_params=integration_params,
        integration_id="SlackV3",
        is_long_running=True,
        instance_name=integration_params.pop(
            "integrationInstanceName", f'e2e-test-{integration_params.get("name", "SlackV3")}'
        )
    ):
        playbook_id_name = "TestSlackAskE2E"
        with create_playbook(
            xsoar_ng_client,
            playbook_path="TestSlackAskE2E.yml",
            playbook_id=playbook_id_name,
            playbook_name=playbook_id_name
        ):
            with create_incident(xsoar_ng_client, playbook_id=playbook_id_name) as incident_response:
                # make sure the playbook finished successfully
                assert is_playbook_state_as_expected(
                    xsoar_ng_client, incident_id=incident_response.id, expected_states={"completed"}
                )

                context = xsoar_ng_client.get_investigation_context(incident_response.investigation_id)
                # make sure the context is populated with thread id(s) from slack ask
                assert context.get("Slack", {}).get("Thread"), f'thread IDs do not exist in context {context}'


def test_qradar_mirroring(request, xsoar_ng_client: XsoarNGApiClient):
    """
    Given:
        - a QRadar offense that is fetched through the integration that is in "OPENED" state.
        - QRadar V3 integration
    When:
        - closing the offense in Qradar
    Then:
        - make sure that the QRadar offense was closed successfully when trying to close it via QRadar api.
        - make sure that the XSOAR incident that represent the offense is closed after it by mirroring.
    """
    integration_params = get_integration_params(
        request.config.option.integration_secrets_path, instance_name="qradar-e2e-instance"
    )

    with create_integration_instance(
        xsoar_ng_client,
        integration_params=integration_params,
        integration_id="QRadar v3",
        is_long_running=True,
        instance_name=integration_params.pop(
            "integrationInstanceName", f'e2e-test-{integration_params.get("name", "Qradar-v3")}'
        )
    ):
        with get_fetched_incident(
            xsoar_ng_client,
            from_date=(datetime.utcnow() - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S"),  # get the incident created in the last 30 seconds
            incident_types=integration_params["incident_type"]
        ) as qradar_incident_response:
            offense_id = qradar_incident_response.get("CustomFields", {}).get("idoffense")
            assert offense_id, f'offense ID is empty in {qradar_incident_response}'
            incident_id = qradar_incident_response.get("id")
            investigation_id = qradar_incident_response.get("investigationId")
            assert incident_id, f'investigation ID is empty in {qradar_incident_response}'

            # TODO - check how to get rid of the sleep to make it work
            time.sleep(180)
            # close the qradar offense
            _, context = xsoar_ng_client.run_cli_command(
                f"!qradar-offense-update offense_id={offense_id} closing_reason_id=1 status=CLOSED",
                investigation_id=investigation_id
            )
            assert context.get("QRadar", {}).get("Offense", {}).get("Status") == "CLOSED"

            # make sure the incident gets closed after closing it in Qradar
            assert is_incident_state_as_expected(xsoar_ng_client, incident_id, expected_state="closed")

