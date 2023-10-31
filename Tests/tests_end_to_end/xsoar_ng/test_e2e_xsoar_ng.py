import time
from datetime import timedelta
from datetime import datetime

import pytest
import requests
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.utils.utils import retry_http_request


@pytest.fixture()
def create_indicators(request, xsoar_ng_client: XsoarNGApiClient):

    response = xsoar_ng_client.list_indicators()
    if response.get("total") > 0:
        return

    indicators = getattr(request.cls, "indicators", [])
    indicators_to_remove = []
    for indicator, indicator_type, score in indicators:
        try:
            response = xsoar_ng_client.create_indicator(indicator, indicator_type=indicator_type, score=score)
            if created_indicator_id := response.get("id"):
                indicators_to_remove.append(created_indicator_id)
        except ApiException as e:
            if "it is in the exclusion list" not in e.reason:
                raise

    def delete_indicators():
        _response = xsoar_ng_client.delete_indicators(indicators_to_remove)
        successful_removed_ids = set(_response.get("updatedIds") or [])
        assert set(indicators_to_remove).issubset(successful_removed_ids)

    if indicators_to_remove:
        request.addfinalizer(delete_indicators)


@pytest.fixture()
def create_instance(request, integration_params: dict, xsoar_ng_client: XsoarNGApiClient):

    integration_id = request.cls.integration_id
    is_long_running = getattr(request.cls, "is_long_running", False)
    instance_name = integration_params.pop("integrationInstanceName", f'e2e-test-{integration_params.get("name", integration_id)}')
    response = xsoar_ng_client.create_integration_instance(
        _id=integration_id,
        name=instance_name,
        integration_instance_config=integration_params,
        integration_log_level="Verbose",
        is_long_running=is_long_running
    )
    assert response
    created_instance_id = response.get("id")

    def delete_instance():
        xsoar_ng_client.delete_integration_instance(created_instance_id)

    request.addfinalizer(delete_instance)
    return instance_name


@pytest.fixture()
def create_incident(request, xsoar_ng_client: XsoarNGApiClient):
    integration_id = request.cls.integration_id
    playbook_id = request.cls.playbook_id
    response = xsoar_ng_client.create_incident(f'end-to-end-{integration_id}-test', should_create_investigation=True, attached_playbook_id=playbook_id)

    incident_id = response.id

    def delete_incident():
        xsoar_ng_client.delete_incidents(incident_id)

    request.addfinalizer(delete_incident)
    return response


@pytest.fixture()
def create_playbook(request, xsoar_ng_client: XsoarNGApiClient):

    playbook_path = request.cls.playbook_path
    xsoar_ng_client.client.import_playbook(playbook_path)

    playbook_id = request.cls.playbook_id
    playbook_name = request.cls.playbook_name

    def delete_playbook():
        xsoar_ng_client.delete_playbook(playbook_name, playbook_id)

    request.addfinalizer(delete_playbook)


class TestEDL:
    """
    Tests EDL on xsoar-ng
    """
    indicators = [
        ("1.1.1.1", "IP", 0),
        ("2.2.2.2", "IP", 0),
        ("3.3.3.3", "IP", 0)
    ]
    instance_name_gsm = "edl_e2e_instance"
    integration_id = "EDL"
    is_long_running = True

    def test_edl(self, xsoar_ng_client: XsoarNGApiClient, create_indicators, create_instance: str, integration_params: dict):
        """
        Given:
            - indicators in xsoar-ng
            - long-running EDL instance
        When:
            - Trying to query the URL of edl
        Then:
            - make sure that indicators are returned in the response of edl instance
        """
        instance_name = create_instance
        username = integration_params["credentials"]["identifier"]
        password = integration_params["credentials"]["password"]

        response = xsoar_ng_client.do_long_running_instance_request(instance_name, username=username, password=password)
        assert response.text, f'could not get indicators from url={response.request.url} with available ' \
                              f'indicators={[indicator.get("value") for indicator in xsoar_ng_client.list_indicators()]}, ' \
                              f'status code={response.status_code}, response={response.text}'


class TestTaxii2Server:
    """
    Tests taxii2-server on xsoar-ng
    """
    indicators = [
        ("1.1.1.1", "IP", 0),
        ("2.2.2.2", "IP", 0),
        ("3.3.3.3", "IP", 0)
    ]
    instance_name_gsm = "taxii2server-e2e"
    integration_id = "TAXII2 Server"
    is_long_running = True

    def test_taxii2_server(
        self, xsoar_ng_client: XsoarNGApiClient, create_indicators, create_instance: str, integration_params: dict
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
        instance_name = create_instance
        username = integration_params["credentials"]["identifier"]
        password = integration_params["credentials"]["password"]
        headers = {"Accept": "application/taxii+json;version=2.1"}

        def get_json_response(_response: requests.Response) -> dict:
            try:
                return _response.json()
            except ValueError as e:
                raise ValueError(f'Could not parse {_response.text}, error: {e}')

        response = xsoar_ng_client.do_long_running_instance_request(
            instance_name, url_suffix="/threatintel/collections", headers=headers, username=username, password=password
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


class TestSlack:

    instance_name_gsm = "cached"
    integration_id = "SlackV3"
    is_long_running = True
    playbook_path = "Tests/tests_end_to_end/xsoar_ng/TestSlackAskE2E.yml"
    # playbook_path = "TestSlackAskE2E.yml"
    playbook_id = "TestSlackAskE2E"
    playbook_name = "TestSlackAskE2E"

    def test_slack_ask(self, xsoar_ng_client: XsoarNGApiClient, create_instance: str, create_playbook, create_incident):
        """
        Given:
            - playbook that runs slack-ask (runs SlackAskV2 and then answers the slack ask with the slack V3 integration)
            - slack V3 integration
        When:
            - running slack ask flow with slack V3
        Then:
            - make sure that the playbook finishes.
            - make sure that the context is populated with thread ID(s) from the slack-ask and slack-response.
        """
        investigation_id = create_incident.investigation_id
        incident_id = create_incident.id

        playbook_status = xsoar_ng_client.get_playbook_state(incident_id)
        playbook_state = playbook_status.get("state", "").lower()
        while playbook_state not in {"completed", "failed"}:
            playbook_status = xsoar_ng_client.get_playbook_state(incident_id)
            playbook_state = playbook_status.get("state", "").lower()

        # make sure the playbook finished successfully.
        assert playbook_state == "completed", f'playbook state ended with status {playbook_state}, full playbook status response: {playbook_status}'

        context = xsoar_ng_client.get_investigation_context(investigation_id)
        # make sure the context is populated with thread id(s) from slack ask
        assert context.get("Slack", {}).get("Thread"), f'thread IDs do not exist in context {context}'


class TestQradar:
    instance_name_gsm = "qradar-e2e-instance"
    integration_id = "QRadar v3"
    is_long_running = True

    @pytest.fixture()
    def qradar_incident(self, request, xsoar_ng_client: XsoarNGApiClient, integration_params: dict) -> dict:
        thirthy_seconds_ago = (datetime.utcnow() - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S")
        qradar_incident_type = integration_params["incident_type"]

        @retry_http_request(times=20, delay=3)
        def get_fetched_offense():
            _found_incidents = xsoar_ng_client.search_incidents(from_date=thirthy_seconds_ago, incident_types=qradar_incident_type, size=1)
            if data := _found_incidents.get("data"):
                return data
            raise Exception(f"Could not get qradar offense with filters: {thirthy_seconds_ago=}, {qradar_incident_type}, got {_found_incidents}")

        def remove_qradar_fetched_incidents():
            incidents_to_remove = xsoar_ng_client.search_incidents(from_date=thirthy_seconds_ago, incident_types=qradar_incident_type)
            if incident_ids_to_remove := [_incident.get("id") for _incident in incidents_to_remove.get("data", [])]:
                xsoar_ng_client.delete_incidents(incident_ids_to_remove)

        request.addfinalizer(remove_qradar_fetched_incidents)

        found_incidents = get_fetched_offense()
        amount_of_found_incidents = len(found_incidents)

        assert amount_of_found_incidents == 1, f'Found {amount_of_found_incidents} incidents'
        _qradar_incident = found_incidents[0]
        assert _qradar_incident["type"] == qradar_incident_type, f'Found wrong incident {_qradar_incident}'

        start_investigation_response = xsoar_ng_client.start_incident_investigation(_qradar_incident.get("id") or "")
        _qradar_incident["investigationId"] = start_investigation_response.get("response", {}).get("id")

        return _qradar_incident

    def test_qradar_mirroring(self, xsoar_ng_client: XsoarNGApiClient, create_instance: str, qradar_incident: dict):
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
        offense_id = qradar_incident.get("CustomFields", {}).get("idoffense")
        incident_id = qradar_incident.get("id")
        investigation_id = qradar_incident.get("investigationId")

        # TODO - check how to get rid of the sleep to make it work
        time.sleep(180)
        _, context = xsoar_ng_client.run_cli_command(
            f"!qradar-offense-update offense_id={offense_id} closing_reason_id=1 status=CLOSED", investigation_id=investigation_id
        )
        assert context.get("QRadar", {}).get("Offense", {}).get("Status") == "CLOSED"

        # wait maximum 5 minutes that the qradar incident will be closed.
        @retry_http_request(times=60, delay=5)
        def validate_offense_is_closed():
            closed_offense = xsoar_ng_client.search_incidents(incident_ids=incident_id)
            # status 2 means the incident is closed.
            incident_status = closed_offense["data"][0].get("status")
            assert incident_status == 2, f'incident {closed_offense} status is {incident_status} and is not closed'

        validate_offense_is_closed()
