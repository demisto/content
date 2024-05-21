from datetime import timedelta
from datetime import datetime

import pytest
from _pytest.fixtures import SubRequest
from requests.exceptions import RequestException
from demisto_client.demisto_api.models.feed_indicator import FeedIndicator
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.commands.common.clients import XsoarSaasClient
from Tests.tools import get_integration_params, get_json_response
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.tests_e2e.client_utils import (
    get_integration_instance_name,
    get_fetched_incident,
    save_integration_instance,
    save_incident,
    save_playbook,
    save_indicators
)
from demisto_sdk.commands.common.constants import InvestigationPlaybookState, IncidentState

install_logging('e2e-xsoar-saas.log', logger=logging)


@pytest.fixture()
def available_indicators(xsoar_saas_client: XsoarSaasClient) -> list[str]:
    """
    Gets the available indicators in XSOAR-NG.
    """
    return [indicator.get("value") for indicator in xsoar_saas_client.list_indicators().get("iocObjects")]


def test_edl_returns_indicators(request: SubRequest, xsoar_saas_client: XsoarSaasClient):
    """
    Given:
        - indicators in xsoar-saas
        - long-running EDL instance
    When:
        - Trying to query the URL of edl
    Then:
        - make sure that edl collect the indicators from xsoar
        - make sure that indicators are returned in the response of edl instance
    """
    feed_indicators = [
        FeedIndicator(value=value, type=_type, score=score) for value, _type, score in
        [("1.1.1.1", "IP", 0), ("2.2.2.2", "IP", 0), ("3.3.3.3", "IP", 0)]
    ]

    with save_indicators(xsoar_saas_client, indicators=feed_indicators):
        integration_params = get_integration_params(
            request.config.option.integration_secrets_path, instance_name="edl_e2e_instance"
        )
        username = integration_params["credentials"]["identifier"]
        password = integration_params["credentials"]["password"]

        for i in range(1, 6):
            with save_integration_instance(
                xsoar_saas_client,
                integration_params=integration_params,
                integration_id="EDL",
                is_long_running=True,
                instance_name=get_integration_instance_name(integration_params, default="EDL")
            ) as edl_instance_response:
                instance_name = edl_instance_response.get("name")
                try:
                    edl_response = xsoar_saas_client.do_long_running_instance_request(
                        instance_name, username=username, password=password
                    )
                    assert edl_response.status_code == 200, f"status code is {edl_response.status_code} " \
                        f"from EDL in URL {edl_response.request.url}"
                    text = edl_response.text
                    assert "1.1.1.1" in text, f"1.1.1.1 indicator from URL {edl_response.request.url} is not in {text}"
                    assert "2.2.2.2" in text, f"2.2.2.2 indicator from URL {edl_response.request.url} is not in {text}"
                    assert "3.3.3.3" in text, f"3.3.3.3 indicator from URL {edl_response.request.url} is not in {text}"
                    break
                except Exception as error:
                    logging.error(f"test_edl_returns_indicators - time {i} - error\n{error}")
                    if i == 5:
                        raise


def test_taxii2_server_returns_indicators(
    request: SubRequest, xsoar_saas_client: XsoarSaasClient, available_indicators: list[str]
):
    """
    Given:
        - indicators in xsoar-saas
        - long-running taxii2 server instance
    When:
        - Trying to query the URL(s) of taxii2 server
    Then:
        - make sure that taxii2-server collect the indicators from xsoar
        - make sure that indicators are returned in the response of taxii2 server instance
    """
    feed_indicators = [
        FeedIndicator(value=value, type=_type, score=score) for value, _type, score in
        [("1.1.1.1", "IP", 0), ("2.2.2.2", "IP", 0), ("3.3.3.3", "IP", 0)]
    ]
    with save_indicators(xsoar_saas_client, indicators=feed_indicators):
        integration_params = get_integration_params(
            request.config.option.integration_secrets_path, instance_name="taxii2server-e2e"
        )
        # there are cases where the port can be taken in the machine, trying in a few other ports
        username = integration_params["credentials"]["identifier"]
        password = integration_params["credentials"]["password"]
        try:
            for port in ("8000", "8001", "8002", "8003", "8004"):
                integration_params["longRunningPort"] = port
                with save_integration_instance(
                    xsoar_saas_client,
                    integration_params=integration_params,
                    integration_id="TAXII2 Server",
                    is_long_running=True,
                    instance_name=get_integration_instance_name(integration_params, default="TAXII2-Server")
                ) as taxii2_instance_response:
                    instance_name = taxii2_instance_response.get("name")
                    headers = {"Accept": "application/taxii+json;version=2.1"}
                    response = xsoar_saas_client.do_long_running_instance_request(
                        instance_name,
                        url_suffix="/threatintel/collections",
                        headers=headers,
                        username=username,
                        password=password
                    )

                    # get the collections available
                    collections = get_json_response(response).get("collections")
                    assert collections, f'Could not get collections from url={response.request.url}, ' \
                        f'status_code={response.status_code}, response={collections}'

                    collection_id = collections[0]["id"]

                    # get the actual indicators from the collection
                    response = xsoar_saas_client.do_long_running_instance_request(
                        instance_name,
                        url_suffix=f"/threatintel/collections/{collection_id}/objects",
                        headers=headers,
                        username=username,
                        password=password
                    )

                    indicators = get_json_response(response).get("objects")
                    assert indicators, f'could not get indicators from url={response.request.url} with available ' \
                        f'indicators={available_indicators}, status code={response.status_code}, response={indicators}'
                    break
        except (ApiException, RequestException) as error:
            if isinstance(error, ApiException):
                logging.error(f'Error when running test_taxii2_server_returns_indicators with {port=}, error:\n{error}')
            else:
                logging.error(
                    f'Error response {error.response} when running '
                    f'test_taxii2_server_returns_indicators with {port=} when sending request {error.request}'
                )
            if port == "8004":
                raise


def test_slack_ask(request: SubRequest, xsoar_saas_client: XsoarSaasClient):
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

    with save_integration_instance(
        xsoar_saas_client,
        integration_params=integration_params,
        integration_id="SlackV3",
        is_long_running=True,
        instance_name=get_integration_instance_name(integration_params, default="SlackV3")
    ):
        playbook_id_name = "TestSlackAskE2E"
        with save_playbook(
            xsoar_saas_client,
            playbook_path="Tests/tests_e2e/content/xsoar_saas/TestSlackAskE2E.yml",
            playbook_id=playbook_id_name,
            playbook_name=playbook_id_name
        ):
            for i in range(1, 6):
                try:
                    with save_incident(xsoar_saas_client, playbook_id=playbook_id_name) as incident_response:
                        # make sure the playbook finished successfully
                        logging.debug(
                            f'test_slack_ask incident metadata:\n{xsoar_saas_client.search_incidents(incident_response.id)}'
                        )
                        assert xsoar_saas_client.poll_playbook_state(
                            incident_response.id, expected_states=(InvestigationPlaybookState.COMPLETED,)
                        )

                        context = xsoar_saas_client.get_investigation_context(incident_response.investigation_id)
                        # make sure the context is populated with thread id(s) from slack ask
                        assert context.get("Slack", {}).get("Thread"), f'thread IDs do not exist in context {context}'
                        break
                except Exception as error:
                    logging.error(f"test_slack_ask - time {i} - error\n{error}")
                    # print incident raw response to get info about it in case of failures
                    if i == 5:
                        raise error


def test_qradar_mirroring(request: SubRequest, xsoar_saas_client: XsoarSaasClient):
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
    instance_name = get_integration_instance_name(integration_params, default="Qradar-v3")

    with save_integration_instance(
        xsoar_saas_client,
        integration_params=integration_params,
        integration_id="QRadar v3",
        is_long_running=True,
        instance_name=instance_name,
    ):
        incidents_type = integration_params["incident_type"]
        with get_fetched_incident(
            xsoar_saas_client,
            source_instance_name=instance_name,
            # get the incident created in the last minute
            from_date=(datetime.utcnow() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S"),
            incident_types=incidents_type,
        ) as qradar_incident_response:

            offense_id = qradar_incident_response.get("CustomFields", {}).get("idoffense")
            assert offense_id, f'offense ID is empty in {qradar_incident_response}'
            incident_id = qradar_incident_response.get("id")
            investigation_id = qradar_incident_response.get("investigationId")
            assert investigation_id, f'investigation ID is empty in {qradar_incident_response}'

            close_offense_command = f"!qradar-offense-update offense_id={offense_id} closing_reason_id=1 status=CLOSED"

            # close the qradar offense
            war_room_entries, context = xsoar_saas_client.run_cli_command(
                close_offense_command,
                investigation_id=investigation_id
            )
            assert context.get("QRadar", {}).get("Offense", {}).get(
                "Status") == "CLOSED", f"Error validating context when running " \
                                       f"{close_offense_command} command, context: {context}, " \
                                       f"war-rooom error entries: " \
                                       f"{xsoar_saas_client.get_formatted_error_entries(war_room_entries)}"

            # make sure the incident gets closed after closing it in Qradar
            assert xsoar_saas_client.poll_incident_state(incident_id, expected_states=(IncidentState.CLOSED,), timeout=300)
