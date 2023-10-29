
import pytest
import requests
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient
from demisto_client.demisto_api.rest import ApiException


@pytest.fixture()
def create_indicators(request, xsoar_ng_client: XsoarNGApiClient):

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
        return

    response = xsoar_ng_client.list_indicators()
    if response.get("total") > 0:
        return

    raise ValueError(f'There are no indicators in {xsoar_ng_client.base_api_url} server')


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
