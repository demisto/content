
import pytest
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.utils.utils import retry_http_request


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
    instance_name = integration_params.pop("integrationInstanceName", f'e2e-test-{integration_params.get("name")}')
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
            - indicators in xsoar
            - long-running EDL instance
        When:
            - Trying to query the URL of edl
        Then:
            - make sure that indicators are returned in the response of edl instance
        """
        import requests
        from requests.auth import HTTPBasicAuth

        instance_name = create_instance
        url = f'{xsoar_ng_client.external_base_url}/instance/execute/{instance_name}'

        basic_auth = HTTPBasicAuth(integration_params["credentials"]["identifier"], integration_params["credentials"]["password"])

        @retry_http_request(times=20)
        def do_edl_request():
            return requests.get(url, auth=basic_auth)

        response = do_edl_request()
        assert response.text, f'could not get indicators from {url=} with available ' \
                              f'indicators={[indicator.get("value") for indicator in xsoar_ng_client.list_indicators()]}, ' \
                              f'status code={response.status_code}, response={response.text}'


class TestTaxiiServer:
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

    def test_taxii2_server(self, xsoar_ng_client: XsoarNGApiClient, create_indicators, create_instance: str, integration_params: dict):
        import requests
        from requests.auth import HTTPBasicAuth

        instance_name = create_instance
        basic_auth = HTTPBasicAuth(integration_params["credentials"]["identifier"], integration_params["credentials"]["password"])

        def get_json_response(_response: requests.Response) -> dict:
            try:
                return _response.json()
            except ValueError as e:
                raise ValueError(f'Could not parse {_response.text}, error: {e}')

        @retry_http_request(times=20)
        def do_taxii2_server_request(url: str):
            return requests.get(url, auth=basic_auth, headers={"Accept": "application/taxii+json;version=2.1"})

        collection_api_url = f'{xsoar_ng_client.external_base_url}/instance/execute/{instance_name}/threatintel/collections/'

        # get the collections available
        response = do_taxii2_server_request(collection_api_url)
        collections = get_json_response(response).get("collections")
        assert collections, f'could not get collections from url={collection_api_url}, ' \
                            f'status_code={response.status_code}, response={collections}'

        collection_id = collections[0]["id"]

        # get the actual indicators from the collection
        indicators_url = f'{xsoar_ng_client.external_base_url}/instance/execute/{instance_name}/' \
                         f'threatintel/collections/{collection_id}/objects'
        response = do_taxii2_server_request(indicators_url)
        indicators = get_json_response(response).get("objects")

        assert indicators, f'could not get indicators from url={indicators_url} with available ' \
                           f'indicators={[indicator.get("value") for indicator in xsoar_ng_client.list_indicators()]}, ' \
                           f'status code={response.status_code}, response={indicators}'


# class TestQradar:
#     """
#     Tests Qradar mirroring
#     """
#     instance_name_gsm = "QRadar v3"
#     integration_id = "QRadar v3"
#
#     def test_qradar_mirroring(self, xsoar_ng_client: XsoarNGApiClient, create_instance: str, integration_params: dict):
