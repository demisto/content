import os
from typing import Dict

import pytest
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient


@pytest.fixture()
def create_indicators(request, xsoar_ng_client: XsoarNGApiClient):

    indicators = getattr(request.cls, "indicators", [])
    indicators_to_remove = []
    for indicator, indicator_type, score in indicators:
        response = xsoar_ng_client.create_indicator(indicator, indicator_type=indicator_type, score=score)
        assert response
        if created_indicator_id := response.get("id"):
            indicators_to_remove.append(created_indicator_id)

    def delete_indicators():
        _response = xsoar_ng_client.delete_indicators(indicators_to_remove)
        successful_removed_ids = set(_response.get("updatedIds") or [])
        assert set(indicators_to_remove).issubset(successful_removed_ids)

    request.addfinalizer(delete_indicators)


@pytest.fixture()
def create_instance(request, integration_params, xsoar_ng_client: XsoarNGApiClient):

    integration_id = getattr(request.cls, "integration_id")
    instance_name = integration_params.pop("integrationInstanceName", f'test-{integration_params.get("name")}')
    response = xsoar_ng_client.create_integration_instance(
        _id=integration_id,
        name=instance_name,
        integration_instance_config=integration_params
    )
    assert response
    created_instance_id = response.get("id")

    def delete_instance():
        xsoar_ng_client.delete_integration_instance(created_instance_id)

    request.addfinalizer(delete_instance)
    return instance_name


class TestEDL:

    indicators = [
        ("1.1.1.1", "IP", 0),
        ("2.2.2.2", "IP", 0),
        ("3.3.3.3", "IP", 0)
    ]
    instance_name_gsm = "edl_auto_from_8_0_0"
    integration_id = "EDL"

    def test_edl(self, xsoar_ng_client: XsoarNGApiClient, create_indicators, create_instance, integration_params):
        import requests
        from requests.auth import HTTPBasicAuth

        instance_name = create_instance
        url = f'{xsoar_ng_client.external_base_url}/xsoar/instance/execute/{instance_name}'

        basic_auth = HTTPBasicAuth(integration_params["credentials"]["identifier"], integration_params["credentials"]["password"])
        response = requests.get(url, verify=False, auth=basic_auth)

        num_of_tries = 20
        i = 0
        while i < num_of_tries and response.status_code != 200:
            response = requests.get(url, verify=False, auth=basic_auth)
            i += 1

        assert response.text == '3.3.3.3\n2.2.2.2\n1.1.1.1'
