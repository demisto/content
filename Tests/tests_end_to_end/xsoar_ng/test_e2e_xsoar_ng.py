import os
from typing import Dict

import pytest
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClient


@pytest.mark.parametrize("instance_name", ["edl_auto_from_8_0_0"])
def test_edl(instance_name: str, integration_params: Dict, xsoar_ng_client: XsoarNGApiClient):
    import requests
    from requests.auth import HTTPBasicAuth

    for indicator in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
        xsoar_ng_client.create_indicator(indicator, indicator_type="IP")

    instance_name = integration_params.pop("integrationInstanceName", "edl")
    xsoar_ng_client.create_integration_instance(
        _id="EDL",
        name=instance_name,
        integration_instance_config=integration_params
    )

    basic_auth = HTTPBasicAuth(integration_params["credentials"]["identifier"], integration_params["credentials"]["password"])
    response = requests.get(f'{xsoar_ng_client.external_base_url}/xsoar/instance/execute/{instance_name}', verify=False,
                            auth=basic_auth)

    num_of_tries = 20
    i = 0
    while i < num_of_tries and response.status_code != 200:
        response = requests.get(f'{xsoar_ng_client.external_base_url}/xsoar/instance/execute/{instance_name}', verify=False,
                                auth=basic_auth)
        i += 1

    assert response.text == '3.3.3.3\n2.2.2.2\n1.1.1.1'
