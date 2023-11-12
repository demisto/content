import os

import pytest

from demisto_sdk.commands.test_content.xsiam_tools.xsiam_client import (
    XsiamApiClient,
    XsiamApiClientConfig
)
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClientConfig, XsoarNGApiClient

from Tests.configure_and_test_integration_instances import CloudBuild


def pytest_addoption(parser):
    parser.addoption("--cloud_machine", action="store", default=None)
    parser.addoption("--cloud_servers_path", action="store", default=None)
    parser.addoption("--cloud_servers_api_keys", action="store", default=None)
    parser.addoption("--integration_secrets_path", action="store", default=None)


def get_cloud_machine_credentials(request):
    """
    Get the cloud machine credentials.

    if those do not exist / were not found, will fall back to the DEMISTO environment variables.
    """
    cloud_machine = request.config.option.cloud_machine
    cloud_servers_path = request.config.option.cloud_servers_path
    cloud_servers_api_keys = request.config.option.cloud_servers_api_keys

    if not cloud_machine or not cloud_servers_path or not cloud_servers_api_keys:
        url = os.getenv("DEMISTO_BASE_URL")
        api_key = os.getenv("DEMISTO_API_KEY")
        api_key_id = os.getenv("XSIAM_AUTH_ID")

        if not url or not api_key or not api_key_id:
            pytest.skip(
                'could not find environment configuration, either pass --cloud_machine --cloud_servers_path --cloud_servers_'
                'api_keys or make sure DEMISTO_BASE_URL/DEMISTO_API_KEY/XSIAM_AUTH_ID environment variables are set'
            )
    else:
        api_key, _, url, api_key_id = CloudBuild.get_cloud_configuration(
            cloud_machine, cloud_servers_path, cloud_servers_api_keys
        )
    return url, api_key, api_key_id


@pytest.fixture(scope="module")
def xsiam_client(request) -> XsiamApiClient:

    xsiam_url, api_key, api_key_id = get_cloud_machine_credentials(request)

    # initialize xsiam client
    xsiam_client_cfg = XsiamApiClientConfig(
        base_url=xsiam_url,
        api_key=api_key,
        auth_id=api_key_id,
        token='test',
        collector_token='test'
    )
    return XsiamApiClient(xsiam_client_cfg)


@pytest.fixture(scope="module")
def xsoar_saas_client(request) -> XsoarNGApiClient:
    xsoar_ng_url, api_key, api_key_id = get_cloud_machine_credentials(request)

    xsoar_client_config = XsoarNGApiClientConfig(
        base_url=xsoar_ng_url,
        api_key=api_key,
        auth_id=api_key_id
    )
    return XsoarNGApiClient(xsoar_client_config)
