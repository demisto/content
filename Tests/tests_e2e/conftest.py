import os

import pytest

from demisto_sdk.commands.common.clients import (
    XsoarSaasClient, XsoarSaasClientConfig, get_client_from_config, XsiamClient, XsiamClientConfig
)

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
            message = 'could not find environment configuration, either pass ' \
                      '--cloud_machine --cloud_servers_path --cloud_servers_api_' \
                      'keys or make sure DEMISTO_BASE_URL/DEMISTO_API_KEY/XSIAM_AUTH_ID environment variables are set'
            if os.getenv("GITLAB_CI"):
                raise ValueError(message)
            pytest.skip(message)
    else:
        api_key, _, url, api_key_id = CloudBuild.get_cloud_configuration(
            cloud_machine, cloud_servers_path, cloud_servers_api_keys
        )
    return url, api_key, api_key_id


@pytest.fixture(scope="module")
def xsiam_client(request) -> XsiamClient:
    xsiam_url, api_key, api_key_id = get_cloud_machine_credentials(request)
    return get_client_from_config(
        XsiamClientConfig(base_api_url=xsiam_url, api_key=api_key, auth_id=api_key_id, token='test', collector_token='test')
    )


@pytest.fixture(scope="module")
def xsoar_saas_client(request) -> XsoarSaasClient:
    xsoar_saas_url, api_key, api_key_id = get_cloud_machine_credentials(request)
    return get_client_from_config(
        XsoarSaasClientConfig(base_api_url=xsoar_saas_url, api_key=api_key, auth_id=api_key_id)
    )
