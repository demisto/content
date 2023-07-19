import pytest

from demisto_sdk.commands.test_content.xsiam_tools.xsiam_client import (
    XsiamApiClient,
    XsiamApiClientConfig
)
from Tests.configure_and_test_integration_instances import CloudBuild


def pytest_addoption(parser):
    parser.addoption("--cloud_machine", action="store")
    parser.addoption("--cloud_servers_path", action="store")
    parser.addoption("--cloud_servers_api_keys", action="store")


@pytest.fixture(scope='module')
def xsiam_client(request):
    cloud_machine = request.config.option.cloud_machine
    cloud_servers_path = request.config.option.cloud_servers_path
    cloud_servers_api_keys = request.config.option.cloud_servers_api_keys

    if not cloud_machine or not cloud_servers_path or not cloud_servers_api_keys:
        pytest.skip()

    api_key, _, xsiam_url, api_key_id = CloudBuild.get_cloud_configuration(cloud_machine,
                                                                           cloud_servers_path,
                                                                           cloud_servers_api_keys)

    # initialize xsiam client
    xsiam_client_cfg = XsiamApiClientConfig(
        base_url=xsiam_url,
        api_key=api_key,
        auth_id=api_key_id,  # type: ignore[arg-type]
        token='test',
        collector_token='test',  # type: ignore[arg-type]
    )
    xsiam_client = XsiamApiClient(xsiam_client_cfg)

    return xsiam_client
