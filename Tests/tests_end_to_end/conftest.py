import json
import os
import pytest

from demisto_sdk.commands.test_content.xsiam_tools.xsiam_client import (
    XsiamApiClient,
    XsiamApiClientConfig
)
from demisto_sdk.commands.test_content.xsoar_tools.xsoar_client import XsoarNGApiClientConfig, XsoarNGApiClient

from Tests.configure_and_test_integration_instances import CloudBuild
from Tests.scripts.utils import logging_wrapper as logging


def pytest_addoption(parser):
    parser.addoption("--cloud_machine", action="store")
    parser.addoption("--cloud_servers_path", action="store")
    parser.addoption("--cloud_servers_api_keys", action="store")
    parser.addoption("--integration_secrets_path", action="store", default=None)


def get_cloud_machine_credentials(request):
    cloud_machine = request.config.option.cloud_machine
    cloud_servers_path = request.config.option.cloud_servers_path
    cloud_servers_api_keys = request.config.option.cloud_servers_api_keys

    if not cloud_machine or not cloud_servers_path or not cloud_servers_api_keys:
        pytest.skip()

    api_key, _, url, api_key_id = CloudBuild.get_cloud_configuration(cloud_machine, cloud_servers_path, cloud_servers_api_keys)
    return url, api_key, api_key_id


def get_integration_params(integration_secrets_path: str, instance_name: str):
    with open(integration_secrets_path) as file:
        integrations_config = json.load(file)["integrations"]

    for config in integrations_config:
        existing_instance_name = config.get("instance_name")
        existing_name = config.get("name")
        logging.info(f'{existing_instance_name=}, {existing_name=}')
        if existing_instance_name == instance_name or existing_name == instance_name:
            return config.get("params")

    raise ValueError(f'Could not find integration parameters for {instance_name}')


@pytest.fixture()
def integration_params(request) -> dict:
    instance_name = request.cls.instance_name_gsm
    integration_secrets_path = request.config.option.integration_secrets_path
    return get_integration_params(integration_secrets_path, instance_name=instance_name)


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
def xsoar_ng_client(request) -> XsoarNGApiClient:
    xsoar_ng_url, api_key, api_key_id = get_cloud_machine_credentials(request)

    xsoar_client_config = XsoarNGApiClientConfig(
        base_url=xsoar_ng_url,
        api_key=api_key,
        auth_id=api_key_id
    )
    return XsoarNGApiClient(xsoar_client_config)
