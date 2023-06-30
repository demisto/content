from DockerHardeningCheck import (check_memory, mem_size_to_bytes, check_pids, check_fd_limits, check_non_root, check_cpus,
                                  get_default_gateway, check_network, CLOUD_METADATA_URL)
import pytest
import os
import ipaddress
import requests_mock
from pytest_mock import MockerFixture


def test_check_memory():
    assert 'memory cgroup configuration' in check_memory("10m", "cgroup")


def test_mem_size():
    assert mem_size_to_bytes("1g") == (1024 * 1024 * 1024)
    assert mem_size_to_bytes("512m") == (512 * 1024 * 1024)


def test_pids():
    assert check_pids(10)


def test_fd_limits():
    assert check_fd_limits(100, 200)


def test_non_root():
    assert not check_non_root()  # we run tests as non root


def test_check_cpus():
    if os.getenv("CI") == "true":
        pytest.skip("skipping as in CI we run with a single CPU")
        return
    assert check_cpus(1)  # during unit tests we should fail


def test_get_default_gateway():
    res = get_default_gateway()
    assert res
    # verify we have an ip
    assert ipaddress.ip_address(res)


def test_check_network(requests_mock: requests_mock.Mocker, mocker: MockerFixture):
    default_gateway_mock = mocker.patch('DockerHardeningCheck.get_default_gateway', return_value='172.12.0.1')
    requests_mock.get(CLOUD_METADATA_URL, text="access is open", headers={'test': 'mock header'})
    requests_mock.get('https://172.12.0.1/', text="local access is open", headers={'test': 'mock local header'})
    res = check_network('all')
    assert default_gateway_mock.call_count == 1
    assert CLOUD_METADATA_URL in res
    assert 'mock header' in res
    assert 'mock local header' in res


def test_podman(mocker):
    import DockerHardeningCheck
    mocker.patch.dict(os.environ, {"container": "podman"})
    mock_return_error = mocker.patch('DockerHardeningCheck.return_error')

    DockerHardeningCheck.main()

    mock_return_error.assert_called_once_with("This script only works in Docker containers. Podman is not supported")
