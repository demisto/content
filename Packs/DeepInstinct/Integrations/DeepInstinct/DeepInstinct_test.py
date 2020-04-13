from unittest import mock

import pytest
import sys

from Packs.DeepInstinct.Integrations.DeepInstinct import DeepInstinct
import demistomock as demisto

params = {
    "apikey": "key",
    "base_url": "https://demisto.poc.deepinstinctweb.com",
    "after_id": 0
}

mock_device = {
  "id": 1,
  "os": "WINDOWS",
  "osv": "Windows",
  "ip_address": "192.168.88.80",
  "mac_address": "00:00:00:00:00:00",
  "hostname": "Mock_2020-04-09 17:49:39.408405_1",
  "domain": "",
  "scanned_files": 0,
  "tag": "",
  "connectivity_status": "OFFLINE",
  "deployment_status": "REGISTERED",
  "last_registration": "2020-04-09T14:49:39.722292Z",
  "last_contact": "2020-04-09T14:49:39.711487Z",
  "distinguished_name": "OU=Organizations & Sites,DC=bancshares,DC=mib",
  "group_name": "Windows Default Group",
  "group_id": 3,
  "policy_name": "Windows Default Policy",
  "policy_id": 3,
  "log_status": "NA",
  "agent_version": "2.3.1.12",
  "brain_version": "115wt",
  "msp_name": "MSP 1",
  "msp_id": 1,
  "tenant_name": "Tenant 1",
  "tenant_id": 1
}


class A:
    status_code = 200
    json = lambda: mock_device


def test_get_device_command(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_id': mock_device['id']})
    requests_mock.get("{0}/api/v1/devices/{1}".format(params['base_url'], mock_device['id']), json=mock_device)
    mocker.patch.object(demisto, 'results')
    DeepInstinct.get_specific_device()
    result = demisto.results.call_args[0][0]
    assert result['Contents'] == mock_device


def test_fetch_incidents(mocker):
    assert True