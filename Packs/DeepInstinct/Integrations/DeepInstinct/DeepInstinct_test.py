import pytest
import sys

from Packs.DeepInstinct.Integrations.DeepInstinct import DeepInstinct
from Tests.demistomock import demistomock as demisto

params = {
    "API_KEY": "key",
    "BASE_URL": "https://demisto.poc.deepinstinctweb.com",
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


def http_request_return():
    class A:
        status_code = 200
        json = lambda: mock_device
    return A

def test_get_device_command(mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'device_id': 1})
    mocker.patch('DeepInstinct.http_request', side_effect=http_request_return)
    mocker.patch.object(demisto, 'results')
    DeepInstinct.get_specific_device()
    result = demisto.results.call_args[0]
    assert result['id'] == mock_device['id']
    assert result['hostname'] == mock_device['hostname']


def test_fetch_incidents(mocker):
    pass