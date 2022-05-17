import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import MsGraphClient
from MicrosoftGraphDeviceManagement import build_device_object, try_parse_integer, find_managed_devices_command, MsGraphClient

with open('test_data/raw_device.json', 'r') as json_file:
    data: dict = json.load(json_file)
    raw_device = data.get('value')

with open('test_data/device_hr.json', 'r') as json_file:
    device_hr: dict = json.load(json_file)

with open('test_data/device.json', 'r') as json_file:
    device: dict = json.load(json_file)


def test_build_device_object():
    assert build_device_object(raw_device) == device


def test_try_parse_integer():
    assert try_parse_integer('8', '') == 8
    assert try_parse_integer(8, '') == 8
    with pytest.raises(DemistoException, match='parse failure'):
        try_parse_integer('a', 'parse failure')


def test_find_managed_devices_command(mocker):
    args = {'device_name': 'Managed Device Name value'}

    with open('test_data/raw_device.json', 'r') as json_file:
        data: dict = json.load(json_file)
        raw_device = data.get('value')

    client_mock = mocker.patch.object(MsGraphClient, 'find_managed_devices',
                        return_value={'list_raw_devices': raw_device, 'raw_response': data})
    

    devices = find_managed_devices_command(client=client_mock, args=args)
    assert devices
