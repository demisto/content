import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import MsGraphClient, build_device_object, try_parse_integer, find_managed_devices_command

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
        raw_device = [data.get('value')]

    client = MsGraphClient(False, 'tenant_id', 'auth_and_token_url', 'enc_key', 'app_name', 'base_url',
                           True, False, (200,), 'certificate_thumbprint',
                           'private_key')
    mocker.patch.object(
        client,
        'find_managed_devices',
        return_value=(raw_device, data),
    )
    outputs = mocker.patch('MicrosoftGraphDeviceManagement.return_outputs')

    find_managed_devices_command(client, args=args)
    context_output = outputs.call_args.args[0]
    assert context_output is not None
