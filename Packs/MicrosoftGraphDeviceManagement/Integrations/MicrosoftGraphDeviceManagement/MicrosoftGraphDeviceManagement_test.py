import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import build_request_body, build_request_body_update_windows_device_account,\
    build_request_body_generic, get_action, dash_to_camelcase, build_device_human_readable, build_device_object,\
    try_parse_integer

with open('test_data/raw_device.json', 'r') as json_file:
    data: dict = json.load(json_file)
    raw_device = data.get('value')

with open('test_data/device_hr.json', 'r') as json_file:
    device_hr: dict = json.load(json_file)

with open('test_data/device.json', 'r') as json_file:
    device: dict = json.load(json_file)

args = {
    'device-id': 'ID',
    'keep-enrollment-data': True,
    'device-account-password': 'Password'
}

expected_body_uwda = {
    'updateWindowsDeviceAccountActionParameter': {
        'keepEnrollmentData': True,
        'deviceAcount': {
            '@odata.type': 'microsoft.graph.windowsDeviceAccount',
            'password': args.get('device-account-password')
        }
    }
}

expected_body_generic = {
    'keepEnrollmentData': True,
    'deviceAccountPassword': 'Password'
}


@pytest.mark.parametrize('s, output', [('disable-lost-mode', 'disableLostMode'), ('locate', 'locate'),
                                       ('sync-device', 'syncDevice'), ('reboot-now', 'rebootNow'),
                                       ('', ''), (8, 8), ('shutdown', 'shutDown')])
def test_dash_to_camelcase(s, output):
    assert dash_to_camelcase(s) == output


def test_build_device_human_readable():
    assert build_device_human_readable(raw_device) == device_hr


def test_build_device_object():
    assert build_device_object(raw_device) == device


def test_try_parse_integer():
    assert try_parse_integer('8', '') == 8
    assert try_parse_integer(8, '') == 8
    with pytest.raises(DemistoException, match='parse failure'):
        try_parse_integer('a', 'parse failure')


@pytest.mark.parametrize('command, action', [('msgraph-device-shutdown', 'shutdown'),
                                             ('msgraph-locate-device', 'locate-device'), ('bad', 'bad')])
def test_get_action(command, action):
    if command != 'bad':
        assert get_action(command) == action
    else:
        with pytest.raises(DemistoException, match='Command bad is not of format msgraph-command'):
            get_action(command)


@pytest.mark.parametrize('action', ['shutdown', 'update-windows-device-account'])
def test_build_request_body(action):
    if action == 'shutdown':
        assert build_request_body(args, action) == expected_body_generic
    else:
        assert build_request_body(args, action) == expected_body_uwda


def test_build_request_body_update_windows_device_account():
    assert build_request_body_update_windows_device_account(args) == expected_body_uwda


def test_build_request_body_generic():
    assert build_request_body_generic(args) == expected_body_generic
