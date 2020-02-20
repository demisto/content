import pytest
import json
from CommonServerPython import DemistoException

with open('test_data/raw_device.json', 'r') as json_file:
    data: dict = json.load(json_file)
    raw_device = data.get('value')

with open('test_data/device_hr.json', 'r') as json_file:
    device_hr: dict = json.load(json_file)

with open('test_data/device.json', 'r') as json_file:
    device: dict = json.load(json_file)


@pytest.mark.parametrize('s, output', [('disable-lost-mode', 'disableLostMode'), ('locate', 'locate'),
                                       ('sync-device', 'syncDevice'), ('reboot-now', 'rebootNow'), ('', ''), (8, 8)])
def test_dash_to_camelcase(s, output):
    from MicrosoftGraphDeviceManagement import dash_to_camelcase
    assert dash_to_camelcase(s) == output


def test_build_device_human_readable():
    from MicrosoftGraphDeviceManagement import build_device_human_readable
    assert build_device_human_readable(raw_device) == device_hr


def test_build_device_object():
    from MicrosoftGraphDeviceManagement import build_device_object
    assert build_device_object(raw_device) == device


def test_try_parse_integer():
    from MicrosoftGraphDeviceManagement import try_parse_integer
    assert try_parse_integer('8', '') == 8
    assert try_parse_integer(8, '') == 8
    with pytest.raises(DemistoException, match='parse failure'):
        try_parse_integer('a', 'parse failure')
