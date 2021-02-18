import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import build_device_object, try_parse_integer

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
