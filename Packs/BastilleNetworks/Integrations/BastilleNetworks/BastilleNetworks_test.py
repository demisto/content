import pytest

from BastilleNetworks import Client, get_zone_events_command, get_device_events_command, add_device_tag_command


@pytest.fixture
def client_mock():
    return Client(base_url="https://api.example.bastille.cloud", verify=False)


MOCK_ZONE_EVENTS_RESPONSE = [
    {
        "event_id": "conference-1_WIFI_04:d4:c4:13:3e:bc_c1_m1_1585766808",
        "time_s": 1585766808,
        "area": {"site_id": "s1", "concentrator_id": "c1", "map_id": "m1"},
        "zone_name": "conference-1",
        "first_seen": {"time_s": 1585766808, "position": [33.9738701222, 12.0545164571]},
        "last_seen": {"position": [31.6220110274, 12.33763776], "time_s": 1585770588},
        "emitter": {
            "transmitter_id": "04:d4:c4:13:3e:bc",
            "protocol": "WIFI",
            "vendor": "AsustekC",
            "network": {"name": "ASUS_B8_5G"},
        },
        "device_info": {"manufacturer": "Apple", "user": "Jane Doe", "model": "iPhone 7", "name": "Jane's iPhone 7"},
        "tags": ["zone:conference-1", "known"],
        "event_type": "zone_event",
    }
]


def test_get_zone_events_command(requests_mock, client_mock):
    requests_mock.get("https://api.example.bastille.cloud/detection/zones", json=MOCK_ZONE_EVENTS_RESPONSE)
    args = {"zone": "conference-1"}

    _, outputs, _ = get_zone_events_command(client_mock, args)
    zone_events = outputs["Bastille.ZoneEvent(val.event_id == obj.event_id)"]

    assert zone_events[0]["event_type"] == "zone_event"
    assert zone_events[0]["zone_name"] == "conference-1"


MOCK_DEVICE_EVENTS_RESPONSE = [
    {
        "event_id": "LTE_vzw:1100:249:6f4d_s1_c1_m1_1585699200",
        "time_s": 1585699200,
        "area": {"site_id": "s1", "concentrator_id": "c1", "map_id": "m1"},
        "first_seen": {"time_s": 1585699200, "position": [34.61, 13.31]},
        "last_seen": {"position": [34.61, 13.31], "time_s": 1585699200},
        "emitter": {
            "protocol": "LTE",
            "transmitter_id": "vzw:1100:249:6f4d",
            "vendor": "Unknown",
            "network": {"name": "Verizon"},
        },
        "device_info": {"manufacturer": "Apple", "user": "Jane Doe", "model": "iPhone 7", "name": "Jane's iPhone 7"},
        "tags": [],
        "event_type": "device_event",
    }
]


def test_get_device_events_command(requests_mock, client_mock):
    requests_mock.get("https://api.example.bastille.cloud/detection/devices", json=MOCK_DEVICE_EVENTS_RESPONSE)
    args = {"transmitter_id": "vzw:1100:249:6f4d"}

    _, outputs, _ = get_device_events_command(client_mock, args)
    device_events = outputs["Bastille.DeviceEvent(val.event_id == obj.event_id)"]

    assert device_events[0]["event_type"] == "device_event"
    assert device_events[0]["emitter"]["transmitter_id"] == "vzw:1100:249:6f4d"


MOCK_ADD_DEVICE_TAG_RESPONSE = {"status": "updated"}


def test_set_device_tag_command(requests_mock, client_mock):
    requests_mock.post("https://api.example.bastille.cloud/admin/devices/action.addTag", json=MOCK_ADD_DEVICE_TAG_RESPONSE)
    args = {
        "transmitter_id": "78:9f:70:7b:62:82",
        "tag": "some-tag",
    }

    readable, _, raw = add_device_tag_command(client_mock, args)

    assert readable == "updated"
    assert raw == MOCK_ADD_DEVICE_TAG_RESPONSE


MOCK_REMOVE_DEVICE_TAG_RESPONSE = {"status": "updated"}


def test_remove_device_tag_command(requests_mock, client_mock):
    requests_mock.post("https://api.example.bastille.cloud/admin/devices/action.addTag", json=MOCK_ADD_DEVICE_TAG_RESPONSE)
    args = {
        "transmitter_id": "78:9f:70:7b:62:82",
        "tag": "some-tag",
    }

    readable, _, raw = add_device_tag_command(client_mock, args)

    assert readable == "updated"
    assert raw == MOCK_ADD_DEVICE_TAG_RESPONSE
