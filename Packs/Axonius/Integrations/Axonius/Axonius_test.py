"""Axonius Integration for Cortex XSOAR - Unit Tests file."""

import warnings
from TestData.Raw_data import USERS_SQS, DUMMY_TAGS, DUMMY_DEVICES_IDS, DUMMY_USER_IDS, DUMMY_DEVICES
from TestData.Expected_data import EXPECTED_USERS_SQS, EXPECTED_DEVICE_TAGS, EXPECTED_DEVICE
from Axonius import run_command
from marshmallow.warnings import RemovedInMarshmallow4Warning
warnings.filterwarnings('ignore', category=RemovedInMarshmallow4Warning)


class DummyDevices:
    def __init__(self):
        self.saved_query = DummyDevicesSavedQueries()
        self.labels = DummyDevicesLabels()
        self.LAST_GET = {}

    @staticmethod
    def get_by_hostname(value: str, max_rows: int, fields: list):
        return DUMMY_DEVICES

    @staticmethod
    def get(query: str, max_rows: int, fields: list):
        return DUMMY_DEVICES


class DummyDevicesSavedQueries:
    @staticmethod
    def get():
        return USERS_SQS


class DummyDevicesLabels:
    @staticmethod
    def get():
        return DUMMY_TAGS

    @staticmethod
    def add(rows: list, labels: list):
        return len(DUMMY_DEVICES_IDS)


class DummyUsers:
    def __init__(self):
        self.saved_query = DummyUsersSavedQueries()
        self.labels = DummyUsersLabels()
        self.LAST_GET = {}


class DummyUsersSavedQueries:
    @staticmethod
    def get():
        return USERS_SQS


class DummyUsersLabels:
    @staticmethod
    def get():
        return DUMMY_TAGS

    @staticmethod
    def remove(rows: list, labels: list):
        return len(DUMMY_USER_IDS)


class DummyConnect:
    def __init__(self):
        self.devices = DummyDevices()
        self.users = DummyUsers()

    @staticmethod
    def start():
        return True


def test_client():
    """Pass."""

    client = DummyConnect()
    expected = "ok"
    args: dict = {}
    result = run_command(client=client, args=args, command="test-module")
    assert expected == result


def test_get_saved_queries():
    client = DummyConnect()
    args: dict = {"type": "users"}
    result = run_command(client=client, args=args, command="axonius-get-saved-queries")
    assert len(EXPECTED_USERS_SQS) == len(result.outputs)


def test_get_tags():
    client = DummyConnect()
    args: dict = {"type": "devices"}
    result = run_command(client=client, args=args, command="axonius-get-tags")
    assert result.outputs == EXPECTED_DEVICE_TAGS


def test_add_tags():
    client = DummyConnect()
    args: dict = {"type": "devices", "ids": DUMMY_DEVICES_IDS, "tag_name": "test"}
    result = run_command(client=client, args=args, command="axonius-add-tag")
    assert len(DUMMY_DEVICES_IDS) == result.outputs


def test_remove_tags():
    client = DummyConnect()
    args: dict = {"type": "users", "ids": DUMMY_USER_IDS, "tag_name": "test"}
    result = run_command(client=client, args=args, command="axonius-remove-tag")
    assert len(DUMMY_USER_IDS) == result.outputs


def test_get_device():
    client = DummyConnect()
    args: dict = {"value": "DESKTOP-Gary-Gaither"}
    result = run_command(client=client, args=args, command="axonius-get-devices-by-hostname")
    assert EXPECTED_DEVICE["internal_axon_id"] == result.outputs["internal_axon_id"]


def test_get_by_aql():
    client = DummyConnect()
    args: dict = {"query": "(\"specific_data.data.name\" == regex(\"john\", \"i\"))"}
    result = run_command(client=client, args=args, command="axonius-get-devices-by-aql")
    assert EXPECTED_DEVICE["internal_axon_id"] == result.outputs["internal_axon_id"]


def test_add_note():
    client = DummyConnect()
    args: dict = {"type": "devices", "ids": DUMMY_DEVICES_IDS, "note": "note1"}
    result = run_command(client=client, args=args, command="axonius-add-note")
    assert result.outputs == 0
