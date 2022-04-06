"""Axonius Integration for Cortex XSOAR - Unit Tests file."""
import inspect
import axonius_api_client as axonapi

from TestData.Raw_data import USERS_SQS, DUMMY_TAGS, DUMMY_DEVICES_IDS, DUMMY_USER_IDS
from TestData.Expected_data import EXPECTED_USERS_SQS, EXPECTED_DEVICE_TAGS
from Axonius import get_saved_queries, get_tags, update_tags


class DummyDevices:
    def __init__(self):
        self.saved_query = DummyDevicesSavedQueries()
        self.labels = DummyDevicesLabels()
        self.LAST_GET = {}


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


def test_client_exists():
    """Pass."""
    assert inspect.isclass(axonapi.connect.Connect)


def test_get_saved_queries():
    client = DummyConnect()
    args = {"type": "users"}
    result = get_saved_queries(client=client, args=args)
    assert len(EXPECTED_USERS_SQS) == len(result.outputs)


def test_get_tags():
    client = DummyConnect()
    args = {"type": "devices"}
    result = get_tags(client=client, args=args)
    assert EXPECTED_DEVICE_TAGS == result.outputs


def test_add_tags():
    client = DummyConnect()
    args = {"type": "devices", "ids": DUMMY_DEVICES_IDS, "tag_name": "test"}
    result = update_tags(client=client, args=args, method_name="add")
    assert len(DUMMY_DEVICES_IDS) == result.outputs


def test_remove_tags():
    client = DummyConnect()
    args = {"type": "users", "ids": DUMMY_USER_IDS, "tag_name": "test"}
    result = update_tags(client=client, args=args, method_name="remove")
    assert len(DUMMY_USER_IDS) == result.outputs
