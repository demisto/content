import pytest

from validate_files_structure import StructureValidator


def test_invalid_skipped_integrations_conf_file():
    validator = StructureValidator()
    validator.conf_data = {
        "skipped_tests": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": "Test1 Test1"
        },
        "skipped_integrations": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": ""
        }
    }

    assert validator.is_valid_conf_json() is False, "Didn't find skipped_integrations as corrupted although it should"


def test_invalid_skipped_test_conf_file():
    validator = StructureValidator()
    validator.conf_data = {
        "skipped_tests": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": ""
        },
        "skipped_integrations": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": "Test1 Test1"
        }
    }
    assert validator.is_valid_conf_json() is False, "Didn't find skipped_tests as corrupted although it should"


def test_invalid_skipped_test_and_integrations_conf_file():
    validator = StructureValidator()
    validator.conf_data = {
        "skipped_tests": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": ""
        },
        "skipped_integrations": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": ""
        }
    }
    assert validator.is_valid_conf_json() is False, "Didn't find skipped_tests nor skipped_integrations " \
        "corrupted although it should"


def test_valid_conf_file():
    validator = StructureValidator()
    validator.conf_data = {
        "skipped_tests": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": "Test1 Test1"
        },
        "skipped_integrations": {
            "Test1": "Test1 Test1",
            "Test2": "Test1 Test1",
            "Test3": "Test1 Test1"
        }
    }

    assert validator.is_valid_conf_json(), "Got a valid conf.json file but found it as an illegal one"