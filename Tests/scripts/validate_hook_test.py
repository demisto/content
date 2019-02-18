import pytest

from validate_files_structure import Validator


def test_invalid_skipped_integrations_conf_file():
    validator = Validator()
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
    validator.validate_conf_json()
    assert validator.get_is_valid() is False, "Didn't find skipped_integrations as corrupted although it should"


def test_invalid_skipped_test_conf_file():
    validator = Validator()
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
    validator.validate_conf_json()
    assert validator.get_is_valid() is False, "Didn't find skipped_tests as corrupted although it should"


def test_invalid_skipped_test_and_integrations_conf_file():
    validator = Validator()
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
    validator.validate_conf_json()
    assert validator.get_is_valid() is False, "Didn't find skipped_tests nor skipped_integrations corrupted although " \
        "it should"


def test_valid_conf_file():
    validator = Validator()
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
    validator.validate_conf_json()
    assert validator.get_is_valid(), "Got a valid conf.json file but found it as an illegal one"
