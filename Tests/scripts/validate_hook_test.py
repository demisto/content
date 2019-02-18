import pytest

from validate_files_structure import Validator


def test_invalid_conf_file():
    validator = Validator()
    validator.CONF_PATH = "./Tests/setup/corrupted_conf.json"
    validator.validate_conf_json()
    assert validator.get_is_valid() is False


def test_valid_conf_file():
    validator = Validator()
    validator.validate_conf_json()
    assert validator.get_is_valid() is False
