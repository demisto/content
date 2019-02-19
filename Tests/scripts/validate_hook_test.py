import pytest

from validate_files_structure import StructureValidator, ScriptValidator, GitCommunicator


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
    validator.validate_conf_json()
    assert validator.is_invalid(), "Didn't find skipped_integrations as corrupted although it should"


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
    validator.validate_conf_json()
    assert validator.is_invalid(), "Didn't find skipped_tests as corrupted although it should"


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
    validator.validate_conf_json()
    assert validator.is_invalid(), "Didn't find skipped_tests nor skipped_integrations corrupted although " \
        "it should"


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
    validator.validate_conf_json()
    assert validator.is_invalid() is False, "Got a valid conf.json file but found it as an illegal one"


def test_added_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", initiate_check=False)
    validator.git = GitCommunicator()
    validator.git.run_git_command = lambda x: "+   dockerimage: sadf"

    validator.validate_docker_image()
    assert validator.is_invalid(), "The script validator couldn't find the docker image as changed"


def test_removed_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", initiate_check=False)
    validator.git = GitCommunicator()
    validator.git.run_git_command = lambda x: "-   dockerimage: sadf"

    validator.validate_docker_image()
    assert validator.is_invalid(), "The script validator couldn't find the docker image as changed"


def test_updated_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", initiate_check=False)
    validator.git = GitCommunicator()
    validator.git.run_git_command = lambda x: "-   dockerimage: sadf\n+   dockerimage: sdf"

    validator.validate_docker_image()
    assert validator.is_invalid(), "The script validator couldn't find the docker image as changed"


def test_not_changed_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", initiate_check=False)
    validator.git = GitCommunicator()
    validator.git.run_git_command = lambda x: "some text"

    validator.validate_docker_image()
    assert validator.is_invalid() is False, "The script validator couldn't find the docker image as changed"


def test_changed_context_():
    validator = ScriptValidator("temp_file", initiate_check=False)
    validator.git = GitCommunicator()
    validator.git.run_git_command = lambda x: "some text"

    validator.validate_docker_image()
    assert validator.is_invalid() is False, "The script validator couldn't find the docker image as changed"