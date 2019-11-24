import pytest
from mock import patch
from typing import Optional
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.integration import IntegrationValidator


def mock_structure(file_path=None, current_file=None, old_file=None):
    # type: (Optional[str], Optional[dict], Optional[dict]) -> StructureValidator
    with patch.object(StructureValidator, '__init__', lambda a, b: None):
        structure = StructureValidator(file_path)
        structure.is_valid = True
        structure.scheme_name = 'integration'
        structure.file_path = file_path
        structure.current_file = current_file
        structure.old_file = old_file
        return structure


class TestIntegrationValidator:
    SCRIPT_WITH_DOCKER_IMAGE_1 = {"script": {"dockerimage": "test"}}
    SCRIPT_WITH_DOCKER_IMAGE_2 = {"script": {"dockerimage": "test1"}}
    SCRIPT_WITH_NO_DOCKER_IMAGE = {"script": {"no": "dockerimage"}}
    EMPTY_CASE = {}
    IS_DOCKER_IMAGE_CHANGED = [
        (SCRIPT_WITH_DOCKER_IMAGE_1, SCRIPT_WITH_NO_DOCKER_IMAGE, True),
        (SCRIPT_WITH_DOCKER_IMAGE_1, SCRIPT_WITH_DOCKER_IMAGE_2, True),
        (EMPTY_CASE, EMPTY_CASE, False),
        (EMPTY_CASE, SCRIPT_WITH_DOCKER_IMAGE_1, True),
        (SCRIPT_WITH_DOCKER_IMAGE_1, EMPTY_CASE, True)
    ]

    @pytest.mark.parametrize("current_file, old_file, answer", IS_DOCKER_IMAGE_CHANGED)
    def test_is_docker_image_changed(self, current_file, old_file, answer):
        structure = mock_structure("", current_file, old_file)
        validator = IntegrationValidator(structure)
        assert validator.is_docker_image_changed() is answer

    REQUIED_FIELDS_FALSE = {"configuration": [{"name": "test", "required": False}]}
    REQUIED_FIELDS_TRUE = {"configuration": [{"name": "test", "required": True}]}
    IS_ADDED_REQUIRED_FIELDS_INPUTS = [
        (REQUIED_FIELDS_FALSE, REQUIED_FIELDS_TRUE, False),
        (REQUIED_FIELDS_TRUE, REQUIED_FIELDS_FALSE, True),
        (REQUIED_FIELDS_TRUE, REQUIED_FIELDS_TRUE, False),
        (REQUIED_FIELDS_FALSE, REQUIED_FIELDS_FALSE, False)
    ]

    @pytest.mark.parametrize("current_file, old_file, answer", IS_ADDED_REQUIRED_FIELDS_INPUTS)
    def test_is_added_required_fields(self, current_file, old_file, answer):
        structure = mock_structure("", current_file, old_file)
        validator = IntegrationValidator(structure)
        assert validator.is_added_required_fields() is answer

    CONFIGURATION_JSON_1 = {"configuration": [{"name": "test", "required": False}, {"name": "test1", "required": True}]}
    EXPECTED_JSON_1 = {"test": False, "test1": True}
    FIELD_TO_REQUIRED_INPUTS = [
        (CONFIGURATION_JSON_1, EXPECTED_JSON_1),
    ]

    @pytest.mark.parametrize("input_json, expected", FIELD_TO_REQUIRED_INPUTS)
    def test_get_field_to_required_dict(self, input_json, expected):
        assert IntegrationValidator._get_field_to_required_dict(input_json) == expected

    IS_CONTEXT_CHANGED_OLD = [{"name": "test", "outputs": [{"contextPath": "test"}]}]
    IS_CONTEXT_CHANGED_NEW = [{"name": "test", "outputs": [{"contextPath": "test2"}]}]
    IS_CONTEXT_CHANGED_ADDED_PATH = [{"name": "test", "outputs": [{"contextPath": "test"}, {"contextPath": "test2"}]}]
    IS_CONTEXT_CHANGED_ADDED_COMMAND = [{"name": "test", "outputs": [{"contextPath": "test"}]},
                                        {"name": "test2", "outputs": [{"contextPath": "new command"}]}]
    IS_CHANGED_CONTEXT_INPUTS = [
        (IS_CONTEXT_CHANGED_OLD, IS_CONTEXT_CHANGED_OLD, False),
        (IS_CONTEXT_CHANGED_NEW, IS_CONTEXT_CHANGED_OLD, True),
        (IS_CONTEXT_CHANGED_NEW, IS_CONTEXT_CHANGED_ADDED_PATH, True),
        (IS_CONTEXT_CHANGED_ADDED_PATH, IS_CONTEXT_CHANGED_NEW, False),
        (IS_CONTEXT_CHANGED_ADDED_COMMAND, IS_CONTEXT_CHANGED_OLD, False),
        (IS_CONTEXT_CHANGED_ADDED_COMMAND, IS_CONTEXT_CHANGED_NEW, True)
    ]

    @pytest.mark.parametrize("current, old, answer", IS_CHANGED_CONTEXT_INPUTS)
    def test_is_changed_context_path(self, current, old, answer):
        current = {'script': {'commands': current}}
        old = {'script': {'commands': old}}
        structure = mock_structure("", current, old)
        validator = IntegrationValidator(structure)
        assert validator.is_changed_context_path() is answer

    CHANGED_COMMAND_INPUT_1 = [{"name": "test", "arguments": [{"name": "test"}]}]
    CHANGED_COMMAND_INPUT_2 = [{"name": "test", "arguments": [{"name": "test1"}]}]
    CHANGED_COMMAND_NAME_INPUT = [{"name": "test1", "arguments": [{"name": "test1"}]}]
    CHANGED_COMMAND_INPUT_ADDED_ARG = [{"name": "test", "arguments": [{"name": "test"}, {"name": "test1"}]}]
    CHANGED_COMMAND_INPUT_REQUIRED = [{"name": "test", "arguments": [{"name": "test", "required": True}]}]
    CHANGED_COMMAND_INPUT_ADDED_REQUIRED = [
        {"name": "test", "arguments": [{"name": "test"}, {"name": "test1", "required": True}]}]
    CHANGED_COMMAND_OR_ARG_INPUTS = [
        (CHANGED_COMMAND_INPUT_1, CHANGED_COMMAND_INPUT_REQUIRED, False),
        (CHANGED_COMMAND_INPUT_ADDED_REQUIRED, CHANGED_COMMAND_INPUT_1, True),
        (CHANGED_COMMAND_INPUT_1, CHANGED_COMMAND_INPUT_ADDED_REQUIRED, True),
        (CHANGED_COMMAND_INPUT_ADDED_ARG, CHANGED_COMMAND_INPUT_1, False),
        (CHANGED_COMMAND_INPUT_1, CHANGED_COMMAND_INPUT_ADDED_ARG, True),
        (CHANGED_COMMAND_INPUT_1, CHANGED_COMMAND_INPUT_2, True),
        (CHANGED_COMMAND_NAME_INPUT, CHANGED_COMMAND_INPUT_1, True),
        (CHANGED_COMMAND_NAME_INPUT, CHANGED_COMMAND_NAME_INPUT, False),
    ]

    @pytest.mark.parametrize("current, old, answer", CHANGED_COMMAND_OR_ARG_INPUTS)
    def test_is_changed_command_name_or_arg(self, current, old, answer):
        current = {'script': {'commands': current}}
        old = {'script': {'commands': old}}
        structure = mock_structure("", current, old)
        validator = IntegrationValidator(structure)
        assert validator.is_changed_command_name_or_arg() is answer

    WITH_DUP = [{"name": "test"}, {"name": "test"}]
    WITHOUT_DUP = [{"name": "test"}, {"name": "test1"}]
    DUPLICATE_PARAMS_INPUTS = [
        (WITH_DUP, True),
        (WITHOUT_DUP, False)
    ]

    @pytest.mark.parametrize("current, answer", DUPLICATE_PARAMS_INPUTS)
    def test_no_duplicate_params(self, current, answer):
        current = {'configuration': current}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        assert validator.is_there_duplicate_params() is answer

    WITHOUT_DUP_ARGS = [{"name": "testing", "arguments": [{"name": "test1"}, {"name": "test2"}]}]
    WITH_DUP_ARGS = [{"name": "testing", "arguments": [{"name": "test1"}, {"name": "test1"}]}]
    DUPLICATE_ARGS_INPUTS = [
        (WITHOUT_DUP_ARGS, False),
        (WITH_DUP_ARGS, True)
    ]

    @pytest.mark.parametrize("current, answer", DUPLICATE_ARGS_INPUTS)
    def test_is_there_duplicate_args(self, current, answer):
        current = {'script': {'commands': current}}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        assert validator.is_there_duplicate_args() is answer

    PYTHON3_SUBTYPE = {
        "type": "python",
        "subtype": "python3"
    }
    PYTHON2_SUBTYPE = {
        "type": "python",
        "subtype": "python2"
    }

    BLA_BLA_SUBTYPE = {
        "type": "python",
        "subtype": "blabla"
    }
    INPUTS_SUBTYPE_TEST = [
        (PYTHON2_SUBTYPE, PYTHON3_SUBTYPE, True),
        (PYTHON3_SUBTYPE, PYTHON2_SUBTYPE, True),
        (PYTHON3_SUBTYPE, PYTHON3_SUBTYPE, False),
        (PYTHON2_SUBTYPE, PYTHON2_SUBTYPE, False)
    ]

    @pytest.mark.parametrize("current, old, answer", INPUTS_SUBTYPE_TEST)
    def test_is_changed_subtype(self, current, old, answer):
        current, old = {'script': current}, {'script': old}
        structure = mock_structure("", current, old)
        validator = IntegrationValidator(structure)
        assert validator.is_changed_subtype() is answer

    INPUTS_VALID_SUBTYPE_TEST = [
        (PYTHON2_SUBTYPE, True),
        (PYTHON3_SUBTYPE, True),
        ({"type": "python", "subtype": "lies"}, False)
    ]

    @pytest.mark.parametrize("current, answer", INPUTS_VALID_SUBTYPE_TEST)
    def test_id_valid_subtype(self, current, answer):
        current = {'script': current}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        assert validator.is_valid_subtype() is answer

    DEFUALT_ARGS_2 = [
        {"name": "email", "arguments": [{"name": "email", "required": False, "default": True}, {"name": "verbose"}]}]
    DEFUALT_ARGS_INVALID_1 = [{"name": "file", "required": True, "default": True}, {"name": "verbose"}]
    DEFUALT_ARGS_INVALID_2 = [
        {"name": "email", "arguments": [{"name": "email", "required": False, "default": False}, {"name": "verbose"}]}]
    DEFUALT_ARGS_INVALID_3 = [{"name": "file", "required": True, "default": False}, {"name": "verbose"}]
    DEFAULT_ARGS_INPUTS = [
        (DEFUALT_ARGS_2, True),
        (DEFUALT_ARGS_INVALID_1, False),
        (DEFUALT_ARGS_INVALID_2, False),
        (DEFUALT_ARGS_INVALID_3, False),
    ]

    @pytest.mark.parametrize("current, answer", DEFAULT_ARGS_INPUTS)
    def test_is_valid_default_arguments(self, current, answer):
        current = {"script": {"commands": current}}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        assert validator.is_valid_default_arguments() is answer

    MOCK_REPUTATIONS_1 = [{"contextPath": "Int.lol", "description": "desc", "type": "number"},
                          {"contextPath": "DBotScore.lives.matter"}]
    MOCK_REPUTATIONS_2 = [{"name": "panorama-commit-status", "outputs": 1}]
    MOCK_REPUTATIONS_INVALID_EMAIL = [
        {"contextPath": "DBotScore.Indicator", "description": "The indicator that was tested.", "type": "string"},
        {"contextPath": "DBotScore.Type", "description": "The indicator type.", "type": "string"},
        {"contextPath": "DBotScore.Vendor", "description": "Vendor used to calculate the score.", "type": "string"},
        {"contextPath": "DBotScore.Sc0re", "description": "The actual score.", "type": "int"},
        {"contextPath": "Email.To", "description": "email to", "type": "string"}]
    MOCK_REPUTATIONS_INVALID_FILE = [
        {"contextPath": "DBotScore.Indicator", "description": "The indicator that was tested.", "type": "string"},
        {"contextPath": "DBotScore.Type", "description": "The indicator type.", "type": "string"},
        {"contextPath": "DBotScore.Vendor", "description": "Vendor used to calculate the score.", "type": "string"},
        {"contextPath": "DBotScore.Score", "description": "The actual score.", "type": "int"},
        {"contextPath": "File.Md5", "description": "The MD5 hash of the file.", "type": "string"}]
    MOCK_REPUTATIONS_VALID_IP = [
        {"contextPath": "DBotScore.Indicator", "description": "The indicator that was tested.", "type": "string"},
        {"contextPath": "DBotScore.Type", "description": "The indicator type.", "type": "string"},
        {"contextPath": "DBotScore.Vendor", "description": "Vendor used to calculate the score.", "type": "string"},
        {"contextPath": "DBotScore.Score", "description": "The actual score.", "type": "int"},
        {"contextPath": "IP.Address", "description": "IP address", "type": "string"}]
    IS_OUTPUT_FOR_REPUTATION_INPUTS = [
        (MOCK_REPUTATIONS_1, "not bang", True),
        (MOCK_REPUTATIONS_2, "not bang", True),
        (MOCK_REPUTATIONS_INVALID_EMAIL, "email", False),
        (MOCK_REPUTATIONS_INVALID_FILE, "file", False),
        (MOCK_REPUTATIONS_VALID_IP, "ip", True)
    ]

    @pytest.mark.parametrize("current, name, answer", IS_OUTPUT_FOR_REPUTATION_INPUTS)
    def test_is_outputs_for_reputations_commands_valid(self, current, name, answer):
        current = {"script": {"commands": [{"name": name, "outputs": current}]}}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        assert validator.is_outputs_for_reputations_commands_valid() is answer

    VALID_BETA = {"commonfields": {"id": "newIntegration"}, "name": "newIntegration",
                  "display": "newIntegration (Beta)", "beta": True}
    INVALID_BETA_DISPLAY = {"commonfields": {"id": "newIntegration"}, "name": "newIntegration",
                            "display": "newIntegration", "beta": True}
    INVALID_BETA_ID = {"commonfields": {"id": "newIntegration-beta"}, "name": "newIntegration",
                       "display": "newIntegration", "beta": True}
    INVALID_BETA_NAME = {"commonfields": {"id": "newIntegration"}, "name": "newIntegration (Beta)",
                         "display": "newIntegration", "beta": True}
    INVALID_BETA_ALL_BETA = {"commonfields": {"id": "newIntegration beta"}, "name": "newIntegration beta",
                             "display": "newIntegration (Beta)"}
    INVALID_BETA_CHANGED_NAME_NO_BETA_FIELD = {"commonfields": {"id": "newIntegration beta"},
                                               "name": "newIntegration beta",
                                               "display": "newIntegration changed (Beta)"}
    IS_VALID_BETA_INPUTS = [
        (VALID_BETA, True, True),
        (INVALID_BETA_DISPLAY, True, False),
        (INVALID_BETA_ID, True, False),
        (INVALID_BETA_NAME, True, False),
        (INVALID_BETA_ALL_BETA, INVALID_BETA_CHANGED_NAME_NO_BETA_FIELD, False),
    ]

    @pytest.mark.parametrize("current, old, answer", IS_VALID_BETA_INPUTS)
    def test_is_valid_beta_integration(self, current, old, answer):
        structure = mock_structure("", current, old)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        validator.old_file = old
        assert validator.is_valid_beta_integration() is answer

    PROXY_VALID = [{"name": "proxy", "type": 8, "display": "Use system proxy settings", "required": False}]
    PROXY_WRONG_TYPE = [{"name": "proxy", "type": 9, "display": "Use system proxy settings", "required": False}]
    PROXY_WRONG_DISPLAY = [{"name": "proxy", "type": 8, "display": "bla", "required": False}]
    PROXY_WRONG_REQUIRED = [{"name": "proxy", "type": 8, "display": "Use system proxy settings", "required": True}]
    IS_PROXY_INPUTS = [
        (PROXY_VALID, True),
        (PROXY_WRONG_TYPE, False),
        (PROXY_WRONG_DISPLAY, False),
        (PROXY_WRONG_REQUIRED, False)
    ]

    @pytest.mark.parametrize("current, answer", IS_PROXY_INPUTS)
    def test_is_proxy_configured_correctly(self, current, answer):
        current = {"configuration": current}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        assert validator.is_proxy_configured_correctly() is answer

    UNSECURE_VALID = [
        {"name": "unsecure", "type": 8, "display": "Trust any certificate (not secure)", "required": False}]
    INSECURE_WRONG_DISPLAY = [
        {"name": "insecure", "type": 8, "display": "Use system proxy settings", "required": False}]
    UNSECURE_WRONG_DISPLAY = [
        {"name": "unsecure", "type": 8, "display": "Use system proxy settings", "required": False}]
    IS_INSECURE_INPUTS = [
        (UNSECURE_VALID, True),
        (INSECURE_WRONG_DISPLAY, False),
        (UNSECURE_WRONG_DISPLAY, False)
    ]

    @pytest.mark.parametrize("current, answer", IS_INSECURE_INPUTS)
    def test_is_insecure_configured_correctly(self, current, answer):
        current = {"configuration": current}
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        assert validator.is_insecure_configured_correctly() is answer

    INVALID_CATEGORY = {"category": "Analytics & SIEMM"}
    VALID_CATEGORY = {"category": "Endpoint"}
    IS_VALID_CATEGORY_INPUTS = [
        (VALID_CATEGORY, True),
        (INVALID_CATEGORY, False)
    ]

    @pytest.mark.parametrize("current, answer", IS_VALID_CATEGORY_INPUTS)
    def test_is_valid_category(self, current, answer):
        structure = mock_structure("", current)
        validator = IntegrationValidator(structure)
        validator.current_file = current
        assert validator.is_valid_category() is answer
