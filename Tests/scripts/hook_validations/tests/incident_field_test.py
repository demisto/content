import pytest

from Tests.scripts.hook_validations.incident_field import IncidentFieldValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from mock import patch


class TestIncidentFieldsValidator:
    NAME_SANITY_FILE = {
        'cliName': 'sanity name',
        'name': 'sanity name',
        'id': 'incident',
        'content': True,
    }

    BAD_CLI_1 = {
        'cliName': 'Incident',
        'name': 'sanity name',
        'content': True,
    }

    BAD_CLI_2 = {
        'cliName': 'case',
        'name': 'sanity name',
        'content': True,
    }

    BAD_CLI_3 = {
        'cliName': 'Playbook',
        'name': 'sanity name',
        'content': True,
    }

    BAD_CLI_4 = {
        'cliName': 'Alerting feature',
        'name': 'sanity name',
        'content': True,
    }

    BAD_CLI_5 = {
        'cliName': 'INciDeNts',
        'name': 'sanity name',
        'content': True,
    }

    BAD_NAME_1 = {
        'cliName': 'sanity name',
        'name': 'Incident',
        'content': True,
    }

    BAD_NAME_2 = {
        'cliName': 'sanity name',
        'name': 'case',
        'content': True,
    }

    BAD_NAME_3 = {
        'cliName': 'sanity name',
        'name': 'Playbook',
        'content': True,
    }

    BAD_NAME_4 = {
        'cliName': 'sanity name',
        'name': 'Alerting feature',
        'content': True,
    }

    BAD_NAME_5 = {
        'cliName': 'sanity name',
        'name': 'INciDeNts',
        'content': True,
    }

    INPUTS_NAMES = [
        (NAME_SANITY_FILE, True),
        (BAD_CLI_1, False),
        (BAD_CLI_2, False),
        (BAD_CLI_3, False),
        (BAD_CLI_4, False),
        (BAD_CLI_5, False),
        (BAD_NAME_1, False),
        (BAD_NAME_2, False),
        (BAD_NAME_3, False),
        (BAD_NAME_4, False),
        (BAD_NAME_5, False)
    ]

    @pytest.mark.parametrize('current_file, answer', INPUTS_NAMES)
    def test_is_valid_name_sanity(self, current_file, answer):
        with patch.object(StructureValidator, '__init__', lambda a, b: None):
            structure = StructureValidator("")
            structure.current_file = current_file
            structure.old_file = None
            structure.file_path = "random_path"
            structure.is_valid = True
            validator = IncidentFieldValidator(structure)
            validator.current_file = current_file
            assert validator.is_valid_name() is answer
            assert validator.is_valid_file() is answer

    CONTENT_1 = {
        'content': True
    }

    CONTENT_BAD_1 = {
        'content': False
    }

    CONTENT_BAD_2 = {
        'something': True
    }

    INPUTS_FLAGS = [
        (CONTENT_1, True),
        (CONTENT_BAD_1, False),
        (CONTENT_BAD_2, False)
    ]

    @pytest.mark.parametrize('current_file, answer', INPUTS_FLAGS)
    def test_is_valid_content_flag_sanity(self, current_file, answer):
        with patch.object(StructureValidator, '__init__', lambda a, b: None):
            structure = StructureValidator("")
            structure.current_file = current_file
            structure.old_file = None
            structure.file_path = "random_path"
            structure.is_valid = True
            validator = IncidentFieldValidator(structure)
            validator.current_file = current_file
            assert validator.is_valid_content_flag() is answer
            assert validator.is_valid_file() is answer

    SYSTEM_FLAG_1 = {
        'system': False,
        'content': True,
    }

    SYSTEM_FLAG_BAD_1 = {
        'system': True,
        'content': True,
    }

    INPUTS_SYSTEM_FLAGS = [
        (SYSTEM_FLAG_1, True),
        (SYSTEM_FLAG_BAD_1, False)
    ]

    @pytest.mark.parametrize('current_file, answer', INPUTS_SYSTEM_FLAGS)
    def test_is_valid_system_flag_sanity(self, current_file, answer):
        with patch.object(StructureValidator, '__init__', lambda a, b: None):
            structure = StructureValidator("")
            structure.current_file = current_file
            structure.old_file = None
            structure.file_path = "random_path"
            structure.is_valid = True
            validator = IncidentFieldValidator(structure)
            validator.current_file = current_file
            assert validator.is_valid_system_flag() is answer
            assert validator.is_valid_file() is answer
