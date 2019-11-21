from mock import patch
import pytest

from Tests.scripts.hook_validations.script import ScriptValidator
from Tests.scripts.hook_validations.structure import StructureValidator


def get_validator(current_file=None, old_file=None, file_path=""):
    with patch.object(StructureValidator, '__init__', lambda a, b: None):
        structure = StructureValidator("")
        structure.current_file = current_file
        structure.old_file = old_file
        structure.file_path = file_path
        structure.is_valid = True
        validator = ScriptValidator(structure)
        validator.old_script = old_file
        validator.current_script = current_file
    return validator


class TestScriptValidator:
    BASE_DOCKER_IMAGE = {
        'dockerimage': '1.0.0'
    }

    CHANGED_DOCKER_IMAGE = {
        'dockerimage': 'test_updated'
    }
    NO_DOCKER_IMAGE = {
        'no': 'dockerimage'
    }

    UPDATED_DOCKER_IMAGE = {
        'dockerimage': '1.0.1'
    }

    NO_SCRIPT = {}

    INPUTS_DOCKER_IMAGES = [
        (BASE_DOCKER_IMAGE, NO_DOCKER_IMAGE, True),
        (BASE_DOCKER_IMAGE, CHANGED_DOCKER_IMAGE, True),
        (BASE_DOCKER_IMAGE, BASE_DOCKER_IMAGE, False),
        (NO_DOCKER_IMAGE, CHANGED_DOCKER_IMAGE, True),
        (BASE_DOCKER_IMAGE, UPDATED_DOCKER_IMAGE, True),
    ]

    @pytest.mark.parametrize('current_file, old_file, answer', INPUTS_DOCKER_IMAGES)
    def test_is_docker_image_changed(self, current_file, old_file, answer):
        validator = get_validator(current_file, old_file)
        assert validator.is_docker_image_changed() is answer

    SANE_DOC_PATH = 'Scripts/SaneDocReport/SaneDocReport.yml'
    SANE_DOC_SUBTYPE = {
        "type": "python",
        "subtype": "python3"
    }

    SAND_DOC_CHANGED_SUBTYPE = {
        "type": "python",
        "subtype": "python2"
    }

    INPUTS_SANE_DOCS_IMAGES = [
        (SANE_DOC_PATH, SANE_DOC_SUBTYPE, SAND_DOC_CHANGED_SUBTYPE, True, False),
        (SANE_DOC_PATH, BASE_DOCKER_IMAGE, UPDATED_DOCKER_IMAGE, False, True)
    ]

    @pytest.mark.parametrize('path, current_file, old_file, answer_subtype, answer_bacwards', INPUTS_SANE_DOCS_IMAGES)
    def test_sane_docs(self, path, current_file, old_file, answer_subtype, answer_bacwards):
        structure = StructureValidator(file_path=path)
        validator = ScriptValidator(structure)
        validator.current_file = current_file
        validator.old_file = old_file

        assert validator.is_changed_subtype() is answer_subtype
        assert validator.is_backward_compatible() is answer_bacwards

    CONTEXT_OLD = {
        'outputs': [
            {
                'contextPath': 'test1'
            },
            {
                'contextPath': 'test2'
            }
        ]
    }

    CONTEXT_NEW = {
        'outputs': [
            {
                'contextPath': 'test1'
            }
        ]
    }

    CONTEXT_CHANGED = {
        'outputs': [
            {
                'contextPath': 'test2'
            }
        ]
    }
    CONTEXT_MULTI_OLD = {
        'outputs': [
            {
                'contextPath': 'test1'
            },
            {
                'contextPath': 'test2'
            }
        ]
    }

    CONTEXT_MULTI_NEW = {
        'outputs': [
            {
                'contextPath': 'test2'
            },
            {
                'contextPath': 'test1'
            }
        ]
    }
    INPUTS_CONTEXT_PATHS = [
        (CONTEXT_NEW, CONTEXT_OLD, True),
        (CONTEXT_OLD, CONTEXT_NEW, False),
        (CONTEXT_CHANGED, CONTEXT_OLD, True),
        (CONTEXT_OLD, CONTEXT_CHANGED, False),
        (CONTEXT_MULTI_NEW, CONTEXT_OLD, False),
        (CONTEXT_NEW, CONTEXT_NEW, False),
        (CONTEXT_NEW, CONTEXT_MULTI_NEW, True),
        (CONTEXT_MULTI_NEW, CONTEXT_NEW, False)
    ]

    @pytest.mark.parametrize('current_file, old_file, answer', INPUTS_CONTEXT_PATHS)
    def test_deleted_context_path(self, current_file, old_file, answer):
        validator = get_validator(current_file, old_file)
        assert validator.is_context_path_changed() is answer

    OLD_ARGS = {
        'args': [
            {
                'name': 'test1'
            }
        ]
    }
    CURRENT_ARGS = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    MOVED_ARG = {
        'args': [
            {
                'name': 'test2'
            },
            {
                'name': 'test1'
            }
        ]
    }
    OLD_MULTI_ARGS = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }

    CURRENT_MULTI_ARGS = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }

    ADDED_MULTI_ARGS = {
        'args': [
            {
                'name': 'test2'
            },
            {
                'name': 'test1'
            },
            {
                'name': 'test3'
            }
        ]
    }
    INPUTS_ARGS_CHANGED = [
        (CURRENT_ARGS, OLD_ARGS, False),
        (MOVED_ARG, OLD_ARGS, False),
        (CURRENT_MULTI_ARGS, OLD_MULTI_ARGS, False),
        (ADDED_MULTI_ARGS, OLD_MULTI_ARGS, False),
        (OLD_MULTI_ARGS, ADDED_MULTI_ARGS, True)
    ]

    @pytest.mark.parametrize('current_file, old_file, answer', INPUTS_ARGS_CHANGED)
    def test_is_arg_changed(self, current_file, old_file, answer):
        validator = get_validator(current_file, old_file)
        assert validator.is_arg_changed() is answer

    DUP_1 = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test1'
            }
        ]
    }
    NO_DUP = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    INPUTS_DUPLICATES = [
        (DUP_1, True),
        (NO_DUP, False)
    ]

    @pytest.mark.parametrize('current_file, answer', INPUTS_DUPLICATES)
    def test_is_there_duplicates_args(self, current_file, answer):
        validator = get_validator(current_file)
        assert validator.is_there_duplicates_args() is answer

    REQUIRED_ARGS_BASE = {
        'args': [
            {
                'name': 'test',
                'required': False
            }
        ]
    }

    REQUIRED_ARGS_TRUE = {
        'args': [
            {
                'name': 'test',
                'required': True
            }
        ]
    }
    INPUTS_REQUIRED_ARGS = [
        (REQUIRED_ARGS_BASE, REQUIRED_ARGS_BASE, False),
        (REQUIRED_ARGS_TRUE, REQUIRED_ARGS_BASE, True),
        (REQUIRED_ARGS_TRUE, REQUIRED_ARGS_TRUE, False),
        (REQUIRED_ARGS_BASE, REQUIRED_ARGS_TRUE, False)
    ]

    @pytest.mark.parametrize('current_file, old_file, answer', INPUTS_REQUIRED_ARGS)
    def test_is_added_required_args(self, current_file, old_file, answer):
        validator = get_validator(current_file, old_file)
        assert validator.is_added_required_args() is answer

    INPUT_CONFIGURATION_1 = {
        'args': [
            {
                'name': 'test',
                'required': False
            },
            {
                'name': 'test1',
                'required': True
            }
        ]
    }
    EXPECTED_CONFIGURATION_1 = {
        'test': False,
        'test1': True
    }
    INPUTS_CONFIGURATION_EXTRACTION = [
        (INPUT_CONFIGURATION_1, EXPECTED_CONFIGURATION_1)
    ]

    @pytest.mark.parametrize('script, expected', INPUTS_CONFIGURATION_EXTRACTION)
    def test_configuration_extraction(self, script, expected):
        assert ScriptValidator._get_arg_to_required_dict(script) == expected, 'Failed to extract configuration'

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

    @pytest.mark.parametrize('current_file, old_file, answer', INPUTS_SUBTYPE_TEST)
    def test_is_changed_subtype_python(self, current_file, old_file, answer):
        validator = get_validator()
        validator.current_file = current_file
        validator.old_file = old_file
        assert validator.is_changed_subtype() is answer

    INPUTS_IS_VALID_SUBTYPE = [
        (BLA_BLA_SUBTYPE, False),
        (PYTHON2_SUBTYPE, True),
        (PYTHON3_SUBTYPE, True)
    ]

    @pytest.mark.parametrize('current_file, answer', INPUTS_IS_VALID_SUBTYPE)
    def test_is_valid_subtype(self, current_file, answer):
        validator = get_validator()
        validator.current_file = current_file
        assert validator.is_valid_subtype() is answer
