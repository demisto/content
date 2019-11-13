from Tests.scripts.hook_validations.script import ScriptValidator


def test_removed_docker_image_on_existing_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'dockerimage': 'test'
    }
    validator.current_script = {
        'no': 'dockerimage'
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_updated_docker_image_on_existing_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'dockerimage': 'test'
    }
    validator.current_script = {
        'dockerimage': 'test_updated'
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_not_changed_docker_image_on_existing_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'dockerimage': 'test'
    }
    validator.current_script = {
        'dockerimage': 'test'
    }

    assert validator.is_docker_image_changed() is False, "The script validator couldn't find the docker " \
        'image as changed'


def test_added_docker_image_on_existing_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
    }
    validator.current_script = {
        'dockerimage': 'test_updated'
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_updated_docker_image_on_sane_doc_reports_fail_name():
    validator = ScriptValidator('SaneDocReport.yml', check_git=False)
    validator.old_script = {
        'dockerimage': '1.0.0'
    }
    validator.current_script = {
        'dockerimage': '1.0.1'
    }

    assert not validator.is_backward_compatible(), "The script validator passed sane-doc-reports eventough it shouldn't"


def test_updated_docker_image_on_sane_doc_reports_fail_subtype():
    validator = ScriptValidator('Scripts/SaneDocReport/SaneDocReport.yml', check_git=False)
    validator.current_script = {
        "type": "python",
        "subtype": "python3"
    }
    validator.old_script = {
        "type": "python",
        "subtype": "python2"
    }

    assert validator.is_changed_subtype() is True, \
        "Did not find changed subtype while it was changed"
    assert validator.is_backward_compatible() is False, "The script validator passed sane-doc-reports"


def test_updated_docker_image_on_sane_doc_reports():
    validator = ScriptValidator('Scripts/SaneDocReport/SaneDocReport.yml',
                                check_git=False)
    validator.old_script = {
        'dockerimage': '1.0.0'
    }
    validator.current_script = {
        'dockerimage': '1.0.1'
    }

    assert validator.is_backward_compatible(), "The script validator didn't pass sane-doc-reports"


def test_deleted_context_path():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            },
            {
                'contextPath': 'test2'
            }
        ]
    }
    validator.current_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            }
        ]
    }

    assert validator.is_context_path_changed(), "The script validator couldn't find the context path as deleted"


def test_changed_context_path():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            }
        ]
    }
    validator.current_script = {
        'outputs': [
            {
                'contextPath': 'test2'
            }
        ]
    }

    assert validator.is_context_path_changed(), "The script validator couldn't find the context path as updated"


def test_moved_context_path():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            },
            {
                'contextPath': 'test2'
            }
        ]
    }
    validator.current_script = {
        'outputs': [
            {
                'contextPath': 'test2'
            },
            {
                'contextPath': 'test1'
            }
        ]
    }

    assert validator.is_context_path_changed() is False, "The script validator couldn't find the context " \
        'path as the same'


def test_not_changed_context_path():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'outputs': [
            {
                'contextPath': 'test'
            }
        ]
    }
    validator.current_script = {
        'outputs': [
            {
                'contextPath': 'test'
            }
        ]
    }

    assert validator.is_context_path_changed() is False, "The script validator couldn't find the context " \
        'path as not touched'


def test_added_new_context_path():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            }
        ]
    }
    validator.current_script = {
        'outputs': [
            {
                'contextPath': 'test1'
            },
            {
                'contextPath': 'test2'
            }
        ]
    }

    assert validator.is_context_path_changed() is False, 'The script validator found an existing context path as ' \
        'changed although it is not, but new context path added to a command'


def test_deleted_arg_from_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test1'
            }
        ]
    }

    assert validator.is_arg_changed(), "The script validator couldn't find deleted arg name"


def test_added_arg_to_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test1'
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }

    assert validator.is_arg_changed() is False, 'The script validator found the arg list has breaking backward ' \
        'compatibility although just new option was added'


def test_moved_arg_in_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test2'
            },
            {
                'name': 'test1'
            }
        ]
    }

    assert validator.is_arg_changed() is False, 'The script validator found the arg list has breaking backward ' \
        'compatibility although just reordered the existing arg list'


def test_untouched_arg_list_in_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }

    assert validator.is_arg_changed() is False, 'The script validator found the arg list has breaking backward ' \
        'compatibility although it was not touched'


def test_changed_arg_in_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }
    validator.current_script = {
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

    assert validator.is_arg_changed() is False, "The script validator didn't found the arg list has breaking " \
        'backward compatibility although an arg was renamed'


def test_duplicate_arg_in_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.current_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test1'
            }
        ]
    }

    assert validator.is_there_duplicate_args(), "The script validator didn't found the duplicate arg"


def test_no_duplicate_arg_in_script():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.current_script = {
        'args': [
            {
                'name': 'test1'
            },
            {
                'name': 'test2'
            }
        ]
    }

    assert validator.is_there_duplicate_args() is False, 'The script validator found duplicate arg although ' \
        'there no such'


def test_added_required_field_in_integration():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test',
                'required': False
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test',
                'required': True
            }
        ]
    }

    assert validator.is_added_required_args(), "The script validator couldn't find the new required args"


def test_changed_required_field_to_not_required_in_integration():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test',
                'required': True
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test',
                'required': False
            }
        ]
    }

    assert validator.is_added_required_args() is False, 'The script validator found the change to not required ' \
        'as a one who breaks backward compatability'


def test_not_changed_required_field_in_integration():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test',
                'required': True
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test',
                'required': True
            }
        ]
    }

    assert validator.is_added_required_args() is False, 'The script validator found a backward compatibility ' \
        'change although no such change was done'


def test_not_changed_required_field_scenario2_in_integration():
    validator = ScriptValidator('temp_file', check_git=False)
    validator.old_script = {
        'args': [
            {
                'name': 'test',
                'required': False
            }
        ]
    }
    validator.current_script = {
        'args': [
            {
                'name': 'test',
                'required': False
            }
        ]
    }

    assert validator.is_added_required_args() is False, 'The script validator found a backward compatibility ' \
        'change although no such change was done'


def test_configuration_extraction():
    validator = ScriptValidator('temp_file', check_git=False)
    script_json = {
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

    expected = {
        'test': False,
        'test1': True
    }

    assert validator.get_arg_to_required_dict(script_json) == expected, 'Failed to extract configuration'


def test_is_changed_subtype_python2_to_3():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "type": "python",
        "subtype": "python3"
    }
    validator.old_script = {
        "type": "python",
        "subtype": "python2"
    }

    assert validator.is_changed_subtype() is True, \
        "Did not find changed subtype while it was changed"


def test_is_changed_subtype_python3():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "type": "python",
        "subtype": "python3"
    }
    validator.old_script = {
        "type": "python",
        "subtype": "python3"
    }

    assert validator.is_changed_subtype() is False, \
        "found changed subtype while it was not changed"


def test_is_valid_subtype_python2():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "type": "python",
        "subtype": "python2"
    }
    validator.old_script = {
        "type": "python",
        "subtype": "python2"
    }

    assert validator.is_valid_subtype() is True, \
        "found invalid subtype while it is valid - python2"


def test_is_valid_subtype_blabla():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "type": "python",
        "subtype": "blabla"
    }
    validator.old_script = {
        "type": "python",
        "subtype": "blabla"
    }

    assert validator.is_valid_subtype() is False, \
        "found valid subtype while it is invalid - blabla"
