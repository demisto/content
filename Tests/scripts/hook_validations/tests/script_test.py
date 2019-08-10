from Tests.scripts.hook_validations.script import ScriptValidator


def test_removed_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "dockerimage": "test"
    }
    validator.current_script = {
        "no": "dockerimage"
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_updated_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "dockerimage": "test"
    }
    validator.current_script = {
        "dockerimage": "test_updated"
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_not_changed_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "dockerimage": "test"
    }
    validator.current_script = {
        "dockerimage": "test"
    }

    assert validator.is_docker_image_changed() is False, "The script validator couldn't find the docker "\
        "image as changed"


def test_added_docker_image_on_existing_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
    }
    validator.current_script = {
        "dockerimage": "test_updated"
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_deleted_context_path():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "outputs": [
            {
                "contextPath": "test1"
            },
            {
                "contextPath": "test2"
            }
        ]
    }
    validator.current_script = {
        "outputs": [
            {
                "contextPath": "test1"
            }
        ]
    }

    assert validator.is_context_path_changed(), "The script validator couldn't find the context path as deleted"


def test_changed_context_path():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "outputs": [
            {
                "contextPath": "test1"
            }
        ]
    }
    validator.current_script = {
        "outputs": [
            {
                "contextPath": "test2"
            }
        ]
    }

    assert validator.is_context_path_changed(), "The script validator couldn't find the context path as updated"


def test_moved_context_path():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "outputs": [
            {
                "contextPath": "test1"
            },
            {
                "contextPath": "test2"
            }
        ]
    }
    validator.current_script = {
        "outputs": [
            {
                "contextPath": "test2"
            },
            {
                "contextPath": "test1"
            }
        ]
    }

    assert validator.is_context_path_changed() is False, "The script validator couldn't find the context " \
        "path as the same"


def test_not_changed_context_path():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "outputs": [
            {
                "contextPath": "test"
            }
        ]
    }
    validator.current_script = {
        "outputs": [
            {
                "contextPath": "test"
            }
        ]
    }

    assert validator.is_context_path_changed() is False, "The script validator couldn't find the context " \
        "path as not touched"


def test_added_new_context_path():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "outputs": [
            {
                "contextPath": "test1"
            }
        ]
    }
    validator.current_script = {
        "outputs": [
            {
                "contextPath": "test1"
            },
            {
                "contextPath": "test2"
            }
        ]
    }

    assert validator.is_context_path_changed() is False, "The script validator found an existing context path as " \
        "changed although it is not, but new context path added to a command"


def test_deleted_arg_from_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }
    validator.current_script = {
        "args": [
            {
                "name": "test1"
            }
        ]
    }

    assert validator.is_arg_changed(), "The script validator couldn't find deleted arg name"


def test_added_arg_to_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "args": [
            {
                "name": "test1"
            }
        ]
    }
    validator.current_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }

    assert validator.is_arg_changed() is False, "The script validator found the arg list has breaking backward " \
        "compatability although just new option was added"


def test_moved_arg_in_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }
    validator.current_script = {
        "args": [
            {
                "name": "test2"
            },
            {
                "name": "test1"
            }
        ]
    }

    assert validator.is_arg_changed() is False, "The script validator found the arg list has breaking backward " \
        "compatability although just reordered the existing arg list"


def test_untouched_arg_list_in_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }
    validator.current_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }

    assert validator.is_arg_changed() is False, "The script validator found the arg list has breaking backward " \
        "compatability although it was not touched"


def test_changed_arg_in_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.old_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }
    validator.current_script = {
        "args": [
            {
                "name": "test2"
            },
            {
                "name": "test1"
            },
            {
                "name": "test3"
            }
        ]
    }

    assert validator.is_arg_changed() is False, "The script validator didn't found the arg list has breaking " \
        "backward compatability although an arg was renamed"


def test_duplicate_arg_in_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test1"
            }
        ]
    }

    assert validator.is_there_duplicates_args(), "The script validator didn't found the duplicate arg"


def test_no_duplicate_arg_in_script():
    validator = ScriptValidator("temp_file", check_git=False)
    validator.current_script = {
        "args": [
            {
                "name": "test1"
            },
            {
                "name": "test2"
            }
        ]
    }

    assert validator.is_there_duplicates_args() is False, "The script validator found duplicate arg although " \
        "there no such"
