from Tests.scripts.hook_validations.integration import IntegrationValidator


def test_removed_docker_image_on_existing_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "dockerimage": "test"
        }
    }
    validator.current_integration = {
        "script": {
            "no": "dockerimage"
        }
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_updated_docker_image_on_existing_integration():
    validator = IntegrationValidator("temp_file", check_git=False)

    validator.old_integration = {
        "script": {
            "dockerimage": "test"
        }
    }
    validator.current_integration = {
        "script": {
            "dockerimage": "test1"
        }
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_not_changed_docker_image_on_existing_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {}
    validator.current_integration = {}

    assert validator.is_docker_image_changed() is False, "The script validator couldn't find the docker "\
        "image as changed"


def test_added_docker_image_on_existing_integration():
    validator = IntegrationValidator("temp_file", check_git=False)

    validator.old_integration = {}
    validator.current_integration = {
        "script": {
            "dockerimage": "test1"
        }
    }

    assert validator.is_docker_image_changed(), "The script validator couldn't find the docker image as changed"


def test_added_required_field_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "configuration": [
            {
                "name": "test",
                "required": False
            }
        ]
    }
    validator.current_integration = {
        "configuration": [
            {
                "name": "test",
                "required": True
            }
        ]
    }

    assert validator.is_added_required_fields(), "The script validator couldn't find the new required fields"


def test_changed_required_field_to_not_required_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "configuration": [
            {
                "name": "test",
                "required": True
            }
        ]
    }
    validator.current_integration = {
        "configuration": [
            {
                "name": "test",
                "required": False
            }
        ]
    }

    assert validator.is_added_required_fields() is False, "The script validator found the change to not reuquired " \
        "as a one who breaks backward compatability"


def test_not_changed_required_field_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "configuration": [
            {
                "name": "test",
                "required": True
            }
        ]
    }
    validator.current_integration = {
        "configuration": [
            {
                "name": "test",
                "required": True
            }
        ]
    }

    assert validator.is_added_required_fields() is False, "The script validator found a backward compatability " \
        "change although no such change was done"


def test_not_changed_required_field_scenario2_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "configuration": [
            {
                "name": "test",
                "required": False
            }
        ]
    }
    validator.current_integration = {
        "configuration": [
            {
                "name": "test",
                "required": False
            }
        ]
    }

    assert validator.is_added_required_fields() is False, "The script validator found a backward compatability " \
        "change although no such change was done"


def test_configuration_extraction():
    validator = IntegrationValidator("temp_file", check_git=False)
    integration_json = {
        "configuration": [
            {
                "name": "test",
                "required": False
            },
            {
                "name": "test1",
                "required": True
            }
        ]
    }

    expected = {
        "test": False,
        "test1": True
    }

    assert validator._get_field_to_required_dict(integration_json) == expected, "Failed to extract configuration"


def test_not_changed_context_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    }
                ]
            }
        ]
    }
    validator.current_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    }
                ]
            }
        ]
    }

    assert validator.is_changed_context_path() is False, "The script validator found a backward compatability " \
        "change although no such change was done"


def test_changed_context_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "outputs": [
                        {
                            "contextPath": "test"
                        }
                    ]
                }
            ]
        }
    }
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "outputs": [
                        {
                            "contextPath": "changed that"
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_changed_context_path(), "The script validator didn't find a backward compatability " \
        "issue although the context path has changed"


def test_added_context_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    }
                ]
            }
        ]
    }
    validator.current_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    },
                    {
                        "contextPath": "changed that"
                    }
                ]
            }
        ]
    }

    assert validator.is_changed_context_path() is False, "The script validator didn't find a backward compatability " \
        "issue although the context path has changed"


def test_added_new_command_context_path_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    }
                ]
            }
        ]
    }
    validator.current_integration = {
        "commands": [
            {
                "name": "test",
                "outputs": [
                    {
                        "contextPath": "test"
                    }
                ]
            },
            {
                "name": "test2",
                "outputs": [
                    {
                        "contextPath": "new command"
                    }
                ]
            }
        ]
    }

    assert validator.is_changed_context_path() is False, "The script validator found a backward compatibility " \
        "issue although the context path has not changed"


def test_changed_required_arg_for_command_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test",
                            "required": True
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_changed_command_name_or_arg(), "The script validator did not found a backward compatibility " \
        "issue although the command was added with required arg"


def test_added_required_arg_for_command_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test",
                        },
                        {
                            "name": "test1",
                            "required": True
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_changed_command_name_or_arg(), "The script validator did not found a backward compatibility " \
        "issue although the command was added with required arg"


def test_renamed_arg_in_command_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test1",
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_changed_command_name_or_arg(), "The script validator did not found a backward compatibility " \
        "issue although the command args were renamed"


def test_not_requires_arg_in_command_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "commands": [
            {
                "name": "test",
                "arguments": [
                    {
                        "name": "test"
                    }
                ]
            }
        ]
    }
    validator.current_integration = {
        "commands": [
            {
                "name": "test",
                "arguments": [
                    {
                        "name": "test"
                    },
                    {
                        "name": "test1",
                    }
                ]
            }
        ]
    }

    assert validator.is_changed_command_name_or_arg() is False, "The script validator found a backward compatibility " \
        "issue although a new not required command was added"


def test_not_changed_command_in_integration():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.old_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "test",
                    "arguments": [
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_changed_command_name_or_arg() is False, "The script validator found a backward compatibility " \
        "issue although the commands haven't changed"


def test_no_duplicate_params():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "configuration": [
            {
                "name": "test"
            },
            {
                "name": "tes1",
            }
        ]
    }

    assert validator.is_there_duplicate_params() is False, \
        "The integration validator found duplicated params although there are none"


def test_duplicated_params():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "configuration": [
            {
                "name": "test"
            },
            {
                "name": "test",
            }
        ]
    }

    assert validator.is_there_duplicate_params(), \
        "The integration validator did not find duplicated params although there are duplicates"


def test_no_duplicate_args():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "testing",
                    "arguments": [
                        {
                            "name": "test1"
                        },
                        {
                            "name": "test2"
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_there_duplicate_args() is False, \
        "The integration validator found duplicated args although there are none"


def test_duplicated_argss():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "testing",
                    "arguments": [
                        {
                            "name": "test"
                        },
                        {
                            "name": "test"
                        }
                    ]
                }
            ]
        }
    }

    assert validator.is_there_duplicate_args(), \
        "The integration validator did not find duplicated args although there are duplicates"
