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


def test_is_changed_subtype_non_changed():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "type": "python",
            "subtype": "python3"
        }
    }
    validator.old_integration = {
        "script": {
            "type": "python",
            "subtype": "python3"
        }
    }

    assert validator.is_changed_subtype(), \
        "The integration validator found changed subtype while it is valid"


def test_is_changed_subtype_changed():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "type": "python",
            "subtype": "python3"
        }
    }
    validator.old_integration = {
        "script": {
            "type": "python",
            "subtype": "python2"
        }
    }

    assert validator.is_changed_subtype() is False, \
        "The integration validator did not find changed subtype while it is changed"


def test_valid_subtype_lies():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "type": "python",
            "subtype": "lies"
        }
    }
    validator.old_integration = None

    assert validator.is_valid_subtype() is False, \
        "The integration validator found valid subtype while it is invalid"


def test_is_default_arguments_non_default():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "file",
                    "arguments": [
                        {
                            "name": "file",
                            "required": True,
                            "default": False
                        },
                        {
                            "name": "verbose"
                        }
                    ]
                }
            ]
        }
    }
    validator.old_integration = None

    assert validator.is_default_arguments() is False, \
        "The integration validator did not find invalid arg (needed to be default and not required)"


def test_is_default_arguments_ok():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "email",
                    "arguments": [
                        {
                            "name": "email",
                            "required": False,
                            "default": True
                        },
                        {
                            "name": "verbose"
                        }
                    ]
                }
            ]
        }
    }
    validator.old_integration = None

    assert validator.is_default_arguments() is True, \
        "The integration validator found an invalid command arg while it is valid"


def test_is_outputs_for_reputations_commands_valid():
    validator = IntegrationValidator("temp_file", check_git=False)
    validator.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "panorama-commit-status",
                    "outputs": [
                        {
                            "contextPath": "Panorama.Commit.JobID",
                            "description": "Job ID of the configuration to be committed",
                            "type": "number"
                        },
                        {
                            "contextPath": "DBotScore.does.not.matter"
                        }
                    ]
                }
            ]
        }
    }
    validator.old_integration = None

    assert validator.is_outputs_for_reputations_commands_valid() is True, \
        "The integration validator found invalid command outputs while it is valid"

    validator_email = IntegrationValidator("temp_file", check_git=False)
    validator_email.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "email",
                    "outputs": [
                        {
                            "contextPath": "DBotScore.Indicator",
                            "description": "The indicator that was tested.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Type",
                            "description": "The indicator type.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Vendor",
                            "description": "Vendor used to calculate the score.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Sc0re",
                            "description": "The actual score.",
                            "type": "int"
                        },
                        {
                            "contextPath": "Email.To",
                            "description": "email to",
                            "type": "string"
                        },
                    ]
                }
            ]
        }
    }
    validator_email.old_integration = None

    assert validator_email.is_outputs_for_reputations_commands_valid() is False, \
        "The integration validator did not find the invalid command output - DBotScore.Sc0re"

    validator_file = IntegrationValidator("temp_file", check_git=False)
    validator_file.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "file",
                    "outputs": [
                        {
                            "contextPath": "DBotScore.Indicator",
                            "description": "The indicator that was tested.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Type",
                            "description": "The indicator type.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Vendor",
                            "description": "Vendor used to calculate the score.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Score",
                            "description": "The actual score.",
                            "type": "int"
                        },
                        {
                            "contextPath": "File.Md5",
                            "description": "The MD5 hash of the file.",
                            "type": "string"
                        },
                    ]
                }
            ]
        }
    }
    validator_file.old_integration = None

    assert validator_file.is_outputs_for_reputations_commands_valid() is False, \
        "The integration validator did not find the invalid command output - File.Md5"

    validator_ip = IntegrationValidator("temp_file", check_git=False)
    validator_ip.current_integration = {
        "script": {
            "commands": [
                {
                    "name": "ip",
                    "outputs": [
                        {
                            "contextPath": "DBotScore.Indicator",
                            "description": "The indicator that was tested.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Type",
                            "description": "The indicator type.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Vendor",
                            "description": "Vendor used to calculate the score.",
                            "type": "string"
                        },
                        {
                            "contextPath": "DBotScore.Score",
                            "description": "The actual score.",
                            "type": "int"
                        },
                        {
                            "contextPath": "IP.Address",
                            "description": "IP address",
                            "type": "string"
                        },
                    ]
                }
            ]
        }
    }
    validator_ip.old_integration = None

    assert validator_ip.is_outputs_for_reputations_commands_valid() is True, \
        "The integration validator found invalid command outputs while it is valid"
