import demistomock as demisto  # noqa: F401


def test_upgrade_package_on_instance_invalid_asmruleid(mocker):
    """
    Test the upgrade_package_on_instance function with an invalid ASM rule ID.
    Expected result: A dictionary with run_command_flag set to False and an
    appropriate error message.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "fake",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": False,
        "run_command_output": "Package upgrade is not supported for the ASM Rule ID.",
    }


def test_upgrade_package_on_instance_invalid_instanceid(mocker):
    """
    Test the upgrade_package_on_instance function with an invalid instance ID.
    Expected result: A dictionary with run_command_flag set to False and an
    appropriate error message.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    def executeCommand(name, args):
        if name == "aws-ssm-inventory-entry-list":
            return [{"Contents": "Invalid instance id and Does not exist"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "InsecureOpenSSH",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": False,
        "run_command_output": "Invalid instance id.",
    }


def test_upgrade_package_on_instance_no_instance(mocker):
    """
    Test the upgrade_package_on_instance function with a non-existent instance.
    Expected result: A dictionary with run_command_flag set to False and an appropriate error message.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    def executeCommand(name, args):
        if name == "aws-ssm-inventory-entry-list":
            return [{"Contents": {"Entries": []}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "InsecureOpenSSH",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": False,
        "run_command_output": "Instance does not exist.",
    }


def test_upgrade_package_on_instance_inactive(mocker):
    """
    Test the upgrade_package_on_instance function with an inactive instance.
    Expected result: A dictionary with run_command_flag set to False and an appropriate error message.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    def executeCommand(name, args):
        if name == "aws-ssm-inventory-entry-list":
            return [{"Contents": {"Entries": [{"InstanceStatus": "Inactive"}]}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "InsecureOpenSSH",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": False,
        "run_command_output": "Instance status is not Active. Check SSM agent on the instance.",
    }


def test_upgrade_package_on_instance_no_package(mocker):
    """
    Test the upgrade_package_on_instance function with an unsupported operating system for package upgrade.
    Expected result: A dictionary with run_command_flag set to False and an appropriate error message.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    def executeCommand(name, args):
        if name == "aws-ssm-inventory-entry-list":
            return [
                {
                    "Contents": {
                        "Entries": [
                            {
                                "InstanceStatus": "Active",
                                "PlatformType": "Linux",
                                "PlatformName": "Not-Ubuntu",
                            }
                        ]
                    }
                }
            ]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "InsecureOpenSSH",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": False,
        "run_command_output": "Package upgrade is not supported for the OS.",
    }


def test_upgrade_package_on_instance_package(mocker):
    """
    Test the upgrade_package_on_instance function with a valid instance and package upgrade scenario.
    Expected result: A dictionary with run_command_flag set to True and a CommandId.
    """
    from AWSPackageUpgrade import upgrade_package_on_instance

    def executeCommand(name, args):
        if name == "aws-ssm-inventory-entry-list":
            return [
                {
                    "Contents": {
                        "Entries": [
                            {
                                "InstanceStatus": "Active",
                                "PlatformType": "Linux",
                                "PlatformName": "Ubuntu",
                            }
                        ]
                    }
                }
            ]
        elif name == "aws-ssm-command-run":
            return [{"Contents": {"CommandId": "123"}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    args = {
        "instance_id": "ou-2222-22222222",
        "asm_rule_id": "InsecureOpenSSH",
        "region": "region",
        "assume_role_arn": "None"
    }
    result = upgrade_package_on_instance(**args)
    assert result == {
        "run_command_flag": True,
        "run_command_output": "AWS SSM Command run initiated successfully.",
        "run_command_id": "123"
    }


def test_aws_package_upgrade(mocker):
    """
    Test the aws_package_upgrade function with a mocked upgrade_package_on_instance function.
    Expected result: A CommandResults object with the correct output and prefix.
    """
    from AWSPackageUpgrade import aws_package_upgrade

    mock_dict = {"run_command_flag": True, "run_command_output": "123"}

    mocker.patch(
        "AWSPackageUpgrade.upgrade_package_on_instance", return_value=mock_dict
    )

    command_results = aws_package_upgrade(
        {"instance_id": "123", "asm_rule_id": "InsecureOpenSSH", "region": "us-east"}
    )

    assert command_results.outputs_prefix == "awspackageupgrade"
    assert command_results.outputs == {
        "run_command_flag": True,
        "run_command_output": "123",
    }
