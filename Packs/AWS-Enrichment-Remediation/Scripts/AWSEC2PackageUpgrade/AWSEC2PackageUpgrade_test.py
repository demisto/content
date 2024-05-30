import pytest
import demistomock as demisto
from AWSEC2PackageUpgrade import aws_ec2_package_upgrade


def test_version_pattern(mocker):
    valid_version = "openssh-9.7p1"
    invalid_version = "openssh-9.7.1"

    args = {
        "instance_id": "i-12345",
        "asm_rule_id": "InsecureOpenSSH",
        "version": valid_version,
        "region": "us-east-1",
    }

    instance_info = {
        "InstanceStatus": "Active",
        "PlatformType": "Linux",
        "PlatformName": "Ubuntu",
    }

    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            [{"Contents": {"Entries": [instance_info]}}],
            [{"Contents": {"CommandId": "12345"}}],
        ],
    )
    aws_ec2_package_upgrade(args)
    demisto.executeCommand.assert_called()

    args["version"] = invalid_version
    with pytest.raises(ValueError):
        aws_ec2_package_upgrade(args)


def test_invalid_instance_id(mocker):
    instance_id = "i-54321"
    args = {
        "instance_id": instance_id,
        "asm_rule_id": "InsecureOpenSSH",
        "version": "openssh-9.7p1",
        "region": "us-east-1",
    }

    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Contents": "Invalid instance id"}]
    )
    with pytest.raises(ValueError):
        aws_ec2_package_upgrade(args)


def test_instance_status_not_active(mocker):
    instance_id = "i-12345"
    args = {
        "instance_id": instance_id,
        "asm_rule_id": "InsecureOpenSSH",
        "version": "openssh-9.7p1",
        "region": "us-east-1",
    }

    instance_info = {
        "InstanceStatus": "Inactive",
        "PlatformType": "Linux",
        "PlatformName": "Ubuntu",
    }

    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"Entries": [instance_info]}}],
    )
    with pytest.raises(ValueError):
        aws_ec2_package_upgrade(args)


def test_successful_upgrade_package_on_instance(mocker):
    instance_id = "i-12345"
    args = {
        "instance_id": instance_id,
        "asm_rule_id": "InsecureOpenSSH",
        "version": "openssh-9.7p1",
        "region": "us-east-1",
    }

    instance_info = {
        "InstanceStatus": "Active",
        "PlatformType": "Linux",
        "PlatformName": "Ubuntu",
    }

    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            [{"Contents": {"Entries": [instance_info]}}],
            [{"Contents": {"CommandId": "12345"}}],
        ],
    )
    result = aws_ec2_package_upgrade(args)
    assert result.outputs["AWSCommandID"] == "12345"
    assert result.raw_response["AWSCommandID"] == "12345"
    assert result.readable_output == "12345"
