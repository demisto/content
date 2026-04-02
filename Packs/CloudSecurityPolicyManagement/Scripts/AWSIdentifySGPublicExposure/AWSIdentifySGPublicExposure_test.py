import demistomock as demisto  # noqa: F401
import json


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_instance_info(mocker):
    """Tests ec2_instance_info helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to ec2_instance_info helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSIdentifySGPublicExposure import ec2_instance_info

    INSTANCE_INFO = util_load_json("./test_data/instance_info_sample.json")

    mocker.patch.object(demisto, "executeCommand", return_value=INSTANCE_INFO)
    args = {
        "account_id": "000000000000",
        "instance_id": "fake-instance-id",
        "public_ip": "1.1.1.1",
        "region": "us-east-1",
        "integration_instance": "fake-integration",
    }
    result = ec2_instance_info(**args)
    assert result == ("eni-00000000000000000", ["sg-00000000000000000"], "AWS")


def test_identify_sgs(mocker):
    """Tests identify_sgs function.

    Given:
        - Mocked arguments
    When:
        - Sending args to identify_sgs function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    import AWSIdentifySGPublicExposure
    from AWSIdentifySGPublicExposure import identify_sgs

    mocker.patch.object(
        AWSIdentifySGPublicExposure,
        "ec2_instance_info",
        return_value=("eni-00000000000000000", ["sg-00000000000000000"], "fake-integration"),
    )
    args = {
        "account_id": "000000000000",
        "instance_id": "fake-instance-id",
        "public_ip": "1.1.1.1",
        "region": "us-east-1",
        "integration_instance": "fake-integration",
    }
    result = identify_sgs(args)
    assert result.outputs == {
        "EC2InstanceID": "fake-instance-id",
        "NetworkInterfaceID": "eni-00000000000000000",
        "PublicIP": "1.1.1.1",
        "SecurityGroups": ["sg-00000000000000000"],
        "IntegrationInstance": "fake-integration",
    }
    assert result.readable_output == (
        "EC2 instance fake-instance-id has public IP 1.1.1.1 on ENI eni-00000000000000000: "
        "\r\nAssociated Security Groups: sg-00000000000000000."
    )
