import demistomock as demisto  # noqa: F401
import pytest
import json
from CommonServerPython import DemistoException


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


def test_instance_info_error(mocker):
    """Tests ec2_instance_info raises DemistoException when the command returns an error.

    Given:
        - A mocked error response from aws-ec2-instances-describe
    When:
        - Calling ec2_instance_info
    Then:
        - A DemistoException is raised
    """
    from AWSIdentifySGPublicExposure import ec2_instance_info

    error_result = [{"Type": 4, "Contents": "Some error occurred", "ContentsFormat": "text"}]
    mocker.patch.object(demisto, "executeCommand", return_value=error_result)

    with pytest.raises(DemistoException, match="Error retrieving instance network interface details"):
        ec2_instance_info(
            account_id="000000000000",
            instance_id="fake-instance-id",
            public_ip="1.1.1.1",
            region="us-east-1",
            integration_instance="",
        )


def test_instance_info_empty_result(mocker):
    """Tests ec2_instance_info raises DemistoException when the command returns an empty list.

    Given:
        - An empty list response from aws-ec2-instances-describe
    When:
        - Calling ec2_instance_info
    Then:
        - A DemistoException is raised indicating no results returned
    """
    from AWSIdentifySGPublicExposure import ec2_instance_info

    mocker.patch.object(demisto, "executeCommand", return_value=[])

    with pytest.raises(DemistoException, match="No results returned"):
        ec2_instance_info(
            account_id="000000000000",
            instance_id="fake-instance-id",
            public_ip="1.1.1.1",
            region="us-east-1",
            integration_instance="",
        )


def test_instance_info_multi_instance(mocker):
    """Tests ec2_instance_info correctly identifies the valid response from multiple integration instances.

    Given:
        - Multiple results from aws-ec2-instances-describe where the first is an error and the second is valid
    When:
        - Calling ec2_instance_info
    Then:
        - The function returns data from the valid (non-error) entry
    """
    from AWSIdentifySGPublicExposure import ec2_instance_info

    INSTANCE_INFO = util_load_json("./test_data/instance_info_sample.json")

    multi_instance_result = [
        {"Type": 4, "Contents": "Error from instance 1", "ContentsFormat": "text"},
        INSTANCE_INFO[0],
    ]

    mocker.patch.object(demisto, "executeCommand", return_value=multi_instance_result)

    result = ec2_instance_info(
        account_id="000000000000",
        instance_id="fake-instance-id",
        public_ip="1.1.1.1",
        region="us-east-1",
        integration_instance="",
    )
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
        "EC2 instance fake-instance-id has public IP 1.1.1.1 on ENI eni-00000000000000000:\n"
        "Associated Security Groups: sg-00000000000000000."
    )
    assert result.raw_response == result.outputs
