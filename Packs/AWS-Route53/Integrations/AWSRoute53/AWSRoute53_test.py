import importlib

AWS_ROUTE53 = importlib.import_module("AWSRoute53")

TEST_PARAMS = {'region': 'test_region', 'roleArn': 'test_arn', 'roleSessionName': 'test_role_session',
               'roleSessionDuration': 'test_role_session_duration'}


class AWSClient:
    def aws_session(self):
        pass


class AWSRoute53Client:
    def list_hosted_zones(self):
        pass


def test_list_hosted_zones(mocker):
    """
    Given:
    - A bucket name and location.
    When:
    - Calling create_bucket_command method.
    Then:
    - Ensure that the bucket was successfully created.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    response = {
        'HostedZones': [
            {
                'Name': 'test-domain.com',
                'Id': 'xxx',
                'ResourceRecordSetCount': 5,
            }
        ]
    }
    mocker.patch.object(AWSClient, "aws_session", return_value=AWSRoute53Client())
    mocker.patch.object(AWSRoute53Client, "list_hosted_zones", return_value=response)

    client = AWSClient()
    res = AWS_ROUTE53.list_hosted_zones(args, client)
    data = {
        'Name': 'test-domain.com',
        'Id': 'xxx',
        'ResourceRecordSetCount': 5,
    }
    assert tableToMarkdown('AWS Route53 Hosted Zones', data) == res.readable_output
