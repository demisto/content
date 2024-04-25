import importlib

AWS_ROUTE53 = importlib.import_module("AWSRoute53")

TEST_PARAMS = {
    'roleArn': 'test_arn',
    'roleSessionName': 'test_role_session',
    'roleSessionDuration': 'test_role_session_duration'
}


class AWSClient:  # pragma: no cover
    def aws_session(self):
        pass


class AWSRoute53ClientWaiter:  # pragma: no cover
    def wait(self, **kwargs):
        pass


class AWSRoute53Client:  # pragma: no cover
    def list_hosted_zones(self):
        pass

    def change_resource_record_sets(self, **kwargs):
        pass

    def list_resource_record_sets(self, **kwargs):
        pass

    def get_waiter(self, *args):  # noqa
        return AWSRoute53ClientWaiter()

    def test_dns_answer(self, **kwargs):
        pass


def test_create_record(mocker):
    """
    Given:
    - A DNS record.
    When:
    - Calling create_record method.
    Then:
    - Ensure that the DNS record was successfully created.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'hostedZoneId': 'test-domain.com',
        'source': 'foo.test-domain.com',
        'type': 'CNAME',
        'ttl': 300,
        'target': 'google.com',
        'comment': 'redirect to google.com'
    })
    response = {
        'ChangeInfo': {
            'Id': '__mock_id__',
            'Status': 'changed',
        }
    }
    mocker.patch.object(AWSRoute53Client, "change_resource_record_sets", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.create_record(args, session)
    data = {
        'Id': '__mock_id__',
        'Status': 'changed',
    }
    assert tableToMarkdown('AWS Route53 record created', data) == res.readable_output


def test_delete_record(mocker):
    """
    Given:
    - A DNS record.
    When:
    - Calling delete_record method.
    Then:
    - Ensure that the DNS record was successfully deleted.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'hostedZoneId': 'test-domain.com',
        'source': 'foo.test-domain.com',
        'type': 'CNAME',
        'ttl': 300,
    })
    response = {
        'ChangeInfo': {
            'Id': '__mock_id__',
            'Status': 'deleted',
        }
    }
    mocker.patch.object(AWSRoute53Client, "change_resource_record_sets", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.delete_record(args, session)
    data = {
        'Id': '__mock_id__',
        'Status': 'deleted',
    }
    assert tableToMarkdown('AWS Route53 record deleted', data) == res.readable_output


def test_upsert_record(mocker):
    """
    Given:
    - A DNS record.
    When:
    - Calling upsert_record method.
    Then:
    - Ensure that the DNS record was successfully updated.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'hostedZoneId': 'test-domain.com',
        'source': 'foo.test-domain.com',
        'type': 'CNAME',
        'ttl': 300,
        'target': 'palo.com',
        'comment': 'redirect to palo.com'
    })
    response = {
        'ChangeInfo': {
            'Id': '__mock_id__',
            'Status': 'updated',
        }
    }
    mocker.patch.object(AWSRoute53Client, "change_resource_record_sets", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.upsert_record(args, session)
    data = {
        'Id': '__mock_id__',
        'Status': 'updated',
    }
    assert tableToMarkdown('AWS Route53 record Upsert', data) == res.readable_output


def test_list_hosted_zones(mocker):
    """
    Given:
    - A Hosted Zone.
    When:
    - Calling list_hosted_zones method.
    Then:
    - Ensure we get the list of hosted zones.
    """
    from CommonServerPython import tableToMarkdown

    response = {
        'HostedZones': [
            {
                'Name': 'test-domain.com',
                'Id': 'xxx',
                'ResourceRecordSetCount': 5,
            }
        ]
    }
    mocker.patch.object(AWSRoute53Client, "list_hosted_zones", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.list_hosted_zones(session)
    data = {
        'Name': 'test-domain.com',
        'Id': 'xxx',
        'ResourceRecordSetCount': 5,
    }
    assert tableToMarkdown('AWS Route53 Hosted Zones', data) == res.readable_output


def test_list_resource_record_sets(mocker):
    """
    Given:
    - A Hosted Zone.
    When:
    - Calling list_resource_record_sets method.
    Then:
    - Ensure we get the list of record sets from the hosted zones.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'HostedZoneId': '__x__',
        'startRecordName': 'aaa',
        'startRecordType': 'CNAME',
        'startRecordIdentifier': 'a',
    })
    response = {
        'ResourceRecordSets': [
            {
                'Name': 'a.test-domain.com',
                'Type': 'A',
                'TTL': 555,
                'ResourceRecords':
                    [
                        {
                            "Value": 'test-domain.com'
                        }
                    ],
            }
        ]
    }
    mocker.patch.object(AWSRoute53Client, "list_resource_record_sets", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.list_resource_record_sets(args, session)
    data = [
        {
            'Name': 'a.test-domain.com',
            'Type': 'A',
            'TTL': 555,
            'ResourceRecords': 'test-domain.com',
        }
    ]
    assert tableToMarkdown('AWS Route53 Record Sets', data) == res.readable_output


def test_list_resource_record_sets_no_ttl(mocker):
    """
    Given:
    - A Hosted Zone.

    When:
    - Calling list_resource_record_sets method.
    - api returns records without TTLs

    Then:
    - Ensure we get the list of record sets from the hosted zones.
    - Ensure parsing is made properly
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'HostedZoneId': '__x__',
        'startRecordName': 'aaa',
        'startRecordType': 'CNAME',
        'startRecordIdentifier': 'a',
    })
    response = {
        'ResourceRecordSets': [
            {
                'Name': 'a.test-domain.com',
                'Type': 'A',
                'ResourceRecords':
                    [
                        {
                            "Value": 'test-domain.com'
                        }
                    ],
            }
        ]
    }
    mocker.patch.object(AWSRoute53Client, "list_resource_record_sets", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.list_resource_record_sets(args, session)
    data = [
        {
            'Name': 'a.test-domain.com',
            'Type': 'A',
            'ResourceRecords': 'test-domain.com',
        }
    ]
    assert tableToMarkdown('AWS Route53 Record Sets', data) == res.readable_output
    assert res.outputs == [
        {'Name': 'a.test-domain.com', 'Type': 'A', 'ResourceRecords': [{'Value': 'test-domain.com'}]}
    ]


def test_waiter_resource_record_sets_changed(mocker):
    """
    Given:
    - A Hosted Zone.
    When:
    - Calling waiter_resource_record_sets_changed method.
    Then:
    - Ensure we call the wait record changed method.
    """

    args = TEST_PARAMS
    args.update({
        'id': '__x__',
        'waiterDelay': 60,
        'waiterMaxAttempts': 3,
    })

    mocker.patch.object(AWSRoute53ClientWaiter, "wait", return_value={})

    session = AWSRoute53Client()
    res = AWS_ROUTE53.waiter_resource_record_sets_changed(args, session)
    assert res.readable_output == "success"


def test_test_dns_answer(mocker):
    """
    Given:
    - A Hosted Zone.
    When:
    - Calling test_dns_answer method.
    Then:
    - Ensure we test the DNS answer.
    """
    from CommonServerPython import tableToMarkdown

    args = TEST_PARAMS
    args.update({
        'HostedZoneId': '__x__',
        'RecordName': 'a.test-domain.com',
        'RecordType': 'CNAME',
        'resolverIP': '8.8.8.8',
    })
    response = {
        'Nameserver': '__Nameserver__',
        'RecordName': '__RecordName__',
        'RecordType': '__RecordType__',
        'ResponseCode': '__ResponseCode__',
        'Protocol': '__Protocol__',
    }
    mocker.patch.object(AWSRoute53Client, "test_dns_answer", return_value=response)

    session = AWSRoute53Client()
    res = AWS_ROUTE53.test_dns_answer(args, session)
    data = {
        'Nameserver': '__Nameserver__',
        'RecordName': '__RecordName__',
        'RecordType': '__RecordType__',
        'ResponseCode': '__ResponseCode__',
        'Protocol': '__Protocol__',
    }
    assert tableToMarkdown('AWS Route53 Test DNS Answer', data) == res.readable_output
