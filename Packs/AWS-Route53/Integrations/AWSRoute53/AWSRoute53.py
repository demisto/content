import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date


SERVICE = 'route53'


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def raise_error(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


def create_record(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': {
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': args.get('source'),
                            'Type': args.get('type'),
                            'TTL': int(args.get('ttl')),
                            'ResourceRecords': [{'Value': args.get('target')}]
                        }
                    }
                ]
            }
        }

        if args.get('comment') is not None:
            kwargs['ChangeBatch'].update({'Comment': args.get('comment')})

        response = client.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.dumps(response['ChangeInfo'], cls=DatetimeEncoder)
        raw = json.loads(output)
        ec = {'AWS.Route53.RecordSetsChange': raw}
        return create_entry('AWS Route53 record created', data, ec)

    except Exception as e:
        return raise_error(e)


def delete_record(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': {
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': args.get('source'),
                            'Type': args.get('type'),
                            'TTL': int(args.get('ttl')),
                            'ResourceRecords': [{'Value': args.get('target')}]
                        }
                    }
                ]
            }
        }

        response = client.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.dumps(response['ChangeInfo'], cls=DatetimeEncoder)
        raw = json.loads(output)
        ec = {'AWS.Route53.RecordSetsChange': raw}
        return create_entry('AWS Route53 record deleted', data, ec)

    except Exception as e:
        return raise_error(e)


def upsert_record(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': {
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': args.get('source'),
                            'Type': args.get('type'),
                            'TTL': int(args.get('ttl')),
                            'ResourceRecords': [{'Value': args.get('target')}]
                        }
                    }
                ]
            }
        }

        if args.get('comment') is not None:
            kwargs['ChangeBatch'].update({'Comment': args.get('comment')})

        response = client.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.dumps(response['ChangeInfo'], cls=DatetimeEncoder)
        raw = json.loads(output)
        ec = {'AWS.Route53.RecordSetsChange': raw}
        return create_entry('AWS Route53 record Upsert', data, ec)

    except Exception as e:
        return raise_error(e)


def list_hosted_zones(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        data = []
        response = client.list_hosted_zones()
        for hostedzone in response['HostedZones']:
            data.append({
                'Name': hostedzone['Name'],
                'Id': hostedzone['Id'],
                'ResourceRecordSetCount': hostedzone['ResourceRecordSetCount'],
            })
        output = json.dumps(response['HostedZones'], cls=DatetimeEncoder)
        raw = json.loads(output)
        ec = {'AWS.Route53.HostedZones': raw}
        return create_entry('AWS Route53 Hosted Zones', data, ec)

    except Exception as e:
        return raise_error(e)


def list_resource_record_sets(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )

        kwargs = {'HostedZoneId': args.get('hostedZoneId')}
        if args.get('startRecordName') is not None:
            kwargs.update({'StartRecordName': args.get('startRecordName')})
        if args.get('startRecordType') is not None:
            kwargs.update({'StartRecordType': args.get('startRecordType')})
        if args.get('startRecordIdentifier') is not None:
            kwargs.update({'StartRecordIdentifier': args.get('startRecordIdentifier')})

        data = []
        response = client.list_resource_record_sets(**kwargs)
        records = response['ResourceRecordSets']
        for record in records:
            data.append({
                'Name': record['Name'],
                'Type': record['Type'],
                'TTL': record['TTL'],
                'ResourceRecords': record['ResourceRecords'][0]['Value']
            })
        output = json.dumps(response['ResourceRecordSets'], cls=DatetimeEncoder)
        raw = json.loads(output)
        ec = {'AWS.Route53.RecordSets': raw}
        return create_entry('AWS Route53 Record Sets', data, ec)

    except Exception as error:
        return error


def waiter_resource_record_sets_changed(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {'Id': args.get('id')}
        if args.get('waiterDelay') is not None:
            kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
        if args.get('waiterMaxAttempts') is not None:
            kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

        waiter = client.get_waiter('resource_record_sets_changed')
        waiter.wait(**kwargs)
        return "success"

    except Exception as e:
        return raise_error(e)


def test_dns_answer(aws_client, args):
    try:
        client = aws_client.aws_session(
            service=SERVICE,
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'RecordName': args.get('recordName'),
            'RecordType': args.get('recordType'),
        }
        if args.get('resolverIP') is not None:
            kwargs.update({'ResolverIP': args.get('resolverIP')})

        response = client.test_dns_answer(**kwargs)
        data = ({
            'Nameserver': response['Nameserver'],
            'RecordName': response['RecordName'],
            'RecordType': response['RecordType'],
            'ResponseCode': response['ResponseCode'],
            'Protocol': response['Protocol']
        })

        ec = {'AWS.Route53.TestDNSAnswer': response}
        return create_entry('AWS Route53 Test DNS Answer', data, ec)

    except Exception as error:
        return error


def test_function(aws_client):
    try:
        client = aws_client.aws_session(service=SERVICE)
        response = client.list_hosted_zones()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as error:
        return error


def main():
    params = demisto.params()

    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries)

        args = demisto.args()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            result = test_function(aws_client)

        if demisto.command() == 'aws-route53-create-record':
            result = create_record(aws_client, args)

        if demisto.command() == 'aws-route53-upsert-record':
            result = upsert_record(aws_client, args)

        if demisto.command() == 'aws-route53-delete-record':
            result = delete_record(aws_client, args)

        if demisto.command() == 'aws-route53-list-hosted-zones':
            result = list_hosted_zones(aws_client, args)

        if demisto.command() == 'aws-route53-list-resource-record-sets':
            result = list_resource_record_sets(aws_client, args)

        if demisto.command() == 'aws-route53-waiter-resource-record-sets-changed':
            result = waiter_resource_record_sets_changed(aws_client, args)

        if demisto.command() == 'aws-route53-test-dns-answer':
            result = test_dns_answer(aws_client, args)

        demisto.results(result)
        sys.exit(0)
    except Exception as e:
        return_error('Error has occurred in the AWS Route53 Integration: {error}\n {message}'.format(
            error=type(e), message=e.message))


from AWSApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
