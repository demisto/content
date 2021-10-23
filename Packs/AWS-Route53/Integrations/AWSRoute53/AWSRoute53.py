import boto3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date

AWS_DEFAULT_REGION = None
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None


def aws_session(service='route53', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None, rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_roleArn and AWS_roleSessionName is not None:
        kwargs.update({
            'RoleArn': AWS_roleArn,
            'RoleSessionName': AWS_roleSessionName,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(AWS_roleSessionDuration)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_rolePolicy is not None:
        kwargs.update({'Policy': AWS_rolePolicy})

    if kwargs:
        sts_client = boto3.client('sts')
        sts_response = sts_client.assume_role(**kwargs)
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
            )
    else:
        if region is not None:
            client = boto3.client(service_name=service, region_name=region)
        else:
            client = boto3.client(service_name=service, region_name=AWS_DEFAULT_REGION)

    return client


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


def create_record(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def delete_record(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def upsert_record(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def list_hosted_zones(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def list_resource_record_sets(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def waiter_resource_record_sets_changed(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def test_dns_answer(args):
    try:
        client = aws_session(
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
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


def test_function():
    try:
        client = aws_session()
        response = client.list_hosted_zones()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as error:
        return error


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    result = test_function()

if demisto.command() == 'aws-route53-create-record':
    result = create_record(demisto.args())

if demisto.command() == 'aws-route53-upsert-record':
    result = upsert_record(demisto.args())

if demisto.command() == 'aws-route53-delete-record':
    result = delete_record(demisto.args())

if demisto.command() == 'aws-route53-list-hosted-zones':
    result = list_hosted_zones(demisto.args())

if demisto.command() == 'aws-route53-list-resource-record-sets':
    result = list_resource_record_sets(demisto.args())

if demisto.command() == 'aws-route53-waiter-resource-record-sets-changed':
    result = waiter_resource_record_sets_changed(demisto.args())

if demisto.command() == 'aws-route53-test-dns-answer':
    result = test_dns_answer(demisto.args())

demisto.results(result)
