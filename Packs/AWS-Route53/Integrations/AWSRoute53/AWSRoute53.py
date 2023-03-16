from datetime import date
from http import HTTPStatus
import demistomock as demisto  # noqa :F401
import urllib3.util

from AWSApiModule import *  # noqa : E402
from CommonServerPython import *  # noqa :F401

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'route53'
DEFAULT_RETRIES = 5


"""HELPER FUNCTIONS"""


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_entry(title: str, data: Union[Dict[str, Any], List[Any]],
                 outputs: Any, outputs_prefix: str) -> CommandResults:

    return CommandResults(entry_type=EntryType.NOTE, content_format=EntryFormat.JSON,
                          readable_output=tableToMarkdown(title, data) if data else 'No result were found',
                          outputs=outputs,
                          outputs_prefix=outputs_prefix)


def create_record(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
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

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record created', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def delete_record(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
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

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record deleted', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def upsert_record(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
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

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record Upsert', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def list_hosted_zones(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
        data = []
        response = client.list_hosted_zones()
        for hosted_zone in response['HostedZones']:
            data.append({
                'Name': hosted_zone['Name'],
                'Id': hosted_zone['Id'],
                'ResourceRecordSetCount': hosted_zone['ResourceRecordSetCount'],
            })
        output = json.loads(json.dumps(response['HostedZones'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 Hosted Zones', data, output, 'AWS.Route53.HostedZones')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def list_resource_record_sets(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
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
        output = json.loads(json.dumps(response['ResourceRecordSets'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 Record Sets', data, output, 'AWS.Route53.RecordSets')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def waiter_resource_record_sets_changed(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
        kwargs = {'Id': args.get('id')}
        if args.get('waiterDelay') is not None:
            kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
        if args.get('waiterMaxAttempts') is not None:
            kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

        waiter = client.get_waiter('resource_record_sets_changed')
        waiter.wait(**kwargs)
        return CommandResults(entry_type=EntryType.NOTE, content_format=EntryFormat.JSON, readable_output="success")

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def test_dns_answer(
        args: Dict[str, Any],
        aws_client: AWSClient  # noqa
) -> CommandResults:
    try:
        client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'), )
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

        return create_entry('AWS Route53 Test DNS Answer', data, response, 'AWS.Route53.TestDNSAnswer')

    except Exception as error:
        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries', DEFAULT_RETRIES)

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,  # noqa
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name,   # noqa
                               aws_role_session_duration, aws_role_policy, aws_access_key_id, aws_secret_access_key,
                               verify_certificate, timeout, retries)

        args = demisto.args()

        demisto.info(f'Command being called is {demisto.command()}')
        if command == 'test-module':
            client = aws_client.aws_session(service=SERVICE)

            response = client.list_hosted_zones()
            if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
                demisto.results('ok')

        elif command == 'aws-route53-create-record':
            return_results(create_record(args, aws_client))

        elif command == 'aws-route53-upsert-record':
            return_results(upsert_record(args, aws_client))

        elif command == 'aws-route53-delete-record':
            return_results(delete_record(args, aws_client))

        elif command == 'aws-route53-list-hosted-zones':
            return_results(list_hosted_zones(args, aws_client))

        elif command == 'aws-route53-list-resource-record-sets':
            return_results(list_resource_record_sets(args, aws_client))

        elif command == 'aws-route53-waiter-resource-record-sets-changed':
            return_results(waiter_resource_record_sets_changed(args, aws_client))

        elif command == 'aws-route53-test-dns-answer':
            return_results(test_dns_answer(args, aws_client))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
