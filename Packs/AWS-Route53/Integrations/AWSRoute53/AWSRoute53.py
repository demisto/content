import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date
from http import HTTPStatus
import urllib3.util

from AWSApiModule import *  # noqa :E402

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'route53'
DEFAULT_RETRIES = 5

"""HELPER FUNCTIONS"""


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_entry(title: str, data: Union[Dict[str, Any], List[Any]],
                 outputs: Any, outputs_prefix: str) -> CommandResults:
    return CommandResults(entry_type=EntryType.NOTE, content_format=EntryFormat.JSON,
                          readable_output=tableToMarkdown(title, data, removeNull=True) if data else 'No result were found',
                          outputs=outputs,
                          outputs_prefix=outputs_prefix)


def raise_error(error: Any) -> CommandResults:
    demisto.error(f"Error occurred in {SERVICE} - {str(error)}")
    return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR, readable_output=str(error))


def create_record(
        args: Dict[Any, Any],
        aws_session: Any,
) -> CommandResults:
    try:
        change_batch: Dict[Any, Any] = {
            'Changes': [
                {
                    'Action': 'CREATE',
                    'ResourceRecordSet': {
                        'Name': args.get('source'),
                        'Type': args.get('type'),
                        'TTL': arg_to_number(args.get('ttl'), "ttl", True),
                        'ResourceRecords': [{'Value': args.get('target')}]
                    }
                }
            ]
        }

        if args.get('comment'):
            change_batch['Comment'] = args.get('comment')

        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': change_batch
        }

        response = aws_session.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record created', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return raise_error(error)


def delete_record(
        args: Dict[Any, Any],
        aws_session: Any
) -> CommandResults:
    try:
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': {
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': args.get('source'),
                            'Type': args.get('type'),
                            'TTL': arg_to_number(args.get('ttl'), "ttl", True),
                            'ResourceRecords': [{'Value': args.get('target')}]
                        }
                    }
                ]
            }
        }

        response = aws_session.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record deleted', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return raise_error(error)


def upsert_record(
        args: Dict[Any, Any],
        aws_session: Any
) -> CommandResults:
    try:
        change_batch: Dict[Any, Any] = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': args.get('source'),
                        'Type': args.get('type'),
                        'TTL': arg_to_number(args.get('ttl'), "ttl", True),
                        'ResourceRecords': [{'Value': args.get('target')}]
                    }
                }
            ]
        }

        if args.get('comment'):
            change_batch['Comment'] = args.get('comment')
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'ChangeBatch': change_batch
        }

        response = aws_session.change_resource_record_sets(**kwargs)
        record = response['ChangeInfo']
        data = ({
            'Id': record['Id'],
            'Status': record['Status']
        })

        output = json.loads(json.dumps(response['ChangeInfo'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 record Upsert', data, output, 'AWS.Route53.RecordSetsChange')

    except Exception as error:
        return raise_error(error)


def list_hosted_zones(
        aws_session: Any
) -> CommandResults:
    try:
        data = []
        response = aws_session.list_hosted_zones()
        for hosted_zone in response['HostedZones']:
            data.append({
                'Name': hosted_zone['Name'],
                'Id': hosted_zone['Id'],
                'ResourceRecordSetCount': hosted_zone['ResourceRecordSetCount'],
            })
        output = json.loads(json.dumps(data, cls=DatetimeEncoder))
        return create_entry('AWS Route53 Hosted Zones', data, output, 'AWS.Route53.HostedZones')

    except Exception as error:
        return raise_error(error)


def list_resource_record_sets(
        args: Dict[Any, Any],
        aws_session: Any
) -> CommandResults:
    try:
        kwargs = {'HostedZoneId': args.get('hostedZoneId')}
        if args.get('startRecordName'):
            kwargs.update({'StartRecordName': args.get('startRecordName')})
        if args.get('startRecordType'):
            kwargs.update({'StartRecordType': args.get('startRecordType')})
        if args.get('startRecordIdentifier'):
            kwargs.update({'StartRecordIdentifier': args.get('startRecordIdentifier')})

        data = []
        response = aws_session.list_resource_record_sets(**kwargs)
        records = response['ResourceRecordSets']
        for record in records:
            resource_records = record.get("ResourceRecords") or []
            data.append({
                'Name': record.get('Name'),
                'Type': record.get('Type'),
                'TTL': record.get('TTL'),
                'ResourceRecords': resource_records[0]['Value'] if resource_records else None
            })
        output = json.loads(json.dumps(response['ResourceRecordSets'], cls=DatetimeEncoder))
        return create_entry('AWS Route53 Record Sets', data, output, 'AWS.Route53.RecordSets')

    except Exception as error:
        return raise_error(error)


def waiter_resource_record_sets_changed(
        args: Dict[Any, Any],
        aws_session: Any
) -> CommandResults:
    try:
        kwargs = {'Id': args.get('id')}
        if args.get('waiterDelay') is not None:
            kwargs.update({
                'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'), 'waiterDelay', True)}
            })
        if args.get('waiterMaxAttempts'):
            kwargs.update({
                'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'), 'waiterMaxAttempts', True)}
            })

        waiter = aws_session.get_waiter('resource_record_sets_changed')
        waiter.wait(**kwargs)
        return CommandResults(entry_type=EntryType.NOTE, content_format=EntryFormat.JSON, readable_output="success")

    except Exception as error:
        return raise_error(error)


def test_dns_answer(
        args: Dict[Any, Any],
        aws_session: Any
) -> CommandResults:
    try:
        kwargs = {
            'HostedZoneId': args.get('hostedZoneId'),
            'RecordName': args.get('recordName'),
            'RecordType': args.get('recordType'),
        }
        if args.get('resolverIP'):
            kwargs.update({'ResolverIP': args.get('resolverIP')})

        response = aws_session.test_dns_answer(**kwargs)
        data = ({
            'Nameserver': response['Nameserver'],
            'RecordName': response['RecordName'],
            'RecordType': response['RecordType'],
            'ResponseCode': response['ResponseCode'],
            'Protocol': response['Protocol']
        })

        return create_entry('AWS Route53 Test DNS Answer', data, response, 'AWS.Route53.TestDNSAnswer')

    except Exception as error:
        return raise_error(error)


def test_module(
        aws_session: Any
) -> CommandResults:
    try:
        response = aws_session.list_hosted_zones()
        if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
            return_results("ok")

        return CommandResults(content_format=EntryFormat.TEXT, entry_type=EntryType.ERROR,
                              readable_output=f"received status code {response['ResponseMetadata']['HTTPStatusCode']}")

    except Exception as error:
        return raise_error(error)


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
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
        args = demisto.args()
        validate_params(True, aws_role_arn, aws_role_session_name, aws_access_key_id,  # noqa
                        aws_secret_access_key)

        aws_client = AWSClient(None, aws_role_arn, aws_role_session_name,  # noqa
                               aws_role_session_duration, aws_role_policy, aws_access_key_id, aws_secret_access_key,
                               verify_certificate, timeout, retries)
        aws_session = aws_client.aws_session(service=SERVICE, role_arn=aws_role_arn,
                                             role_session_name=aws_role_session_name,
                                             role_session_duration=aws_role_session_duration)

        demisto.info(f'Command being called is {demisto.command()}')
        if command == 'test-module':
            return_results(test_module(aws_session))

        elif command == 'aws-route53-create-record':
            return_results(create_record(args, aws_session))

        elif command == 'aws-route53-upsert-record':
            return_results(upsert_record(args, aws_session))

        elif command == 'aws-route53-delete-record':
            return_results(delete_record(args, aws_session))

        elif command == 'aws-route53-list-hosted-zones':
            return_results(list_hosted_zones(aws_session))

        elif command == 'aws-route53-list-resource-record-sets':
            return_results(list_resource_record_sets(args, aws_session))

        elif command == 'aws-route53-waiter-resource-record-sets-changed':
            return_results(waiter_resource_record_sets_changed(args, aws_session))

        elif command == 'aws-route53-test-dns-answer':
            return_results(test_dns_answer(args, aws_session))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
