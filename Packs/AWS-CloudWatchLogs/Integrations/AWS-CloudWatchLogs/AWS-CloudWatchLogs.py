import boto3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date

AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None


def aws_session(service='logs', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None, rolePolicy=None):
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


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


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


def create_log_group(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'logGroupName': args.get('logGroupName')}

        if args.get('kmsKeyId') is not None:
            kwargs.update({'kmsKeyId': args.get('kmsKeyId')})

        response = client.create_log_group(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group was created successfully"

    except Exception as e:
        return raise_error(e)


def create_log_stream(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName')
        }
        response = client.create_log_stream(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Stream was created successfully"

    except Exception as e:
        return raise_error(e)


def delete_log_stream(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName')
        }
        response = client.delete_log_stream(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Stream was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def delete_log_group(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'logGroupName': args.get('logGroupName')}
        response = client.delete_log_group(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def filter_log_events(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        data = []
        kwargs = {'logGroupName': args.get('logGroupName')}

        if args.get('logStreamNames') is not None:
            kwargs.update({'logStreamNames': parse_resource_ids(args.get('logStreamNames'))})
        if args.get('startTime') is not None:
            kwargs.update({'startTime': int(args.get('startTime'))})
        if args.get('endTime') is not None:
            kwargs.update({'endTime': int(args.get('endTime'))})
        if args.get('filterPattern') is not None:
            kwargs.update({'filterPattern': args.get('filterPattern')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})
        if args.get('interleaved') is not None:
            kwargs.update({'interleaved': True if args.get('interleaved') == 'True' else False})

        response = client.filter_log_events(**kwargs)
        for event in response['events']:
            data.append({
                'LogStreamName': event['logStreamName'],
                'Timestamp': event['timestamp'],
                'Message': event['message'],
                'IngestionTime': event['ingestionTime'],
                'EventId': event['eventId']
            })

        ec = {"AWS.CloudWatchLogs.Events(val.eventId === obj.eventId)": data}
        return create_entry('AWS CloudWatch Logs Events', data, ec)

    except Exception as e:
        return raise_error(e)


def describe_log_groups(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {}
        if args.get('logGroupNamePrefix') is not None:
            kwargs.update({'logGroupNamePrefix': args.get('logGroupNamePrefix')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})

        response = client.describe_log_groups(**kwargs)
        for i, logGroup in enumerate(response['logGroups']):
            data.append({
                'LogGroupName': logGroup['logGroupName'],
                'CreationTime': logGroup['creationTime'],
                'Arn': logGroup['arn'],
            })
            if 'retentionInDays' in logGroup:
                data[i].update({'RetentionInDays': logGroup['retentionInDays']})
            if 'metricFilterCount' in logGroup:
                data[i].update({'MetricFilterCount': logGroup['metricFilterCount']})
            if 'storedBytes' in logGroup:
                data[i].update({'StoredBytes': logGroup['storedBytes']})
            if 'kmsKeyId' in logGroup:
                data[i].update({'KmsKeyId': logGroup['kmsKeyId']})

        ec = {"AWS.CloudWatchLogs.LogGroups(val.LogGroupName === obj.LogGroupName)": data}
        return create_entry('AWS CloudWatch Log Groups', data, ec)

    except Exception as e:
        return raise_error(e)


def describe_log_streams(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {'logGroupName': args.get('logGroupName')}
        if args.get('logStreamNamePrefix') is not None:
            kwargs.update({'logStreamNamePrefix': args.get('logStreamNamePrefix')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})
        if args.get('orderBy') is not None:
            kwargs.update({'orderBy': args.get('orderBy')})

        response = client.describe_log_streams(**kwargs)
        for i, logStream in enumerate(response['logStreams']):
            data.append({
                'LogGroupName': args.get('logGroupName'),
                'LogStreamName': logStream['creationTime'],
                'CreationTime': logStream['creationTime'],
                'Arn': logStream['arn'],
            })
            if 'firstEventTimestamp' in logStream:
                data[i].update({'FirstEventTimestamp': logStream['firstEventTimestamp']})
            if 'lastEventTimestamp' in logStream:
                data[i].update({'LastEventTimestamp': logStream['lastEventTimestamp']})
            if 'storedBytes' in logStream:
                data[i].update({'StoredBytes': logStream['storedBytes']})
            if 'lastIngestionTime' in logStream:
                data[i].update({'LastIngestionTime': logStream['lastIngestionTime']})
            if 'uploadSequenceToken' in logStream:
                data[i].update({'UploadSequenceToken': logStream['uploadSequenceToken']})

        ec = {"AWS.CloudWatchLogs.LogGroups(val.LogGroupName === obj.LogGroupName).LogStreams": data}
        return create_entry('AWS CloudWatch Log Streams', data, ec)

    except Exception as e:
        return raise_error(e)


def put_retention_policy(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'retentionInDays': int(args.get('retentionInDays')),
        }
        response = client.put_retention_policy(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group Retention Policy was added successfully"

    except Exception as e:
        return raise_error(e)


def delete_retention_policy(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.delete_retention_policy(logGroupName=args.get('logGroupName'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group Retention Policy was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def put_log_events(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName'),
            'logEvents': [{
                'timestamp': int(args.get('timestamp')),
                'message': args.get('message'),
            }]
        }
        if args.get('sequenceToken') is not None:
            kwargs.update({'sequenceToken': args.get('sequenceToken')})

        response = client.put_log_events(**kwargs)
        data = ({'NextSequenceToken': response['nextSequenceToken']})

        ec = {"AWS.CloudWatchLogs.PutLogEvents": data}
        return create_entry('AWS CloudWatch Log Put Log Events', data, ec)

    except Exception as e:
        return raise_error(e)


def put_metric_filter(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'filterName': args.get('filterName'),
            'filterPattern': args.get('filterPattern'),
            'metricTransformations': [{
                'metricName': args.get('metricName'),
                'metricNamespace': args.get('metricNamespace'),
                'metricValue': args.get('metricValue'),
            }]
        }
        response = client.put_metric_filter(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Metric Filter was added successfully"

    except Exception as e:
        return raise_error(e)


def delete_metric_filter(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'filterName': args.get('filterName'),
        }

        response = client.delete_metric_filter(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Metric Filter was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def describe_metric_filters(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {}
        if args.get('logGroupName') is not None:
            kwargs.update({'logGroupName': args.get('logGroupName')})
        if args.get('filterNamePrefix') is not None:
            kwargs.update({'filterNamePrefix': args.get('filterNamePrefix')})
        if args.get('metricName') is not None:
            kwargs.update({'metricName': args.get('metricName')})
        if args.get('metricNamespace') is not None:
            kwargs.update({'metricNamespace': args.get('metricNamespace')})

        response = client.describe_metric_filters(**kwargs)
        for metric in response['metricFilters']:
            data.append({
                'FilterName': metric['filterName'],
                'FilterPattern': metric['filterPattern'],
                'CreationTime': metric['creationTime'],
                'LogGroupName': metric['logGroupName']
            })

        raw = json.loads(json.dumps(response['metricFilters'], cls=DatetimeEncoder))
        ec = {"AWS.CloudWatchLogs.MetricFilters(val.FilterName === obj.FilterName)": raw}
        return create_entry('AWS CloudWatch Metric Filters', data, ec)

    except Exception as e:
        return raise_error(e)


def test_function():
    try:
        client = aws_session()
        response = client.describe_log_groups()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as error:
        return error


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    result = test_function()

if demisto.command() == 'aws-logs-create-log-group':
    result = create_log_group(demisto.args())

if demisto.command() == 'aws-logs-create-log-stream':
    result = create_log_stream(demisto.args())

if demisto.command() == 'aws-logs-delete-log-group':
    result = delete_log_group(demisto.args())

if demisto.command() == 'aws-logs-delete-log-stream':
    result = delete_log_stream(demisto.args())

if demisto.command() == 'aws-logs-filter-log-events':
    result = filter_log_events(demisto.args())

if demisto.command() == 'aws-logs-describe-log-groups':
    result = describe_log_groups(demisto.args())

if demisto.command() == 'aws-logs-describe-log-streams':
    result = describe_log_streams(demisto.args())

if demisto.command() == 'aws-logs-put-retention-policy':
    result = put_retention_policy(demisto.args())

if demisto.command() == 'aws-logs-delete-retention-policy':
    result = delete_retention_policy(demisto.args())

if demisto.command() == 'aws-logs-put-log-events':
    result = put_log_events(demisto.args())

if demisto.command() == 'aws-logs-put-metric-filter':
    result = put_metric_filter(demisto.args())

if demisto.command() == 'aws-logs-delete-metric-filter':
    result = delete_metric_filter(demisto.args())

if demisto.command() == 'aws-logs-describe-metric-filters':
    result = describe_metric_filters(demisto.args())

demisto.results(result)
