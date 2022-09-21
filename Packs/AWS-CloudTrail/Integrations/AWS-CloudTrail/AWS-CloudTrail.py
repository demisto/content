from datetime import date, datetime

import boto3
import demistomock as demisto  # noqa: F401
import urllib3.util
from botocore.config import Config
from botocore.parsers import ResponseParserError
from CommonServerPython import *  # noqa: F401
from dateparser import parse
from pytz import utc

# Disable insecure warnings
urllib3.disable_warnings()

AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_ROLE_ARN = demisto.params()['roleArn']
AWS_ROLE_SESSION_NAME = demisto.params()['roleSessionName']
AWS_ROLE_SESSION_DURATION = demisto.params()['sessionDuration']
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)

"""HELPER FUNCTIONS"""


def aws_session(service='cloudtrail', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None,
                rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and not AWS_ACCESS_KEY_ID:

        if not AWS_ACCESS_KEY_ID:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE,
                                      region_name=AWS_DEFAULT_REGION)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


def handle_returning_date_to_string(date_obj):
    """Gets date object to string"""
    # if the returning date is a string leave it as is.
    if isinstance(date_obj, str):
        return date_obj

    # if event time is datetime object - convert it to string.
    else:
        return date_obj.isoformat()


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def create_trail(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
        'S3BucketName': args.get('s3BucketName')
    }

    if args.get('s3KeyPrefix') is not None:
        kwargs.update({'S3KeyPrefix': args.get('s3KeyPrefix')})
    if args.get('snsTopicName') is not None:
        kwargs.update({'SnsTopicName': args.get('snsTopicName')})
    if args.get('includeGlobalServiceEvents') is not None:
        kwargs.update({'IncludeGlobalServiceEvents': True if args.get(
            'includeGlobalServiceEvents') == 'True' else False})
    if args.get('isMultiRegionTrail') is not None:
        kwargs.update(
            {'IsMultiRegionTrail': True if args.get('isMultiRegionTrail') == 'True' else False})
    if args.get('enableLogFileValidation') is not None:
        kwargs.update({'EnableLogFileValidation': True if args.get(
            'enableLogFileValidation') == 'True' else False})
    if args.get('cloudWatchLogsLogGroupArn') is not None:
        kwargs.update({'CloudWatchLogsLogGroupArn': args.get('cloudWatchLogsLogGroupArn')})
    if args.get('cloudWatchLogsRoleArn') is not None:
        kwargs.update({'CloudWatchLogsRoleArn': args.get('cloudWatchLogsRoleArn')})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.create_trail(**kwargs)

    data = ({
        'Name': response['Name'],
        'S3BucketName': response['S3BucketName'],
        'IncludeGlobalServiceEvents': response['IncludeGlobalServiceEvents'],
        'IsMultiRegionTrail': response['IsMultiRegionTrail'],
        'TrailARN': response['TrailARN'],
        'LogFileValidationEnabled': response['LogFileValidationEnabled'],
        'HomeRegion': obj['_user_provided_options']['region_name']
    })
    if 'SnsTopicName' in response:
        data.update({'SnsTopicName': response['SnsTopicName']})
    if 'S3KeyPrefix' in response:
        data.update({'S3KeyPrefix': response['S3KeyPrefix']})
    if 'SnsTopicARN' in response:
        data.update({'SnsTopicARN': response['SnsTopicARN']})
    if 'CloudWatchLogsLogGroupArn' in response:
        data.update({'CloudWatchLogsLogGroupArn': response['CloudWatchLogsLogGroupArn']})
    if 'CloudWatchLogsRoleArn' in response:
        data.update({'CloudWatchLogsRoleArn': response['CloudWatchLogsRoleArn']})
    if 'KmsKeyId' in response:
        data.update({'KmsKeyId': response['KmsKeyId']})

    ec = {'AWS.CloudTrail.Trails(val.Name == obj.Name)': data}
    human_readable = tableToMarkdown('AWS CloudTrail Trails', data)
    return_outputs(human_readable, ec)


def delete_trail(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.delete_trail(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Trail {0} was deleted".format(args.get('name')))


def describe_trails(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {}
    data = []
    output = []
    if args.get('trailNameList') is not None:
        kwargs.update({'trailNameList': parse_resource_ids(args.get('trailNameList'))})
    if args.get('includeShadowTrails') is not None:
        kwargs.update({'includeShadowTrails': True if args.get(
            'includeShadowTrails') == 'True' else False})

    response = client.describe_trails(**kwargs)
    for trail in response['trailList']:
        data.append({
            'Name': trail['Name'],
            'S3BucketName': trail['S3BucketName'],
            'IncludeGlobalServiceEvents': trail['IncludeGlobalServiceEvents'],
            'IsMultiRegionTrail': trail['IsMultiRegionTrail'],
            'TrailARN': trail['TrailARN'],
            'LogFileValidationEnabled': trail['LogFileValidationEnabled'],
            'HomeRegion': trail['HomeRegion'],
        })
        output.append(trail)

    raw = json.loads(json.dumps(output))
    ec = {'AWS.CloudTrail.Trails(val.Name == obj.Name)': raw}
    human_readable = tableToMarkdown('AWS CloudTrail Trails', data)
    return_outputs(human_readable, ec)


def update_trail(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
    }

    if args.get('s3BucketName') is not None:
        kwargs.update({'S3BucketName': args.get('s3BucketName')})
    if args.get('s3KeyPrefix') is not None:
        kwargs.update({'S3KeyPrefix': args.get('s3KeyPrefix')})
    if args.get('snsTopicName') is not None:
        kwargs.update({'SnsTopicName': args.get('snsTopicName')})
    if args.get('includeGlobalServiceEvents') is not None:
        kwargs.update({'IncludeGlobalServiceEvents': True if args.get(
            'includeGlobalServiceEvents') == 'True' else False})
    if args.get('isMultiRegionTrail') is not None:
        kwargs.update(
            {'IsMultiRegionTrail': True if args.get('isMultiRegionTrail') == 'True' else False})
    if args.get('enableLogFileValidation') is not None:
        kwargs.update({'EnableLogFileValidation': True if args.get(
            'enableLogFileValidation') == 'True' else False})
    if args.get('cloudWatchLogsLogGroupArn') is not None:
        kwargs.update({'CloudWatchLogsLogGroupArn': args.get('cloudWatchLogsLogGroupArn')})
    if args.get('cloudWatchLogsRoleArn') is not None:
        kwargs.update({'CloudWatchLogsRoleArn': args.get('cloudWatchLogsRoleArn')})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.update_trail(**kwargs)

    data = ({
        'Name': response['Name'],
        'S3BucketName': response['S3BucketName'],
        'IncludeGlobalServiceEvents': response['IncludeGlobalServiceEvents'],
        'IsMultiRegionTrail': response['IsMultiRegionTrail'],
        'TrailARN': response['TrailARN'],
        'LogFileValidationEnabled': response['LogFileValidationEnabled'],
        'HomeRegion': obj['_user_provided_options']['region_name']
    })
    if 'SnsTopicName' in response:
        data.update({'SnsTopicName': response['SnsTopicName']})
    if 'S3KeyPrefix' in response:
        data.update({'S3KeyPrefix': response['S3KeyPrefix']})
    if 'SnsTopicARN' in response:
        data.update({'SnsTopicARN': response['SnsTopicARN']})
    if 'CloudWatchLogsLogGroupArn' in response:
        data.update({'CloudWatchLogsLogGroupArn': response['CloudWatchLogsLogGroupArn']})
    if 'CloudWatchLogsRoleArn' in response:
        data.update({'CloudWatchLogsRoleArn': response['CloudWatchLogsRoleArn']})
    if 'KmsKeyId' in response:
        data.update({'KmsKeyId': response['KmsKeyId']})

    ec = {'AWS.CloudTrail.Trails(val.Name == obj.Name)': data}
    human_readable = tableToMarkdown('AWS CloudTrail Trails', data)
    return_outputs(human_readable, ec)


def start_logging(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.start_logging(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Trail {0} started logging".format(args.get('name')))


def stop_logging(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.stop_logging(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Trail {0} stopped logging".format(args.get('name')))


def lookup_events(args: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {
        'LookupAttributes': [{
            'AttributeKey': args.get('attributeKey'),
            'AttributeValue': args.get('attributeValue')
        }]
    }

    if args.get('startTime') is not None:
        kwargs.update({'StartTime': datetime.strptime(args.get('startTime'),  # type:ignore
                                                      "%Y-%m-%dT%H:%M:%S")})
    if args.get('endTime') is not None:
        kwargs.update(
            {'EndTime': datetime.strptime(args.get('endTime'), "%Y-%m-%dT%H:%M:%S")})  # type:ignore

    client.lookup_events(**kwargs)
    paginator = client.get_paginator('lookup_events')
    demisto.log(**kwargs)
    demisto.log("This is the end")
    for response in paginator.paginate(**kwargs):
        for i, event in enumerate(response['Events']):
            data.append({
                'EventId': event.get('EventId'),
                'EventName': event.get('EventName'),
                'EventTime': handle_returning_date_to_string(event.get('EventTime', '01-01-01T00:00:00')),
                'EventSource': event.get('EventSource'),
                'ResourceName': event.get('Resources')[0].get('ResourceName') if event.get('Resources') else None,
                'ResourceType': event.get('Resources')[0].get('ResourceType') if event.get('Resources') else None,
                'CloudTrailEvent': event.get('CloudTrailEvent')
            })
            if 'Username' in event:
                data[i].update({'Username': event['Username']})

    ec = {'AWS.CloudTrail.Events(val.EventId == obj.EventId)': data}
    human_readable = tableToMarkdown('AWS CloudTrail Trails', data)
    return_outputs(human_readable, ec)


def test_function():
    client = aws_session()
    response = client.describe_trails()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def calculate_fetch_start_time(last_fetch, first_fetch):
    if not last_fetch:
        if not first_fetch:
            first_fetch = '5 days'
        first_fetch_dt = parse(first_fetch).replace(tzinfo=utc)
        first_fetch_time = first_fetch_dt.timestamp()
        return first_fetch_time
    else:
        return float(last_fetch)


def fetch_incidents(args: dict, params: dict):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    last_fetch = demisto.getLastRun()
    first_fetch = params.get('first_fetch')
    attribute_key = params.get('AttributeKey')
    if not attribute_key:
        attribute_key = 'EventName'
    attribute_value = params.get('AttributeValue')

    fetch_limit = int(params.get('fetch_limit'))
    if fetch_limit > 50 or fetch_limit <= 0:
        fetch_limit = 50

    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch)
    demisto.debug("Fetch start time")
    demisto.debug(str(fetch_start_time))

    incidents = []
    incident_created_time = fetch_start_time
    kwargs = {
        'LookupAttributes': [{
            'AttributeKey': attribute_key,
            'AttributeValue': attribute_value
        }]
    }

    kwargs.update({'StartTime': fetch_start_time})

    client.lookup_events(**kwargs)
    paginator = client.get_paginator('lookup_events')
    for response in paginator.paginate(PaginationConfig={'MaxItems': fetch_limit}, **kwargs):
        for i, event in enumerate(response['Events']):
            incident = {
                'EventId': event.get('EventId'),
                'Name': event.get('EventName'),
                'EventTime': handle_returning_date_to_string(event.get('EventTime', '01-01-01T00:00:00')),
                'EventSource': event.get('EventSource'),
                'ResourceName': event.get('Resources')[0].get('ResourceName') if event.get('Resources') else None,
                'ResourceType': event.get('Resources')[0].get('ResourceType') if event.get('Resources') else None,
                'CloudTrailEvent': event.get('CloudTrailEvent'),
                'Username': event.get('Username'),
                'rawJSON': json.dumps(event, indent=4, sort_keys=True, default=str)
            }
            incidents.append(incident)
            incident_created_time = (event.get('EventTime', '01-01-01T00:00:00') + timedelta(seconds=1)).timestamp()

    if incident_created_time > fetch_start_time:
        last_fetch = str(incident_created_time)
        demisto.setLastRun(last_fetch)
    demisto.debug("Last fetch time")
    demisto.debug(str(last_fetch))

    demisto.incidents(incidents)


'''EXECUTION BLOCK'''


try:
    args = demisto.args()
    params = demisto.params()

    if demisto.command() == 'test-module':
        test_function()
    if demisto.command() == 'fetch-incidents':
        fetch_incidents(args, params)
    if demisto.command() == 'aws-cloudtrail-create-trail':
        create_trail(args)
    if demisto.command() == 'aws-cloudtrail-delete-trail':
        delete_trail(args)
    if demisto.command() == 'aws-cloudtrail-describe-trails':
        describe_trails(args)
    if demisto.command() == 'aws-cloudtrail-update-trail':
        update_trail(args)
    if demisto.command() == 'aws-cloudtrail-start-logging':
        start_logging(args)
    if demisto.command() == 'aws-cloudtrail-stop-logging':
        stop_logging(args)
    if demisto.command() == 'aws-cloudtrail-lookup-events':
        lookup_events(args)

except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
        error=type(e)))
    demisto.error(traceback.format_exc())

except Exception as e:
    demisto.error(traceback.format_exc())
    return_error('Error has occurred in the AWS CloudTrail Integration: {code}\n {message}'.format(
        code=type(e), message=str(e)))
