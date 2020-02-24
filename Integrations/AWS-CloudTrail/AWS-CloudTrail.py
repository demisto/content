import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
import datetime
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

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


def aws_session(service='cloudtrail',region=None,roleArn=None,roleSessionName=None,roleSessionDuration=None,rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn':roleArn,
            'RoleSessionName':roleSessionName,
            })
    elif AWS_roleArn and AWS_roleSessionName is not None:
        kwargs.update({
            'RoleArn':AWS_roleArn,
            'RoleSessionName':AWS_roleSessionName,
            })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds':int(roleSessionDuration)})
    elif AWS_roleSessionDuration is not None:
        kwargs.update({'DurationSeconds':int(AWS_roleSessionDuration)})

    if rolePolicy is not None:
        kwargs.update({'Policy':rolePolicy})
    elif AWS_rolePolicy is not None:
        kwargs.update({'Policy':AWS_rolePolicy})

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
            client = boto3.client(service_name=service,region_name=region)
        else:
            client = boto3.client(service_name=service,region_name=AWS_DEFAULT_REGION)

    return client

class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
  def default(self, obj):
    if isinstance (obj, datetime.datetime):
        return obj.strftime ('%Y-%m-%dT%H:%M:%S')
    elif isinstance (obj, datetime.date):
        return obj.strftime ('%Y-%m-%d')
    elif isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%dT%H:%M:%S')
    elif isinstance(obj, date):
        return obj.strftime('%Y-%m-%d')
    # Let the base class default method raise the TypeError
    return json.JSONEncoder.default(self, obj)

def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds

def create_entry(title,data, ec):
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
        'Type' : entryTypes['error'],
        'ContentsFormat' : formats['text'],
        'Contents' : str(error)
    }

def create_trail(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        obj = vars(client._client_config)
        kwargs = {
            'Name':args.get('name'),
            'S3BucketName':args.get('s3BucketName'),
        }

        if args.get('s3KeyPrefix') is not None:
            kwargs.update({'S3KeyPrefix':args.get('s3KeyPrefix')})
        if args.get('snsTopicName') is not None:
            kwargs.update({'SnsTopicName':args.get('snsTopicName')})
        if args.get('includeGlobalServiceEvents') is not None:
            kwargs.update({'IncludeGlobalServiceEvents':True if args.get('includeGlobalServiceEvents') == 'True'  else False})
        if args.get('isMultiRegionTrail') is not None:
            kwargs.update({'IsMultiRegionTrail':True if args.get('isMultiRegionTrail') == 'True'  else False})
        if args.get('enableLogFileValidation') is not None:
            kwargs.update({'EnableLogFileValidation':True if args.get('enableLogFileValidation') == 'True'  else False})
        if args.get('cloudWatchLogsLogGroupArn') is not None:
            kwargs.update({'CloudWatchLogsLogGroupArn':args.get('cloudWatchLogsLogGroupArn')})
        if args.get('cloudWatchLogsRoleArn') is not None:
            kwargs.update({'CloudWatchLogsRoleArn':args.get('cloudWatchLogsRoleArn')})
        if args.get('kmsKeyId') is not None:
            kwargs.update({'KmsKeyId':args.get('kmsKeyId')})

        response = client.create_trail(**kwargs)

        data = ({
            'Name': response['Name'],
            'S3BucketName': response['S3BucketName'],
            'IncludeGlobalServiceEvents': response['IncludeGlobalServiceEvents'],
            'IsMultiRegionTrail': response['IsMultiRegionTrail'],
            'TrailARN': response['TrailARN'],
            'LogFileValidationEnabled':response['LogFileValidationEnabled'],
            'HomeRegion': obj['_user_provided_options']['region_name']
        })
        if 'SnsTopicName' in response:
            data.update({'SnsTopicName':response['SnsTopicName']})
        if 'S3KeyPrefix' in response:
            data.update({'S3KeyPrefix':response['S3KeyPrefix']})
        if 'SnsTopicARN' in response:
            data.update({'SnsTopicARN':response['SnsTopicARN']})
        if 'CloudWatchLogsLogGroupArn' in response:
            data.update({'CloudWatchLogsLogGroupArn':response['CloudWatchLogsLogGroupArn']})
        if 'CloudWatchLogsRoleArn' in response:
            data.update({'CloudWatchLogsRoleArn':response['CloudWatchLogsRoleArn']})
        if 'KmsKeyId' in response:
            data.update({'KmsKeyId':response['KmsKeyId']})

        ec = {'AWS.CloudTrail.Trails(val.Name == obj.Name)': data}
        return create_entry('AWS CloudTrail Trails',data, ec)


    except Exception as e:
        return raise_error(e)

def delete_trail(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {'Name':args.get('name')}

        response = client.delete_trail(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Trail {0} was deleted".format(args.get('name'))

    except Exception as e:
        return raise_error(e)


def describe_trails(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {}
        data =[]
        output = []
        if args.get('trailNameList') is not None:
            kwargs.update({'trailNameList':parse_resource_ids(args.get('trailNameList'))})
        if args.get('includeShadowTrails') is not None:
            kwargs.update({'includeShadowTrails':True if args.get('includeShadowTrails') == 'True'  else False})

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
        return  create_entry('AWS CloudTrail Trails',data, ec)


    except Exception as e:
        return raise_error(e)

def update_trail(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        obj = vars(client._client_config)
        kwargs = {
            'Name':args.get('name'),
        }

        if args.get('s3BucketName') is not None:
            kwargs.update({'S3BucketName':args.get('s3BucketName')})
        if args.get('s3KeyPrefix') is not None:
            kwargs.update({'S3KeyPrefix':args.get('s3KeyPrefix')})
        if args.get('snsTopicName') is not None:
            kwargs.update({'SnsTopicName':args.get('snsTopicName')})
        if args.get('includeGlobalServiceEvents') is not None:
            kwargs.update({'IncludeGlobalServiceEvents':True if args.get('includeGlobalServiceEvents') == 'True'  else False})
        if args.get('isMultiRegionTrail') is not None:
            kwargs.update({'IsMultiRegionTrail':True if args.get('isMultiRegionTrail') == 'True'  else False})
        if args.get('enableLogFileValidation') is not None:
            kwargs.update({'EnableLogFileValidation':True if args.get('enableLogFileValidation') == 'True'  else False})
        if args.get('cloudWatchLogsLogGroupArn') is not None:
            kwargs.update({'CloudWatchLogsLogGroupArn':args.get('cloudWatchLogsLogGroupArn')})
        if args.get('cloudWatchLogsRoleArn') is not None:
            kwargs.update({'CloudWatchLogsRoleArn':args.get('cloudWatchLogsRoleArn')})
        if args.get('kmsKeyId') is not None:
            kwargs.update({'KmsKeyId':args.get('kmsKeyId')})

        response = client.update_trail(**kwargs)

        data = ({
            'Name': response['Name'],
            'S3BucketName': response['S3BucketName'],
            'IncludeGlobalServiceEvents': response['IncludeGlobalServiceEvents'],
            'IsMultiRegionTrail': response['IsMultiRegionTrail'],
            'TrailARN': response['TrailARN'],
            'LogFileValidationEnabled':response['LogFileValidationEnabled'],
            'HomeRegion': obj['_user_provided_options']['region_name']
        })
        if 'SnsTopicName' in response:
            data.update({'SnsTopicName':response['SnsTopicName']})
        if 'S3KeyPrefix' in response:
            data.update({'S3KeyPrefix':response['S3KeyPrefix']})
        if 'SnsTopicARN' in response:
            data.update({'SnsTopicARN':response['SnsTopicARN']})
        if 'CloudWatchLogsLogGroupArn' in response:
            data.update({'CloudWatchLogsLogGroupArn':response['CloudWatchLogsLogGroupArn']})
        if 'CloudWatchLogsRoleArn' in response:
            data.update({'CloudWatchLogsRoleArn':response['CloudWatchLogsRoleArn']})
        if 'KmsKeyId' in response:
            data.update({'KmsKeyId':response['KmsKeyId']})

        ec = {'AWS.CloudTrail.Trails(val.Name == obj.Name)': data}
        return  create_entry('AWS CloudTrail Trails',data, ec)


    except Exception as e:
        return raise_error(e)

def start_logging(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {'Name':args.get('name')}

        response = client.start_logging(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Trail {0} started logging".format(args.get('name'))

    except Exception as e:
        return raise_error(e)

def stop_logging(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {'Name':args.get('name')}

        response = client.stop_logging(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Trail {0} stopped logging".format(args.get('name'))

    except Exception as e:
        return raise_error(e)


def lookup_events(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        data = []
        kwargs = {
            'LookupAttributes':[{
                'AttributeKey': args.get('attributeKey'),
                'AttributeValue': args.get('attributeValue')
            }]
        }

        if args.get('startTime') is not None:
            kwargs.update({'StartTime':datetime.datetime.strptime(args.get('startTime'), "%Y-%m-%dT%H:%M:%S")})
        if args.get('endTime') is not None:
            kwargs.update({'EndTime':datetime.datetime.strptime(args.get('endTime'), "%Y-%m-%dT%H:%M:%S")})


        response = client.lookup_events(**kwargs)
        paginator = client.get_paginator('lookup_events')
        for response in paginator.paginate(**kwargs):
            for i, event in enumerate(response['Events']):
                data.append({
                    'EventId': event['EventId'],
                    'EventName': event['EventName'],
                    'EventTime': datetime.datetime.strftime(event['EventTime'], '%Y-%m-%dT%H:%M:%S'),
                    'EventSource': event['EventSource'],
                    'ResourceName':event['Resources'][0]['ResourceName'],
                    'ResourceType':event['Resources'][0]['ResourceType'],
                    'CloudTrailEvent': event['CloudTrailEvent']
                })
                if 'Username' in event: data[i].update({'Username': image['Username']})

        ec = {'AWS.CloudTrail.Events(val.EventId == obj.EventId)': data}
        return  create_entry('AWS CloudTrail Trails',data, ec)

    except Exception as e:
        return raise_error(e)


def test_function():
    try:
        client = aws_session()
        response = client.describe_trails()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as error:
        return error

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    result = test_function()

if demisto.command() == 'aws-cloudtrail-create-trail':
    result = create_trail(demisto.args())

if demisto.command() == 'aws-cloudtrail-delete-trail':
    result = delete_trail(demisto.args())

if demisto.command() == 'aws-cloudtrail-describe-trails':
    result = describe_trails(demisto.args())

if demisto.command() == 'aws-cloudtrail-update-trail':
    result = update_trail(demisto.args())

if demisto.command() == 'aws-cloudtrail-start-logging':
    result = start_logging(demisto.args())

if demisto.command() == 'aws-cloudtrail-stop-logging':
    result = stop_logging(demisto.args())

if demisto.command() == 'aws-cloudtrail-lookup-events':
    result = lookup_events(demisto.args())

demisto.results(result)
sys.exit(0)
