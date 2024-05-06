import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import boto3
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util
from datetime import datetime
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

PARAMS = demisto.params()
AWS_DEFAULT_REGION = PARAMS['defaultRegion']
AWS_ROLE_ARN = PARAMS['roleArn']
AWS_ROLE_SESSION_NAME = PARAMS['roleSessionName']
AWS_ROLE_SESSION_DURATION = PARAMS['sessionDuration']
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = PARAMS.get('credentials', {}).get('identifier') or PARAMS.get('access_key')
AWS_SECRET_ACCESS_KEY = PARAMS.get('credentials', {}).get('password') or PARAMS.get('secret_key')
VERIFY_CERTIFICATE = not PARAMS.get('insecure', True)
AWS_STS_REGIONAL_ENDPOINTS = PARAMS.get('sts_regional_endpoint') or None
if AWS_STS_REGIONAL_ENDPOINTS:
    demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={AWS_STS_REGIONAL_ENDPOINTS}")
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = AWS_STS_REGIONAL_ENDPOINTS.lower()
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries={"max_attempts": 5},
    proxies=proxies,
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
        sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE,
                                  region_name=AWS_DEFAULT_REGION)
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=region or AWS_DEFAULT_REGION,
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
        client = boto3.client(
            service_name=service,
            region_name=region or AWS_DEFAULT_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )

    return client


def handle_returning_date_to_string(date_obj: datetime | str) -> str:
    """Gets date object to string"""
    # if the returning date is a string or None, leave it as is.
    if date_obj is None or isinstance(date_obj, str):
        return date_obj

    # if event time is datetime object - convert it to string.
    return date_obj.isoformat()


def parse_resource_ids(resource_id: str | None) -> list[str]:
    if resource_id is None:
        raise ValueError("Resource ID cannot be empty")
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def create_trail(args: dict) -> CommandResults:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
        'S3BucketName': args.get('s3BucketName'),
    }

    if args.get('s3KeyPrefix') is not None:
        kwargs.update({'S3KeyPrefix': args.get('s3KeyPrefix')})
    if args.get('snsTopicName') is not None:
        kwargs.update({'SnsTopicName': args.get('snsTopicName')})
    if args.get('includeGlobalServiceEvents') is not None:
        kwargs.update({'IncludeGlobalServiceEvents': args.get('includeGlobalServiceEvents') == 'True'})
    if args.get('isMultiRegionTrail') is not None:
        kwargs.update(
            {'IsMultiRegionTrail': args.get('isMultiRegionTrail') == 'True'})
    if args.get('enableLogFileValidation') is not None:
        kwargs.update({'EnableLogFileValidation': args.get('enableLogFileValidation') == 'True'})
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

    return CommandResults(
        outputs_prefix="AWS.CloudTrail.Trails",
        outputs_key_field="Name",
        outputs=data,
        readable_output=tableToMarkdown('AWS CloudTrail Trails', data),
    )


def delete_trail(args: dict) -> str:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.delete_trail(**kwargs)

    if (response_code := response['ResponseMetadata']['HTTPStatusCode']) == 200:
        return f"The Trail {args.get('name')} was deleted"
    raise DemistoException(f"Unexpected status code: {response_code}")


def describe_trails(args: dict) -> CommandResults:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs: dict[str, Any] = {}
    data = []
    output = []
    if args.get('trailNameList') is not None:
        kwargs.update({'trailNameList': parse_resource_ids(args.get('trailNameList'))})
    if args.get('includeShadowTrails') is not None:
        kwargs.update({'includeShadowTrails': args.get('includeShadowTrails') == 'True'})

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
    return CommandResults(
        outputs_prefix="AWS.CloudTrail.Trails",
        outputs_key_field="Name",
        outputs=raw,
        readable_output=tableToMarkdown('AWS CloudTrail Trails', data),
    )


def get_trail_status(args: dict) -> CommandResults:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.get_trail_status(**kwargs)

    data = {
        'IsLogging': response.get('IsLogging'),
        'LatestDeliveryTime': handle_returning_date_to_string(response.get('LatestDeliveryTime')),
        'LatestCloudWatchLogsDeliveryError': response.get('LatestCloudWatchLogsDeliveryError'),
        'LatestDeliveryErrorDetails': response.get('LatestDeliveryErrorDetails'),
        'LatestNotificationError': response.get('LatestNotificationError'),
        'LatestNotificationTime': handle_returning_date_to_string(response.get('LatestNotificationTime')),
        'StartLoggingTime': handle_returning_date_to_string(response.get('StartLoggingTime')),
        'StopLoggingTime': handle_returning_date_to_string(response.get('StopLoggingTime')),
        'LatestCloudWatchLogsDeliveryTime': handle_returning_date_to_string(response.get('LatestCloudWatchLogsDeliveryTime')),
        'LatestDigestDeliveryTime': handle_returning_date_to_string(response.get('LatestDigestDeliveryTime')),
        'LatestDigestDeliveryError': response.get('LatestDigestDeliveryError')
    }

    return CommandResults(
        outputs_prefix="AWS.CloudTrail.TrailStatus",
        outputs_key_field="Name",
        outputs=data,
        readable_output=tableToMarkdown('AWS CloudTrail TrailStatus', data),
    )


def update_trail(args: dict) -> CommandResults:
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
        kwargs.update({'IncludeGlobalServiceEvents': args.get('includeGlobalServiceEvents') == 'True'})
    if args.get('isMultiRegionTrail') is not None:
        kwargs.update({'IsMultiRegionTrail': args.get('isMultiRegionTrail') == 'True'})
    if args.get('enableLogFileValidation') is not None:
        kwargs.update({'EnableLogFileValidation': args.get('enableLogFileValidation') == 'True'})
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

    return CommandResults(
        outputs_prefix="AWS.CloudTrail.Trails",
        outputs_key_field="Name",
        outputs=data,
        readable_output=tableToMarkdown('AWS CloudTrail Trails', data),
    )


def start_logging(args: dict) -> str:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.start_logging(**kwargs)

    if (response_code := response['ResponseMetadata']['HTTPStatusCode']) == 200:
        return f"The Trail {args.get('name')} started logging"
    raise DemistoException(f"Unexpected status code: {response_code}")


def stop_logging(args: dict) -> str:
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'Name': args.get('name')}

    response = client.stop_logging(**kwargs)

    if (response_code := response['ResponseMetadata']['HTTPStatusCode']) == 200:
        return f"The Trail {args.get('name')} stopped logging"
    raise DemistoException(f"Unexpected status code: {response_code}")


def lookup_events(args: dict) -> CommandResults:
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

    return CommandResults(
        outputs_prefix="AWS.CloudTrail.Events",
        outputs_key_field="EventId",
        outputs=data,
        readable_output=tableToMarkdown('AWS CloudTrail Trails', data),
    )


def test_function() -> str:
    client = aws_session()
    response = client.describe_trails()
    if (response_code := response['ResponseMetadata']['HTTPStatusCode']) == 200:
        return "ok"
    raise DemistoException(f"Unexpected status code: {response_code}")


def main():
    command = demisto.command()
    args = demisto.args()
    try:
        if command == 'test-module':
            return_results(test_function())
        if command == 'aws-cloudtrail-create-trail':
            return_results(create_trail(args))
        if command == 'aws-cloudtrail-delete-trail':
            return_results(delete_trail(args))
        if command == 'aws-cloudtrail-describe-trails':
            return_results(describe_trails(args))
        if command == 'aws-cloudtrail-update-trail':
            return_results(update_trail(args))
        if command == 'aws-cloudtrail-start-logging':
            return_results(start_logging(args))
        if command == 'aws-cloudtrail-stop-logging':
            return_results(stop_logging(args))
        if command == 'aws-cloudtrail-lookup-events':
            return_results(lookup_events(args))
        if command == 'aws-cloudtrail-get-trail-status':
            return_results(get_trail_status(args))

    except Exception as e:
        err = "Error has occurred in the AWS CloudTrail Integration."
        if isinstance(e, ResponseParserError):
            err += " Could not connect to the AWS endpoint. Please check that the region is valid."
        return_error(f"{err}\nError: {e}")


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
