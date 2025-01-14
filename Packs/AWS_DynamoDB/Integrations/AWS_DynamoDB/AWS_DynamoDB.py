import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# flake8: noqa
import boto3
import json
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util


# Disable insecure warnings
urllib3.disable_warnings()


"""PARAMETERS"""
PARAMS = demisto.params()
AWS_DEFAULT_REGION = PARAMS.get('defaultRegion')
AWS_ROLE_ARN = PARAMS.get('roleArn')
AWS_ROLE_SESSION_NAME = PARAMS.get('roleSessionName')
AWS_ROLE_SESSION_DURATION = PARAMS.get('sessionDuration')
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
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


"""HELPER FUNCTIONS"""


def parse_resource_ids(resource_id):
    if not resource_id:
        return None
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(
        r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
    if demisto.args().get('tag_key') and demisto.args().get('tag_value'):
        if demisto.args().get('tags'):
            return_error(
                "Please select either the arguments 'tag_key' and 'tag_value' or only 'tags'.")
        tags.append({
            'Key': demisto.args().get('tag_key'),
            'Value': demisto.args().get('tag_value')
        })
    else:
        if tags_str is not None:
            for f in tags_str.split(';'):
                match = regex.match(f)
                if match is None:
                    demisto.debug('could not parse field: %s' % (f,))
                    continue

                tags.append({
                    'Key': match.group(1),
                    'Value': match.group(2)
                })

    return tags


def aws_session(service='dynamodb', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None, rolePolicy=None):
    client = None
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


def batch_get_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "RequestItems": json.loads(args.get("request_items", "{}")),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.batch_get_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB BatchGetItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def batch_write_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "RequestItems": json.loads(args.get("request_items", "{}")),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.batch_write_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB BatchWriteItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "BackupName": args.get("backup_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.create_backup(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.BackupDetails(val.BackupName && val.BackupName === obj.BackupName)': response.get('BackupDetails')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB CreateBackup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None),
        "ReplicationGroup": [{
            "RegionName": args.get("replication_group_region_name", None),

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.create_global_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.GlobalTableDescription(val.GlobalTableArn && val.GlobalTableArn === obj.GlobalTableArn)': response.get('GlobalTableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB CreateGlobalTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def create_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "AttributeDefinitions": [{
            "AttributeName": args.get("attribute_definitions_attribute_name", None),
            "AttributeType": args.get("attribute_definitions_attribute_type", None),

        }],
        "TableName": args.get("table_name", None),
        "KeySchema": [{
            "AttributeName": args.get("key_schema_attribute_name", None),
            "KeyType": args.get("key_schema_key_type", None),

        }],
        "LocalSecondaryIndexes": [{
            "IndexName": args.get("local_secondary_indexes_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },

        }],
        "GlobalSecondaryIndexes": [{
            "IndexName": args.get("global_secondary_indexes_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

            },

        }],
        "BillingMode": args.get("billing_mode", None),
        "ProvisionedThroughput": {
            "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

        },
        "StreamSpecification": {
            "StreamEnabled": True if args.get("stream_specification_stream_enabled", "") == "true" else None,
            "StreamViewType": args.get("stream_specification_stream_view_type", None),

        },
        "SSESpecification": {
            "Enabled": True if args.get("sse_specification_enabled", "") == "true" else None,
            "SSEType": args.get("sse_specification_sse_type", None),
            "KMSMasterKeyId": args.get("sse_specification_kms_master_key_id", None),

        },
        "Tags": parse_tag_field(args.get("tags")),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.create_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TableDescription(val.TableArn && val.TableArn === obj.TableArn)': response.get('TableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB CreateTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "BackupArn": args.get("backup_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.delete_backup(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.BackupDetails(val.BackupName && val.BackupName === obj.BackupName)': response.get('BackupDetails')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DeleteBackup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "Key": json.loads(args.get("key", "{}")),
        "Expected": json.loads(args.get("expected", "{}")),
        "ConditionalOperator": args.get("conditional_operator", None),
        "ReturnValues": args.get("return_values", None),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None),
        "ConditionExpression": args.get("condition_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}")),
        "ExpressionAttributeValues": json.loads(args.get("expression_attribute_values", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.delete_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DeleteItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def delete_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.delete_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TableDescription(val.TableArn && val.TableArn === obj.TableArn)': response.get('TableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DeleteTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "BackupArn": args.get("backup_arn", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_backup(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.BackupDescription': response['BackupDescription']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeBackup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_continuous_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_continuous_backups(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.ContinuousBackupsDescription': response['ContinuousBackupsDescription']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeContinuousBackups'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_endpoints_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {  # type:ignore

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_endpoints(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.Endpoints': response['Endpoints']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeEndpoints'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_global_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.GlobalTableDescription(val.GlobalTableArn && val.GlobalTableArn === obj.GlobalTableArn)': response.get('GlobalTableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeGlobalTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_global_table_settings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_global_table_settings(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB(val.GlobalTableName && val.GlobalTableName === obj.GlobalTableName)': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeGlobalTableSettings'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_limits_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {  # type:ignore

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_limits(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeLimits'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.Table(val.TableArn && val.TableArn === obj.TableArn)': response.get('Table')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def describe_time_to_live_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.describe_time_to_live(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TimeToLiveDescription': response['TimeToLiveDescription']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB DescribeTimeToLive'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def get_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "Key": json.loads(args.get("key", "{}")),
        "AttributesToGet": parse_resource_ids(args.get("attributes_to_get", "")),
        "ConsistentRead": True if args.get("consistent_read", "") == "true" else None,
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ProjectionExpression": args.get("projection_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.get_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB GetItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "ExclusiveStartBackupArn": args.get("exclusive_start_backup_arn", None),
        "BackupType": args.get("backup_type", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.list_backups(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.BackupSummaries(val.BackupArn && val.BackupArn === obj.BackupArn)': response.get('BackupSummaries')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB ListBackups'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_global_tables_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ExclusiveStartGlobalTableName": args.get("exclusive_start_global_table_name", None),
        "RegionName": args.get("region_name", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.list_global_tables(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.GlobalTables': response['GlobalTables']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB ListGlobalTables'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_tables_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ExclusiveStartTableName": args.get("exclusive_start_table_name", None),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.list_tables(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.TableNames': response['TableNames']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB ListTables'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def list_tags_of_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "NextToken": args.get("next_token", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.list_tags_of_resource(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB ListTagsOfResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def put_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "Item": json.loads(args.get("item", "{}")),
        "Expected": json.loads(args.get("expected", "{}")),
        "ReturnValues": args.get("return_values", None),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None),
        "ConditionalOperator": args.get("conditional_operator", None),
        "ConditionExpression": args.get("condition_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}")),
        "ExpressionAttributeValues": json.loads(args.get("expression_attribute_values", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.put_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB PutItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def query_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "IndexName": args.get("index_name", None),
        "Select": args.get("select", None),
        "AttributesToGet": parse_resource_ids(args.get("attributes_to_get", "")),
        "ConsistentRead": True if args.get("consistent_read", "") == "true" else None,
        "KeyConditions": json.loads(args.get("key_conditions", "{}")),
        "QueryFilter": json.loads(args.get("query_filter", "{}")),
        "ConditionalOperator": args.get("conditional_operator", None),
        "ScanIndexForward": True if args.get("scan_index_forward", "") == "true" else None,
        "ExclusiveStartKey": json.loads(args.get("exclusive_start_key", "{}")),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ProjectionExpression": args.get("projection_expression", None),
        "FilterExpression": args.get("filter_expression", None),
        "KeyConditionExpression": args.get("key_condition_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}")),
        "ExpressionAttributeValues": json.loads(args.get("expression_attribute_values", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.query(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB Query'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def restore_table_from_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TargetTableName": args.get("target_table_name", None),
        "BackupArn": args.get("backup_arn", None),
        "BillingModeOverride": args.get("billing_mode_override", None),
        "GlobalSecondaryIndexOverride": [{
            "IndexName": args.get("global_secondary_index_override_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

            },

        }],
        "LocalSecondaryIndexOverride": [{
            "IndexName": args.get("local_secondary_index_override_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },

        }],
        "ProvisionedThroughputOverride": {
            "ReadCapacityUnits": args.get("provisioned_throughput_override_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_override_write_capacity_units", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.restore_table_from_backup(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TableDescription(val.TableArn && val.TableArn === obj.TableArn)': response.get('TableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB RestoreTableFromBackup'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def restore_table_to_point_in_time_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "SourceTableName": args.get("source_table_name", None),
        "TargetTableName": args.get("target_table_name", None),
        "UseLatestRestorableTime": True if args.get("use_latest_restorable_time", "") == "true" else None,
        "BillingModeOverride": args.get("billing_mode_override", None),
        "GlobalSecondaryIndexOverride": [{
            "IndexName": args.get("global_secondary_index_override_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

            },

        }],
        "LocalSecondaryIndexOverride": [{
            "IndexName": args.get("local_secondary_index_override_index_name", None),
            "KeySchema": [{
                "AttributeName": args.get("key_schema_attribute_name", None),
                "KeyType": args.get("key_schema_key_type", None),

            }],
            "Projection": {
                "ProjectionType": args.get("projection_projection_type", None),
                "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

            },

        }],
        "ProvisionedThroughputOverride": {
            "ReadCapacityUnits": args.get("provisioned_throughput_override_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_override_write_capacity_units", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.restore_table_to_point_in_time(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TableDescription(val.TableArn && val.TableArn === obj.TableArn)': response.get('TableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB RestoreTableToPointInTime'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def scan_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "IndexName": args.get("index_name", None),
        "AttributesToGet": parse_resource_ids(args.get("attributes_to_get", "")),
        "Select": args.get("select", None),
        "ScanFilter": json.loads(args.get("scan_filter", "{}")),
        "ConditionalOperator": args.get("conditional_operator", None),
        "ExclusiveStartKey": json.loads(args.get("exclusive_start_key", "{}")),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ProjectionExpression": args.get("projection_expression", None),
        "FilterExpression": args.get("filter_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}")),
        "ExpressionAttributeValues": json.loads(args.get("expression_attribute_values", "{}")),
        "ConsistentRead": True if args.get("consistent_read", "") == "true" else None
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.scan(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB Scan'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def tag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "Tags": parse_tag_field(args.get("tags")),

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.tag_resource(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB TagResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def transact_get_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TransactItems": [{
            "Get": {
                "Key": json.loads(args.get("get_key", "{}")),
                "TableName": args.get("get_table_name", None),
                "ProjectionExpression": args.get("get_projection_expression", None),
                "ExpressionAttributeNames": json.loads(args.get("get_expression_attribute_names", "{}")),

            },

        }],
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.transact_get_items(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.ConsumedCapacity': response['ConsumedCapacity']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB TransactGetItems'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def transact_write_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TransactItems": [{
            "ConditionCheck": {
                "Key": json.loads(args.get("condition_check_key", "{}")),
                "TableName": args.get("condition_check_table_name", None),
                "ConditionExpression": args.get("condition_check_condition_expression", None),
                "ExpressionAttributeNames": json.loads(args.get("condition_check_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(args.get("condition_check_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": args.get("condition_check_return_values_on_condition_check_failure", None),

            },
            "Put": {
                "Item": json.loads(args.get("put_item", "{}")),
                "TableName": args.get("put_table_name", None),
                "ConditionExpression": args.get("put_condition_expression", None),
                "ExpressionAttributeNames": json.loads(args.get("put_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(args.get("put_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": args.get("put_return_values_on_condition_check_failure", None),

            },
            "Delete": {
                "Key": json.loads(args.get("delete_key", "{}")),
                "TableName": args.get("delete_table_name", None),
                "ConditionExpression": args.get("delete_condition_expression", None),
                "ExpressionAttributeNames": json.loads(args.get("delete_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(args.get("delete_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": args.get("delete_return_values_on_condition_check_failure", None),

            },
            "Update": {
                "Key": json.loads(args.get("update_key", "{}")),
                "UpdateExpression": args.get("update_update_expression", None),
                "TableName": args.get("update_table_name", None),
                "ConditionExpression": args.get("update_condition_expression", None),
                "ExpressionAttributeNames": json.loads(args.get("update_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(args.get("update_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": args.get("update_return_values_on_condition_check_failure", None),

            },

        }],
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None),
        "ClientRequestToken": args.get("client_request_token", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.transact_write_items(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.ConsumedCapacity': response['ConsumedCapacity']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB TransactWriteItems'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def untag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "TagKeys": parse_resource_ids(args.get("tag_keys", ""))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.untag_resource(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB.ConsumedCapacity': response.get('ConsumedCapacity')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UntagResource'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_continuous_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "PointInTimeRecoverySpecification": {
            "PointInTimeRecoveryEnabled": True if args.get("point_in_time_recovery_specification_point_in_time_recovery_enabled", "") == "true" else None,

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_continuous_backups(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.ContinuousBackupsDescription': response['ContinuousBackupsDescription']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateContinuousBackups'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None),
        "ReplicaUpdates": [{
            "Create": {
                "RegionName": args.get("create_region_name", None),

            },
            "Delete": {
                "RegionName": args.get("delete_region_name", None),

            },

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_global_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.GlobalTableDescription(val.GlobalTableArn && val.GlobalTableArn === obj.GlobalTableArn)': response.get('GlobalTableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateGlobalTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_global_table_settings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None),
        "GlobalTableBillingMode": args.get("global_table_billing_mode", None),
        "GlobalTableProvisionedWriteCapacityUnits": args.get("global_table_provisioned_write_capacity_units", None),
        "GlobalTableProvisionedWriteCapacityAutoScalingSettingsUpdate": {
            "MinimumUnits": args.get("global_table_provisioned_write_capacity_auto_scaling_settings_update_minimum_units", None),
            "MaximumUnits": args.get("global_table_provisioned_write_capacity_auto_scaling_settings_update_maximum_units", None),
            "AutoScalingDisabled": True if args.get("global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
            "AutoScalingRoleArn": args.get("global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
            "ScalingPolicyUpdate": {
                "PolicyName": args.get("scaling_policy_update_policy_name", None),
                "TargetTrackingScalingPolicyConfiguration": {
                    "DisableScaleIn": True if args.get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

                },

            },

        },
        "IndexName": args.get("index_name", None),
        "ProvisionedWriteCapacityUnits": args.get("provisioned_write_capacity_units", None),
        "ProvisionedWriteCapacityAutoScalingSettingsUpdate": {
            "MinimumUnits": args.get("provisioned_write_capacity_auto_scaling_settings_update_minimum_units", None),
            "MaximumUnits": args.get("provisioned_write_capacity_auto_scaling_settings_update_maximum_units", None),
            "AutoScalingDisabled": True if args.get("provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
            "AutoScalingRoleArn": args.get("provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
            "ScalingPolicyUpdate": {
                "PolicyName": args.get("scaling_policy_update_policy_name", None),
                "TargetTrackingScalingPolicyConfiguration": {
                    "DisableScaleIn": True if args.get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

                },

            },

        },

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_global_table_settings(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateGlobalTableSettings'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "Key": json.loads(args.get("key", "{}")),
        "AttributeUpdates": json.loads(args.get("attribute_updates", "{}")),
        "Expected": json.loads(args.get("expected", "{}")),
        "ConditionalOperator": args.get("conditional_operator", None),
        "ReturnValues": args.get("return_values", None),
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None),
        "UpdateExpression": args.get("update_expression", None),
        "ConditionExpression": args.get("condition_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}")),
        "ExpressionAttributeValues": json.loads(args.get("expression_attribute_values", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_item(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {'AWS-DynamoDB': response}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateItem'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "AttributeDefinitions": [{
            "AttributeName": args.get("attribute_definitions_attribute_name", None),
            "AttributeType": args.get("attribute_definitions_attribute_type", None),

        }],
        "TableName": args.get("table_name", None),
        "BillingMode": args.get("billing_mode", None),
        "ProvisionedThroughput": {
            "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

        },
        "GlobalSecondaryIndexUpdates": [{
            "Update": {
                "IndexName": args.get("update_index_name", None),
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
                    "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

                },

            },
            "Create": {
                "IndexName": args.get("create_index_name", None),
                "KeySchema": [{
                    "AttributeName": args.get("key_schema_attribute_name", None),
                    "KeyType": args.get("key_schema_key_type", None),

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": parse_resource_ids(args.get("projection_non_key_attributes", "")),

                },
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
                    "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

                },

            },
            "Delete": {
                "IndexName": args.get("delete_index_name", None),

            },

        }],
        "StreamSpecification": {
            "StreamEnabled": True if args.get("stream_specification_stream_enabled", "") == "true" else None,
            "StreamViewType": args.get("stream_specification_stream_view_type", None),

        },
        "SSESpecification": {
            "Enabled": True if args.get("sse_specification_enabled", "") == "true" else None,
            "SSEType": args.get("sse_specification_sse_type", None),
            "KMSMasterKeyId": args.get("sse_specification_kms_master_key_id", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_table(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TableDescription(val.TableArn && val.TableArn === obj.TableArn)': response.get('TableDescription')}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateTable'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


def update_time_to_live_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TableName": args.get("table_name", None),
        "TimeToLiveSpecification": {
            "Enabled": True if args.get("time_to_live_specification_enabled", "") == "true" else None,
            "AttributeName": args.get("time_to_live_specification_attribute_name", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        raise ValueError("Please remove other arguments before using 'raw_json'.")
    response = client.update_time_to_live(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)
    outputs = {
        'AWS-DynamoDB.TimeToLiveSpecification': response['TimeToLiveSpecification']}
    del response['ResponseMetadata']
    table_header = 'AWS DynamoDB UpdateTimeToLive'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    args = demisto.args()
    human_readable = None
    outputs = None
    try:
        LOG('Command being called is {command}'.format(
            command=demisto.command()))
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client = aws_session()
            response = client.describe_limits()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif demisto.command() == 'aws-dynamodb-batch-get-item':
            human_readable, outputs, response = batch_get_item_command(args)
        elif demisto.command() == 'aws-dynamodb-batch-write-item':
            human_readable, outputs, response = batch_write_item_command(args)
        elif demisto.command() == 'aws-dynamodb-create-backup':
            human_readable, outputs, response = create_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-create-global-table':
            human_readable, outputs, response = create_global_table_command(
                args)
        elif demisto.command() == 'aws-dynamodb-create-table':
            human_readable, outputs, response = create_table_command(args)
        elif demisto.command() == 'aws-dynamodb-delete-backup':
            human_readable, outputs, response = delete_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-delete-item':
            human_readable, outputs, response = delete_item_command(args)
        elif demisto.command() == 'aws-dynamodb-delete-table':
            human_readable, outputs, response = delete_table_command(args)
        elif demisto.command() == 'aws-dynamodb-describe-backup':
            human_readable, outputs, response = describe_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-describe-continuous-backups':
            human_readable, outputs, response = describe_continuous_backups_command(
                args)
        elif demisto.command() == 'aws-dynamodb-describe-endpoints':
            human_readable, outputs, response = describe_endpoints_command(
                args)
        elif demisto.command() == 'aws-dynamodb-describe-global-table':
            human_readable, outputs, response = describe_global_table_command(
                args)
        elif demisto.command() == 'aws-dynamodb-describe-global-table-settings':
            human_readable, outputs, response = describe_global_table_settings_command(
                args)
        elif demisto.command() == 'aws-dynamodb-describe-limits':
            human_readable, outputs, response = describe_limits_command(args)
        elif demisto.command() == 'aws-dynamodb-describe-table':
            human_readable, outputs, response = describe_table_command(args)
        elif demisto.command() == 'aws-dynamodb-describe-time-to-live':
            human_readable, outputs, response = describe_time_to_live_command(
                args)
        elif demisto.command() == 'aws-dynamodb-get-item':
            human_readable, outputs, response = get_item_command(args)
        elif demisto.command() == 'aws-dynamodb-list-backups':
            human_readable, outputs, response = list_backups_command(args)
        elif demisto.command() == 'aws-dynamodb-list-global-tables':
            human_readable, outputs, response = list_global_tables_command(
                args)
        elif demisto.command() == 'aws-dynamodb-list-tables':
            human_readable, outputs, response = list_tables_command(args)
        elif demisto.command() == 'aws-dynamodb-list-tags-of-resource':
            human_readable, outputs, response = list_tags_of_resource_command(
                args)
        elif demisto.command() == 'aws-dynamodb-put-item':
            human_readable, outputs, response = put_item_command(args)
        elif demisto.command() == 'aws-dynamodb-query':
            human_readable, outputs, response = query_command(args)
        elif demisto.command() == 'aws-dynamodb-restore-table-from-backup':
            human_readable, outputs, response = restore_table_from_backup_command(
                args)
        elif demisto.command() == 'aws-dynamodb-restore-table-to-point-in-time':
            human_readable, outputs, response = restore_table_to_point_in_time_command(
                args)
        elif demisto.command() == 'aws-dynamodb-scan':
            human_readable, outputs, response = scan_command(args)
        elif demisto.command() == 'aws-dynamodb-tag-resource':
            human_readable, outputs, response = tag_resource_command(args)
        elif demisto.command() == 'aws-dynamodb-transact-get-items':
            human_readable, outputs, response = transact_get_items_command(
                args)
        elif demisto.command() == 'aws-dynamodb-transact-write-items':
            human_readable, outputs, response = transact_write_items_command(
                args)
        elif demisto.command() == 'aws-dynamodb-untag-resource':
            human_readable, outputs, response = untag_resource_command(args)
        elif demisto.command() == 'aws-dynamodb-update-continuous-backups':
            human_readable, outputs, response = update_continuous_backups_command(
                args)
        elif demisto.command() == 'aws-dynamodb-update-global-table':
            human_readable, outputs, response = update_global_table_command(
                args)
        elif demisto.command() == 'aws-dynamodb-update-global-table-settings':
            human_readable, outputs, response = update_global_table_settings_command(
                args)
        elif demisto.command() == 'aws-dynamodb-update-item':
            human_readable, outputs, response = update_item_command(args)
        elif demisto.command() == 'aws-dynamodb-update-table':
            human_readable, outputs, response = update_table_command(args)
        elif demisto.command() == 'aws-dynamodb-update-time-to-live':
            human_readable, outputs, response = update_time_to_live_command(
                args)
        return_outputs(human_readable, outputs, response)

    except ResponseParserError as e:
        return_error('Could not connect to the AWS endpoint. Please check that the region is valid. {error}'.format(
            error=type(e)))
    except Exception as e:
        return_error('Error has occurred in the AWS dynamodb Integration: {code} {message}'.format(
            code=type(e), message=e))


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()
