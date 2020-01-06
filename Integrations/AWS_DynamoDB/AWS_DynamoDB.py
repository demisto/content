import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# flake8: noqa
import boto3
import json
import datetime
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
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


def safe_load_json(o):
    kwargs = None
    try:
        try:
            path = demisto.getFilePath(o)
            with open(path['path'], 'rb') as data:
                try:
                    kwargs = json.load(data)
                except:
                    kwargs = json.loads(data.read())
        except:
            kwargs = json.loads(o)
    except ValueError as e:
        return_error('Unable to parse JSON file/string. Please verify the JSON is valid.', e)
    return kwargs


def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


def remove_empty_elements(d):
    """recursively remove empty lists, empty dicts, or None elements from a dictionary"""

    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if
                not empty(v)}


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
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
                    demisto.log('could not parse field: %s' % (f,))
                    continue

                tags.append({
                    'Key': match.group(1),
                    'Value': match.group(2)
                })

    return tags


def aws_session(service='dynamodb', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None, rolePolicy=None):
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
    if kwargs and AWS_ACCESS_KEY_ID is None:

        if AWS_ACCESS_KEY_ID is None:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.batch_get_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.BatchGetItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb BatchGetItem', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.batch_write_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.BatchWriteItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb BatchWriteItem', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.create_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.CreateBackup.AWS-dynamodbBackupDetails(val.BackupArn === obj.BackupArn)':
            response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateBackup', response)
    return human_readable, ec


def create_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None),
        "ReplicationGroup": safe_load_json(args.get("ReplicationGroup")) if args.get(
            "ReplicationGroup") else [{
            "Replica": {
                "RegionName": args.get("replica_region_name", None)
            },

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.create_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.CreateGlobalTable.AWS-dynamodbGlobalTableDescription(val.GlobalTableArn === '
        'obj.GlobalTableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateGlobalTable', response)
    return human_readable, ec


def create_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "AttributeDefinitions": safe_load_json(args.get("AttributeDefinitions")) if args.get(
            "AttributeDefinitions") else [{
            "AttributeDefinition": {
                "AttributeName": args.get("attribute_definition_attribute_name", None),
                "AttributeType": args.get("attribute_definition_attribute_type", None)
            },

        }],
        "TableName": args.get("table_name", None),
        "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
            "KeySchemaElement": {
                "AttributeName": args.get("key_schema_element_attribute_name", None),
                "KeyType": args.get("key_schema_element_key_type", None)
            },

        }],
        "LocalSecondaryIndexes": safe_load_json(args.get("LocalSecondaryIndexes")) if args.get(
            "LocalSecondaryIndexes") else [{
            "LocalSecondaryIndex": {
                "IndexName": args.get("local_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                }

            },

        }],
        "GlobalSecondaryIndexes": safe_load_json(args.get("GlobalSecondaryIndexes")) if args.get(
            "GlobalSecondaryIndexes") else [{
            "GlobalSecondaryIndex": {
                "IndexName": args.get("global_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                },
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units",
                                                  None),
                    "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units",
                                                   None),

                }

            },

        }],
        "BillingMode": args.get("billing_mode", None),
        "ProvisionedThroughput": {
            "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

        },
        "StreamSpecification": {
            "StreamEnabled": True if args.get("stream_specification_stream_enabled",
                                              "") == "true" else None,
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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.create_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.CreateTable.AWS-dynamodbTableDescription(val.TableArn === obj.TableArn)':
            response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateTable', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.delete_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.DeleteBackup.AWS-dynamodbBackupDescriptionBackupDetails(val.BackupArn === '
        'obj.BackupArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteBackup', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.delete_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DeleteItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteItem', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.delete_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.DeleteTable.AWS-dynamodbTableDescription(val.TableArn === obj.TableArn)':
            response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteTable', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.DescribeBackup.AWS-dynamodbBackupDescriptionBackupDetails(val.BackupArn === '
        'obj.BackupArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeBackup', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_continuous_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DescribeContinuousBackups': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeContinuousBackups', response)
    return human_readable, ec


def describe_endpoints_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_endpoints(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DescribeEndpoints': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeEndpoints', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.DescribeGlobalTable.AWS-dynamodbGlobalTableDescription(val.GlobalTableArn '
        '=== obj.GlobalTableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeGlobalTable', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_global_table_settings(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.DescribeGlobalTableSettings.AWS'
        '-dynamodbReplicaSettingsReplicaSettingsDescriptionReplicaProvisionedReadCapacityAutoScalingSettings(val.AutoScalingRoleArn === obj.AutoScalingRoleArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeGlobalTableSettings', response)
    return human_readable, ec


def describe_limits_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_limits(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DescribeLimits': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeLimits', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DescribeTable.AWS-dynamodbTable(val.TableArn === obj.TableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeTable', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.describe_time_to_live(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.DescribeTimeToLive': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeTimeToLive', response)
    return human_readable, ec


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
        "AttributesToGet": safe_load_json(args.get("AttributesToGet")) if args.get(
            "AttributesToGet") else [{
            "AttributeName": args.get("attributes_to_get_attribute_name", None),

        }],
        "ConsistentRead": True if args.get("consistent_read", "") == "true" else None,
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ProjectionExpression": args.get("projection_expression", None),
        "ExpressionAttributeNames": json.loads(args.get("expression_attribute_names", "{}"))
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.get_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.GetItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb GetItem', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.list_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.ListBackups.AWS-dynamodbBackupSummariesBackupSummary(val.TableArn === '
        'obj.TableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListBackups', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.list_global_tables(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.ListGlobalTables': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListGlobalTables', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.list_tables(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.ListTables': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListTables', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.list_tags_of_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.ListTagsOfResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListTagsOfResource', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.put_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.PutItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb PutItem', response)
    return human_readable, ec


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
        "AttributesToGet": safe_load_json(args.get("AttributesToGet")) if args.get(
            "AttributesToGet") else [{
            "AttributeName": args.get("attributes_to_get_attribute_name", None),

        }],
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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.query(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.Query': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb Query', response)
    return human_readable, ec


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
        "GlobalSecondaryIndexOverride": safe_load_json(
            args.get("GlobalSecondaryIndexOverride")) if args.get(
            "GlobalSecondaryIndexOverride") else [{
            "GlobalSecondaryIndex": {
                "IndexName": args.get("global_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                },
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units",
                                                  None),
                    "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units",
                                                   None),

                }

            },

        }],
        "LocalSecondaryIndexOverride": safe_load_json(
            args.get("LocalSecondaryIndexOverride")) if args.get(
            "LocalSecondaryIndexOverride") else [{
            "LocalSecondaryIndex": {
                "IndexName": args.get("local_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                }

            },

        }],
        "ProvisionedThroughputOverride": {
            "ReadCapacityUnits": args.get("provisioned_throughput_override_read_capacity_units",
                                          None),
            "WriteCapacityUnits": args.get("provisioned_throughput_override_write_capacity_units",
                                           None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.restore_table_from_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.RestoreTableFromBackup.AWS-dynamodbTableDescription(val.TableArn === '
        'obj.TableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb RestoreTableFromBackup', response)
    return human_readable, ec


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
        "UseLatestRestorableTime": True if args.get("use_latest_restorable_time",
                                                    "") == "true" else None,
        "BillingModeOverride": args.get("billing_mode_override", None),
        "GlobalSecondaryIndexOverride": safe_load_json(
            args.get("GlobalSecondaryIndexOverride")) if args.get(
            "GlobalSecondaryIndexOverride") else [{
            "GlobalSecondaryIndex": {
                "IndexName": args.get("global_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                },
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units",
                                                  None),
                    "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units",
                                                   None),

                }

            },

        }],
        "LocalSecondaryIndexOverride": safe_load_json(
            args.get("LocalSecondaryIndexOverride")) if args.get(
            "LocalSecondaryIndexOverride") else [{
            "LocalSecondaryIndex": {
                "IndexName": args.get("local_secondary_index_index_name", None),
                "KeySchema": safe_load_json(args.get("KeySchema")) if args.get("KeySchema") else [{
                    "KeySchemaElement": {
                        "AttributeName": args.get("key_schema_element_attribute_name", None),
                        "KeyType": args.get("key_schema_element_key_type", None)
                    },

                }],
                "Projection": {
                    "ProjectionType": args.get("projection_projection_type", None),
                    "NonKeyAttributes": safe_load_json(args.get("NonKeyAttributes")) if args.get(
                        "NonKeyAttributes") else [{
                        "NonKeyAttributeName": args.get("non_key_attributes_non_key_attribute_name",
                                                        None),

                    }],

                }

            },

        }],
        "ProvisionedThroughputOverride": {
            "ReadCapacityUnits": args.get("provisioned_throughput_override_read_capacity_units",
                                          None),
            "WriteCapacityUnits": args.get("provisioned_throughput_override_write_capacity_units",
                                           None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.restore_table_to_point_in_time(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.RestoreTableToPointInTime.AWS-dynamodbTableDescription(val.TableArn === '
        'obj.TableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb RestoreTableToPointInTime', response)
    return human_readable, ec


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
        "AttributesToGet": safe_load_json(args.get("AttributesToGet")) if args.get(
            "AttributesToGet") else [{
            "AttributeName": args.get("attributes_to_get_attribute_name", None),

        }],
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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.scan(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.Scan': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb Scan', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.tag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.TagResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TagResource', response)
    return human_readable, ec


def transact_get_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TransactItems": safe_load_json(args.get("TransactItems")) if args.get(
            "TransactItems") else [{
            "TransactGetItem": {
                "Get": {
                    "Key": json.loads(args.get("get_key", "{}")),
                    "TableName": args.get("get_table_name", None),
                    "ProjectionExpression": args.get("get_projection_expression", None),
                    "ExpressionAttributeNames": json.loads(
                        args.get("get_expression_attribute_names", "{}")),

                }

            },

        }],
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.transact_get_items(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.TransactGetItems': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TransactGetItems', response)
    return human_readable, ec


def transact_write_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "TransactItems": safe_load_json(args.get("TransactItems")) if args.get(
            "TransactItems") else [{
            "TransactWriteItem": {
                "ConditionCheck": {
                    "Key": json.loads(args.get("condition_check_key", "{}")),
                    "TableName": args.get("condition_check_table_name", None),
                    "ConditionExpression": args.get("condition_check_condition_expression", None),
                    "ExpressionAttributeNames": json.loads(
                        args.get("condition_check_expression_attribute_names", "{}")),
                    "ExpressionAttributeValues": json.loads(
                        args.get("condition_check_expression_attribute_values", "{}")),
                    "ReturnValuesOnConditionCheckFailure": args.get(
                        "condition_check_return_values_on_condition_check_failure", None),

                },
                "Put": {
                    "Item": json.loads(args.get("put_item", "{}")),
                    "TableName": args.get("put_table_name", None),
                    "ConditionExpression": args.get("put_condition_expression", None),
                    "ExpressionAttributeNames": json.loads(
                        args.get("put_expression_attribute_names", "{}")),
                    "ExpressionAttributeValues": json.loads(
                        args.get("put_expression_attribute_values", "{}")),
                    "ReturnValuesOnConditionCheckFailure": args.get(
                        "put_return_values_on_condition_check_failure", None),

                },
                "Delete": {
                    "Key": json.loads(args.get("delete_key", "{}")),
                    "TableName": args.get("delete_table_name", None),
                    "ConditionExpression": args.get("delete_condition_expression", None),
                    "ExpressionAttributeNames": json.loads(
                        args.get("delete_expression_attribute_names", "{}")),
                    "ExpressionAttributeValues": json.loads(
                        args.get("delete_expression_attribute_values", "{}")),
                    "ReturnValuesOnConditionCheckFailure": args.get(
                        "delete_return_values_on_condition_check_failure", None),

                },
                "Update": {
                    "Key": json.loads(args.get("update_key", "{}")),
                    "UpdateExpression": args.get("update_update_expression", None),
                    "TableName": args.get("update_table_name", None),
                    "ConditionExpression": args.get("update_condition_expression", None),
                    "ExpressionAttributeNames": json.loads(
                        args.get("update_expression_attribute_names", "{}")),
                    "ExpressionAttributeValues": json.loads(
                        args.get("update_expression_attribute_values", "{}")),
                    "ReturnValuesOnConditionCheckFailure": args.get(
                        "update_return_values_on_condition_check_failure", None),

                }

            },

        }],
        "ReturnConsumedCapacity": args.get("return_consumed_capacity", None),
        "ReturnItemCollectionMetrics": args.get("return_item_collection_metrics", None),
        "ClientRequestToken": args.get("client_request_token", None)
    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.transact_write_items(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.TransactWriteItems': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TransactWriteItems', response)
    return human_readable, ec


def untag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "ResourceArn": args.get("resource_arn", None),
        "TagKeys": safe_load_json(args.get("TagKeys")) if args.get("TagKeys") else [{
            "TagKeyString": args.get("tag_keys_tag_key_string", None),

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.untag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.UntagResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UntagResource', response)
    return human_readable, ec


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
            "PointInTimeRecoveryEnabled": True if args.get(
                "point_in_time_recovery_specification_point_in_time_recovery_enabled",
                "") == "true" else None,

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_continuous_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.UpdateContinuousBackups': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateContinuousBackups', response)
    return human_readable, ec


def update_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "GlobalTableName": args.get("global_table_name", None),
        "ReplicaUpdates": safe_load_json(args.get("ReplicaUpdates")) if args.get(
            "ReplicaUpdates") else [{
            "ReplicaUpdate": {
                "Create": {
                    "RegionName": args.get("create_region_name", None),

                },
                "Delete": {
                    "RegionName": args.get("delete_region_name", None),

                }

            },

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.UpdateGlobalTable.AWS-dynamodbGlobalTableDescription(val.GlobalTableArn === '
        'obj.GlobalTableArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateGlobalTable', response)
    return human_readable, ec


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
        "GlobalTableProvisionedWriteCapacityUnits": args.get(
            "global_table_provisioned_write_capacity_units", None),
        "GlobalTableProvisionedWriteCapacityAutoScalingSettingsUpdate": {
            "MinimumUnits": args.get(
                "global_table_provisioned_write_capacity_auto_scaling_settings_update_minimum_units",
                None),
            "MaximumUnits": args.get(
                "global_table_provisioned_write_capacity_auto_scaling_settings_update_maximum_units",
                None),
            "AutoScalingDisabled": True if args.get(
                "global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled",
                "") == "true" else None,
            "AutoScalingRoleArn": args.get(
                "global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn",
                None),
            "ScalingPolicyUpdate": {
                "PolicyName": args.get("scaling_policy_update_policy_name", None),
                "TargetTrackingScalingPolicyConfiguration": {
                    "DisableScaleIn": True if args.get(
                        "target_tracking_scaling_policy_configuration_disable_scale_in",
                        "") == "true" else None,

                },

            },

        },
        "GlobalTableGlobalSecondaryIndexSettingsUpdate": safe_load_json(
            args.get("GlobalTableGlobalSecondaryIndexSettingsUpdate")) if args.get(
            "GlobalTableGlobalSecondaryIndexSettingsUpdate") else [{
            "GlobalTableGlobalSecondaryIndexSettingsUpdate": {
                "IndexName": args.get(
                    "global_table_global_secondary_index_settings_update_index_name", None),
                "ProvisionedWriteCapacityUnits": args.get(
                    "global_table_global_secondary_index_settings_update_provisioned_write_capacity_units",
                    None),
                "ProvisionedWriteCapacityAutoScalingSettingsUpdate": {
                    "MinimumUnits": args.get(
                        "provisioned_write_capacity_auto_scaling_settings_update_minimum_units",
                        None),
                    "MaximumUnits": args.get(
                        "provisioned_write_capacity_auto_scaling_settings_update_maximum_units",
                        None),
                    "AutoScalingDisabled": True if args.get(
                        "provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled",
                        "") == "true" else None,
                    "AutoScalingRoleArn": args.get(
                        "provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn",
                        None),
                    "ScalingPolicyUpdate": {
                        "PolicyName": args.get("scaling_policy_update_policy_name", None),
                        "TargetTrackingScalingPolicyConfiguration": {
                            "DisableScaleIn": True if args.get(
                                "target_tracking_scaling_policy_configuration_disable_scale_in",
                                "") == "true" else None,

                        },

                    },

                }

            },

        }],
        "ReplicaSettingsUpdate": safe_load_json(args.get("ReplicaSettingsUpdate")) if args.get(
            "ReplicaSettingsUpdate") else [{
            "ReplicaSettingsUpdate": {
                "RegionName": args.get("replica_settings_update_region_name", None),
                "ReplicaProvisionedReadCapacityUnits": args.get(
                    "replica_settings_update_replica_provisioned_read_capacity_units", None),
                "ReplicaProvisionedReadCapacityAutoScalingSettingsUpdate": {
                    "MinimumUnits": args.get(
                        "replica_provisioned_read_capacity_auto_scaling_settings_update_minimum_units",
                        None),
                    "MaximumUnits": args.get(
                        "replica_provisioned_read_capacity_auto_scaling_settings_update_maximum_units",
                        None),
                    "AutoScalingDisabled": True if args.get(
                        "replica_provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_disabled",
                        "") == "true" else None,
                    "AutoScalingRoleArn": args.get(
                        "replica_provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_role_arn",
                        None),
                    "ScalingPolicyUpdate": {
                        "PolicyName": args.get("scaling_policy_update_policy_name", None),
                        "TargetTrackingScalingPolicyConfiguration": {
                            "DisableScaleIn": True if args.get(
                                "target_tracking_scaling_policy_configuration_disable_scale_in",
                                "") == "true" else None,

                        },

                    },

                },
                "ReplicaGlobalSecondaryIndexSettingsUpdate": safe_load_json(
                    args.get("ReplicaGlobalSecondaryIndexSettingsUpdate")) if args.get(
                    "ReplicaGlobalSecondaryIndexSettingsUpdate") else [{
                    "ReplicaGlobalSecondaryIndexSettingsUpdate": {
                        "IndexName": args.get(
                            "replica_global_secondary_index_settings_update_index_name", None),
                        "ProvisionedReadCapacityUnits": args.get(
                            "replica_global_secondary_index_settings_update_provisioned_read_capacity_units",
                            None),
                        "ProvisionedReadCapacityAutoScalingSettingsUpdate": {
                            "MinimumUnits": args.get(
                                "provisioned_read_capacity_auto_scaling_settings_update_minimum_units",
                                None),
                            "MaximumUnits": args.get(
                                "provisioned_read_capacity_auto_scaling_settings_update_maximum_units",
                                None),
                            "AutoScalingDisabled": True if args.get(
                                "provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_disabled",
                                "") == "true" else None,
                            "AutoScalingRoleArn": args.get(
                                "provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_role_arn",
                                None),
                            "ScalingPolicyUpdate": {
                                "PolicyName": args.get("scaling_policy_update_policy_name", None),
                                "TargetTrackingScalingPolicyConfiguration": {
                                    "DisableScaleIn": True if args.get(
                                        "target_tracking_scaling_policy_configuration_disable_scale_in",
                                        "") == "true" else None,

                                },

                            },

                        }

                    },

                }],

            },

        }],

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_global_table_settings(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.UpdateGlobalTableSettings.AWS'
        '-dynamodbReplicaSettingsReplicaSettingsDescriptionReplicaProvisionedReadCapacityAutoScalingSettings(val.AutoScalingRoleArn === obj.AutoScalingRoleArn)': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateGlobalTableSettings', response)
    return human_readable, ec


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
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.UpdateItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateItem', response)
    return human_readable, ec


def update_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        "AttributeDefinitions": safe_load_json(args.get("AttributeDefinitions")) if args.get(
            "AttributeDefinitions") else [{
            "AttributeDefinition": {
                "AttributeName": args.get("attribute_definition_attribute_name", None),
                "AttributeType": args.get("attribute_definition_attribute_type", None)
            },

        }],
        "TableName": args.get("table_name", None),
        "BillingMode": args.get("billing_mode", None),
        "ProvisionedThroughput": {
            "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units", None),
            "WriteCapacityUnits": args.get("provisioned_throughput_write_capacity_units", None),

        },
        "GlobalSecondaryIndexUpdates": safe_load_json(
            args.get("GlobalSecondaryIndexUpdates")) if args.get(
            "GlobalSecondaryIndexUpdates") else [{
            "GlobalSecondaryIndexUpdate": {
                "Update": {
                    "IndexName": args.get("update_index_name", None),
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units",
                                                      None),
                        "WriteCapacityUnits": args.get(
                            "provisioned_throughput_write_capacity_units", None),

                    },

                },
                "Create": {
                    "IndexName": args.get("create_index_name", None),
                    "KeySchema": safe_load_json(args.get("KeySchema")) if args.get(
                        "KeySchema") else [{
                        "KeySchemaElement": {
                            "AttributeName": args.get("key_schema_element_attribute_name", None),
                            "KeyType": args.get("key_schema_element_key_type", None)
                        },

                    }],
                    "Projection": {
                        "ProjectionType": args.get("projection_projection_type", None),
                        "NonKeyAttributes": safe_load_json(
                            args.get("NonKeyAttributes")) if args.get("NonKeyAttributes") else [{
                            "NonKeyAttributeName": args.get(
                                "non_key_attributes_non_key_attribute_name", None),

                        }],

                    },
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": args.get("provisioned_throughput_read_capacity_units",
                                                      None),
                        "WriteCapacityUnits": args.get(
                            "provisioned_throughput_write_capacity_units", None),

                    },

                },
                "Delete": {
                    "IndexName": args.get("delete_index_name", None),

                }

            },

        }],
        "StreamSpecification": {
            "StreamEnabled": True if args.get("stream_specification_stream_enabled",
                                              "") == "true" else None,
            "StreamViewType": args.get("stream_specification_stream_view_type", None),

        },
        "SSESpecification": {
            "Enabled": True if args.get("sse_specification_enabled", "") == "true" else None,
            "SSEType": args.get("sse_specification_sse_type", None),
            "KMSMasterKeyId": args.get("sse_specification_kms_master_key_id", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {
        'AWS-Dynamodb.UpdateTable.AWS-dynamodbTableDescription(val.TableArn === obj.TableArn)':
            response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateTable', response)
    return human_readable, ec


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
            "Enabled": True if args.get("time_to_live_specification_enabled",
                                        "") == "true" else None,
            "AttributeName": args.get("time_to_live_specification_attribute_name", None),

        }

    }
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json'))
    response = client.update_time_to_live(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS-Dynamodb.UpdateTimeToLive': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateTimeToLive', response)
    return human_readable, ec


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    args = demisto.args()
    human_readable = None
    ec = None
    try:
        LOG('Command being called is {command}'.format(command=demisto.command()))
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client = aws_session()
            response = client.describe_endpoints()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif demisto.command() == 'aws-dynamodb-batch_get_item':
            human_readable, ec = batch_get_item_command(args)
        elif demisto.command() == 'aws-dynamodb-batch_write_item':
            human_readable, ec = batch_write_item_command(args)
        elif demisto.command() == 'aws-dynamodb-create_backup':
            human_readable, ec = create_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-create_global_table':
            human_readable, ec = create_global_table_command(args)
        elif demisto.command() == 'aws-dynamodb-create_table':
            human_readable, ec = create_table_command(args)
        elif demisto.command() == 'aws-dynamodb-delete_backup':
            human_readable, ec = delete_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-delete_item':
            human_readable, ec = delete_item_command(args)
        elif demisto.command() == 'aws-dynamodb-delete_table':
            human_readable, ec = delete_table_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_backup':
            human_readable, ec = describe_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_continuous_backups':
            human_readable, ec = describe_continuous_backups_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_endpoints':
            human_readable, ec = describe_endpoints_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_global_table':
            human_readable, ec = describe_global_table_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_global_table_settings':
            human_readable, ec = describe_global_table_settings_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_limits':
            human_readable, ec = describe_limits_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_table':
            human_readable, ec = describe_table_command(args)
        elif demisto.command() == 'aws-dynamodb-describe_time_to_live':
            human_readable, ec = describe_time_to_live_command(args)
        elif demisto.command() == 'aws-dynamodb-get_item':
            human_readable, ec = get_item_command(args)
        elif demisto.command() == 'aws-dynamodb-list_backups':
            human_readable, ec = list_backups_command(args)
        elif demisto.command() == 'aws-dynamodb-list_global_tables':
            human_readable, ec = list_global_tables_command(args)
        elif demisto.command() == 'aws-dynamodb-list_tables':
            human_readable, ec = list_tables_command(args)
        elif demisto.command() == 'aws-dynamodb-list_tags_of_resource':
            human_readable, ec = list_tags_of_resource_command(args)
        elif demisto.command() == 'aws-dynamodb-put_item':
            human_readable, ec = put_item_command(args)
        elif demisto.command() == 'aws-dynamodb-query':
            human_readable, ec = query_command(args)
        elif demisto.command() == 'aws-dynamodb-restore_table_from_backup':
            human_readable, ec = restore_table_from_backup_command(args)
        elif demisto.command() == 'aws-dynamodb-restore_table_to_point_in_time':
            human_readable, ec = restore_table_to_point_in_time_command(args)
        elif demisto.command() == 'aws-dynamodb-scan':
            human_readable, ec = scan_command(args)
        elif demisto.command() == 'aws-dynamodb-tag_resource':
            human_readable, ec = tag_resource_command(args)
        elif demisto.command() == 'aws-dynamodb-transact_get_items':
            human_readable, ec = transact_get_items_command(args)
        elif demisto.command() == 'aws-dynamodb-transact_write_items':
            human_readable, ec = transact_write_items_command(args)
        elif demisto.command() == 'aws-dynamodb-untag_resource':
            human_readable, ec = untag_resource_command(args)
        elif demisto.command() == 'aws-dynamodb-update_continuous_backups':
            human_readable, ec = update_continuous_backups_command(args)
        elif demisto.command() == 'aws-dynamodb-update_global_table':
            human_readable, ec = update_global_table_command(args)
        elif demisto.command() == 'aws-dynamodb-update_global_table_settings':
            human_readable, ec = update_global_table_settings_command(args)
        elif demisto.command() == 'aws-dynamodb-update_item':
            human_readable, ec = update_item_command(args)
        elif demisto.command() == 'aws-dynamodb-update_table':
            human_readable, ec = update_table_command(args)
        elif demisto.command() == 'aws-dynamodb-update_time_to_live':
            human_readable, ec = update_time_to_live_command(args)
        return_outputs(human_readable, ec)

    except ResponseParserError as e:
        return_error(
            'Could not connect to the AWS endpoint. Please check that the region is valid. {error}'.format(
                error=type(e)))
        LOG(e)
    except Exception as e:
        LOG(e)
        return_error('Error has occurred in the AWS dynamodb Integration: {code} {message}'.format(
            code=type(e), message=e))


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()

