import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import boto3
import io
import math
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
def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()
        
        
def scrub_dict(d):
    if type(d) is dict:
        return dict((k, scrub_dict(v)) for k, v in d.iteritems() if v and scrub_dict(v))
    else:
        return d

    
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
    "RequestItems": json.loads(demisto.args().get("request_items", "{}")),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.batch_get_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.BatchGetItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb BatchGetItem', response)
    return_outputs(human_readable, ec)


def batch_write_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "RequestItems": json.loads(demisto.args().get("request_items", "{}")),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ReturnItemCollectionMetrics": demisto.args().get("return_item_collection_metrics", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.batch_write_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.BatchWriteItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb BatchWriteItem', response)
    return_outputs(human_readable, ec)


def create_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "BackupName": demisto.args().get("backup_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.create_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.CreateBackup': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateBackup', response)
    return_outputs(human_readable, ec)


def create_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "GlobalTableName": demisto.args().get("global_table_name", None),
    "ReplicationGroup": {
        "Replica": {
            "RegionName": demisto.args().get("replica_region_name", None)
         },

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.create_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.CreateGlobalTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateGlobalTable', response)
    return_outputs(human_readable, ec)


def create_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "AttributeDefinitions": {
        "AttributeDefinition": {
            "AttributeName": demisto.args().get("attribute_definition_attribute_name", None),
            "AttributeType": demisto.args().get("attribute_definition_attribute_type", None)
         },

     },
    "TableName": demisto.args().get("table_name", None),
    "KeySchema": {
        "KeySchemaElement": {
            "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
            "KeyType": demisto.args().get("key_schema_element_key_type", None)
         },

     },
    "LocalSecondaryIndexes": {
        "LocalSecondaryIndex": {
            "IndexName": demisto.args().get("local_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             }

         },

     },
    "GlobalSecondaryIndexes": {
        "GlobalSecondaryIndex": {
            "IndexName": demisto.args().get("global_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

             }

         },

     },
    "BillingMode": demisto.args().get("billing_mode", None),
    "ProvisionedThroughput": {
        "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
        "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

     },
    "StreamSpecification": {
        "StreamEnabled": True if demisto.args().get("stream_specification_stream_enabled", "") == "true" else None,
        "StreamViewType": demisto.args().get("stream_specification_stream_view_type", None),

     },
    "SSESpecification": {
        "Enabled": True if demisto.args().get("sse_specification_enabled", "") == "true" else None,
        "SSEType": demisto.args().get("sse_specification_sse_type", None),
        "KMSMasterKeyId": demisto.args().get("sse_specification_kms_master_key_id", None),

     },
    "Tags": {
        "Tag": {
            "Key": demisto.args().get("tag_key", None),
            "Value": demisto.args().get("tag_value", None)
         },

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.create_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.CreateTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb CreateTable', response)
    return_outputs(human_readable, ec)


def delete_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "BackupArn": demisto.args().get("backup_arn", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.delete_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DeleteBackup': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteBackup', response)
    return_outputs(human_readable, ec)


def delete_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "Key": json.loads(demisto.args().get("key", "{}")),
    "Expected": json.loads(demisto.args().get("expected", "{}")),
    "ConditionalOperator": demisto.args().get("conditional_operator", None),
    "ReturnValues": demisto.args().get("return_values", None),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ReturnItemCollectionMetrics": demisto.args().get("return_item_collection_metrics", None),
    "ConditionExpression": demisto.args().get("condition_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}")),
    "ExpressionAttributeValues": json.loads(demisto.args().get("expression_attribute_values", "{}"))
    }
    kwargs = scrub_dict(kwargs)
    response = client.delete_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DeleteItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteItem', response)
    return_outputs(human_readable, ec)


def delete_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.delete_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DeleteTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DeleteTable', response)
    return_outputs(human_readable, ec)


def describe_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "BackupArn": demisto.args().get("backup_arn", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeBackup': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeBackup', response)
    return_outputs(human_readable, ec)


def describe_continuous_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_continuous_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeContinuousBackups': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeContinuousBackups', response)
    return_outputs(human_readable, ec)


def describe_endpoints_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {

    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_endpoints(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeEndpoints': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeEndpoints', response)
    return_outputs(human_readable, ec)


def describe_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "GlobalTableName": demisto.args().get("global_table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeGlobalTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeGlobalTable', response)
    return_outputs(human_readable, ec)


def describe_global_table_settings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "GlobalTableName": demisto.args().get("global_table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_global_table_settings(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeGlobalTableSettings': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeGlobalTableSettings', response)
    return_outputs(human_readable, ec)


def describe_limits_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {

    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_limits(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeLimits': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeLimits', response)
    return_outputs(human_readable, ec)


def describe_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeTable', response)
    return_outputs(human_readable, ec)


def describe_time_to_live_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.describe_time_to_live(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.DescribeTimeToLive': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb DescribeTimeToLive', response)
    return_outputs(human_readable, ec)


def get_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "Key": json.loads(demisto.args().get("key", "{}")),
    "AttributesToGet": {
        "AttributeName": demisto.args().get("attributes_to_get_attribute_name", None),

     },
    "ConsistentRead": True if demisto.args().get("consistent_read", "") == "true" else None,
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ProjectionExpression": demisto.args().get("projection_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}"))
    }
    kwargs = scrub_dict(kwargs)
    response = client.get_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.GetItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb GetItem', response)
    return_outputs(human_readable, ec)


def list_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "ExclusiveStartBackupArn": demisto.args().get("exclusive_start_backup_arn", None),
    "BackupType": demisto.args().get("backup_type", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.list_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.ListBackups': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListBackups', response)
    return_outputs(human_readable, ec)


def list_global_tables_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "ExclusiveStartGlobalTableName": demisto.args().get("exclusive_start_global_table_name", None),
    "RegionName": demisto.args().get("region_name", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.list_global_tables(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.ListGlobalTables': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListGlobalTables', response)
    return_outputs(human_readable, ec)


def list_tables_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "ExclusiveStartTableName": demisto.args().get("exclusive_start_table_name", None),

    }
    kwargs = scrub_dict(kwargs)
    response = client.list_tables(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.ListTables': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListTables', response)
    return_outputs(human_readable, ec)


def list_tags_of_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "ResourceArn": demisto.args().get("resource_arn", None),
    "NextToken": demisto.args().get("next_token", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.list_tags_of_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.ListTagsOfResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb ListTagsOfResource', response)
    return_outputs(human_readable, ec)


def put_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "Item": json.loads(demisto.args().get("item", "{}")),
    "Expected": json.loads(demisto.args().get("expected", "{}")),
    "ReturnValues": demisto.args().get("return_values", None),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ReturnItemCollectionMetrics": demisto.args().get("return_item_collection_metrics", None),
    "ConditionalOperator": demisto.args().get("conditional_operator", None),
    "ConditionExpression": demisto.args().get("condition_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}")),
    "ExpressionAttributeValues": json.loads(demisto.args().get("expression_attribute_values", "{}"))
    }
    kwargs = scrub_dict(kwargs)
    response = client.put_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.PutItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb PutItem', response)
    return_outputs(human_readable, ec)


def query_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "IndexName": demisto.args().get("index_name", None),
    "Select": demisto.args().get("select", None),
    "AttributesToGet": {
        "AttributeName": demisto.args().get("attributes_to_get_attribute_name", None),

     },
    "ConsistentRead": True if demisto.args().get("consistent_read", "") == "true" else None,
    "KeyConditions": json.loads(demisto.args().get("key_conditions", "{}")),
    "QueryFilter": json.loads(demisto.args().get("query_filter", "{}")),
    "ConditionalOperator": demisto.args().get("conditional_operator", None),
    "ScanIndexForward": True if demisto.args().get("scan_index_forward", "") == "true" else None,
    "ExclusiveStartKey": json.loads(demisto.args().get("exclusive_start_key", "{}")),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ProjectionExpression": demisto.args().get("projection_expression", None),
    "FilterExpression": demisto.args().get("filter_expression", None),
    "KeyConditionExpression": demisto.args().get("key_condition_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}")),
    "ExpressionAttributeValues": json.loads(demisto.args().get("expression_attribute_values", "{}"))
    }
    kwargs = scrub_dict(kwargs)
    response = client.query(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.Query': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb Query', response)
    return_outputs(human_readable, ec)


def restore_table_from_backup_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TargetTableName": demisto.args().get("target_table_name", None),
    "BackupArn": demisto.args().get("backup_arn", None),
    "BillingModeOverride": demisto.args().get("billing_mode_override", None),
    "GlobalSecondaryIndexOverride": {
        "GlobalSecondaryIndex": {
            "IndexName": demisto.args().get("global_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

             }

         },

     },
    "LocalSecondaryIndexOverride": {
        "LocalSecondaryIndex": {
            "IndexName": demisto.args().get("local_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             }

         },

     },
    "ProvisionedThroughputOverride": {
        "ReadCapacityUnits": demisto.args().get("provisioned_throughput_override_read_capacity_units", None),
        "WriteCapacityUnits": demisto.args().get("provisioned_throughput_override_write_capacity_units", None),

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.restore_table_from_backup(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.RestoreTableFromBackup': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb RestoreTableFromBackup', response)
    return_outputs(human_readable, ec)


def restore_table_to_point_in_time_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "SourceTableName": demisto.args().get("source_table_name", None),
    "TargetTableName": demisto.args().get("target_table_name", None),
    "UseLatestRestorableTime": True if demisto.args().get("use_latest_restorable_time", "") == "true" else None,
    "BillingModeOverride": demisto.args().get("billing_mode_override", None),
    "GlobalSecondaryIndexOverride": {
        "GlobalSecondaryIndex": {
            "IndexName": demisto.args().get("global_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
                "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

             }

         },

     },
    "LocalSecondaryIndexOverride": {
        "LocalSecondaryIndex": {
            "IndexName": demisto.args().get("local_secondary_index_index_name", None),
            "KeySchema": {
                "KeySchemaElement": {
                    "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                    "KeyType": demisto.args().get("key_schema_element_key_type", None)
                 },

             },
            "Projection": {
                "ProjectionType": demisto.args().get("projection_projection_type", None),
                "NonKeyAttributes": {
                    "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                 },

             }

         },

     },
    "ProvisionedThroughputOverride": {
        "ReadCapacityUnits": demisto.args().get("provisioned_throughput_override_read_capacity_units", None),
        "WriteCapacityUnits": demisto.args().get("provisioned_throughput_override_write_capacity_units", None),

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.restore_table_to_point_in_time(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.RestoreTableToPointInTime': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb RestoreTableToPointInTime', response)
    return_outputs(human_readable, ec)


def scan_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "IndexName": demisto.args().get("index_name", None),
    "AttributesToGet": {
        "AttributeName": demisto.args().get("attributes_to_get_attribute_name", None),

     },
    "Select": demisto.args().get("select", None),
    "ScanFilter": json.loads(demisto.args().get("scan_filter", "{}")),
    "ConditionalOperator": demisto.args().get("conditional_operator", None),
    "ExclusiveStartKey": json.loads(demisto.args().get("exclusive_start_key", "{}")),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ProjectionExpression": demisto.args().get("projection_expression", None),
    "FilterExpression": demisto.args().get("filter_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}")),
    "ExpressionAttributeValues": json.loads(demisto.args().get("expression_attribute_values", "{}")),
    "ConsistentRead": True if demisto.args().get("consistent_read", "") == "true" else None
    }
    kwargs = scrub_dict(kwargs)
    response = client.scan(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.Scan': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb Scan', response)
    return_outputs(human_readable, ec)


def tag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "ResourceArn": demisto.args().get("resource_arn", None),
    "Tags": {
        "Tag": {
            "Key": demisto.args().get("tag_key", None),
            "Value": demisto.args().get("tag_value", None)
         },

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.tag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.TagResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TagResource', response)
    return_outputs(human_readable, ec)


def transact_get_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TransactItems": {
        "TransactGetItem": {
            "Get": {
                "Key": json.loads(demisto.args().get("get_key", "{}")),
                "TableName": demisto.args().get("get_table_name", None),
                "ProjectionExpression": demisto.args().get("get_projection_expression", None),
                "ExpressionAttributeNames": json.loads(demisto.args().get("get_expression_attribute_names", "{}")),

             }

         },

     },
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.transact_get_items(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.TransactGetItems': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TransactGetItems', response)
    return_outputs(human_readable, ec)


def transact_write_items_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TransactItems": {
        "TransactWriteItem": {
            "ConditionCheck": {
                "Key": json.loads(demisto.args().get("condition_check_key", "{}")),
                "TableName": demisto.args().get("condition_check_table_name", None),
                "ConditionExpression": demisto.args().get("condition_check_condition_expression", None),
                "ExpressionAttributeNames": json.loads(demisto.args().get("condition_check_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(demisto.args().get("condition_check_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": demisto.args().get("condition_check_return_values_on_condition_check_failure", None),

             },
            "Put": {
                "Item": json.loads(demisto.args().get("put_item", "{}")),
                "TableName": demisto.args().get("put_table_name", None),
                "ConditionExpression": demisto.args().get("put_condition_expression", None),
                "ExpressionAttributeNames": json.loads(demisto.args().get("put_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(demisto.args().get("put_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": demisto.args().get("put_return_values_on_condition_check_failure", None),

             },
            "Delete": {
                "Key": json.loads(demisto.args().get("delete_key", "{}")),
                "TableName": demisto.args().get("delete_table_name", None),
                "ConditionExpression": demisto.args().get("delete_condition_expression", None),
                "ExpressionAttributeNames": json.loads(demisto.args().get("delete_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(demisto.args().get("delete_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": demisto.args().get("delete_return_values_on_condition_check_failure", None),

             },
            "Update": {
                "Key": json.loads(demisto.args().get("update_key", "{}")),
                "UpdateExpression": demisto.args().get("update_update_expression", None),
                "TableName": demisto.args().get("update_table_name", None),
                "ConditionExpression": demisto.args().get("update_condition_expression", None),
                "ExpressionAttributeNames": json.loads(demisto.args().get("update_expression_attribute_names", "{}")),
                "ExpressionAttributeValues": json.loads(demisto.args().get("update_expression_attribute_values", "{}")),
                "ReturnValuesOnConditionCheckFailure": demisto.args().get("update_return_values_on_condition_check_failure", None),

             }

         },

     },
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ReturnItemCollectionMetrics": demisto.args().get("return_item_collection_metrics", None),
    "ClientRequestToken": demisto.args().get("client_request_token", None)
    }
    kwargs = scrub_dict(kwargs)
    response = client.transact_write_items(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.TransactWriteItems': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb TransactWriteItems', response)
    return_outputs(human_readable, ec)


def untag_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "ResourceArn": demisto.args().get("resource_arn", None),
    "TagKeys": {
        "TagKeyString": demisto.args().get("tag_keys_tag_key_string", None),

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.untag_resource(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UntagResource': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UntagResource', response)
    return_outputs(human_readable, ec)


def update_continuous_backups_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "PointInTimeRecoverySpecification": {
        "PointInTimeRecoveryEnabled": True if demisto.args().get("point_in_time_recovery_specification_point_in_time_recovery_enabled", "") == "true" else None,

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.update_continuous_backups(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateContinuousBackups': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateContinuousBackups', response)
    return_outputs(human_readable, ec)


def update_global_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "GlobalTableName": demisto.args().get("global_table_name", None),
    "ReplicaUpdates": {
        "ReplicaUpdate": {
            "Create": {
                "RegionName": demisto.args().get("create_region_name", None),

             },
            "Delete": {
                "RegionName": demisto.args().get("delete_region_name", None),

             }

         },

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.update_global_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateGlobalTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateGlobalTable', response)
    return_outputs(human_readable, ec)


def update_global_table_settings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "GlobalTableName": demisto.args().get("global_table_name", None),
    "GlobalTableBillingMode": demisto.args().get("global_table_billing_mode", None),
    "GlobalTableProvisionedWriteCapacityUnits": demisto.args().get("global_table_provisioned_write_capacity_units", None),
    "GlobalTableProvisionedWriteCapacityAutoScalingSettingsUpdate": {
        "MinimumUnits": demisto.args().get("global_table_provisioned_write_capacity_auto_scaling_settings_update_minimum_units", None),
        "MaximumUnits": demisto.args().get("global_table_provisioned_write_capacity_auto_scaling_settings_update_maximum_units", None),
        "AutoScalingDisabled": True if demisto.args().get("global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
        "AutoScalingRoleArn": demisto.args().get("global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
        "ScalingPolicyUpdate": {
            "PolicyName": demisto.args().get("scaling_policy_update_policy_name", None),
            "TargetTrackingScalingPolicyConfiguration": {
                "DisableScaleIn": True if demisto.args().get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

             },

         },

     },
    "GlobalTableGlobalSecondaryIndexSettingsUpdate": {
        "GlobalTableGlobalSecondaryIndexSettingsUpdate": {
            "IndexName": demisto.args().get("global_table_global_secondary_index_settings_update_index_name", None),
            "ProvisionedWriteCapacityUnits": demisto.args().get("global_table_global_secondary_index_settings_update_provisioned_write_capacity_units", None),
            "ProvisionedWriteCapacityAutoScalingSettingsUpdate": {
                "MinimumUnits": demisto.args().get("provisioned_write_capacity_auto_scaling_settings_update_minimum_units", None),
                "MaximumUnits": demisto.args().get("provisioned_write_capacity_auto_scaling_settings_update_maximum_units", None),
                "AutoScalingDisabled": True if demisto.args().get("provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
                "AutoScalingRoleArn": demisto.args().get("provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
                "ScalingPolicyUpdate": {
                    "PolicyName": demisto.args().get("scaling_policy_update_policy_name", None),
                    "TargetTrackingScalingPolicyConfiguration": {
                        "DisableScaleIn": True if demisto.args().get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

                     },

                 },

             }

         },

     },
    "ReplicaSettingsUpdate": {
        "ReplicaSettingsUpdate": {
            "RegionName": demisto.args().get("replica_settings_update_region_name", None),
            "ReplicaProvisionedReadCapacityUnits": demisto.args().get("replica_settings_update_replica_provisioned_read_capacity_units", None),
            "ReplicaProvisionedReadCapacityAutoScalingSettingsUpdate": {
                "MinimumUnits": demisto.args().get("replica_provisioned_read_capacity_auto_scaling_settings_update_minimum_units", None),
                "MaximumUnits": demisto.args().get("replica_provisioned_read_capacity_auto_scaling_settings_update_maximum_units", None),
                "AutoScalingDisabled": True if demisto.args().get("replica_provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
                "AutoScalingRoleArn": demisto.args().get("replica_provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
                "ScalingPolicyUpdate": {
                    "PolicyName": demisto.args().get("scaling_policy_update_policy_name", None),
                    "TargetTrackingScalingPolicyConfiguration": {
                        "DisableScaleIn": True if demisto.args().get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

                     },

                 },

             },
            "ReplicaGlobalSecondaryIndexSettingsUpdate": {
                "ReplicaGlobalSecondaryIndexSettingsUpdate": {
                    "IndexName": demisto.args().get("replica_global_secondary_index_settings_update_index_name", None),
                    "ProvisionedReadCapacityUnits": demisto.args().get("replica_global_secondary_index_settings_update_provisioned_read_capacity_units", None),
                    "ProvisionedReadCapacityAutoScalingSettingsUpdate": {
                        "MinimumUnits": demisto.args().get("provisioned_read_capacity_auto_scaling_settings_update_minimum_units", None),
                        "MaximumUnits": demisto.args().get("provisioned_read_capacity_auto_scaling_settings_update_maximum_units", None),
                        "AutoScalingDisabled": True if demisto.args().get("provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_disabled", "") == "true" else None,
                        "AutoScalingRoleArn": demisto.args().get("provisioned_read_capacity_auto_scaling_settings_update_auto_scaling_role_arn", None),
                        "ScalingPolicyUpdate": {
                            "PolicyName": demisto.args().get("scaling_policy_update_policy_name", None),
                            "TargetTrackingScalingPolicyConfiguration": {
                                "DisableScaleIn": True if demisto.args().get("target_tracking_scaling_policy_configuration_disable_scale_in", "") == "true" else None,

                             },

                         },

                     }

                 },

             }

         },

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.update_global_table_settings(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateGlobalTableSettings': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateGlobalTableSettings', response)
    return_outputs(human_readable, ec)


def update_item_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "Key": json.loads(demisto.args().get("key", "{}")),
    "AttributeUpdates": json.loads(demisto.args().get("attribute_updates", "{}")),
    "Expected": json.loads(demisto.args().get("expected", "{}")),
    "ConditionalOperator": demisto.args().get("conditional_operator", None),
    "ReturnValues": demisto.args().get("return_values", None),
    "ReturnConsumedCapacity": demisto.args().get("return_consumed_capacity", None),
    "ReturnItemCollectionMetrics": demisto.args().get("return_item_collection_metrics", None),
    "UpdateExpression": demisto.args().get("update_expression", None),
    "ConditionExpression": demisto.args().get("condition_expression", None),
    "ExpressionAttributeNames": json.loads(demisto.args().get("expression_attribute_names", "{}")),
    "ExpressionAttributeValues": json.loads(demisto.args().get("expression_attribute_values", "{}"))
    }
    kwargs = scrub_dict(kwargs)
    response = client.update_item(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateItem': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateItem', response)
    return_outputs(human_readable, ec)


def update_table_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "AttributeDefinitions": {
        "AttributeDefinition": {
            "AttributeName": demisto.args().get("attribute_definition_attribute_name", None),
            "AttributeType": demisto.args().get("attribute_definition_attribute_type", None)
         },

     },
    "TableName": demisto.args().get("table_name", None),
    "BillingMode": demisto.args().get("billing_mode", None),
    "ProvisionedThroughput": {
        "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
        "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

     },
    "GlobalSecondaryIndexUpdates": {
        "GlobalSecondaryIndexUpdate": {
            "Update": {
                "IndexName": demisto.args().get("update_index_name", None),
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
                    "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

                 },

             },
            "Create": {
                "IndexName": demisto.args().get("create_index_name", None),
                "KeySchema": {
                    "KeySchemaElement": {
                        "AttributeName": demisto.args().get("key_schema_element_attribute_name", None),
                        "KeyType": demisto.args().get("key_schema_element_key_type", None)
                     },

                 },
                "Projection": {
                    "ProjectionType": demisto.args().get("projection_projection_type", None),
                    "NonKeyAttributes": {
                        "NonKeyAttributeName": demisto.args().get("non_key_attributes_non_key_attribute_name", None),

                     },

                 },
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": demisto.args().get("provisioned_throughput_read_capacity_units", None),
                    "WriteCapacityUnits": demisto.args().get("provisioned_throughput_write_capacity_units", None),

                 },

             },
            "Delete": {
                "IndexName": demisto.args().get("delete_index_name", None),

             }

         },

     },
    "StreamSpecification": {
        "StreamEnabled": True if demisto.args().get("stream_specification_stream_enabled", "") == "true" else None,
        "StreamViewType": demisto.args().get("stream_specification_stream_view_type", None),

     },
    "SSESpecification": {
        "Enabled": True if demisto.args().get("sse_specification_enabled", "") == "true" else None,
        "SSEType": demisto.args().get("sse_specification_sse_type", None),
        "KMSMasterKeyId": demisto.args().get("sse_specification_kms_master_key_id", None),

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.update_table(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateTable': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateTable', response)
    return_outputs(human_readable, ec)


def update_time_to_live_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
    "TableName": demisto.args().get("table_name", None),
    "TimeToLiveSpecification": {
        "Enabled": True if demisto.args().get("time_to_live_specification_enabled", "") == "true" else None,
        "AttributeName": demisto.args().get("time_to_live_specification_attribute_name", None),

     }

    }
    kwargs = scrub_dict(kwargs)
    response = client.update_time_to_live(**kwargs)
    response = json.dumps(response, default=myconverter)
    response = json.loads(response)
    ec = {'AWS.Dynamodb.UpdateTimeToLive': response}
    del response['ResponseMetadata']
    human_readable = tableToMarkdown('AWS Dynamodb UpdateTimeToLive', response)
    return_outputs(human_readable, ec)


    '''COMMAND BLOCK'''
    
    
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        client = aws_session()
        response = client.REPLACE_WITH_TEST_FUNCTION()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')
    
    elif demisto.command() == 'aws-dynamodb-batch_get_item':
        batch_get_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-batch_write_item':
        batch_write_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-create_backup':
        create_backup_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-create_global_table':
        create_global_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-create_table':
        create_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-delete_backup':
        delete_backup_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-delete_item':
        delete_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-delete_table':
        delete_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_backup':
        describe_backup_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_continuous_backups':
        describe_continuous_backups_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_endpoints':
        describe_endpoints_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_global_table':
        describe_global_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_global_table_settings':
        describe_global_table_settings_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_limits':
        describe_limits_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_table':
        describe_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-describe_time_to_live':
        describe_time_to_live_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-get_item':
        get_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-list_backups':
        list_backups_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-list_global_tables':
        list_global_tables_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-list_tables':
        list_tables_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-list_tags_of_resource':
        list_tags_of_resource_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-put_item':
        put_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-query':
        query_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-restore_table_from_backup':
        restore_table_from_backup_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-restore_table_to_point_in_time':
        restore_table_to_point_in_time_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-scan':
        scan_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-tag_resource':
        tag_resource_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-transact_get_items':
        transact_get_items_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-transact_write_items':
        transact_write_items_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-untag_resource':
        untag_resource_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_continuous_backups':
        update_continuous_backups_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_global_table':
        update_global_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_global_table_settings':
        update_global_table_settings_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_item':
        update_item_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_table':
        update_table_command(demisto.args())
    elif demisto.command() == 'aws-dynamodb-update_time_to_live':
        update_time_to_live_command(demisto.args())
except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid. {error}'.format(
        error=type(e)))
    LOG(e)

except Exception as e:
    LOG(e)
    return_error('Error has occurred in the AWS dynamodb Integration: {code} {message}'.format(
        code=type(e), message=e))    
