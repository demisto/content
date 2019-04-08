import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
import json
import re
import datetime
from botocore.config import Config
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_roleArn = demisto.params().get('roleArn')
AWS_roleSessionName = demisto.params().get('roleSessionName')
AWS_roleSessionDuration = demisto.params().get('sessionDuration')
AWS_rolePolicy = None
AWS_access_key_id = demisto.params().get('access_key')
AWS_secret_access_key = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
if not demisto.params().get('proxy', False):
    config = Config(
        retries=dict(
            max_attempts=10
        )
    )
else:
    config = None


"""HELPER FUNCTIONS"""


def aws_session(service='ec2', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
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
    if kwargs and AWS_access_key_id is None:
        sts_client = boto3.client('sts')
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
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_access_key_id,
                aws_secret_access_key=AWS_secret_access_key,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_access_key_id,
                aws_secret_access_key=AWS_secret_access_key,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


def parse_filter_field(filter_str):
    filters = []
    regex = re.compile(r'name=([\w\d_:.-]+),values=([ /\w\d@_,.*-]+)', flags=re.I)
    for f in filter_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse filter: %s' % (f,))
            continue

        filters.append({
            'Name': match.group(1),
            'Values': match.group(2).split(',')
        })

    return filters


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
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


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


"""MAIN FUNCTIONS"""


def describe_regions(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {}
    if args.get('regionNames') is not None:
        kwargs.update({'RegionNames': parse_resource_ids(args.get('regionNames'))})

    response = client.describe_regions(**kwargs)
    for region in response['Regions']:
        data.append({
            'Endpoint': region['Endpoint'],
            'RegionName': region['RegionName']
        })

    ec = {'AWS.Regions(val.RegionName === obj.RegionName)': data}
    human_readable = tableToMarkdown('AWS Regions', data)
    return_outputs(human_readable, ec)


def describe_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    data = []
    kwargs = {}
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})

    response = client.describe_instances(**kwargs)
    for i, reservation in enumerate(response['Reservations']):
        for instance in reservation['Instances']:
            data.append({
                'InstanceId': instance['InstanceId'],
                'ImageId': instance['ImageId'],
                'State': instance['State']['Name'],
                'PublicIPAddress': instance.get('PublicIpAddress'),
                'Region': obj['_user_provided_options']['region_name'],
                'Type': instance['InstanceType'],
                'LaunchDate': datetime.datetime.strftime(instance['LaunchTime'], '%Y-%m-%dT%H:%M:%SZ'),
                'PublicDNSName': instance['PublicDnsName'],
                'KeyName': instance['KeyName'],
                'Monitoring': instance['Monitoring']['State'],
            })
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    data[i].update({
                        tag['Key']: tag['Value']
                    })
        instance.update({'Region': obj['_user_provided_options']['region_name']})
        output.append(instance)

    raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    ec = {'AWS.EC2.Instances(val.InstanceId === obj.InstanceId)': raw}
    human_readable = tableToMarkdown('AWS Instances', data)
    return_outputs(human_readable, ec)


def describe_images(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('imageIds') is not None:
        kwargs.update({'ImageIds': parse_resource_ids(args.get('imageIds'))})
    if args.get('owners') is not None:
        kwargs.update({'Owners': parse_resource_ids(args.get('owners'))})
    if args.get('executableUsers') is not None:
        kwargs.update({'ExecutableUsers': parse_resource_ids(args.get('executableUsers'))})

    response = client.describe_images(**kwargs)
    for i, image in enumerate(response['Images']):
        data.append({
            'CreationDate': image['CreationDate'],
            'ImageId': image['ImageId'],
            'Public': image['Public'],
            'State': image['State'],
            'Region': obj['_user_provided_options']['region_name'],
        })
        if 'Description' in image:
            data[i].update({'Description': image['Description']})
        if 'EnaSupport' in image:
            data[i].update({'EnaSupport': image['EnaSupport']})
        if 'Name' in image:
            data[i].update({'Name': image['Name']})
        if 'Tags' in image:
            for tag in image['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['Images'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Images(val.ImageId === obj.ImageId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Images', data)
    return_outputs(human_readable, ec)


def describe_addresses(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('publicIps') is not None:
        kwargs.update({'PublicIps': parse_resource_ids(args.get('publicIps'))})
    if args.get('allocationIds') is not None:
        kwargs.update({'AllocationIds': parse_resource_ids(args.get('allocationIds'))})

    response = client.describe_addresses(**kwargs)

    for i, address in enumerate(response['Addresses']):
        data.append({
            'PublicIp': address['PublicIp'],
            'AllocationId': address['AllocationId'],
            'Domain': address['Domain'],
            'Region': obj['_user_provided_options']['region_name'],
        })
        if 'InstanceId' in address:
            data[i].update({'InstanceId': address['InstanceId']})
        if 'AssociationId' in address:
            data[i].update({'AssociationId': address['AssociationId']})
        if 'NetworkInterfaceId' in address:
            data[i].update({'NetworkInterfaceId': address['NetworkInterfaceId']})
        if 'PrivateIpAddress' in address:
            data[i].update({'PrivateIpAddress': address['PrivateIpAddress']})
        if 'Tags' in address:
            for tag in address['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    raw = response['Addresses']
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.ElasticIPs(val.AllocationId === obj.AllocationId)': raw}
    human_readable = tableToMarkdown('AWS EC2 ElasticIPs', data)
    return_outputs(human_readable, ec)


def describe_snapshots(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('ownerIds') is not None:
        kwargs.update({'OwnerIds': parse_resource_ids(args.get('ownerIds'))})
    if args.get('snapshotIds') is not None:
        kwargs.update({'SnapshotIds': parse_resource_ids(args.get('snapshotIds'))})
    if args.get('restorableByUserIds') is not None:
        kwargs.update({'RestorableByUserIds': parse_resource_ids(args.get('restorableByUserIds'))})

    response = client.describe_snapshots(**kwargs)

    for i, snapshot in enumerate(response['Snapshots']):
        data.append({
            'Description': snapshot['Description'],
            'Encrypted': snapshot['Encrypted'],
            'OwnerId': snapshot['OwnerId'],
            'Progress': snapshot['Progress'],
            'SnapshotId': snapshot['SnapshotId'],
            'StartTime': datetime.datetime.strftime(snapshot['StartTime'], '%Y-%m-%dT%H:%M:%SZ'),
            'State': snapshot['State'],
            'VolumeId': snapshot['VolumeId'],
            'VolumeSize': snapshot['VolumeSize'],
            'Region': obj['_user_provided_options']['region_name'],
        })
        if 'Tags' in snapshot:
            for tag in snapshot['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['Snapshots'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Snapshots(val.SnapshotId === obj.SnapshotId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Snapshots', data)
    return_outputs(human_readable, ec)


def describe_volumes(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('volumeIds') is not None:
        kwargs.update({'VolumeIds': parse_resource_ids(args.get('volumeIds'))})

    response = client.describe_volumes(**kwargs)

    for i, volume in enumerate(response['Volumes']):
        data.append({
            'AvailabilityZone': volume['AvailabilityZone'],
            'Encrypted': volume['Encrypted'],
            'State': volume['State'],
            'VolumeId': volume['VolumeId'],
            'VolumeType': volume['VolumeType'],
            'CreateTime': datetime.datetime.strftime(volume['CreateTime'], '%Y-%m-%dT%H:%M:%SZ'),
        })
        if 'Tags' in volume:
            for tag in volume['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['Volumes'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Volumes(val.VolumeId === obj.VolumeId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Volumes', data)
    return_outputs(human_readable, ec)


def describe_launch_templates(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('launchTemplateIds') is not None:
        kwargs.update({'LaunchTemplateIds': parse_resource_ids(args.get('launchTemplateIds'))})
    if args.get('launchTemplateNames') is not None:
        kwargs.update({'LaunchTemplateNames': parse_resource_ids(args.get('launchTemplateNamess'))})

    response = client.describe_launch_templates(**kwargs)

    for i, template in enumerate(response['LaunchTemplates']):
        data.append({
            'LaunchTemplateId': template['LaunchTemplateId'],
            'LaunchTemplateName': template['LaunchTemplateName'],
            'CreatedBy': template['CreatedBy'],
            'DefaultVersionNumber': template['DefaultVersionNumber'],
            'LatestVersionNumber': template['LatestVersionNumber'],
            'CreateTime': datetime.datetime.strftime(template['CreateTime'], '%Y-%m-%dT%H:%M:%SZ'),
            'Region': obj['_user_provided_options']['region_name'],
        })

        if 'Tags' in template:
            for tag in template['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['LaunchTemplates'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.LaunchTemplates(val.LaunchTemplateId === obj.LaunchTemplateId)': raw}
    human_readable = tableToMarkdown('AWS EC2 LaunchTemplates', data)
    return_outputs(human_readable, ec)


def describe_key_pairs(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('keyNames') is not None:
        kwargs.update({'KeyNames': parse_resource_ids(args.get('keyNames'))})

    response = client.describe_key_pairs(**kwargs)

    for key in response['KeyPairs']:
        data.append({
            'KeyFingerprint': key['KeyFingerprint'],
            'KeyName': key['KeyName'],
            'Region': obj['_user_provided_options']['region_name'],
        })

    ec = {'AWS.EC2.KeyPairs(val.KeyName === obj.KeyName)': data}
    human_readable = tableToMarkdown('AWS EC2 Key Pairs', data)
    return_outputs(human_readable, ec)


def describe_vpcs(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('vpcIds') is not None:
        kwargs.update({'VpcIds': parse_resource_ids(args.get('vpcIds'))})

    response = client.describe_vpcs(**kwargs)

    for i, vpc in enumerate(response['Vpcs']):
        data.append({
            'CidrBlock': vpc['CidrBlock'],
            'DhcpOptionsId': vpc['DhcpOptionsId'],
            'State': vpc['State'],
            'VpcId': vpc['VpcId'],
            'InstanceTenancy': vpc['InstanceTenancy'],
            'IsDefault': vpc['IsDefault'],
            'Region': obj['_user_provided_options']['region_name'],
        })

        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['Vpcs'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Vpcs(val.VpcId === obj.VpcId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Vpcs', data)
    return_outputs(human_readable, ec)


def describe_subnets(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('subnetIds') is not None:
        kwargs.update({'SubnetIds': parse_resource_ids(args.get('subnetIds'))})

    response = client.describe_subnets(**kwargs)

    for i, subnet in enumerate(response['Subnets']):
        data.append({
            'AvailabilityZone': subnet['AvailabilityZone'],
            'AvailableIpAddressCount': subnet['AvailableIpAddressCount'],
            'CidrBlock': subnet['CidrBlock'],
            'DefaultForAz': subnet['DefaultForAz'],
            'State': subnet['State'],
            'SubnetId': subnet['SubnetId'],
            'VpcId': subnet['VpcId'],
            'Region': obj['_user_provided_options']['region_name'],
        })

        if 'Tags' in subnet:
            for tag in subnet['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['Subnets'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Subnets(val.SubnetId === obj.SubnetId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Subnets', data)
    return_outputs(human_readable, ec)


def describe_security_groups(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('groupIds') is not None:
        kwargs.update({'GroupIds': parse_resource_ids(args.get('groupIds'))})
    if args.get('groupNames') is not None:
        kwargs.update({'GroupNames': parse_resource_ids(args.get('groupNames'))})

    response = client.describe_security_groups(**kwargs)

    for i, sg in enumerate(response['SecurityGroups']):
        data.append({
            'Description': sg['Description'],
            'GroupName': sg['GroupName'],
            'OwnerId': sg['OwnerId'],
            'GroupId': sg['GroupId'],
            'VpcId': sg['VpcId'],
            'Region': obj['_user_provided_options']['region_name'],
        })

        if 'Tags' in sg:
            for tag in sg['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    output = json.dumps(response['SecurityGroups'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.SecurityGroups(val.GroupId === obj.GroupId)': raw}
    human_readable = tableToMarkdown('AWS EC2 SecurityGroups', data)
    return_outputs(human_readable, ec)


def allocate_address(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)

    response = client.allocate_address(Domain='vpc')
    data = ({
        'PublicIp': response['PublicIp'],
        'AllocationId': response['AllocationId'],
        'Domain': response['Domain'],
        'Region': obj['_user_provided_options']['region_name']
    })
    ec = {'AWS.EC2.ElasticIPs': data}
    human_readable = tableToMarkdown('AWS EC2 ElasticIP', data)
    return_outputs(human_readable, ec)


def associate_address(args):
    client = aws_session(
        service='ec2',
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {'AllocationId': args.get('allocationId')}

    if args.get('instanceId') is not None:
        kwargs.update({'InstanceId': args.get('instanceId')})
    if args.get('allowReassociation') is not None:
        kwargs.update({'AllowReassociation': True if args.get('allowReassociation') == 'True' else False})
    if args.get('networkInterfaceId') is not None:
        kwargs.update({'NetworkInterfaceId': args.get('networkInterfaceId')})
    if args.get('privateIpAddress') is not None:
        kwargs.update({'PrivateIpAddress': args.get('privateIpAddress')})

    response = client.associate_address(**kwargs)
    data = ({
        'AllocationId': args.get('allocationId'),
        'AssociationId': response['AssociationId'],
        'Region': obj['_user_provided_options']['region_name']
    })

    ec = {"AWS.EC2.ElasticIPs(val.AllocationId === obj.AllocationId)": data}
    human_readable = tableToMarkdown('AWS EC2 ElasticIP', data)
    return_outputs(human_readable, ec)


def create_snapshot(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {'VolumeId': args.get('volumeId')}

    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('tags') is not None:
        kwargs.update({
            'TagSpecifications': [{
                'ResourceType': 'snapshot',
                'Tags': parse_tag_field(args.get('tags'))}]
        })

    response = client.create_snapshot(**kwargs)

    data = ({
        'Description': response['Description'],
        'Encrypted': response['Encrypted'],
        'Progress': response['Progress'],
        'SnapshotId': response['SnapshotId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
        'VolumeSize': response['VolumeSize'],
        'StartTime': datetime.datetime.strftime(response['StartTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'Region': obj['_user_provided_options']['region_name'],
    })

    if 'Tags' in response:
        for tag in response['Tags']:
            data.update({
                tag['Key']: tag['Value']
            })

    output = json.dumps(response, cls=DatetimeEncoder)
    raw = json.loads(output)
    del raw['ResponseMetadata']
    raw.update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Snapshots': raw}
    human_readable = tableToMarkdown('AWS EC2 Snapshots', data)
    return_outputs(human_readable, ec)


def delete_snapshot(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_snapshot(SnapshotId=args.get('snapshotId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Snapshot with ID: {0} was deleted".format(args.get('snapshotId')))


def create_image(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
        'InstanceId': args.get('instanceId')
    }

    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('noReboot') is not None:
        kwargs.update({'NoReboot': True if args.get('noReboot') == 'True' else False})

    response = client.create_image(**kwargs)

    data = ({
        'ImageId': response['ImageId'],
        'Name': args.get('name'),
        'InstanceId': args.get('instanceId'),
        'Region': obj['_user_provided_options']['region_name'],
    })

    ec = {'AWS.EC2.Images': data}
    human_readable = tableToMarkdown('AWS EC2 Images', data)
    return_outputs(human_readable, ec)


def deregister_image(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.deregister_image(ImageId=args.get('imageId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The AMI with ID: {0} was deregistered".format(args.get('imageId')))


def modify_volume(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    obj = vars(client._client_config)
    kwargs = {'VolumeId': args.get('volumeId')}

    if args.get('size') is not None:
        kwargs.update({'Size': int(args.get('size'))})
    if args.get('volumeType') is not None:
        kwargs.update({'VolumeType': args.get('volumeType')})
    if args.get('iops') is not None:
        kwargs.update({'Iops': int(args.get('iops'))})

    response = client.modify_volume(**kwargs)
    volumeModification = response['VolumeModification']

    data = ({
        'VolumeId': volumeModification['VolumeId'],
        'ModificationState': volumeModification['ModificationState'],
        'TargetSize': volumeModification['TargetSize'],
        'TargetIops': volumeModification['TargetIops'],
        'TargetVolumeType': volumeModification['TargetVolumeType'],
        'OriginalSize': volumeModification['OriginalSize'],
        'OriginalIops': volumeModification['OriginalIops'],
        'OriginalVolumeType': volumeModification['OriginalVolumeType'],
        'StartTime': datetime.datetime.strftime(volumeModification['StartTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'Progress': volumeModification['Progress'],
        'Region': obj['_user_provided_options']['region_name'],
    })

    output = json.dumps(response['VolumeModification'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw.update({'Region': obj['_user_provided_options']['region_name']})

    ec = {'AWS.EC2.Volumes(val.VolumeId === obj.VolumeId).Modification': raw}
    human_readable = tableToMarkdown('AWS EC2 Volume Modification', data)
    return_outputs(human_readable, ec)


def create_tags(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'Resources': parse_resource_ids(args.get('resources')),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.create_tags(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The recources where taged successfully")


def disassociate_address(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.disassociate_address(AssociationId=args.get('associationId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Elastic IP was disassociated")


def release_address(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.release_address(AllocationId=args.get('allocationId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Elastic IP was released")


def start_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.start_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instances were started")


def stop_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.stop_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instances were stopped")


def terminate_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.terminate_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instances were terminated")


def create_volume(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {'AvailabilityZone': args.get('availabilityZone')}

    if args.get('encrypted') is not None:
        kwargs.update({'Encrypted': True if args.get('encrypted') == 'True' else False})
    if args.get('iops') is not None:
        kwargs.update({'Iops': int(args.get('iops'))})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})
    if args.get('size') is not None:
        kwargs.update({'Size': int(args.get('size'))})
    if args.get('snapshotId') is not None:
        kwargs.update({'SnapshotId': args.get('snapshotId')})
    if args.get('volumeType') is not None:
        kwargs.update({'VolumeType': args.get('volumeType')})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})
    if args.get('tags') is not None:
        kwargs.update({
            'TagSpecifications': [{
                'ResourceType': 'volume',
                'Tags': parse_tag_field(args.get('tags'))}]
        })

    response = client.create_volume(**kwargs)

    data = ({
        'AvailabilityZone': response['AvailabilityZone'],
        'CreateTime': datetime.datetime.strftime(response['CreateTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'Encrypted': response['Encrypted'],
        'Size': response['Size'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
        'Iops': response['Iops'],
        'VolumeType': response['VolumeType'],
        'Region': obj['_user_provided_options']['region_name'],
    })
    if 'SnapshotId' in response:
        data.update({'SnapshotId': response['SnapshotId']})
    if 'KmsKeyId' in response:
        data.update({'KmsKeyId': response['KmsKeyId']})
    if 'Tags' in response:
        for tag in response['Tags']:
            data.update({
                tag['Key']: tag['Value']
            })

    ec = {'AWS.EC2.Volumes': data}
    human_readable = tableToMarkdown('AWS EC2 Volumes', data)
    return_outputs(human_readable, ec)


def attach_volume(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'Device': args.get('device'),
        'InstanceId': args.get('instanceId'),
        'VolumeId': args.get('volumeId'),
    }
    response = client.attach_volume(**kwargs)
    data = ({
        'AttachTime': datetime.datetime.strftime(response['AttachTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'Device': response['Device'],
        'InstanceId': response['InstanceId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
    })
    if 'DeleteOnTermination' in response:
        data.update({'DeleteOnTermination': response['DeleteOnTermination']})

    ec = {'AWS.EC2.Volumes(val.VolumeId === obj.VolumeId).Attachments': data}
    human_readable = tableToMarkdown('AWS EC2 Volume Attachments', data)
    return_outputs(human_readable, ec)


def detach_volume(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'VolumeId': args.get('volumeId')}

    if args.get('force') is not None:
        kwargs.update({'Force': True if args.get('force') == 'True' else False})
    if args.get('device') is not None:
        kwargs.update({'Device': int(args.get('device'))})
    if args.get('instanceId') is not None:
        kwargs.update({'InstanceId': args.get('instanceId')})

    response = client.detach_volume(**kwargs)
    data = ({
        'AttachTime': datetime.datetime.strftime(response['AttachTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'Device': response['Device'],
        'InstanceId': response['InstanceId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
    })
    if 'DeleteOnTermination' in response:
        data.update({'DeleteOnTermination': response['DeleteOnTermination']})

    ec = {'AWS.EC2.Volumes(val.VolumeId === obj.VolumeId).Attachments': data}
    human_readable = tableToMarkdown('AWS EC2 Volume Attachments', data)
    return_outputs(human_readable, ec)


def delete_volume(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_volume(VolumeId=args.get('volumeId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Volume was deleted")


def run_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'MinCount': int(args.get('count')),
        'MaxCount': int(args.get('count'))
    }
    BlockDeviceMappings = None
    if args.get('imageId') is not None:
        kwargs.update({'ImageId': (args.get('imageId'))})
    if args.get('instanceType') is not None:
        kwargs.update({'InstanceType': args.get('instanceType')})
    if args.get('securityGroupIds') is not None:
        kwargs.update({'SecurityGroupIds': parse_resource_ids(args.get('securityGroupIds'))})
    if args.get('securityGroups') is not None:
        kwargs.update({'SecurityGroups': parse_resource_ids(args.get('securityGroups'))})
    if args.get('subnetId') is not None:
        kwargs.update({'SubnetId': args.get('subnetId')})
    if args.get('userData') is not None:
        kwargs.update({'UserData': args.get('userData')})
    if args.get('keyName') is not None:
        kwargs.update({'KeyName': args.get('keyName')})
    if args.get('ebsOptimized') is not None:
        kwargs.update({'EbsOptimized': args.get('ebsOptimized')})
    if args.get('disableApiTermination') is not None:
        kwargs.update({'DisableApiTermination': True if args.get('disableApiTermination') == 'True' else False})
    if args.get('deviceName') is not None:
        BlockDeviceMappings = {'DeviceName': args.get('deviceName')}
        BlockDeviceMappings.update({'Ebs': {}})
    if args.get('ebsVolumeSize') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeSize': int(args.get('ebsVolumeSize'))})
    if args.get('ebsVolumeType') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeType': args.get('ebsVolumeType')})
    if args.get('ebsIops') is not None:
        BlockDeviceMappings['Ebs'].update({'Iops': int(args.get('ebsIops'))})
    if args.get('ebsDeleteOnTermination') is not None:
        BlockDeviceMappings['Ebs'].update(
            {'DeleteOnTermination': True if args.get('ebsDeleteOnTermination') == 'True' else False})
    if args.get('ebsKmsKeyId') is not None:
        BlockDeviceMappings['Ebs'].update({'KmsKeyId': args.get('ebsKmsKeyId')})
    if args.get('ebsSnapshotId') is not None:
        BlockDeviceMappings['Ebs'].update({'SnapshotId': args.get('ebsSnapshotId')})
    if args.get('ebsEncrypted') is not None:
        BlockDeviceMappings['Ebs'].update({'Encrypted': True if args.get('ebsEncrypted') == 'True' else False})
    if BlockDeviceMappings:
        kwargs.update({'BlockDeviceMappings': [BlockDeviceMappings]})

    if args.get('iamInstanceProfileArn') and args.get('iamInstanceProfileName') is not None:
        kwargs.update({
            'IamInstanceProfile': {
                'Arn': args.get('iamInstanceProfileArn'),
                'Name': args.get('iamInstanceProfileName')}
        })
    if args.get('launchTemplateId') is not None:
        kwargs.update({
            'LaunchTemplate': {
                'LaunchTemplateId': args.get('launchTemplateId')}
        })
    if args.get('launchTemplateName') is not None:
        kwargs.update({
            'LaunchTemplate': {
                'LaunchTemplateName': args.get('launchTemplateName')}
        })
    if args.get('launchTemplateVersion') is not None:
        kwargs['LaunchTemplate'].update({
            'Version': args.get('launchTemplateVersion')
        })
    if args.get('tags') is not None:
        kwargs.update({
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': parse_tag_field(args.get('tags'))}]
        })

    response = client.run_instances(**kwargs)
    data = []
    for i, instance in enumerate(response['Instances']):
        data.append({
            'InstanceId': instance['InstanceId'],
            'ImageId': instance['ImageId'],
            'State': instance['State']['Name'],
            'PublicIPAddress': instance.get('PublicIpAddress'),
            'Region': obj['_user_provided_options']['region_name'],
            'Type': instance['InstanceType'],
            'LaunchDate': datetime.datetime.strftime(instance['LaunchTime'], '%Y-%m-%dT%H:%M:%SZ'),
            'PublicDNSName': instance['PublicDnsName'],
            'KeyName': instance['KeyName'],
            'Monitoring': instance['Monitoring']['State'],
        })
        if 'Tags' in instance:
            for tag in instance['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
    output = json.dumps(response['Instances'], cls=DatetimeEncoder)
    raw = json.loads(output)
    raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Instances': raw}
    human_readable = tableToMarkdown('AWS Instances', data)
    return_outputs(human_readable, ec)


def waiter_instance_running(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_running')
    waiter.wait(**kwargs)
    demisto.results("success")


def waiter_instance_status_ok(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_status_ok')
    waiter.wait(**kwargs)
    demisto.results("success")


def waiter_instance_stopped(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_stopped')
    waiter.wait(**kwargs)
    demisto.results("success")


def waiter_instance_terminated(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_terminated')
    waiter.wait(**kwargs)
    demisto.results("success")


def waiter_image_available(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('imageIds') is not None:
        kwargs.update({'ImageIds': parse_resource_ids(args.get('imageIds'))})
    if args.get('executableUsers') is not None:
        kwargs.update({'ExecutableUsers': parse_resource_ids(args.get('executableUsers'))})
    if args.get('owners') is not None:
        kwargs.update({'Owners': parse_resource_ids(args.get('owners'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('image_available')
    waiter.wait(**kwargs)
    demisto.results("success")


def waiter_snapshot_completed(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('ownerIds') is not None:
        kwargs.update({'OwnerIds': parse_resource_ids(args.get('ownerIds'))})
    if args.get('restorableByUserIds') is not None:
        kwargs.update({'RestorableByUserIds': parse_resource_ids(args.get('restorableByUserIds'))})
    if args.get('snapshotIds') is not None:
        kwargs.update({'SnapshotIds': parse_resource_ids(args.get('snapshotIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': int(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': int(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(**kwargs)
    demisto.results("success")


def get_latest_ami(args):
    client = aws_session(
        service='ec2',
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('imageIds') is not None:
        kwargs.update({'ImageIds': parse_resource_ids(args.get('imageIds'))})
    if args.get('owners') is not None:
        kwargs.update({'Owners': parse_resource_ids(args.get('owners'))})
    if args.get('executableUsers') is not None:
        kwargs.update({'ExecutableUsers': parse_resource_ids(args.get('executableUsers'))})
    response = client.describe_images(**kwargs)
    amis = sorted(response['Images'],
                  key=lambda x: x['CreationDate'],
                  reverse=True)
    image = amis[0]
    data = ({
        'CreationDate': image['CreationDate'],
        'ImageId': image['ImageId'],
        'Public': image['Public'],
        'Name': image['Name'],
        'State': image['State'],
        'Region': obj['_user_provided_options']['region_name'],
    })
    if 'Description' in image:
        data.update({'Description': image['Description']})
    if 'Tags' in image:
        for tag in image['Tags']:
            data.update({
                tag['Key']: tag['Value']
            })

    raw = json.loads(json.dumps(image, cls=DatetimeEncoder))
    raw.update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.EC2.Images': image}
    human_readable = tableToMarkdown('AWS EC2 Images', data)
    return_outputs(human_readable, ec)


def create_security_group(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'GroupName': args.get('groupName'),
        'Description': args.get('description'),
        'VpcId': args.get('vpcId'),
    }
    response = client.create_security_group(**kwargs)
    data = ({
        'GroupName': args.get('groupName'),
        'Description': args.get('description'),
        'VpcId': args.get('vpcId'),
        'GroupId': response['GroupId']
    })
    ec = {'AWS.EC2.SecurityGroups': data}
    human_readable = tableToMarkdown('AWS EC2 Security Groups', data)
    return_outputs(human_readable, ec)


def delete_security_group(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {}
    if args.get('groupId') is not None:
        kwargs.update({'GroupId': args.get('groupId')})
    if args.get('groupName') is not None:
        kwargs.update({'GroupName': args.get('groupName')})

    response = client.delete_security_group(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Security Group was Deleted")


def authorize_security_group_ingress(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'GroupId': args.get('groupId')}

    if args.get('fromPort') is not None:
        kwargs.update({'FromPort': int(args.get('fromPort'))})
    if args.get('cidrIp') is not None:
        kwargs.update({'CidrIp': args.get('cidrIp')})
    if args.get('toPort') is not None:
        kwargs.update({'ToPort': int(args.get('toPort'))})
    if args.get('ipProtocol') is not None:
        kwargs.update({'IpProtocol': args.get('ipProtocol')})
    if args.get('sourceSecurityGroupName') is not None:
        kwargs.update({'SourceSecurityGroupName': args.get('sourceSecurityGroupName')})

    response = client.authorize_security_group_ingress(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Security Group ingress rule was created")


def revoke_security_group_ingress(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'GroupId': args.get('groupId')}

    if args.get('fromPort') is not None:
        kwargs.update({'FromPort': int(args.get('fromPort'))})
    if args.get('cidrIp') is not None:
        kwargs.update({'CidrIp': args.get('cidrIp')})
    if args.get('toPort') is not None:
        kwargs.update({'ToPort': int(args.get('toPort'))})
    if args.get('ipProtocol') is not None:
        kwargs.update({'IpProtocol': args.get('ipProtocol')})
    if args.get('sourceSecurityGroupName') is not None:
        kwargs.update({'SourceSecurityGroupName': args.get('sourceSecurityGroupName')})

    response = client.revoke_security_group_ingress(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Security Group ingress rule was revoked")


def copy_image(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
        'SourceImageId': args.get('sourceImageId'),
        'SourceRegion': args.get('sourceRegion'),
    }
    if args.get('clientToken') is not None:
        kwargs.update({'ClientToken': args.get('clientToken')})
    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('encrypted') is not None:
        kwargs.update({'Encrypted': True if args.get('ebsEncrypted') == 'True' else False})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.copy_image(**kwargs)
    data = ({
        'ImageId': response['ImageId'],
        'Region': obj['_user_provided_options']['region_name']
    })

    ec = {'AWS.EC2.Images(val.ImageId === obj.ImageId)': data}
    human_readable = tableToMarkdown('AWS EC2 Images', data)
    return_outputs(human_readable, ec)


def copy_snapshot(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {
        'SourceSnapshotId': args.get('sourceSnapshotId'),
        'SourceRegion': args.get('sourceRegion'),
    }
    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('encrypted') is not None:
        kwargs.update({'Encrypted': True if args.get('ebsEncrypted') == 'True' else False})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.copy_snapshot(**kwargs)
    data = ({
        'SnapshotId': response['SnapshotId'],
        'Region': obj['_user_provided_options']['region_name']
    })

    ec = {'AWS.EC2.Snapshots(val.SnapshotId === obj.SnapshotId)': data}
    human_readable = tableToMarkdown('AWS EC2 Snapshots', data)
    return_outputs(human_readable, ec)


def describe_reserved_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {}
    data = []
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('offeringClass') is not None:
        kwargs.update({'OfferingClass': args.get('offeringClass')})
    if args.get('reservedInstancesIds') is not None:
        kwargs.update({'ReservedInstancesIds': parse_resource_ids(args.get('reservedInstancesIds'))})

    response = client.describe_reserved_instances(**kwargs)
    for i, reservation in enumerate(response['ReservedInstances']):
        data.append({
            'ReservedInstancesId': reservation['ReservedInstancesId'],
            'Start': datetime.datetime.strftime(reservation['Start'], '%Y-%m-%dT%H:%M:%SZ'),
            'End': datetime.datetime.strftime(reservation['End'], '%Y-%m-%dT%H:%M:%SZ'),
            'Duration': reservation['Duration'],
            'InstanceType': reservation['InstanceType'],
            'InstanceCount': reservation['InstanceCount'],
            'OfferingClass': reservation['OfferingClass'],
            'Scope': reservation['Scope'],
            'State': reservation['State']
        })
        if 'Tags' in reservation:
            for tag in reservation['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
        reservation.update({'Region': obj['_user_provided_options']['region_name']})
        output.append(reservation)

    raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    ec = {'AWS.EC2.ReservedInstances(val.ReservedInstancesId === obj.ReservedInstancesId)': raw}
    human_readable = tableToMarkdown('AWS EC2 Reserved Instances', data)
    return_outputs(human_readable, ec)


def monitor_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.monitor_instances(InstanceIds=parse_resource_ids(args.get('instancesIds')))

    for instance in response['InstanceMonitorings']:
        data.append({
            'InstanceId': instance['InstanceId'],
            'MonitoringState': instance['Monitoring']['State']
        })

    ec = {'AWS.EC2.Instances(val.InstancesId === obj.InstancesId)': response['InstanceMonitorings']}
    human_readable = tableToMarkdown('AWS EC2 Instances', data)
    return_outputs(human_readable, ec)


def unmonitor_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.unmonitor_instances(InstanceIds=parse_resource_ids(args.get('instancesIds')))

    for instance in response['InstanceMonitorings']:
        data.append({
            'InstanceId': instance['InstanceId'],
            'MonitoringState': instance['Monitoring']['State']
        })

    ec = {'AWS.EC2.Instances(val.InstancesId === obj.InstancesId)': response['InstanceMonitorings']}
    human_readable = tableToMarkdown('AWS EC2 Instances', data)
    return_outputs(human_readable, ec)


def reboot_instances(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.reboot_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instances were rebooted")


def get_password_data(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.get_password_data(InstanceId=args.get('instanceId'))
    data = {
        'InstanceId': response['InstanceId'],
        'PasswordData': response['PasswordData'],
        'Timestamp': datetime.datetime.strftime(response['Timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    }

    ec = {'AWS.EC2.Instances(val.InstancesId === obj.InstancesId).PasswordData': data}
    human_readable = tableToMarkdown('AWS EC2 Instances', data)
    return_outputs(human_readable, ec)


def modify_network_interface_attribute(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'NetworkInterfaceId': args.get('networkInterfaceId')}

    if args.get('sourceDestCheck') is not None:
        kwargs.update({'SourceDestCheck': {'Value': True if args.get('sourceDestCheck') == 'True' else False}})
    if args.get('attachmentId') is not None and args.get('deleteOnTermination') is not None:
        kwargs.update({
            'Attachment': {
                'AttachmentId': args.get('attachmentId'),
                'DeleteOnTermination': True if args.get('deleteOnTermination') == 'True' else False
            }})
    if args.get('description') is not None:
        kwargs.update({'Description': {'Value': args.get('description')}})
    if args.get('groups') is not None:
        kwargs.update({'Groups': parse_resource_ids(args.get('groups'))})

    response = client.modify_network_interface_attribute(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Network Interface Aattribute was successfully modified")


def modify_instance_attribute(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'InstanceId': args.get('instanceId')}

    if args.get('sourceDestCheck') is not None:
        kwargs.update({'SourceDestCheck': {'Value': True if args.get('sourceDestCheck') == 'True' else False}})
    if args.get('disableApiTermination') is not None:
        kwargs.update(
            {'DisableApiTermination': {'Value': True if args.get('disableApiTermination') == 'True' else False}})
    if args.get('ebsOptimized') is not None:
        kwargs.update({'EbsOptimized': {'Value': True if args.get('ebsOptimized') == 'True' else False}})
    if args.get('enaSupport') is not None:
        kwargs.update({'EnaSupport': {'Value': True if args.get('enaSupport') == 'True' else False}})
    if args.get('instanceType') is not None:
        kwargs.update({'InstanceType': {'Value': args.get('instanceType')}})
    if args.get('instanceInitiatedShutdownBehavior') is not None:
        kwargs.update(
            {'InstanceInitiatedShutdownBehavior': {'Value': args.get('instanceInitiatedShutdownBehavior')}})
    if args.get('groups') is not None:
        kwargs.update({'Groups': parse_resource_ids(args.get('groups'))})

    response = client.modify_instance_attribute(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instance attribute was successfully modified")


def create_network_acl(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {'VpcId': args.get('VpcId')}

    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': True if args.get('DryRun') == 'True' else False})

    response = client.create_network_acl(**kwargs)
    network_acl = response['NetworkAcl']

    data = {
        'Associations': network_acl['Associations'],
        'IsDefault': network_acl['IsDefault'],
        'NetworkAclId': network_acl['NetworkAclId'],
        'Tags': network_acl['Tags'],
        'VpcId': network_acl['VpcId']
    }
    entries = []
    for entry in network_acl['Entries']:
        entries.append(entry)
    hr_entries = tableToMarkdown('AWS EC2 ACL Entries', entries, removeNull=True)
    ec = {'AWS.EC2.VpcId(val.VpcId === obj.VpcId).NetworkAcl': network_acl}
    hr_acl = tableToMarkdown('AWS EC2 Instance ACL', data, removeNull=True)
    human_readable = hr_acl + hr_entries
    return_outputs(human_readable, ec)


def create_network_acl_entry(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'Egress': True if args.get('Egress') == 'True' else False,
        'NetworkAclId': args.get('NetworkAclId'),
        'Protocol': args.get('Protocol'),
        'RuleAction': args.get('RuleAction'),
        'RuleNumber': int(args.get('RuleNumber'))
    }

    if args.get('CidrBlock') is not None:
        kwargs.update({'CidrBlock': args.get('CidrBlock')})
    if args.get('Code') is not None:
        kwargs.update({'IcmpTypeCode': {'Code': int(args.get('Code'))}})
    if args.get('Type') is not None:
        kwargs.update({'IcmpTypeCode': {'Type': int(args.get('Type'))}})
    if args.get('Ipv6CidrBlock') is not None:
        kwargs.update({'Ipv6CidrBlock': args.get('Ipv6CidrBlock')})
    if args.get('From') is not None:
        kwargs.update({'PortRange': {'From': int(args.get('From'))}})
    if args.get('To') is not None:
        kwargs.update({'PortRange': {'To': int(args.get('To'))}})
    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': True if args.get('DryRun') == 'True' else False})

    response = client.create_network_acl_entry(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Instance ACL was successfully modified")


"""COMMAND BLOCK"""
try:
    LOG('Command being called is {}'.format(demisto.command()))
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        client = aws_session()
        response = client.describe_regions()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')

    elif demisto.command() == 'aws-ec2-describe-regions':
        describe_regions(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-instances':
        describe_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-images':
        describe_images(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-addresses':
        describe_addresses(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-snapshots':
        describe_snapshots(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-volumes':
        describe_volumes(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-launch-templates':
        describe_launch_templates(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-key-pairs':
        describe_key_pairs(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-vpcs':
        describe_vpcs(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-subnets':
        describe_subnets(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-security-groups':
        describe_security_groups(demisto.args())

    elif demisto.command() == 'aws-ec2-allocate-address':
        allocate_address(demisto.args())

    elif demisto.command() == 'aws-ec2-associate-address':
        associate_address(demisto.args())

    elif demisto.command() == 'aws-ec2-create-snapshot':
        create_snapshot(demisto.args())

    elif demisto.command() == 'aws-ec2-delete-snapshot':
        delete_snapshot(demisto.args())

    elif demisto.command() == 'aws-ec2-create-image':
        create_image(demisto.args())

    elif demisto.command() == 'aws-ec2-deregister-image':
        deregister_image(demisto.args())

    elif demisto.command() == 'aws-ec2-modify-volume':
        modify_volume(demisto.args())

    elif demisto.command() == 'aws-ec2-create-tags':
        create_tags(demisto.args())

    elif demisto.command() == 'aws-ec2-disassociate-address':
        disassociate_address(demisto.args())

    elif demisto.command() == 'aws-ec2-release-address':
        release_address(demisto.args())

    elif demisto.command() == 'aws-ec2-start-instances':
        start_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-stop-instances':
        stop_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-terminate-instances':
        terminate_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-create-volume':
        create_volume(demisto.args())

    elif demisto.command() == 'aws-ec2-attach-volume':
        attach_volume(demisto.args())

    elif demisto.command() == 'aws-ec2-detach-volume':
        detach_volume(demisto.args())

    elif demisto.command() == 'aws-ec2-delete-volume':
        delete_volume(demisto.args())

    elif demisto.command() == 'aws-ec2-run-instances':
        run_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-instance-running':
        waiter_instance_running(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-instance-status-ok':
        waiter_instance_status_ok(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-instance-stopped':
        waiter_instance_stopped(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-instance-terminated':
        waiter_instance_terminated(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-instance-terminated':
        waiter_instance_terminated(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-image-available':
        waiter_image_available(demisto.args())

    elif demisto.command() == 'aws-ec2-waiter-snapshot_completed':
        waiter_snapshot_completed(demisto.args())

    elif demisto.command() == 'aws-ec2-get-latest-ami':
        get_latest_ami(demisto.args())

    elif demisto.command() == 'aws-ec2-create-security-group':
        create_security_group(demisto.args())

    elif demisto.command() == 'aws-ec2-delete-security-group':
        delete_security_group(demisto.args())

    elif demisto.command() == 'aws-ec2-authorize-security-group-ingress-rule':
        authorize_security_group_ingress(demisto.args())

    elif demisto.command() == 'aws-ec2-revoke-security-group-ingress-rule':
        revoke_security_group_ingress(demisto.args())

    elif demisto.command() == 'aws-ec2-copy-image':
        copy_image(demisto.args())

    elif demisto.command() == 'aws-ec2-copy-snapshot':
        copy_snapshot(demisto.args())

    elif demisto.command() == 'aws-ec2-describe-reserved-instances':
        describe_reserved_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-monitor-instances':
        monitor_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-unmonitor-instances':
        unmonitor_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-reboot-instances':
        reboot_instances(demisto.args())

    elif demisto.command() == 'aws-ec2-get-password-data':
        get_password_data(demisto.args())

    elif demisto.command() == 'aws-ec2-modify-network-interface-attribute':
        modify_network_interface_attribute(demisto.args())

    elif demisto.command() == 'aws-ec2-modify-instance-attribute':
        modify_instance_attribute(demisto.args())

    elif demisto.command() == 'aws-ec2-create-network-acl':
        create_network_acl(demisto.args())

    elif demisto.command() == 'aws-ec2-create-network-acl-entry':
        create_network_acl_entry(demisto.args())
except Exception as e:
    return_error('Error has occurred in the AWS EC2 Integration: {}\n {}'.format(type(e), e.message))
