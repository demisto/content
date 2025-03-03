import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date
from AWSApiModule import *  # noqa: E402
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

"""CONSTANTS"""

PARAMS = demisto.params()
MAX_WORKERS = arg_to_number(PARAMS.get('max_workers'))
ROLE_NAME: str = PARAMS.get('access_role_name', '')
IS_ARN_PROVIDED = bool(demisto.getArg('roleArn'))

"""HELPER FUNCTIONS"""


def parse_filter_field(filter_str):
    filters = []
    regex = re.compile(r'name=([\w\d_:.-]+),values=([ /\w\d@_,.*-:]+)', flags=re.I)
    for f in filter_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.debug(f'could not parse filter: {f}')
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
            demisto.debug(f'could not parse field: {f}')
            continue

        tags.append({
            'Key': match.group(1),
            'Value': match.group(2)
        })

    return tags


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
    resourceIds = id_list.split(",")
    return resourceIds


def multi_split(data):
    data = data.replace(" ", "")
    data = data.split(";")
    return data


def parse_date(dt):
    try:
        arr = dt.split("-")
        parsed_date = (datetime(int(arr[0]), int(arr[1]), int(arr[2]))).isoformat()
    except ValueError as e:
        raise DemistoException(f"Date could not be parsed. Please check the date again.\n{e}")
    return parsed_date


def build_client(args: dict):
    aws_default_region = PARAMS.get('defaultRegion')
    aws_role_arn = PARAMS.get('roleArn')
    aws_role_session_name = PARAMS.get('roleSessionName')
    aws_role_session_duration = PARAMS.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = PARAMS.get('credentials', {}).get('identifier') or PARAMS.get('access_key')
    aws_secret_access_key = PARAMS.get('credentials', {}).get('password') or PARAMS.get('secret_key')
    verify_certificate = not PARAMS.get('insecure', True)
    timeout = PARAMS.get('timeout')
    retries = PARAMS.get('retries') or 5
    sts_endpoint_url = PARAMS.get('sts_endpoint_url') or None
    endpoint_url = PARAMS.get('endpoint_url') or None

    validate_params(
        aws_default_region, aws_role_arn, aws_role_session_name,
        aws_access_key_id, aws_secret_access_key
    )

    return AWSClient(
        aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
        aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
        retries, sts_endpoint_url=sts_endpoint_url, endpoint_url=endpoint_url
    ).aws_session(
        service='ec2',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )


def run_on_all_accounts(func: Callable[[dict], CommandResults]):
    """Decorator that runs the given command function on all AWS accounts configured in the params.

    Args:
        func (callable): The command function to run on each account.
            Must accept the args dict and an AWSClient as arguments.
            Must return a CommandResults object.

    Returns:
        callable: If a role name is configured in the params, returns a function
        that handles running on all accounts.
        If no role exists, returns the passed in func unchanged.

    This decorator handles setting up the proper roleArn, roleSessionName,
    roleSessionDuration for accessing each account before calling the function
    and adds the account details to the result.
    """

    def account_runner(args: dict) -> list[CommandResults]:

        role_name = ROLE_NAME.removeprefix('role/')
        accounts = argToList(PARAMS.get('accounts_to_access'))

        def run_command(account_id: str) -> CommandResults:
            new_args = args | {
                #  the role ARN must be of the format: arn:aws:iam::<account_id>:role/<role_name>
                'roleArn': f'arn:aws:iam::{account_id}:role/{role_name}',
                'roleSessionName': args.get('roleSessionName', f'account_{account_id}'),
                'roleSessionDuration': args.get('roleSessionDuration', 900),
            }
            try:
                result = func(new_args)
                result.readable_output = f'#### Result for account `{account_id}`:\n{result.readable_output}'
                if isinstance(result.outputs, list):
                    for obj in result.outputs:
                        obj['AccountId'] = account_id
                elif isinstance(result.outputs, dict):
                    result.outputs['AccountId'] = account_id
                return result
            except Exception as e:  # catch any errors raised from "func" to be tagged with the account ID and displayed
                return CommandResults(
                    readable_output=f'#### Error in command call for account `{account_id}`\n{e}',
                    entry_type=EntryType.ERROR,
                    content_format=EntryFormat.MARKDOWN,
                )

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(run_command, accounts)
        return list(results)

    return account_runner if (ROLE_NAME and not IS_ARN_PROVIDED) else func


"""MAIN FUNCTIONS"""


def test_module() -> str:
    client = build_client({})
    response = client.describe_regions()
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Test Module failed. Response: {response}')
    if ROLE_NAME:
        if not PARAMS.get('accounts_to_access'):
            raise DemistoException("'AWS organization accounts' must not be empty when an access role is provided.")

        def test_account(args: dict) -> CommandResults:
            build_client(args)
            return CommandResults()

        fails = [
            result.readable_output
            for result in run_on_all_accounts(test_account)({})  # type: ignore
            if result.entry_type == EntryType.ERROR
        ]
        if fails:
            demisto.debug('\n\n'.join(fails))
            #  extract the account ID form the readable_output encased in backticks
            fail_ids = ', '.join(res.split('`')[1] for res in fails)
            raise DemistoException(
                f'AssumeRole with role name {ROLE_NAME!r} failed for the following accounts: {fail_ids}.'
            )
    return 'ok'


@run_on_all_accounts
def describe_regions_command(args: dict) -> CommandResults:
    client = build_client(args)
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

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.Regions',
        outputs_key_field='RegionName',
        readable_output=tableToMarkdown('AWS Regions', data)
    )


@run_on_all_accounts
def describe_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    data = []
    kwargs = {}
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})

    response = client.describe_instances(**kwargs)

    if len(response['Reservations']) == 0:
        return CommandResults(readable_output='No reservations were found.')

    for i, reservation in enumerate(response['Reservations']):
        for instance in reservation['Instances']:
            try:
                launch_date = datetime.strftime(instance['LaunchTime'], '%Y-%m-%dT%H:%M:%SZ')
            except ValueError as e:
                raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
            data.append({
                'InstanceId': instance['InstanceId'],
                'ImageId': instance['ImageId'],
                'State': instance['State']['Name'],
                'PublicIPAddress': instance.get('PublicIpAddress'),
                'Region': obj['_user_provided_options']['region_name'],
                'Type': instance['InstanceType'],
                'LaunchDate': launch_date,
                'PublicDNSName': instance['PublicDnsName'],
                'Monitoring': instance['Monitoring']['State'],
            })
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    data[i].update({
                        tag['Key']: tag['Value']
                    })
            if 'KeyName' in instance:
                data[i].update({'KeyName': instance['KeyName']})

            instance.update({'Region': obj['_user_provided_options']['region_name']})
            output.append(instance)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Instances',
        outputs_key_field='InstanceId',
        readable_output=tableToMarkdown('AWS Instances', data)
    )


@run_on_all_accounts
def describe_iam_instance_profile_associations_command(args: dict) -> CommandResults:
    client = build_client(args)
    data = []
    kwargs = {}
    output = []
    if (filters := args.get('filters')) is not None:
        kwargs.update({'Filters': parse_filter_field(filters)})
    if (association_ids := args.get('associationIds')) is not None:
        kwargs.update({'AssociationIds': parse_resource_ids(association_ids)})
    if (max_results := args.get('maxResults')) is not None:
        kwargs.update({'MaxResults': max_results})
    if (next_token := args.get('nextToken')) is not None:
        kwargs.update({'NextToken': next_token})

    response = client.describe_iam_instance_profile_associations(**kwargs)

    if len(response['IamInstanceProfileAssociations']) == 0:
        return CommandResults(readable_output='No instance profile associations were found.')

    for _i, association in enumerate(response['IamInstanceProfileAssociations']):
        data.append({
            'InstanceId': association['InstanceId'],
            'State': association['State'],
            'AssociationId': association['AssociationId'],
            'IamInstanceProfile': association['IamInstanceProfile'],
        })
        output.append(association)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.IamInstanceProfileAssociations',
        outputs_key_field='AssociationId',
        readable_output=tableToMarkdown('AWS IAM Instance Profile Associations', data)
    )


@run_on_all_accounts
def describe_images_command(args: dict) -> CommandResults:
    client = build_client(args)
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

    if len(response['Images']) == 0:
        return CommandResults(readable_output='No images were found.')

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
    try:
        output = json.dumps(response['Images'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Images',
        outputs_key_field='ImageId',
        readable_output=tableToMarkdown('AWS EC2 Images', data)
    )


@run_on_all_accounts
def describe_addresses_command(args: dict) -> CommandResults:
    client = build_client(args)

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

    if len(response['Addresses']) == 0:
        return CommandResults(readable_output='No addresses were found.')

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

    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.ElasticIPs',
        outputs_key_field='AllocationId',
        readable_output=tableToMarkdown('AWS EC2 ElasticIPs', data)
    )


@run_on_all_accounts
def describe_snapshots_command(args: dict) -> CommandResults:
    client = build_client(args)

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

    if len(response['Snapshots']) == 0:
        return CommandResults(readable_output='No snapshots were found.')
    for i, snapshot in enumerate(response['Snapshots']):
        try:
            start_time = datetime.strftime(snapshot['StartTime'], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as e:
            raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
        data.append({
            'Description': snapshot['Description'],
            'Encrypted': snapshot['Encrypted'],
            'OwnerId': snapshot['OwnerId'],
            'Progress': snapshot['Progress'],
            'SnapshotId': snapshot['SnapshotId'],
            'StartTime': start_time,
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

    try:
        output = json.dumps(response['Snapshots'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Snapshots',
        outputs_key_field='SnapshotId',
        readable_output=tableToMarkdown('AWS EC2 Snapshots', data)
    )


@run_on_all_accounts
def describe_volumes_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('volumeIds') is not None:
        kwargs.update({'VolumeIds': parse_resource_ids(args.get('volumeIds'))})

    response = client.describe_volumes(**kwargs)

    if len(response['Volumes']) == 0:
        return CommandResults(readable_output='No EC2 volumes were found.')
    for i, volume in enumerate(response['Volumes']):
        try:
            create_date = datetime.strftime(volume['CreateTime'], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as e:
            raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
        data.append({
            'AvailabilityZone': volume['AvailabilityZone'],
            'Encrypted': volume['Encrypted'],
            'State': volume['State'],
            'VolumeId': volume['VolumeId'],
            'VolumeType': volume['VolumeType'],
            'CreateTime': create_date,
        })
        if 'Tags' in volume:
            for tag in volume['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
    try:
        output = json.dumps(response['Volumes'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Volumes',
        outputs_key_field='VolumeId',
        readable_output=tableToMarkdown('AWS EC2 Volumes', data)
    )


@run_on_all_accounts
def describe_launch_templates_command(args: dict) -> CommandResults:
    client = build_client(args)

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

    if len(response['LaunchTemplates']) == 0:
        return CommandResults(readable_output='No launch templates were found.')
    for i, template in enumerate(response['LaunchTemplates']):
        try:
            create_time = datetime.strftime(template['CreateTime'], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as e:
            raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
        data.append({
            'LaunchTemplateId': template['LaunchTemplateId'],
            'LaunchTemplateName': template['LaunchTemplateName'],
            'CreatedBy': template['CreatedBy'],
            'DefaultVersionNumber': template['DefaultVersionNumber'],
            'LatestVersionNumber': template['LatestVersionNumber'],
            'CreateTime': create_time,
            'Region': obj['_user_provided_options']['region_name'],
        })

        if 'Tags' in template:
            for tag in template['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })

    try:
        output = json.dumps(response['LaunchTemplates'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.LaunchTemplates',
        outputs_key_field='LaunchTemplateId',
        readable_output=tableToMarkdown('AWS EC2 LaunchTemplates', data)
    )


@run_on_all_accounts
def describe_key_pairs_command(args: dict) -> CommandResults:
    client = build_client(args)

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

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.KeyPairs',
        outputs_key_field='KeyName',
        readable_output=tableToMarkdown('AWS EC2 Key Pairs', data)
    )


@run_on_all_accounts
def describe_vpcs_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('vpcIds') is not None:
        kwargs.update({'VpcIds': parse_resource_ids(args.get('vpcIds'))})

    response = client.describe_vpcs(**kwargs)

    if len(response['Vpcs']) == 0:
        return CommandResults(readable_output='No VPCs were found.')
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

    try:
        output = json.dumps(response['Vpcs'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as e:
        raise DemistoException(f'Could not decode/encode the raw response - {e}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Vpcs',
        outputs_key_field='VpcId',
        readable_output=tableToMarkdown('AWS EC2 Vpcs', data)
    )


@run_on_all_accounts
def describe_subnets_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)
    kwargs = {}
    data = []

    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('subnetIds') is not None:
        kwargs.update({'SubnetIds': parse_resource_ids(args.get('subnetIds'))})

    response = client.describe_subnets(**kwargs)

    if len(response['Subnets']) == 0:
        return CommandResults(readable_output='No Subnets were found.')
    for i, subnet in enumerate(response['Subnets']):
        data.append({
            'AvailabilityZone': subnet['AvailabilityZone'],
            'AvailableIpAddressCount': subnet['AvailableIpAddressCount'],
            'CidrBlock': subnet.get('CidrBlock', ""),
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

    try:
        output = json.dumps(response['Subnets'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Subnets',
        outputs_key_field='SubnetId',
        readable_output=tableToMarkdown('AWS EC2 Subnets', data)
    )


@run_on_all_accounts
def describe_security_groups_command(args: dict) -> CommandResults:
    client = build_client(args)

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

    if len(response['SecurityGroups']) == 0:
        return CommandResults(readable_output='No security groups were found.')
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

    try:
        output = json.dumps(response['SecurityGroups'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.SecurityGroups',
        outputs_key_field='GroupId',
        readable_output=tableToMarkdown('AWS EC2 SecurityGroups', data)
    )


@run_on_all_accounts
def allocate_address_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)

    response = client.allocate_address(Domain='vpc')
    data = ({
        'PublicIp': response['PublicIp'],
        'AllocationId': response['AllocationId'],
        'Domain': response['Domain'],
        'Region': obj['_user_provided_options']['region_name']
    })
    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.ElasticIPs',
        readable_output=tableToMarkdown('AWS EC2 ElasticIP', data)
    )


@run_on_all_accounts
def associate_address_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)
    kwargs = {'AllocationId': args.get('allocationId')}

    if args.get('instanceId') is not None:
        kwargs.update({'InstanceId': args.get('instanceId')})
    if args.get('allowReassociation') is not None:
        kwargs.update({'AllowReassociation': argToBoolean(args.get('allowReassociation'))})
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

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.ElasticIPs',
        outputs_key_field='AllocationId',
        readable_output=tableToMarkdown('AWS EC2 ElasticIP', data)
    )


@run_on_all_accounts
def create_snapshot_command(args: dict) -> CommandResults:
    client = build_client(args)
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

    try:
        start_time = datetime.strftime(response['StartTime'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')

    data = ({
        'Description': response['Description'],
        'Encrypted': response['Encrypted'],
        'Progress': response['Progress'],
        'SnapshotId': response['SnapshotId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
        'VolumeSize': response['VolumeSize'],
        'StartTime': start_time,
        'Region': obj['_user_provided_options']['region_name'],
    })

    if 'Tags' in response:
        for tag in response['Tags']:
            data.update({
                tag['Key']: tag['Value']
            })

    try:
        output = json.dumps(response, cls=DatetimeEncoder)
        raw = json.loads(output)
        del raw['ResponseMetadata']
        raw.update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Snapshots',
        readable_output=tableToMarkdown('AWS EC2 Snapshots', data)
    )


@run_on_all_accounts
def delete_snapshot_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.delete_snapshot(SnapshotId=args.get('snapshotId'))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(
        readable_output="The Snapshot with ID: {snapshot_id} was deleted".format(snapshot_id=args.get('snapshotId'))
    )


@run_on_all_accounts
def create_image_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {
        'Name': args.get('name'),
        'InstanceId': args.get('instanceId')
    }

    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('noReboot') is not None:
        kwargs.update({'NoReboot': argToBoolean(args.get('noReboot'))})

    response = client.create_image(**kwargs)

    data = ({
        'ImageId': response['ImageId'],
        'Name': args.get('name'),
        'InstanceId': args.get('instanceId'),
        'Region': obj['_user_provided_options']['region_name'],
    })

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.Images',
        readable_output=tableToMarkdown('AWS EC2 Images', data)
    )


@run_on_all_accounts
def deregister_image_command(args: dict) -> CommandResults:
    client = build_client(args)

    response = client.deregister_image(ImageId=args.get('imageId'))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The AMI with ID: {image_id} was deregistered".format(image_id=args.get('imageId')))


@run_on_all_accounts
def modify_volume_command(args: dict) -> CommandResults:
    client = build_client(args)

    obj = vars(client._client_config)
    kwargs = {'VolumeId': args.get('volumeId')}

    if args.get('size') is not None:
        kwargs.update({'Size': arg_to_number(args.get('size'))})
    if args.get('volumeType') is not None:
        kwargs.update({'VolumeType': args.get('volumeType')})
    if args.get('iops') is not None:
        kwargs.update({'Iops': arg_to_number(args.get('iops'))})

    response = client.modify_volume(**kwargs)
    volumeModification = response['VolumeModification']

    try:
        start_time = datetime.strftime(volumeModification['StartTime'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')

    data = ({
        'VolumeId': volumeModification['VolumeId'],
        'ModificationState': volumeModification['ModificationState'],
        'TargetSize': volumeModification['TargetSize'],
        'TargetIops': volumeModification['TargetIops'],
        'TargetVolumeType': volumeModification['TargetVolumeType'],
        'OriginalSize': volumeModification['OriginalSize'],
        'OriginalIops': volumeModification['OriginalIops'],
        'OriginalVolumeType': volumeModification['OriginalVolumeType'],
        'StartTime': start_time,
        'Progress': volumeModification['Progress'],
        'Region': obj['_user_provided_options']['region_name'],
    })

    output = json.dumps(volumeModification, cls=DatetimeEncoder)
    raw = json.loads(output)
    raw.update({'Region': obj['_user_provided_options']['region_name']})

    return CommandResults(
        outputs={
            'Modification': raw,
            'VolumeId': raw['VolumeId']
        },
        outputs_prefix='AWS.EC2.Volumes',
        outputs_key_field='VolumeId',
        readable_output=tableToMarkdown('AWS EC2 Volume Modification', data)
    )


@run_on_all_accounts
def create_tags_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {
        'Resources': parse_resource_ids(args.get('resources')),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.create_tags(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The recources where taged successfully")


@run_on_all_accounts
def disassociate_address_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.disassociate_address(AssociationId=args.get('associationId'))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Elastic IP was disassociated")


@run_on_all_accounts
def release_address_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.release_address(AllocationId=args.get('allocationId'))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Elastic IP was released")


@run_on_all_accounts
def start_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.start_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instances were started")


@run_on_all_accounts
def stop_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.stop_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instances were stopped")


@run_on_all_accounts
def terminate_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.terminate_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instances were terminated")


@run_on_all_accounts
def create_volume_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {'AvailabilityZone': args.get('availabilityZone')}

    if args.get('encrypted') is not None:
        kwargs.update({'Encrypted': argToBoolean(args.get('encrypted'))})
    if args.get('iops') is not None:
        kwargs.update({'Iops': arg_to_number(args.get('iops'))})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})
    if args.get('size') is not None:
        kwargs.update({'Size': arg_to_number(args.get('size'))})
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

    try:
        create_time = datetime.strftime(response['CreateTime'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')

    data = ({
        'AvailabilityZone': response['AvailabilityZone'],
        'CreateTime': create_time,
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

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.Volumes',
        readable_output=tableToMarkdown('AWS EC2 Volumes', data)
    )


@run_on_all_accounts
def attach_volume_command(args: dict) -> CommandResults:
    client = build_client(args)

    kwargs = {
        'Device': args.get('device'),
        'InstanceId': args.get('instanceId'),
        'VolumeId': args.get('volumeId'),
    }
    response = client.attach_volume(**kwargs)
    try:
        attach_time = datetime.strftime(response['AttachTime'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
    data = ({
        'AttachTime': attach_time,
        'Device': response['Device'],
        'InstanceId': response['InstanceId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
    })
    if 'DeleteOnTermination' in response:
        data.update({'DeleteOnTermination': response['DeleteOnTermination']})

    return CommandResults(
        outputs={
            'Attachments': data,
            'VolumeId': data['VolumeId'],
        },
        outputs_prefix='AWS.EC2.Volumes',
        outputs_key_field='VolumeId',
        readable_output=tableToMarkdown('AWS EC2 Volume Attachments', data)
    )


@run_on_all_accounts
def detach_volume_command(args: dict) -> CommandResults:
    client = build_client(args)

    kwargs = {'VolumeId': args.get('volumeId')}

    if args.get('force') is not None:
        kwargs.update({'Force': argToBoolean(args.get('force'))})
    if args.get('device') is not None:
        kwargs.update({'Device': arg_to_number(args.get('device'))})
    if args.get('instanceId') is not None:
        kwargs.update({'InstanceId': args.get('instanceId')})

    response = client.detach_volume(**kwargs)
    try:
        attach_time = datetime.strftime(response['AttachTime'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
    data = ({
        'AttachTime': attach_time,
        'Device': response['Device'],
        'InstanceId': response['InstanceId'],
        'State': response['State'],
        'VolumeId': response['VolumeId'],
    })
    if 'DeleteOnTermination' in response:
        data.update({'DeleteOnTermination': response['DeleteOnTermination']})

    return CommandResults(
        outputs={
            'Attachments': data,
            'VolumeId': data['VolumeId'],
        },
        outputs_prefix='AWS.EC2.Volumes',
        outputs_key_field='VolumeId',
        readable_output=tableToMarkdown('AWS EC2 Volume Attachments', data)
    )


@run_on_all_accounts
def delete_volume_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.delete_volume(VolumeId=args.get('volumeId'))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Volume was deleted")


@run_on_all_accounts
def run_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {
        'MinCount': arg_to_number(args.get('count')),
        'MaxCount': arg_to_number(args.get('count'))
    }  # type: dict
    BlockDeviceMappings = {}  # type: dict
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
        kwargs.update({'EbsOptimized': argToBoolean(args.get('ebsOptimized'))})
    if args.get('disableApiTermination') is not None:
        kwargs.update({'DisableApiTermination': argToBoolean(args.get('disableApiTermination'))})
    if args.get('deviceName') is not None:
        BlockDeviceMappings = {'DeviceName': args.get('deviceName')}
        BlockDeviceMappings.update({'Ebs': {}})
    if args.get('ebsVolumeSize') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeSize': arg_to_number(args.get('ebsVolumeSize'))})
    if args.get('ebsVolumeType') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeType': args.get('ebsVolumeType')})
    if args.get('ebsIops') is not None:
        BlockDeviceMappings['Ebs'].update({'Iops': arg_to_number(args.get('ebsIops'))})
    if args.get('ebsDeleteOnTermination') is not None:
        BlockDeviceMappings['Ebs'].update(
            {'DeleteOnTermination': argToBoolean(args.get('ebsDeleteOnTermination'))})
    if args.get('ebsKmsKeyId') is not None:
        BlockDeviceMappings['Ebs'].update({'KmsKeyId': args.get('ebsKmsKeyId')})
    if args.get('ebsSnapshotId') is not None:
        BlockDeviceMappings['Ebs'].update({'SnapshotId': args.get('ebsSnapshotId')})
    if args.get('ebsEncrypted') is not None:
        BlockDeviceMappings['Ebs'].update({'Encrypted': argToBoolean(args.get('ebsEncrypted'))})
    if BlockDeviceMappings:
        kwargs.update({'BlockDeviceMappings': [BlockDeviceMappings]})  # type: ignore

    if args.get('iamInstanceProfileArn') is not None:
        kwargs.update({
            'IamInstanceProfile': {
                'Arn': args.get('iamInstanceProfileArn')}
        })
    if args.get('iamInstanceProfileName') is not None:
        kwargs.update({  # type: ignore
            'IamInstanceProfile': {
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
        kwargs['LaunchTemplate'].update({  # type: ignore
            'Version': args.get('launchTemplateVersion')
        })
    if args.get('tags') is not None:
        kwargs.update({
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': parse_tag_field(args.get('tags'))}]
        })
    if args.get('host_id'):
        kwargs.update({'Placement': {
            'HostId': args.get('host_id')
        }})

    response = client.run_instances(**kwargs)
    data = []

    if len(response['Instances']) == 0:
        return CommandResults(readable_output='No instances were found.')
    for i, instance in enumerate(response['Instances']):
        try:
            launch_date = datetime.strftime(instance['LaunchTime'], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as e:
            raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
        data.append({
            'InstanceId': instance['InstanceId'],
            'ImageId': instance['ImageId'],
            'State': instance['State']['Name'],
            'PublicIPAddress': instance.get('PublicIpAddress'),
            'Region': obj['_user_provided_options']['region_name'],
            'Type': instance['InstanceType'],
            'LaunchDate': launch_date,
            'PublicDNSName': instance['PublicDnsName'],
            'KeyName': instance['KeyName'],
            'Monitoring': instance['Monitoring']['State'],
        })
        if 'Tags' in instance:
            for tag in instance['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
    try:
        output = json.dumps(response['Instances'], cls=DatetimeEncoder)
        raw = json.loads(output)
        raw[0].update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Instances',
        outputs_key_field='InstanceId',
        readable_output=tableToMarkdown('AWS Instances', data)
    )


@run_on_all_accounts
def waiter_instance_running_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_running')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="success")


@run_on_all_accounts
def waiter_instance_status_ok_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_status_ok')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="success")


@run_on_all_accounts
def waiter_instance_stopped_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_stopped')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="success")


@run_on_all_accounts
def waiter_instance_terminated_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('instanceIds') is not None:
        kwargs.update({'InstanceIds': parse_resource_ids(args.get('instanceIds'))})
    if args.get('waiterDelay') is not None:
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('instance_terminated')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="success")


@run_on_all_accounts
def waiter_image_available_command(args: dict) -> CommandResults:
    client = build_client(args)
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
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('image_available')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="success")


@run_on_all_accounts
def waiter_snapshot_completed_command(args: dict) -> CommandResults:
    client = build_client(args)
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
        kwargs.update({'WaiterConfig': {'Delay': arg_to_number(args.get('waiterDelay'))}})
    if args.get('waiterMaxAttempts') is not None:
        kwargs.update({'WaiterConfig': {'MaxAttempts': arg_to_number(args.get('waiterMaxAttempts'))}})

    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(**kwargs)
    return CommandResults(readable_output="Success")


@run_on_all_accounts
def get_latest_ami_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {}
    data = {}  # type: dict

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

    try:
        raw = json.loads(json.dumps(image, cls=DatetimeEncoder))
        raw.update({'Region': obj['_user_provided_options']['region_name']})
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=image,
        outputs_prefix='AWS.EC2.Images',
        readable_output=tableToMarkdown('AWS EC2 Images', data)
    )


@run_on_all_accounts
def create_security_group_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {
        'GroupName': args.get('groupName'),
        'Description': args.get('description', ''),
        'VpcId': args.get('vpcId'),
    }
    response = client.create_security_group(**kwargs)
    data = ({
        'GroupName': args.get('groupName'),
        'Description': args.get('description', ''),
        'VpcId': args.get('vpcId'),
        'GroupId': response['GroupId']
    })
    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.SecurityGroups',
        readable_output=tableToMarkdown('AWS EC2 Security Groups', data)
    )


@run_on_all_accounts
def delete_security_group_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('groupId') is not None:
        kwargs.update({'GroupId': args.get('groupId')})
    if args.get('groupName') is not None:
        kwargs.update({'GroupName': args.get('groupName')})

    response = client.delete_security_group(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Security Group was Deleted")


@run_on_all_accounts
def authorize_security_group_ingress_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {'GroupId': args.get('groupId')}
    if IpPermissionsFull := args.get('IpPermissionsFull', None):
        IpPermissions = json.loads(IpPermissionsFull)
    else:
        IpPermissions = []
        UserIdGroupPairs = []
        IpPermissions_dict = create_ip_permissions_dict(args)
        UserIdGroupPairs_dict = create_user_id_group_pairs_dict(args)

        kwargs.update(create_policy_kwargs_dict(args))

        UserIdGroupPairs.append(UserIdGroupPairs_dict)
        IpPermissions_dict.update({'UserIdGroupPairs': UserIdGroupPairs})  # type: ignore

        IpPermissions.append(IpPermissions_dict)
    kwargs.update({'IpPermissions': IpPermissions})

    response = client.authorize_security_group_ingress(**kwargs)
    if not (response['ResponseMetadata']['HTTPStatusCode'] == 200 and response['Return']):
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Security Group ingress rule was created")


@run_on_all_accounts
def authorize_security_group_egress_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {'GroupId': args.get('groupId')}
    if IpPermissionsFull := args.get('IpPermissionsFull', None):
        IpPermissions = json.loads(IpPermissionsFull)
    else:
        IpPermissions = []
        UserIdGroupPairs = []
        IpPermissions_dict = create_ip_permissions_dict(args)
        UserIdGroupPairs_dict = create_user_id_group_pairs_dict(args)

        UserIdGroupPairs.append(UserIdGroupPairs_dict)
        IpPermissions_dict.update({'UserIdGroupPairs': UserIdGroupPairs})  # type: ignore
        IpPermissions.append(IpPermissions_dict)
    kwargs.update({'IpPermissions': IpPermissions})

    response = client.authorize_security_group_egress(**kwargs)
    if not (response['ResponseMetadata']['HTTPStatusCode'] == 200 and response['Return']):
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Security Group egress rule was created")


def create_ip_permissions_dict(args):
    IpPermissions_dict: dict[str, Any] = {}
    UserIdGroupPairs_keys = (('IpPermissionsfromPort', 'FromPort'), ('IpPermissionsToPort', 'ToPort'))
    for args_key, dict_key in UserIdGroupPairs_keys:
        if args.get(args_key) is not None:
            IpPermissions_dict.update({dict_key: int(args.get(args_key))})

    if args.get('IpPermissionsIpProtocol') is not None:
        IpPermissions_dict.update({'IpProtocol': str(args.get('IpPermissionsIpProtocol'))})

    if args.get('IpRangesCidrIp') is not None:
        IpRanges_dict = {'CidrIp': args.get('IpRangesCidrIp')}
        desc = args.get('IpRangesDesc', "") or args.get('IpRangesDescription', "")
        if desc:
            IpRanges_dict['Description'] = desc
        IpPermissions_dict.update({'IpRanges': [IpRanges_dict]})  # type: ignore
    if args.get('Ipv6RangesCidrIp') is not None:
        Ipv6Ranges_dict = {'CidrIp': args.get('Ipv6RangesCidrIp')}
        desc = args.get('Ipv6RangesDesc', "") or args.get('Ipv6RangesDescription', "")
        if desc:
            Ipv6Ranges_dict['Description'] = desc
        IpPermissions_dict.update({'Ipv6Ranges': [Ipv6Ranges_dict]})  # type: ignore
    if args.get('PrefixListId') is not None:
        PrefixListIds_dict = {'PrefixListId': args.get('PrefixListId')}
        desc = args.get('PrefixListIdDesc', "") or args.get('PrefixListIdDescription', "")
        if desc:
            PrefixListIds_dict['Description'] = desc
        IpPermissions_dict.update({'PrefixListIds': [PrefixListIds_dict]})  # type: ignore
    return IpPermissions_dict


def create_policy_kwargs_dict(args):
    policy_kwargs_keys = (('fromPort', 'FromPort'), ('toPort', 'ToPort'))
    policy_kwargs = {}
    for args_key, dict_key in policy_kwargs_keys:
        if key := args.get(args_key):
            policy_kwargs.update({dict_key: arg_to_number(key)})
    policy_kwargs_keys = (('cidrIp', 'CidrIp'), ('ipProtocol', 'IpProtocol'),
                          ('sourceSecurityGroupName', 'SourceSecurityGroupName'),
                          ('SourceSecurityGroupOwnerId', 'SourceSecurityGroupOwnerId'),
                          ('cidrIpv6', 'CidrIpv6'),
                          )
    for args_key, dict_key in policy_kwargs_keys:
        if args.get(args_key) is not None:
            policy_kwargs.update({dict_key: args.get(args_key)})
    return policy_kwargs


def create_user_id_group_pairs_dict(args):
    UserIdGroupPairs_dict = {}
    UserIdGroupPairs_keys = (('UserIdGroupPairsDescription', 'Description'), ('UserIdGroupPairsGroupId', 'GroupId'),
                             ('UserIdGroupPairsGroupName', 'GroupName'), ('UserIdGroupPairsPeeringStatus', 'PeeringStatus'),
                             ('UserIdGroupPairsUserId', 'UserId'), ('UserIdGroupPairsVpcId', 'VpcId'),
                             ('UserIdGroupPairsVpcPeeringConnectionId', 'VpcPeeringConnectionId'))
    for args_key, dict_key in UserIdGroupPairs_keys:
        if args.get(args_key) is not None:
            UserIdGroupPairs_dict.update({dict_key: args.get(args_key)})
    return UserIdGroupPairs_dict


@run_on_all_accounts
def revoke_security_group_ingress_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {'GroupId': args.get('groupId')}
    if IpPermissionsFull := args.get('IpPermissionsFull', None):
        IpPermissions = json.loads(IpPermissionsFull)
        kwargs['IpPermissions'] = IpPermissions
    else:
        kwargs.update(create_policy_kwargs_dict(args))

    response = client.revoke_security_group_ingress(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200 and response['Return']:
        if 'UnknownIpPermissions' in response:
            raise DemistoException("Security Group ingress rule not found.")
        return CommandResults(readable_output="The Security Group ingress rule was revoked")
    else:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')


@run_on_all_accounts
def revoke_security_group_egress_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {
        'GroupId': args.get('groupId')
    }
    if IpPermissionsFull := args.get('IpPermissionsFull'):
        IpPermissions = json.loads(IpPermissionsFull)
        kwargs['IpPermissions'] = IpPermissions
    else:
        IpPermissions_dict = create_ip_permissions_dict(args)
        UserIdGroupPairs_dict = create_user_id_group_pairs_dict(args)

        IpPermissions_dict['UserIdGroupPairs'] = [UserIdGroupPairs_dict]
        kwargs['IpPermissions'] = [IpPermissions_dict]

    response = client.revoke_security_group_egress(**kwargs)
    if not (response['ResponseMetadata']['HTTPStatusCode'] == 200 and response['Return']):
        demisto.debug(response.message)
        raise DemistoException(f"An error has occurred: {response}")
    if 'UnknownIpPermissions' in response:
        raise DemistoException("Security Group egress rule not found.")
    demisto.info(f"the response is: {response}")
    return CommandResults(readable_output="The Security Group egress rule was revoked")


@run_on_all_accounts
def copy_image_command(args: dict) -> CommandResults:
    client = build_client(args)
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
        kwargs.update({'Encrypted': argToBoolean(args.get('ebsEncrypted'))})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.copy_image(**kwargs)
    data = ({
        'ImageId': response['ImageId'],
        'Region': obj['_user_provided_options']['region_name']
    })

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.Images',
        outputs_key_field='ImageId',
        readable_output=tableToMarkdown('AWS EC2 Images', data)
    )


@run_on_all_accounts
def copy_snapshot_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {
        'SourceSnapshotId': args.get('sourceSnapshotId'),
        'SourceRegion': args.get('sourceRegion'),
    }
    if args.get('description') is not None:
        kwargs.update({'Description': args.get('description')})
    if args.get('encrypted') is not None:
        kwargs.update({'Encrypted': argToBoolean(args.get('ebsEncrypted'))})
    if args.get('kmsKeyId') is not None:
        kwargs.update({'KmsKeyId': args.get('kmsKeyId')})

    response = client.copy_snapshot(**kwargs)
    data = ({
        'SnapshotId': response['SnapshotId'],
        'Region': obj['_user_provided_options']['region_name']
    })

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.Snapshots',
        outputs_key_field='SnapshotId',
        readable_output=tableToMarkdown('AWS EC2 Snapshots', data)
    )


@run_on_all_accounts
def describe_reserved_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
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

    if len(response['ReservedInstances']) == 0:
        return CommandResults(readable_output='No reserved instances were found.')

    for i, reservation in enumerate(response['ReservedInstances']):
        try:
            start_time = datetime.strftime(reservation['Start'], '%Y-%m-%dT%H:%M:%SZ')
            end_time = datetime.strftime(reservation['End'], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as e:
            raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
        data.append({
            'ReservedInstancesId': reservation['ReservedInstancesId'],
            'Start': start_time,
            'End': end_time,
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

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.ReservedInstances',
        outputs_key_field='ReservedInstancesId',
        readable_output=tableToMarkdown('AWS EC2 Reserved Instances', data)
    )


@run_on_all_accounts
def monitor_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    data = []
    response = client.monitor_instances(InstanceIds=parse_resource_ids(args.get('instancesIds')))

    for instance in response['InstanceMonitorings']:
        data.append({
            'InstanceId': instance['InstanceId'],
            'MonitoringState': instance['Monitoring']['State']
        })

    return CommandResults(
        outputs=response['InstanceMonitorings'],
        outputs_prefix='AWS.EC2.Instances',
        outputs_key_field='InstanceId',
        readable_output=tableToMarkdown('AWS EC2 Instances', data)
    )


@run_on_all_accounts
def unmonitor_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    data = []
    response = client.unmonitor_instances(InstanceIds=parse_resource_ids(args.get('instancesIds')))

    for instance in response['InstanceMonitorings']:
        data.append({
            'InstanceId': instance['InstanceId'],
            'MonitoringState': instance['Monitoring']['State']
        })

    return CommandResults(
        outputs=response['InstanceMonitorings'],
        outputs_prefix='AWS.EC2.Instances',
        outputs_key_field='InstanceId',
        readable_output=tableToMarkdown('AWS EC2 Instances', data)
    )


@run_on_all_accounts
def reboot_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    response = client.reboot_instances(InstanceIds=parse_resource_ids(args.get('instanceIds')))
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instances were rebooted")


@run_on_all_accounts
def get_password_data_command(args: dict) -> CommandResults:
    client = build_client(args)

    response = client.get_password_data(InstanceId=args.get('instanceId'))
    try:
        time_stamp = datetime.strftime(response['Timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        raise DemistoException(f'Date could not be parsed. Please check the date again.\n{e}')
    data = {
        'InstanceId': response['InstanceId'],
        'PasswordData': response['PasswordData'],
        'Timestamp': time_stamp
    }

    return CommandResults(
        outputs={
            'PasswordData': data,
            'InstanceId': data['InstanceId'],
        },
        outputs_prefix='AWS.EC2.Instances',
        outputs_key_field='InstanceId',
        readable_output=tableToMarkdown('AWS EC2 Instances', data)
    )


@run_on_all_accounts
def modify_network_interface_attribute_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {'NetworkInterfaceId': args.get('networkInterfaceId')}
    if args.get('sourceDestCheck') is not None:
        kwargs.update({'SourceDestCheck': {'Value': argToBoolean(args.get('sourceDestCheck'))}})
    if args.get('attachmentId') is not None and args.get('deleteOnTermination') is not None:
        kwargs.update({
            'Attachment': {
                'AttachmentId': args.get('attachmentId'),
                'DeleteOnTermination': argToBoolean(args.get('deleteOnTermination'))
            }})
    if args.get('description') is not None:
        kwargs.update({'Description': {'Value': args.get('description')}})
    if args.get('groups') is not None:
        kwargs.update({'Groups': parse_resource_ids(args.get('groups'))})

    response = client.modify_network_interface_attribute(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Network Interface Atttribute was successfully modified")


@run_on_all_accounts
def modify_instance_attribute_command(args: dict) -> CommandResults:
    client = build_client(args)

    kwargs = {'InstanceId': args.get('instanceId')}
    if args.get('sourceDestCheck') is not None:
        kwargs.update({'SourceDestCheck': {'Value': argToBoolean(args.get('sourceDestCheck'))}})
    if args.get('disableApiTermination') is not None:
        kwargs.update(
            {'DisableApiTermination': {'Value': argToBoolean(args.get('disableApiTermination'))}})
    if args.get('ebsOptimized') is not None:
        kwargs.update({'EbsOptimized': {'Value': argToBoolean(args.get('ebsOptimized'))}})
    if args.get('enaSupport') is not None:
        kwargs.update({'EnaSupport': {'Value': argToBoolean(args.get('enaSupport'))}})
    if args.get('instanceType') is not None:
        kwargs.update({'InstanceType': {'Value': args.get('instanceType')}})
    if args.get('instanceInitiatedShutdownBehavior') is not None:
        kwargs.update(
            {'InstanceInitiatedShutdownBehavior': {'Value': args.get('instanceInitiatedShutdownBehavior')}})
    if args.get('groups') is not None:
        kwargs.update({'Groups': parse_resource_ids(args.get('groups'))})

    response = client.modify_instance_attribute(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instance attribute was successfully modified")


@run_on_all_accounts
def create_network_acl_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {'VpcId': args.get('VpcId')}

    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': argToBoolean(args.get('DryRun'))})

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
    return CommandResults(
        outputs=network_acl,
        outputs_prefix='AWS.EC2.VpcId.NetworkAcl',
        outputs_key_field='VpcId',
        readable_output=(
            tableToMarkdown('AWS EC2 ACL Entries', entries, removeNull=True)
            + tableToMarkdown('AWS EC2 Instance ACL', data, removeNull=True)
        )
    )


@run_on_all_accounts
def create_network_acl_entry_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {
        'Egress': argToBoolean(args.get('Egress')),
        'NetworkAclId': args.get('NetworkAclId'),
        'Protocol': args.get('Protocol'),
        'RuleAction': args.get('RuleAction'),
        'RuleNumber': arg_to_number(args.get('RuleNumber'))
    }
    if args.get('CidrBlock') is not None:
        kwargs.update({'CidrBlock': args.get('CidrBlock')})
    if args.get('Code') is not None:
        kwargs.update({'IcmpTypeCode': {'Code': arg_to_number(args.get('Code'))}})
    if args.get('Type') is not None:
        kwargs.update({'IcmpTypeCode': {'Type': arg_to_number(args.get('Type'))}})
    if args.get('Ipv6CidrBlock') is not None:
        kwargs.update({'Ipv6CidrBlock': args.get('Ipv6CidrBlock')})
    if args.get('From') is not None:
        kwargs.update({'PortRange': {'From': arg_to_number(args.get('From'))}})
    if args.get('To') is not None:
        kwargs.update({'PortRange': {'To': arg_to_number(args.get('To'))}})
    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': argToBoolean(args.get('DryRun'))})

    response = client.create_network_acl_entry(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The Instance ACL was successfully modified")


@run_on_all_accounts
def create_fleet_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}  # type: dict

    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': argToBoolean(args.get('DryRun'))})

    if args.get('ClientToken') is not None:
        kwargs.update({'ClientToken': (args.get('ClientToken'))})

    SpotOptions = {}
    if args.get('SpotAllocationStrategy') is not None:
        SpotOptions.update({
            'AllocationStrategy': args.get('SpotAllocationStrategy')
        })
    if args.get('InstanceInterruptionBehavior') is not None:
        SpotOptions.update({
            'InstanceInterruptionBehavior': args.get('InstanceInterruptionBehavior')
        })
    if args.get('InstancePoolsToUseCount') is not None:
        SpotOptions.update({
            'InstancePoolsToUseCount': args.get('InstancePoolsToUseCount')
        })
    if args.get('SpotSingleInstanceType') is not None:
        SpotOptions.update({'SpotSingleInstanceType': argToBoolean(args.get('SpotSingleInstanceType'))})
    if args.get('SingleAvailabilityZone') is not None:
        SpotOptions.update({
            'SingleAvailabilityZone': argToBoolean(args.get('SingleAvailabilityZone'))
        })
    if args.get('MinTargetCapacity') is not None:
        SpotOptions.update({
            'MinTargetCapacity': arg_to_number(args.get('MinTargetCapacity'))
        })

    if SpotOptions:
        kwargs.update({'SpotOptions': SpotOptions})

    OnDemandOptions = {}
    if args.get('OnDemandAllocationStrategy') is not None:
        OnDemandOptions.update({
            'AllocationStrategy': args.get('OnDemandAllocationStrategy')
        })
    if args.get('OnDemandSingleInstanceType') is not None:
        SpotOptions.update({
            'SingleInstanceType': argToBoolean(args.get('OnDemandSingleInstanceType'))
        })
    if args.get('OnDemandSingleAvailabilityZone') is not None:
        SpotOptions.update({
            'SingleAvailabilityZone': argToBoolean(args.get('OnDemandSingleAvailabilityZone'))
        })
    if args.get('OnDemandMinTargetCapacity') is not None:
        SpotOptions.update({
            'MinTargetCapacity': arg_to_number(args.get('OnDemandMinTargetCapacity'))
        })

    if OnDemandOptions:
        kwargs.update({'OnDemandOptions': OnDemandOptions})

    if args.get('ExcessCapacityTerminationPolicy') is not None:
        kwargs.update({'ExcessCapacityTerminationPolicy': (args.get('ExcessCapacityTerminationPolicy'))})

    LaunchTemplateConfigs = {}  # type: dict
    LaunchTemplateSpecification = {}
    if args.get('LaunchTemplateId') is not None:
        LaunchTemplateSpecification.update({
            'LaunchTemplateId': args.get('LaunchTemplateId')
        })
    if args.get('LaunchTemplateName') is not None:
        LaunchTemplateSpecification.update({
            'LaunchTemplateName': args.get('LaunchTemplateName')
        })
    if args.get('LaunchTemplateVersion') is not None:
        LaunchTemplateSpecification.update({
            'Version': str(args.get('LaunchTemplateVersion'))
        })

    if LaunchTemplateSpecification:
        LaunchTemplateConfigs.update({'LaunchTemplateSpecification': LaunchTemplateSpecification})

    Overrides = []  # type: list

    if args.get('OverrideInstanceType') is not None:
        arr = multi_split(args.get('OverrideInstanceType'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'InstanceType': item
            })
    if args.get('OverrideMaxPrice') is not None:
        arr = multi_split(args.get('OverrideMaxPrice'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'MaxPrice': item
            })

    if args.get('OverrideSubnetId') is not None:
        arr = multi_split(args.get('OverrideSubnetId'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'SubnetId': item
            })

    if args.get('OverrideAvailabilityZone') is not None:
        arr = multi_split(args.get('OverrideAvailabilityZone'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'AvailabilityZone': item
            })

    if args.get('OverrideWeightedCapacity') is not None:
        arr = multi_split(args.get('OverrideWeightedCapacity'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'WeightedCapacity': item
            })

    if args.get('OverridePriority') is not None:
        arr = multi_split(args.get('OverridePriority'))
        for i, item in enumerate(arr):
            if len(Overrides) - 1 < i:
                Overrides.append({})
            Overrides[i].update({
                'Priority': item
            })

    if Overrides:
        LaunchTemplateConfigs.update({'Overrides': Overrides})

    if LaunchTemplateConfigs:
        kwargs.update({'LaunchTemplateConfigs': [LaunchTemplateConfigs]})

    TargetCapacitySpecification = {}
    if args.get('TotalTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'TotalTargetCapacity': arg_to_number(args.get('TotalTargetCapacity'))
        })
    if args.get('OnDemandTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'OnDemandTargetCapacity': arg_to_number(args.get('OnDemandTargetCapacity'))
        })
    if args.get('SpotTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'SpotTargetCapacity': arg_to_number(args.get('SpotTargetCapacity'))
        })
    if args.get('DefaultTargetCapacityType') is not None:
        TargetCapacitySpecification.update({
            'DefaultTargetCapacityType': args.get('DefaultTargetCapacityType')
        })
    if TargetCapacitySpecification:
        kwargs.update({'TargetCapacitySpecification': TargetCapacitySpecification})

    if args.get('TerminateInstancesWithExpiration') is not None:
        kwargs.update({'TerminateInstancesWithExpiration': argToBoolean(args.get('TerminateInstancesWithExpiration'))})

    if args.get('Type') is not None:
        kwargs.update({'Type': (args.get('Type'))})

    if args.get('ValidFrom') is not None:
        kwargs.update({'ValidFrom': (parse_date(args.get('ValidFrom')))})

    if args.get('ValidUntil') is not None:
        kwargs.update({'ValidUntil': (parse_date(args.get('ValidUntil')))})

    if args.get('ReplaceUnhealthyInstances') is not None:
        kwargs.update({'ReplaceUnhealthyInstances': (args.get('ReplaceUnhealthyInstances'))})

    TagSpecifications = []  # type: List[dict]
    if args.get('Tags') is not None:
        arr = args.get('Tags', '').split('#')
        for i, item in enumerate(arr):
            if len(TagSpecifications) - 1 < (i):
                TagSpecifications.append({})
            tg = item.split(':')
            TagSpecifications[i].update({
                'ResourceType': tg[0],
                'Tags': parse_tag_field(tg[1])
            })

    if TagSpecifications:
        kwargs.update({'TagSpecifications': TagSpecifications})
    response = client.create_fleet(**kwargs)
    data = [{
        'FleetId': response['FleetId'],
    }]
    output = json.dumps(response)
    raw = json.loads(output)
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Fleet',
        readable_output=tableToMarkdown('AWS EC2 Fleet', data)
    )


@run_on_all_accounts
def delete_fleet_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    data = []
    kwargs = {}
    output = []
    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': argToBoolean(args.get('DryRun'))})
    if args.get('FleetIds') is not None:
        kwargs.update({'FleetIds': parse_resource_ids(args.get('FleetIds'))})
    if args.get('TerminateInstances') is not None:
        kwargs.update({'TerminateInstances': bool(args.get('TerminateInstances'))})

    response = client.delete_fleets(**kwargs)

    if len(response['SuccessfulFleetDeletions']) > 0:
        for _i, item in enumerate(response['SuccessfulFleetDeletions']):
            data.append({'SuccessfulFleetDeletions': {
                'CurrentFleetState': item['CurrentFleetState'],
                'PreviousFleetState': item['PreviousFleetState'],
                'FleetId': item['FleetId'],
                'Region': obj['_user_provided_options']['region_name'],
            }})
            output.append(item)

    if len(response['UnsuccessfulFleetDeletions']) > 0:
        for _i, item in enumerate(response['UnsuccessfulFleetDeletions']):
            data.append({'UnsuccessfulFleetDeletions': {
                'Error-Code': item['Error']['Code'],
                'Error-Message': item['Error']['Message'],
                'FleetId': item['FleetId'],
                'Region': obj['_user_provided_options']['region_name'],
            }})
            output.append(item)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.DeletedFleets',
        readable_output=tableToMarkdown('AWS Deleted Fleets', data)
    )


@run_on_all_accounts
def describe_fleets_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)  # noqa:F841
    data = []
    kwargs = {}
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('FleetIds') is not None:
        kwargs.update({'FleetIds': parse_resource_ids(args.get('FleetIds'))})
    if args.get('MaxResults') is not None:
        kwargs.update({'MaxResults': args.get('MaxResults')})
    if args.get('NextToken') is not None:
        kwargs.update({'NextToken': args.get('NextToken')})

    response = client.describe_fleets(**kwargs)

    if len(response['Fleets']) == 0:
        return CommandResults(readable_output='No fleets were found.')
    for i, item in enumerate(response['Fleets']):

        data.append({
            'ActivityStatus': item['ActivityStatus'] if 'ActivityStatus' in list(item.keys()) is not None else "None",
            'FleetId': item['FleetId'],
            'FleetState': item['FleetState'],
            'FulfilledCapacity': item['FulfilledCapacity'],
            'FulfilledOnDemandCapacity': item['FulfilledOnDemandCapacity'],
            'LaunchTemplateId': item['LaunchTemplateConfigs'][0]['LaunchTemplateSpecification'][
                'LaunchTemplateId'],
            'CreateTime': datetime.strftime(item['CreateTime'], '%Y-%m-%dT%H:%M:%SZ'),
            'TotalTargetCapacity': item['TargetCapacitySpecification']['TotalTargetCapacity'],
            'OnDemandTargetCapacity': item['TargetCapacitySpecification']['OnDemandTargetCapacity'],
            'SpotTargetCapacity': item['TargetCapacitySpecification']['SpotTargetCapacity'],
            'DefaultTargetCapacityType': item['TargetCapacitySpecification']['DefaultTargetCapacityType'],
            'TerminateInstancesWithExpiration': item['TerminateInstancesWithExpiration'],
            'Type': item['Type'],
            'InstanceInterruptionBehavior': item['SpotOptions']['InstanceInterruptionBehavior'],
        })
        if 'Tags' in item:
            for tag in item['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
        output.append(item)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Fleet',
        outputs_key_field='FleetId',
        readable_output=tableToMarkdown('AWS EC2 Fleets', data)
    )


@run_on_all_accounts
def describe_fleet_instances_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    data = []
    kwargs = {}
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('FleetId') is not None:
        kwargs.update({'FleetId': args.get('FleetId')})
    if args.get('MaxResults') is not None:
        kwargs.update({'MaxResults': arg_to_number(args.get('MaxResults'))})
    if args.get('NextToken') is not None:
        kwargs.update({'NextToken': args.get('NextToken')})

    response = client.describe_fleet_instances(**kwargs)

    if len(response['ActiveInstances']) == 0:
        return CommandResults(readable_output='No active instances were found.')

    for _i, item in enumerate(response['ActiveInstances']):
        demisto.debug(str(item))
        data.append({
            'InstanceId': item['InstanceId'],
            'InstanceType': item['InstanceType'],
            'SpotInstanceRequestId': item['SpotInstanceRequestId'],
            'FleetId': response['FleetId'],
            'Region': obj['_user_provided_options']['region_name'],
        })
        if 'InstanceHealth' in item:
            data.append({'InstanceHealth': item['InstanceHealth']})
        output.append({
            'ActiveInstances': item,
            'FleetId': response['FleetId'],
        })

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.Fleet',
        outputs_key_field='FleetId',
        readable_output=tableToMarkdown('AWS EC2 Fleets Instances', data)
    )


@run_on_all_accounts
def modify_fleet_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('FleetId') is not None:
        kwargs.update({'FleetIds': args.get('FleetId')})
    if args.get('ExcessCapacityTerminationPolicy') is not None:
        kwargs.update({'ExcessCapacityTerminationPolicy': args.get('ExcessCapacityTerminationPolicy')})
    TargetCapacitySpecification = {}
    if args.get('TotalTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'TotalTargetCapacity': arg_to_number(args.get('TotalTargetCapacity'))
        })
    if args.get('OnDemandTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'OnDemandTargetCapacity': arg_to_number(args.get('OnDemandTargetCapacity'))
        })
    if args.get('SpotTargetCapacity') is not None:
        TargetCapacitySpecification.update({
            'SpotTargetCapacity': arg_to_number(args.get('SpotTargetCapacity'))
        })
    if args.get('DefaultTargetCapacityType') is not None:
        TargetCapacitySpecification.update({
            'DefaultTargetCapacityType': args.get('DefaultTargetCapacityType')
        })
    if TargetCapacitySpecification:
        kwargs.update({'TargetCapacitySpecification': TargetCapacitySpecification})

    response = client.modify_fleet(**kwargs)

    readable_output = (
        "AWS EC2 Fleet was successfully modified"
        if response['Return'] == 'True'
        else "AWS EC2 Fleet was not successfully modified: " + response['Return']
    )
    return CommandResults(readable_output=readable_output)


@run_on_all_accounts
def create_launch_template_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)  # noqa:F841
    kwargs = {}

    BlockDeviceMappings = {}  # type: dict

    LaunchTemplateData = {}  # type: dict

    if args.get('ClientToken') is not None:
        kwargs.update({'ClientToken': args.get('ClientToken')})
    if args.get('LaunchTemplateName') is not None:
        kwargs.update({'LaunchTemplateName': args.get('LaunchTemplateName')})
    if args.get('VersionDescription') is not None:
        kwargs.update({'VersionDescription': args.get('VersionDescription')})

    if args.get('KernelId') is not None:
        LaunchTemplateData.update({'KernelId': args.get('KernelId')})
    if args.get('EbsOptimized') is not None:
        LaunchTemplateData.update({'EbsOptimized': argToBoolean(args.get('EbsOptimized'))})

    if args.get('iamInstanceProfileArn') is not None and args.get('iamInstanceProfileName') is not None:
        LaunchTemplateData.update({
            'IamInstanceProfile': {
                'Arn': args.get('iamInstanceProfileArn'),
                'Name': args.get('iamInstanceProfileName')}
        })

    if args.get('deviceName') is not None:
        BlockDeviceMappings = {'DeviceName': args.get('deviceName')}
        BlockDeviceMappings.update({'Ebs': {}})
    if args.get('VirtualName') is not None:
        BlockDeviceMappings.update({'VirtualName': {args.get('VirtualName')}})
    if args.get('ebsVolumeSize') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeSize': arg_to_number(args.get('ebsVolumeSize'))})
    if args.get('ebsVolumeType') is not None:
        BlockDeviceMappings['Ebs'].update({'VolumeType': args.get('ebsVolumeType')})
    if args.get('ebsIops') is not None:
        BlockDeviceMappings['Ebs'].update({'Iops': arg_to_number(args.get('ebsIops'))})
    if args.get('ebsDeleteOnTermination') is not None:
        BlockDeviceMappings['Ebs'].update(
            {'DeleteOnTermination': argToBoolean(args.get('ebsDeleteOnTermination'))})
    if args.get('ebsKmsKeyId') is not None:
        BlockDeviceMappings['Ebs'].update({'KmsKeyId': args.get('ebsKmsKeyId')})
    if args.get('ebsSnapshotId') is not None:
        BlockDeviceMappings['Ebs'].update({'SnapshotId': args.get('ebsSnapshotId')})
    if args.get('ebsEncrypted') is not None:
        BlockDeviceMappings['Ebs'].update({'Encrypted': argToBoolean(args.get('ebsEncrypted'))})
    if args.get('NoDevice') is not None:
        BlockDeviceMappings.update({'NoDevice': {args.get('NoDevice')}})
    if BlockDeviceMappings:
        LaunchTemplateData.update({'BlockDeviceMappings': [BlockDeviceMappings]})

    NetworkInterfaces = {}  # type: dict
    if args.get('AssociatePublicIpAddress') is not None:
        NetworkInterfaces.update({'AssociatePublicIpAddress': argToBoolean(args.get('AssociatePublicIpAddress'))})
    if args.get('NetworkInterfacesDeleteOnTermination') is not None:
        NetworkInterfaces.update({'DeleteOnTermination': argToBoolean(args.get('NetworkInterfacesDeleteOnTermination'))})
    if args.get('NetworkInterfacesDescription') is not None:
        NetworkInterfaces.update({'Description': args.get('NetworkInterfacesDescription')})
    if args.get('NetworkInterfacesDeviceIndex') is not None:
        NetworkInterfaces.update({'DeviceIndex': args.get('NetworkInterfacesDeviceIndex')})
    if args.get('NetworkInterfaceGroups') is not None:
        NetworkInterfaces.update({'Groups': parse_resource_ids(args.get('NetworkInterfaceGroups'))})
    if args.get('Ipv6AddressCount') is not None:
        NetworkInterfaces.update({'Ipv6AddressCount': args.get('Ipv6AddressCount')})
    if args.get('Ipv6Addresses') is not None:
        arr = args.get('Ipv6Addresses', '').split(',')
        NetworkInterfaces.update({'Ipv6Addresses': []})
        for a in arr:
            NetworkInterfaces['Ipv6Addresses'].append({'Ipv6Address': a})
    if args.get('NetworkInterfaceId') is not None:
        NetworkInterfaces.update({'NetworkInterfaceId': args.get('NetworkInterfaceId')})
    if args.get('PrivateIpAddress') is not None:
        NetworkInterfaces.update({'PrivateIpAddress': args.get('PrivateIpAddress')})
    if args.get('SubnetId') is not None:
        NetworkInterfaces.update({'SubnetId': args.get('SubnetId')})
    if NetworkInterfaces:
        LaunchTemplateData.update({'NetworkInterfaces': [NetworkInterfaces]})
    if args.get('ImageId') is not None:
        LaunchTemplateData.update({'ImageId': args.get('ImageId')})
    if args.get('InstanceType') is not None:
        LaunchTemplateData.update({'InstanceType': args.get('InstanceType')})
    if args.get('KeyName') is not None:
        LaunchTemplateData.update({'KeyName': args.get('KeyName')})
    if args.get('Monitoring') is not None:
        LaunchTemplateData.update({'Monitoring': {'Enabled': argToBoolean(args.get('Monitoring'))}})
    if args.get('AvailabilityZone') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'AvailabilityZone': args.get('AvailabilityZone')}
        })
    if args.get('AvailabilityZoneGroupName') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'GroupName': args.get('AvailabilityZoneGroupName')}
        })
    if args.get('PlacementTenancy') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'Tenancy': args.get('PlacementTenancy')}
        })
    if args.get('PlacementAffinity') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'Affinity': args.get('PlacementAffinity')}
        })
    if args.get('PlacementHostId') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'HostId': args.get('PlacementHostId')}
        })
    if args.get('PlacementSpreadDomain') is not None:
        LaunchTemplateData.update({
            'Placement': {
                'SpreadDomain': args.get('PlacementSpreadDomain')}
        })
    if args.get('RamDiskId') is not None:
        LaunchTemplateData.update({'RamDiskId': args.get('RamDiskId')})
    if args.get('DisableApiTermination') is not None:
        LaunchTemplateData.update({'DisableApiTermination': argToBoolean(args.get('DisableApiTermination'))})
    if args.get('InstanceInitiatedShutdownBehavior') is not None:
        LaunchTemplateData.update(
            {'InstanceInitiatedShutdownBehavior': args.get('InstanceInitiatedShutdownBehavior')})
    if args.get('UserData') is not None:
        LaunchTemplateData.update({'UserData': args.get('UserData')})
    TagSpecifications = []  # type: list
    if args.get('Tags') is not None:
        arr = args.get('Tags', '').split('#')
        for i, item in enumerate(arr):
            if len(TagSpecifications) - 1 < (i):
                TagSpecifications.append({})
            tg = item.split(':')
            TagSpecifications[i].update({
                'ResourceType': tg[0],
                'Tags': parse_tag_field(tg[1])
            })

    ElasticGpuSpecifications = []  # type: list
    if args.get('ElasticGpuSpecificationsType') is not None:
        arr = multi_split(args.get('ElasticGpuSpecificationsType'))
        for i, item in enumerate(arr):
            if len(ElasticGpuSpecifications) - 1 < i:
                ElasticGpuSpecifications.append({})
            ElasticGpuSpecifications[i].update({
                'Type': item
            })

    if ElasticGpuSpecifications:
        LaunchTemplateData.update({'ElasticGpuSpecifications': ElasticGpuSpecifications})

    ElasticInferenceAccelerators = []  # type: list
    if args.get('ElasticInferenceAcceleratorsType') is not None:
        arr = multi_split(args.get('ElasticInferenceAcceleratorsType'))
        for i, item in enumerate(arr):
            if len(ElasticInferenceAccelerators) - 1 < i:
                ElasticInferenceAccelerators.append({})
            ElasticInferenceAccelerators[i].update({
                'Type': item
            })
    if ElasticGpuSpecifications:
        LaunchTemplateData.update({'ElasticInferenceAccelerators': ElasticInferenceAccelerators})
    if TagSpecifications:
        LaunchTemplateData.update({'TagSpecifications': TagSpecifications})
    if args.get('securityGroupIds') is not None:
        LaunchTemplateData.update({'SecurityGroupIds': parse_resource_ids(args.get('securityGroupIds'))})
    if args.get('securityGroups') is not None:
        LaunchTemplateData.update({'SecurityGroups': parse_resource_ids(args.get('securityGroups'))})

    InstanceMarketOptions = {}  # type: dict
    if args.get('MarketType') is not None:
        InstanceMarketOptions.update({
            'MarketType': args.get('MarketType')
        })

    SpotOptions = {}  # type: dict
    if args.get('SpotInstanceType') is not None:
        SpotOptions.update({
            'SpotInstanceType': args.get('SpotInstanceType')
        })
    if args.get('BlockDurationMinutes') is not None:
        SpotOptions.update({
            'BlockDurationMinutes': args.get('BlockDurationMinutes')
        })
    if args.get('SpotValidUntil') is not None:
        SpotOptions.update({
            'ValidUntil': parse_date(args.get('SpotValidUntil'))
        })
    if args.get('SpotInstanceInterruptionBehavior') is not None:
        SpotOptions.update({
            'InstanceInterruptionBehavior': args.get('SpotInstanceInterruptionBehavior')
        })
    if args.get('SpotMaxPrice') is not None:
        SpotOptions.update({
            'MaxPrice': args.get('SpotMaxPrice')
        })

    if SpotOptions:
        InstanceMarketOptions.update({'SpotOptions': SpotOptions})

    if InstanceMarketOptions:
        LaunchTemplateData.update({'InstanceMarketOptions': InstanceMarketOptions})

    if LaunchTemplateData:
        kwargs.update({'LaunchTemplateData': LaunchTemplateData})

    response = client.create_launch_template(**kwargs)

    data = []
    template = response['LaunchTemplate']
    data.append({
        'LaunchTemplateId': response['LaunchTemplate']['LaunchTemplateId'],
        'LaunchTemplateName': response['LaunchTemplate']['LaunchTemplateName'],
        'CreateTime': response['LaunchTemplate']['CreateTime'],
        'CreatedBy': response['LaunchTemplate']['CreatedBy'],
        'DefaultVersionNumber': response['LaunchTemplate']['DefaultVersionNumber'],
        'LatestVersionNumber': response['LaunchTemplate']['LatestVersionNumber'],
    })
    try:
        output = json.dumps(template, cls=DatetimeEncoder)
        data_json = json.dumps(data, cls=DatetimeEncoder)
        data_hr = json.loads(data_json)  # type: ignore
        raw = json.loads(output)
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.LaunchTemplates',
        readable_output=tableToMarkdown('AWS LaunchTemplates', data_hr)
    )


@run_on_all_accounts
def delete_launch_template_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)  # noqa:F841
    data = []
    kwargs = {}
    output = []
    if args.get('LaunchTemplateId') is not None:
        kwargs.update({'LaunchTemplateId': args.get('LaunchTemplateId')})
    if args.get('LaunchTemplateName') is not None:
        kwargs.update({'LaunchTemplateName': args.get('LaunchTemplateName')})

    response = client.delete_launch_template(**kwargs)
    item = response['LaunchTemplate']
    data.append({
        'LaunchTemplateId': item['LaunchTemplateId'],
        'LaunchTemplateName': item['LaunchTemplateName'],
        'CreateTime': datetime.strftime(item['CreateTime'], '%Y-%m-%dT%H:%M:%SZ'),
        'CreatedBy': item['CreatedBy'],
        'DefaultVersionNumber': item['DefaultVersionNumber'],
        'LatestVersionNumber': item['LatestVersionNumber'],
    })
    output.append(item)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.DeletedLaunchTemplates',
        readable_output=tableToMarkdown('AWS Deleted Launch Templates', data)
    )


@run_on_all_accounts
def modify_image_attribute_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)  # noqa:F841
    kwargs = {}

    if args.get('Attribute') is not None:
        kwargs.update({'Attribute': args.get('Attribute')})
    if args.get('Description') is not None:
        kwargs.update({'Description': {'Value': args.get('Description')}})
    if args.get('ImageId') is not None:
        kwargs.update({'ImageId': args.get('ImageId')})

    LaunchPermission = {"Add": [], "Remove": []}  # type: dict
    if args.get('LaunchPermission-Add-Group') is not None:
        LaunchPermission["Add"].append({'Group': args.get('LaunchPermission-Add-Group')})
    if args.get('LaunchPermission-Add-UserId') is not None:
        LaunchPermission["Add"].append({'UserId': args.get('LaunchPermission-Add-UserId')})

    if args.get('LaunchPermission-Remove-Group') is not None:
        LaunchPermission["Remove"].append({'Group': args.get('LaunchPermission-Remove-Group')})
    if args.get('LaunchPermission-Remove-UserId') is not None:
        LaunchPermission["Remove"].append({'UserId': args.get('LaunchPermission-Remove-UserId')})

    if LaunchPermission:
        kwargs.update({'LaunchPermission': LaunchPermission})

    if args.get('OperationType') is not None:
        kwargs.update({'OperationType': args.get('OperationType')})
    if args.get('ProductCodes') is not None:
        kwargs.update({'ProductCodes': parse_resource_ids(args.get('ProductCodes'))})
    if args.get('UserGroups') is not None:
        kwargs.update({'UserGroups': parse_resource_ids(args.get('UserGroups'))})
    if args.get('UserIds') is not None:
        kwargs.update({'UserIds': parse_resource_ids(args.get('UserIds'))})
    if args.get('Value') is not None:
        kwargs.update({'Value': args.get('Value')})

    response = client.modify_image_attribute(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output='Image attribute sucessfully modified')


@run_on_all_accounts
def detach_internet_gateway_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('InternetGatewayId') is not None:
        kwargs.update({'InternetGatewayId': args.get('InternetGatewayId')})
    if args.get('VpcId') is not None:
        kwargs.update({'VpcId': args.get('VpcId')})

    response = client.detach_internet_gateway(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output='Internet gateway sucessfully detached')


@run_on_all_accounts
def delete_subnet_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('SubnetId') is not None:
        kwargs.update({'SubnetId': args.get('SubnetId')})

    response = client.delete_subnet(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output='Subnet sucessfully deleted')


@run_on_all_accounts
def delete_vpc_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('VpcId') is not None:
        kwargs.update({'VpcId': args.get('VpcId')})

    response = client.delete_vpc(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output='VPC sucessfully deleted')


@run_on_all_accounts
def delete_internet_gateway_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('InternetGatewayId') is not None:
        kwargs.update({'InternetGatewayId': args.get('InternetGatewayId')})

    response = client.delete_internet_gateway(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output='Internet gateway sucessfully deleted')


@run_on_all_accounts
def describe_internet_gateway_command(args: dict) -> CommandResults:
    client = build_client(args)
    obj = vars(client._client_config)
    kwargs = {}
    data = []
    output = []
    if args.get('filters') is not None:
        kwargs.update({'Filters': parse_filter_field(args.get('filters'))})
    if args.get('InternetGatewayIds') is not None:
        kwargs.update({'InternetGatewayIds': parse_resource_ids(args.get('InternetGatewayIds'))})

    response = client.describe_internet_gateways(**kwargs)

    if len(response['InternetGateways']) == 0:
        return CommandResults(readable_output='No Internet Gateways were found.')
    for i, internet_gateway in enumerate(response['InternetGateways']):
        data.append({
            'InternetGatewayId': internet_gateway['InternetGatewayId'],
            'OwnerId': internet_gateway['OwnerId']
        })
        if 'Tags' in internet_gateway:
            for tag in internet_gateway['Tags']:
                data[i].update({
                    tag['Key']: tag['Value']
                })
        if 'Attachments' in internet_gateway:
            for attachment in internet_gateway['Attachments']:
                data[i].update({
                    'State': attachment['State'],
                    'VpcId': attachment['VpcId']
                })
        internet_gateway.update({'Region': obj['_user_provided_options']['region_name']})
        output.append(internet_gateway)

    try:
        raw = json.loads(json.dumps(output, cls=DatetimeEncoder))
    except ValueError as err_msg:
        raise DemistoException(f'Could not decode/encode the raw response - {err_msg}')
    return CommandResults(
        outputs=raw,
        outputs_prefix='AWS.EC2.InternetGateways',
        outputs_key_field='InternetGatewayId',
        readable_output=tableToMarkdown('AWS EC2 Internet Gateway Ids', data)
    )


@run_on_all_accounts
def create_traffic_mirror_session_command(args: dict) -> CommandResults:
    client = build_client(args)
    kwargs = {}
    if args.get('NetworkInterfaceId') is not None:
        kwargs.update({'NetworkInterfaceId': args.get('NetworkInterfaceId')})
    if args.get('TrafficMirrorTargetId') is not None:
        kwargs.update({'TrafficMirrorTargetId': args.get('TrafficMirrorTargetId')})
    if args.get('TrafficMirrorFilterId') is not None:
        kwargs.update({'TrafficMirrorFilterId': args.get('TrafficMirrorFilterId')})
    if args.get('PacketLength') is not None:
        kwargs.update({'PacketLength': arg_to_number(args.get('PacketLength'))})
    if args.get('SessionNumber') is not None:
        kwargs.update({'SessionNumber': arg_to_number(args.get('SessionNumber'))})
    if args.get('VirtualNetworkId') is not None:
        kwargs.update({'VirtualNetworkId': arg_to_number(args.get('VirtualNetworkId'))})
    if args.get('Description') is not None:
        kwargs.update({'Description': args.get('Description')})
    if args.get('ClientToken') is not None:
        kwargs.update({'ClientToken': args.get('ClientToken')})
    if args.get('DryRun') is not None:
        kwargs.update({'DryRun': argToBoolean(args.get('DryRun'))})

    tag_specifications = []  # type: list
    if args.get('Tags') is not None:
        arr = args.get('Tags', '').split('#')
        for i, item in enumerate(arr):
            if len(tag_specifications) - 1 < (i):
                tag_specifications.append({})
            tg = item.split(':')
            tag_specifications[i].update({
                'ResourceType': tg[0],
                'Tags': parse_tag_field(tg[1])
            })
    if tag_specifications:
        kwargs.update({'TagSpecifications': tag_specifications})

    response = client.create_traffic_mirror_session(**kwargs)
    traffic_mirror_session = response['TrafficMirrorSession']
    client_token = response['ClientToken']
    data = {
        'TrafficMirrorSessionId': traffic_mirror_session['TrafficMirrorSessionId'],
        'TrafficMirrorTargetId': traffic_mirror_session['TrafficMirrorTargetId'],
        'TrafficMirrorFilterId': traffic_mirror_session['TrafficMirrorFilterId'],
        'NetworkInterfaceId': traffic_mirror_session['NetworkInterfaceId'],
        'OwnerId': traffic_mirror_session['OwnerId'],
        'PacketLength': traffic_mirror_session['PacketLength'],
        'SessionNumber': traffic_mirror_session['SessionNumber'],
        'VirtualNetworkId': traffic_mirror_session['VirtualNetworkId'],
        'Description': traffic_mirror_session['Description'],
        'Tags': traffic_mirror_session['Tags'],
        'VpcId': traffic_mirror_session['VpcId'],
        'ClientToken': client_token
    }
    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.TrafficMirrorSession',
        readable_output=tableToMarkdown('AWS Traffic Mirror Session', data)
    )


@run_on_all_accounts
def allocate_hosts_command(args: dict) -> CommandResults:
    client = build_client(args)

    availability_zone = args.get('availability_zone')
    quantity = arg_to_number(args.get('quantity'))

    kwargs = {}
    if args.get('auto_placement'):
        kwargs.update({'AutoPlacement': args.get('auto_placement')})
    if args.get('client_token'):
        kwargs.update({'ClientToken': args.get('client_token')})
    if args.get('instance_type'):
        kwargs.update({'InstanceType': args.get('instance_type')})
    if args.get('instance_family'):
        kwargs.update({'InstanceFamily': args.get('instance_family')})
    if args.get('host_recovery'):
        kwargs.update({'HostRecovery': args.get('host_recovery')})

    response = client.allocate_hosts(AvailabilityZone=availability_zone, Quantity=quantity, **kwargs)
    data = {'HostId': response.get('HostIds')}

    return CommandResults(
        outputs=data,
        outputs_prefix='AWS.EC2.Host',
        readable_output=tableToMarkdown('AWS EC2 Dedicated Host ID', data)
    )


@run_on_all_accounts
def release_hosts_command(args: dict) -> CommandResults:
    client = build_client(args)
    host_id = argToList(args.get('host_id'))
    response = client.release_hosts(HostIds=host_id)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output="The host was successfully released.")


@run_on_all_accounts
def modify_snapshot_permission_command(args: dict) -> CommandResults:
    client = build_client(args)

    group_names = argToList(args.get('groupNames'))
    user_ids = argToList(args.get('userIds'))
    if group_names and user_ids or not (group_names or user_ids):
        raise DemistoException('Please provide either "groupNames" or "userIds"')

    accounts = assign_params(GroupNames=group_names, UserIds=user_ids)

    operation_type = args.get('operationType')
    response = client.modify_snapshot_attribute(
        Attribute='createVolumePermission',
        SnapshotId=args.get('snapshotId'),
        OperationType=operation_type,
        DryRun=argToBoolean(args.get('dryRun', False)),
        **accounts
    )
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise DemistoException(f'Unexpected response from AWS - EC2:\n{response}')
    return CommandResults(readable_output=f"Snapshot {args.get('snapshotId')} permissions was successfully updated.")


@run_on_all_accounts
def describe_ipam_resource_discoveries_command(args: dict) -> CommandResults:
    """
    aws-ec2-describe-ipam-resource-discoveries command: Describes IPAM resource discoveries. A resource discovery is an IPAM
    component that enables IPAM to manage and monitor resources that belong to the owning account.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains IPAM resource
        discoveries.
    """
    client = build_client(args)

    kwargs = {}
    if (filters := args.get('Filters')) is not None:
        kwargs.update({'Filters': parse_filter_field(filters)})
    if (max_results := args.get('MaxResults')) is not None:
        kwargs.update({'MaxResults': int(max_results)})
    if (next_token := args.get('NextToken')) is not None:
        kwargs.update({'NextToken': next_token})
    if (ipam_ids := args.get('IpamResourceDiscoveryIds')) is not None:
        kwargs.update({'IpamResourceDiscoveryIds': argToList(ipam_ids)})

    response = client.describe_ipam_resource_discoveries(**kwargs)

    if len(response['IpamResourceDiscoveries']) == 0:
        return CommandResults(readable_output='No Ipam Resource Discoveries were found.')

    human_readable = tableToMarkdown('Ipam Resource Discoveries', response['IpamResourceDiscoveries'])
    command_results = CommandResults(
        outputs_prefix="AWS.EC2.IpamResourceDiscoveries",
        outputs_key_field="IpamResourceDiscoveryId",
        outputs=response['IpamResourceDiscoveries'],
        raw_response=response,
        readable_output=human_readable,
    )
    return command_results


@run_on_all_accounts
def describe_ipam_resource_discovery_associations_command(args: dict) -> CommandResults:
    """
    aws-ec2-describe-ipam-resource-discovery-associations command: Describes resource discovery association with an Amazon VPC
    IPAM. An associated resource discovery is a resource discovery that has been associated with an IPAM.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains IPAM discovery
        associations.
    """
    client = build_client(args)

    kwargs = {}
    if (filters := args.get('Filters')) is not None:
        kwargs.update({'Filters': parse_filter_field(filters)})
    if (max_results := args.get('MaxResults')) is not None:
        kwargs.update({'MaxResults': int(max_results)})
    if (next_token := args.get('NextToken')) is not None:
        kwargs.update({'NextToken': next_token})
    if (ipam_ids := args.get('IpamResourceDiscoveryAssociationIds')) is not None:
        kwargs.update({'IpamResourceDiscoveryAssociationIds': argToList(ipam_ids)})

    response = client.describe_ipam_resource_discovery_associations(**kwargs)

    if len(response['IpamResourceDiscoveryAssociations']) == 0:
        return CommandResults(readable_output='No Ipam Resource Discovery Associations were found.')

    human_readable = tableToMarkdown('Ipam Resource Discovery Associations', response['IpamResourceDiscoveryAssociations'])
    command_results = CommandResults(
        outputs_prefix="AWS.EC2.IpamResourceDiscoveryAssociations",
        outputs_key_field="IpamResourceDiscoveryId",
        outputs=response['IpamResourceDiscoveryAssociations'],
        raw_response=response,
        readable_output=human_readable,
    )
    return command_results


@run_on_all_accounts
def get_ipam_discovered_public_addresses_command(args: dict) -> CommandResults:
    """
    aws-ec2-get-ipam-discovered-public-addresses: Gets the public IP addresses that have been discovered by IPAM.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains public IP addresses
        that have been discovered by IPAM.
    """
    client = build_client(args)

    if (args.get('IpamResourceDiscoveryId') is None) or (args.get('AddressRegion') is None):
        return_error('IpamResourceDiscoveryId and AddressRegion need to be defined')

    kwargs = {}
    kwargs.update({'IpamResourceDiscoveryId': args.get('IpamResourceDiscoveryId'), 'AddressRegion': args.get('AddressRegion')})
    if (filters := args.get('Filters')) is not None:
        kwargs.update({'Filters': parse_filter_field(filters)})
    if (max_results := args.get('MaxResults')) is not None:
        kwargs.update({'MaxResults': int(max_results)})
    if (next_token := args.get('NextToken')) is not None:
        kwargs.update({'NextToken': next_token})

    response = client.get_ipam_discovered_public_addresses(**kwargs)

    if len(response['IpamDiscoveredPublicAddresses']) == 0:
        return CommandResults(readable_output='No Ipam Discovered Public Addresses were found.')

    output = json.loads(json.dumps(response, cls=DatetimeEncoder))

    human_readable = tableToMarkdown('Ipam Discovered Public Addresses', output['IpamDiscoveredPublicAddresses'])
    command_results = CommandResults(
        outputs_prefix="AWS.EC2.IpamDiscoveredPublicAddresses",
        outputs_key_field="Address",
        outputs=output['IpamDiscoveredPublicAddresses'],
        raw_response=output,
        readable_output=human_readable,
    )
    return command_results


@run_on_all_accounts
def create_vpc_endpoint_command(args: dict) -> CommandResults:
    """
    aws-ec2-aws-ec2-create-vpc-endpoint: Creates a VPC endpoint.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``.
    """
    output_headers = ['VpcEndpointId', 'State', 'ServiceName', 'VpcId', 'VpcEndpointType']
    client = build_client(args)

    kwargs = {}
    kwargs.update({'VpcId': args.get('vpcId'),
                   'ServiceName': args.get('serviceName')})
    if (endpoint_type := args.get('endpointType')) is not None:
        kwargs.update({'VpcEndpointType': endpoint_type})
    if (subnet_ids := args.get('subnetIds')) is not None:
        kwargs.update({'SubnetIds': argToList(subnet_ids)})
    if (security_group_ids := args.get('securityGroupIds')) is not None:
        kwargs.update({'SecurityGroupIds': argToList(security_group_ids)})
    if (dry_run := args.get('dryRun')) is not None:
        kwargs.update({'DryRun': argToBoolean(dry_run)})
    if (vpc_endpoint_type := args.get('vpcEndpointType')) is not None:
        kwargs.update({'VpcEndpointType': vpc_endpoint_type})
    if (policy_document := args.get('policyDocument')) is not None:
        kwargs.update({'PolicyDocument': policy_document})
    if (route_table_ids := args.get('routeTableIds')) is not None:
        kwargs.update({'RouteTableIds': argToList(route_table_ids)})
    if (client_token := args.get('clientToken')) is not None:
        kwargs.update({'ClientToken': client_token})
    if (private_dns_enabled := args.get('privateDnsEnabled')) is not None:
        kwargs.update({'PrivateDnsEnabled': argToBoolean(private_dns_enabled)})
    if (tag_specifications := args.get('tagSpecifications')) is not None:
        kwargs.update({'TagSpecifications': {'Tags': json.loads(tag_specifications)}})

    response = client.create_vpc_endpoint(**kwargs).get('VpcEndpoint')
    response["CreationTimestamp"] = datetime_to_string(response.get('CreationTimestamp'))  # Parse timestamp to string

    outputs = {key: response[key] for key in output_headers if key in response}

    human_readable = tableToMarkdown('VPC Endpoint', outputs, headerTransform=pascalToSpace, removeNull=True)

    command_results = CommandResults(
        outputs_prefix="AWS.EC2.Vpcs.VpcEndpoint",
        outputs_key_field="VpcEndpointId",
        outputs=remove_empty_elements(response),
        raw_response=response,
        readable_output=human_readable,
    )
    return command_results


def main():
    try:

        command = demisto.command()
        args = demisto.args()

        demisto.debug(f'Command being called is {command}')

        if (ROLE_NAME and not IS_ARN_PROVIDED):
            support_multithreading()
            demisto.debug('using multiple accounts')

        match command:
            case 'test-module':
                return_results(test_module())

            case 'aws-ec2-describe-regions':
                return_results(describe_regions_command(args))

            case 'aws-ec2-describe-instances':
                return_results(describe_instances_command(args))

            case 'aws-ec2-describe-iam-instance-profile-associations':
                return_results(describe_iam_instance_profile_associations_command(args))

            case 'aws-ec2-describe-images':
                return_results(describe_images_command(args))

            case 'aws-ec2-describe-addresses':
                return_results(describe_addresses_command(args))

            case 'aws-ec2-describe-snapshots':
                return_results(describe_snapshots_command(args))

            case 'aws-ec2-describe-volumes':
                return_results(describe_volumes_command(args))

            case 'aws-ec2-describe-launch-templates':
                return_results(describe_launch_templates_command(args))

            case 'aws-ec2-describe-key-pairs':
                return_results(describe_key_pairs_command(args))

            case 'aws-ec2-describe-vpcs':
                return_results(describe_vpcs_command(args))

            case 'aws-ec2-describe-subnets':
                return_results(describe_subnets_command(args))

            case 'aws-ec2-describe-security-groups':
                return_results(describe_security_groups_command(args))

            case 'aws-ec2-allocate-address':
                return_results(allocate_address_command(args))

            case 'aws-ec2-associate-address':
                return_results(associate_address_command(args))

            case 'aws-ec2-create-snapshot':
                return_results(create_snapshot_command(args))

            case 'aws-ec2-delete-snapshot':
                return_results(delete_snapshot_command(args))

            case 'aws-ec2-create-image':
                return_results(create_image_command(args))

            case 'aws-ec2-deregister-image':
                return_results(deregister_image_command(args))

            case 'aws-ec2-modify-volume':
                return_results(modify_volume_command(args))

            case 'aws-ec2-create-tags':
                return_results(create_tags_command(args))

            case 'aws-ec2-disassociate-address':
                return_results(disassociate_address_command(args))

            case 'aws-ec2-release-address':
                return_results(release_address_command(args))

            case 'aws-ec2-start-instances':
                return_results(start_instances_command(args))

            case 'aws-ec2-stop-instances':
                return_results(stop_instances_command(args))

            case 'aws-ec2-terminate-instances':
                return_results(terminate_instances_command(args))

            case 'aws-ec2-create-volume':
                return_results(create_volume_command(args))

            case 'aws-ec2-attach-volume':
                return_results(attach_volume_command(args))

            case 'aws-ec2-detach-volume':
                return_results(detach_volume_command(args))

            case 'aws-ec2-delete-volume':
                return_results(delete_volume_command(args))

            case 'aws-ec2-run-instances':
                return_results(run_instances_command(args))

            case 'aws-ec2-waiter-instance-running':
                return_results(waiter_instance_running_command(args))

            case 'aws-ec2-waiter-instance-status-ok':
                return_results(waiter_instance_status_ok_command(args))

            case 'aws-ec2-waiter-instance-stopped':
                return_results(waiter_instance_stopped_command(args))

            case 'aws-ec2-waiter-instance-terminated':
                return_results(waiter_instance_terminated_command(args))

            case 'aws-ec2-waiter-image-available':
                return_results(waiter_image_available_command(args))

            case 'aws-ec2-waiter-snapshot_completed':
                return_results(waiter_snapshot_completed_command(args))

            case 'aws-ec2-get-latest-ami':
                return_results(get_latest_ami_command(args))

            case 'aws-ec2-create-security-group':
                return_results(create_security_group_command(args))

            case 'aws-ec2-delete-security-group':
                return_results(delete_security_group_command(args))

            case 'aws-ec2-authorize-security-group-ingress-rule':
                return_results(authorize_security_group_ingress_command(args))

            case 'aws-ec2-authorize-security-group-egress-rule':
                return_results(authorize_security_group_egress_command(args))

            case 'aws-ec2-revoke-security-group-ingress-rule':
                return_results(revoke_security_group_ingress_command(args))

            case 'aws-ec2-revoke-security-group-egress-rule':
                return_results(revoke_security_group_egress_command(args))

            case 'aws-ec2-copy-image':
                return_results(copy_image_command(args))

            case 'aws-ec2-copy-snapshot':
                return_results(copy_snapshot_command(args))

            case 'aws-ec2-describe-reserved-instances':
                return_results(describe_reserved_instances_command(args))

            case 'aws-ec2-monitor-instances':
                return_results(monitor_instances_command(args))

            case 'aws-ec2-unmonitor-instances':
                return_results(unmonitor_instances_command(args))

            case 'aws-ec2-reboot-instances':
                return_results(reboot_instances_command(args))

            case 'aws-ec2-get-password-data':
                return_results(get_password_data_command(args))

            case 'aws-ec2-modify-network-interface-attribute':
                return_results(modify_network_interface_attribute_command(args))

            case 'aws-ec2-create-network-acl':
                return_results(create_network_acl_command(args))

            case 'aws-ec2-create-network-acl-entry':
                return_results(create_network_acl_entry_command(args))

            case 'aws-ec2-create-fleet':
                return_results(create_fleet_command(args))

            case 'aws-ec2-delete-fleet':
                return_results(delete_fleet_command(args))

            case 'aws-ec2-describe-fleets':
                return_results(describe_fleets_command(args))

            case 'aws-ec2-describe-fleet-instances':
                return_results(describe_fleet_instances_command(args))

            case 'aws-ec2-modify-fleet':
                return_results(modify_fleet_command(args))

            case 'aws-ec2-create-launch-template':
                return_results(create_launch_template_command(args))

            case 'aws-ec2-delete-launch-template':
                return_results(delete_launch_template_command(args))

            case 'aws-ec2-modify-image-attribute':
                return_results(modify_image_attribute_command(args))

            case 'aws-ec2-modify-instance-attribute':
                return_results(modify_instance_attribute_command(args))

            case 'aws-ec2-detach-internet-gateway':
                return_results(detach_internet_gateway_command(args))

            case 'aws-ec2-delete-internet-gateway':
                return_results(delete_internet_gateway_command(args))

            case 'aws-ec2-describe-internet-gateway':
                return_results(describe_internet_gateway_command(args))

            case 'aws-ec2-delete-subnet':
                return_results(delete_subnet_command(args))

            case 'aws-ec2-delete-vpc':
                return_results(delete_vpc_command(args))

            case 'aws-ec2-create-traffic-mirror-session':
                return_results(create_traffic_mirror_session_command(args))

            case 'aws-ec2-allocate-hosts':
                return_results(allocate_hosts_command(args))

            case 'aws-ec2-release-hosts':
                return_results(release_hosts_command(args))

            case 'aws-ec2-modify-snapshot-permission':
                return_results(modify_snapshot_permission_command(args))

            case 'aws-ec2-describe-ipam-resource-discoveries':
                return_results(describe_ipam_resource_discoveries_command(args))

            case 'aws-ec2-describe-ipam-resource-discovery-associations':
                return_results(describe_ipam_resource_discovery_associations_command(args))

            case 'aws-ec2-get-ipam-discovered-public-addresses':
                return_results(get_ipam_discovered_public_addresses_command(args))

            case 'aws-ec2-create-vpc-endpoint':
                return_results(create_vpc_endpoint_command(args))

    except Exception as e:
        LOG(e)
        return_error(f'Error occurred in the AWS EC2 Integration:\n{e}')


if __name__ in ['__builtin__', 'builtins', '__main__']:
    main()
