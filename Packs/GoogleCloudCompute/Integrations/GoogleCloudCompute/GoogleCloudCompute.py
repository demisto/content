import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

import json
import time

from google.oauth2 import service_account
from googleapiclient import discovery

# disable weak-typing warnings by pylint.
# See: https://github.com/GoogleCloudPlatform/python-docs-samples/blob/master/iam/api-client/quickstart.py#L36
# pylint: disable=no-member

""" GLOBALS/PARAMS """

# Params for assembling object of the Service Account Credentials File Contents
SERVICE_ACCOUNT_FILE = demisto.params().get('credentials_service_account_json',
                                            {}).get('password') or demisto.params().get('service')
SERVICE_ACT_PROJECT_ID = None

# Params for constructing googleapiclient service object
API_VERSION = 'v1'
GSERVICE = 'compute'
ASSET_SERVICE = 'cloudasset'
SCOPE = ['https://www.googleapis.com/auth/cloud-platform']
COMPUTE = None  # variable set by build_and_authenticate() function
ASSET = None  # variable set by build_and_authenticate() function

"""
HELPER FUNCTIONS
"""


def get_compute():
    """
    Gets an initialized instance of COMPUTE
    """
    if not COMPUTE:
        return build_and_authenticate(GSERVICE)
    return COMPUTE


def get_asset():
    """
    Gets an initialized instance of ASSET
    """
    if not ASSET:
        return build_and_authenticate(ASSET_SERVICE)
    return ASSET


def parse_resource_ids(resource_id):
    """
    Split the resource ids to a list
    parameter: (string) resource_id
    Return the resource_ids as a list
    """
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def parse_firewall_rule(rule_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) rules
        A firewall rule in the specified project
    Return firewall rules as dictionary list
    """
    rules = []
    regex = re.compile(r'ipprotocol=([\w\d_:.-]+),ports=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in rule_str.split(';'):
        match = regex.match(f)
        if match is None:
            raise ValueError('Could not parse field: {}. Please make sure you provided like so: '
                             'ipprotocol=abc,ports=123;ipprotocol=fed,ports=456'.format(f))

        rules.append({'IPProtocol': match.group(1), 'ports': match.group(2).split(',')})

    return rules


def parse_metadata_items(tags_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) metadata_items

    Return metadata items as a dictionary list
    """
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            raise ValueError('Could not parse field: {}. Please make sure you provided like so: '
                             'key=abc,value=123;key=fed,value=456'.format(f))

        tags.append({'key': match.group(1), 'value': match.group(2)})

    return tags


def parse_named_ports(tags_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) namedPorts

    Return named ports as a dictionary list
    """
    tags = []
    regex = re.compile(r'name=([\w\d_:.-]+),port=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            raise ValueError('Could not parse field: {}. Please make sure you provided like so: '
                             'name=abc,port=123;name=fed,port=456'.format(f))

        tags.append({'name': match.group(1).lower(), 'port': match.group(2)})

    return tags


def parse_labels(tags_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) labels

    Return labels as a dictionary list
    """
    tags = {}
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            raise ValueError('Could not parse field: {}. Please make sure you provided like so: '
                             'key=abc,value=123;key=def,value=456'.format(f))

        tags.update({match.group(1).lower(): match.group(2).lower()})

    return tags


def build_and_authenticate(googleservice):
    """
    Return a service object via which can call GRM API.

    Use the service_account credential file generated in the Google Cloud
    Platform to build the Google Resource Manager API Service object.

    returns: service
        Google Resource Manager API Service object via which commands in the
        integration will make API calls
    """

    global SERVICE_ACT_PROJECT_ID, COMPUTE, ASSET
    auth_json_string = str(SERVICE_ACCOUNT_FILE).replace("\'", "\"").replace("\\\\", "\\")
    service_account_info = json.loads(auth_json_string)
    SERVICE_ACT_PROJECT_ID = service_account_info.get('project_id')
    service_credentials = service_account.Credentials.from_service_account_info(
        service_account_info, scopes=SCOPE
    )
    if googleservice == 'compute':
        COMPUTE = discovery.build(googleservice, API_VERSION, credentials=service_credentials)
        return COMPUTE
    elif googleservice == 'cloudasset':
        ASSET = discovery.build(googleservice, API_VERSION, credentials=service_credentials)
        return ASSET
    return None


def wait_for_zone_operation(args):
    """
    This command will block until an operation has been marked as complete.

    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) name
        Name of the operations resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    name = args.get('name')
    while True:
        result = (
            get_compute().zoneOperations()
            .get(project=project, zone=zone, operation=name)
            .execute()
        )
        if result.get('status') == 'DONE':
            if 'error' in result:
                raise Exception(result['error'])
            operation = result
            data_res = {
                'status': operation.get('status'),
                'kind': operation.get('kind'),
                'name': operation.get('name'),
                'id': operation.get('id'),
                'progress': operation.get('progress'),
                'startTime': operation.get('startTime'),
                'operationType': operation.get('operationType')
            }
            ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': operation}
            return_outputs(
                tableToMarkdown(
                    'Google Cloud Compute Operations', data_res, removeNull=True
                )
                if data_res
                else 'No results were found',
                ec
            )
            break

        time.sleep(2)


def wait_for_region_operation(args):
    """
    This command will block until an operation has been marked as complete.

    parameter: (string) region
        Name of the region for this request.
    parameter: (string) name
        Name of the operations resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    region = args.get('region')
    name = args.get('name')
    while True:
        result = (
            get_compute().regionOperations()
            .get(project=project, region=region, operation=name)
            .execute()
        )
        if result.get('status') == 'DONE':
            if 'error' in result:
                raise Exception(result['error'])
            operation = result
            data_res = {
                'status': operation.get('status'),
                'kind': operation.get('kind'),
                'name': operation.get('name'),
                'id': operation.get('id'),
                'progress': operation.get('progress'),
                'startTime': operation.get('startTime'),
                'operationType': operation.get('operationType')
            }
            ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': operation}
            return_outputs(
                tableToMarkdown(
                    'Google Cloud Compute Operations', data_res, removeNull=True
                ),
                ec
            )
            break

        time.sleep(2)


def wait_for_global_operation(args):
    """
    This command will block until an operation has been marked as complete.

    parameter: (string) name
        Name of the operations resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    while True:
        result = (
            get_compute().globalOperations().get(project=project, operation=name).execute()
        )
        if result.get('status') == 'DONE':
            if 'error' in result:
                raise Exception(result['error'])

            operation = result
            data_res = {
                'status': operation.get('status'),
                'kind': operation.get('kind'),
                'name': operation.get('name'),
                'id': operation.get('id'),
                'progress': operation.get('progress'),
                'startTime': operation.get('startTime'),
                'operationType': operation.get('operationType')
            }
            ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': operation}

            return_outputs(
                tableToMarkdown(
                    'Google Cloud Compute Operations', data_res, removeNull=True
                ),
                ec
            )
            break

        time.sleep(2)


def test_module():
    build_and_authenticate(GSERVICE)
    demisto.results('ok')


# instances()
def create_instance(args):
    """
    Creates an instance resource in the specified project using the data included in the request.
    parameter: (string) name
    parameter: (string) description
    parameter: (boolean) canIpForward (true/false)
    parameter: (list) tags
    parameter: (string) tagsFingerprint
    parameter: (string) zone
    parameter: (string) machine_type
    parameter: (string) network
    parameter: (string) sub_network
    parameter: (string) networkIP
    parameter: (string) networkInterfacesfingerprint
    parameter: (boolean) externalInternetAccess (true/false)
    parameter: (string) externalNatIP
    parameter: (boolean) setPublicPtr (true/false)
    parameter: (string) publicPtrDomainName
    parameter: (string) networkTier (PREMIUM,STANDARD)
    parameter: (string) ipCidrRange
    parameter: (string) subnetworkRangeName
    parameter: (string) diskType (PERSISTENT,SCRATCH)
    parameter: (string) diskMode (READ_WRITE,READ_ONLY)
    parameter: (string) diskSource
    parameter: (string) diskDeviceName
    parameter: (boolean) diskBoot (true/false)
    parameter: (string) initializeParamsDiskName
    parameter: (string) initializeParamsSourceImage
    parameter: (int) initializeParamsdiskSizeGb
    parameter: (string) initializeParamsDiskType
    parameter: (string) initializeParamsSourceImageEncryptionKeyRawKey
    parameter: (string) initializeParamsSourceImageEncryptionKeykmsKeyName
    parameter: (string) initializeParamsDiskLabels
    parameter: (string) initializeParamsDiskDescription
    parameter: (boolean) diskAutodelete (true/false)
    parameter: (string) diskInterface (SCSI,NVME)
    parameter: (list) diskGuestOsFeatures
    parameter: (string) diskEncryptionKeyRawKey
    parameter: (string) diskEncryptionKeyKmsKeyName
    parameter: (dict) metadataItems
    parameter: (string) serviceAccountEmail
    parameter: (list) serviceAccountscopes
    parameter: (string) schedulingOnHostMaintenance (MIGRATE,TERMINATE)
    parameter: (boolean) schedulingAutomaticRestart (true/false)
    parameter: (boolean) schedulingPreemptible (true/false)
    parameter: (dict) labels
    parameter: (string) labelFingerprint
    parameter: (string) minCpuPlatform
    parameter: (string) guestAcceleratorsAcceleratorType
    parameter: (integer) guestAcceleratorsAcceleratorCount
    parameter: (boolean) deletionProtection (true/false)

    Return the created instance to the war room
    """
    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('tags'):
        tags = args.get('tags')
        if 'tags' not in config.keys():
            config.update({'tags': [{}]})
        config['tags'][0].update({'items': parse_resource_ids(tags)})

    if args.get('canIpForward'):
        can_ip_forward = args.get('canIpForward') == 'true'
        config.update({'canIpForward': can_ip_forward})

    if args.get('tagsFingerprint'):
        tags_fingerprint = args.get('tagsFingerprint')
        if 'tags' not in config.keys():
            config.update({'tags': [{}]})
        config['tags'][0].update({'fingerprint': tags_fingerprint})

    zone = args.get('zone')
    machine_type = args.get('machine_type')

    zone_machine_type = 'zones/' + zone + '/machineTypes/' + machine_type
    config.update({'machineType': zone_machine_type})

    if args.get('network'):
        network = args.get('network')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        config['networkInterfaces'][0].update({'network': network})

    if args.get('subnetwork'):
        sub_network = args.get('subnetwork')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        config['networkInterfaces'][0].update({'subnetwork': sub_network})

    if args.get('networkIP'):
        network_ip = args.get('networkIP')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        config['networkInterfaces'][0].update({'networkIP': network_ip})

    if args.get('networkInterfacesfingerprint'):
        network_interfaces_fingerprint = args.get('networkInterfacesfingerprint')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        config['networkInterfaces'][0].update(
            {'fingerprint': network_interfaces_fingerprint}
        )

    if args.get('externalInternetAccess'):
        external_network = (
            args.get('externalInternetAccess') == 'true'
        )
        if external_network:
            if 'networkInterfaces' not in config.keys():
                config.update({'networkInterfaces': [{}]})
            if 'accessConfigs' not in config['networkInterfaces'][0].keys():
                config['networkInterfaces'][0].update({'accessConfigs': [{}]})
            config['networkInterfaces'][0]['accessConfigs'][0].update(
                {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT'}
            )

    if args.get('externalNatIP'):
        nat_ip = args.get('externalNatIP')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'accessConfigs' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'accessConfigs': [{}]})

        config['networkInterfaces'][0]['accessConfigs'][0].update({'natIP': nat_ip})

    if args.get('setPublicPtr'):
        set_public_ptr = args.get('setPublicPtr') == 'true'
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'accessConfigs' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'accessConfigs': [{}]})

        config['networkInterfaces'][0]['accessConfigs'][0].update(
            {'setPublicPtr': set_public_ptr}
        )

    if args.get('publicPtrDomainName'):
        public_ptr_domain_name = args.get('setPublicPtr')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'accessConfigs' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'accessConfigs': [{}]})

        config['networkInterfaces'][0]['accessConfigs'][0].update(
            {'publicPtrDomainName': public_ptr_domain_name}
        )

    if args.get('networkTier'):
        network_tier = args.get('networkTier')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'accessConfigs' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'accessConfigs': [{}]})

        config['networkInterfaces'][0]['accessConfigs'][0].update(
            {'networkTier': network_tier}
        )

    if args.get('ipCidrRange'):
        ip_cidr_range = args.get('ipCidrRange')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'aliasIpRanges' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'aliasIpRanges': [{}]})

        config['networkInterfaces'][0]['aliasIpRanges'][0].update(
            {'ipCidrRange': ip_cidr_range}
        )

    if args.get('subnetworkRangeName'):
        subnet_work_range_name = args.get('subnetworkRangeName')
        if 'networkInterfaces' not in config.keys():
            config.update({'networkInterfaces': [{}]})
        if 'aliasIpRanges' not in config['networkInterfaces'][0].keys():
            config['networkInterfaces'][0].update({'aliasIpRanges': [{}]})

        config['networkInterfaces'][0]['aliasIpRanges'][0].update(
            {'subnetworkRangeName': subnet_work_range_name}
        )

    if args.get('diskType'):
        disk_type = args.get('diskType')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'type': disk_type})

    if args.get('diskMode'):
        disk_mode = args.get('diskMode')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'mode': disk_mode})

    if args.get('diskSource'):
        disk_source = args.get('diskSource')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'source': disk_source})

    if args.get('diskDeviceName'):
        disk_device_name = args.get('diskDeviceName')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'deviceName': disk_device_name})

    if args.get('diskBoot') is not None:
        disk_boot = args.get('diskBoot') == 'true'
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'boot': disk_boot})

    if args.get('initializeParamsDiskName'):
        initialize_params_disk_name = args.get('initializeParamsDiskName')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update(
            {'diskName': initialize_params_disk_name}
        )

    if args.get('initializeParamsSourceImage'):
        image = args.get('initializeParamsSourceImage')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update({'sourceImage': image})

    if args.get('initializeParamsdiskSizeGb'):
        initialize_params_disk_size_gb = args.get('initializeParamsdiskSizeGb')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update(
            {'diskSizeGb': int(initialize_params_disk_size_gb)}
        )

    if args.get('initializeParamsDiskType'):
        initialize_params_disk_type = args.get('initializeParamsDiskType')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update(
            {'diskType': initialize_params_disk_type}
        )

    if args.get('initializeParamsSourceImageEncryptionKeyRawKey'):
        initialize_params_source_image_encryption_key_raw_key = args.get(
            'initializeParamsSourceImageEncryptionKeyRawKey'
        )
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        if (
                'sourceImageEncryptionKey'
                not in config['disks'][0]['initializeParams'].keys()
        ):
            config['disks'][0]['initializeParams'].update(
                {'sourceImageEncryptionKey': {}}
            )
        config['disks'][0]['initializeParams']['sourceImageEncryptionKey'].update(
            {'rawKey': initialize_params_source_image_encryption_key_raw_key}
        )

    if args.get('initializeParamsSourceImageEncryptionKeykmsKeyName'):
        initialize_params_source_image_encryption_key_kms_key_name = args.get(
            'initializeParamsSourceImageEncryptionKeykmsKeyName'
        )
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        if (
                'sourceImageEncryptionKey'
                not in config['disks'][0]['initializeParams'].keys()
        ):
            config['disks'][0]['initializeParams'].update(
                {'sourceImageEncryptionKey': {}}
            )
        config['disks'][0]['initializeParams']['sourceImageEncryptionKey'].update(
            {'kmsKeyName': initialize_params_source_image_encryption_key_kms_key_name}
        )

    if args.get('initializeParamsDiskLabels'):
        initialize_params_disk_labels = args.get('initializeParamsDiskLabels')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update(
            {'labels': parse_labels(initialize_params_disk_labels)}
        )

    if args.get('initializeParamsDiskDescription'):
        initialize_params_disk_description = args.get('initializeParamsDiskDescription')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'initializeParams' not in config['disks'][0].keys():
            config['disks'][0].update({'initializeParams': {}})
        config['disks'][0]['initializeParams'].update(
            {'description': initialize_params_disk_description}
        )

    if args.get('diskAutodelete'):
        disk_auto_delete = args.get('diskAutodelete') == 'true'
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'autoDelete': disk_auto_delete})

    if args.get('diskInterface'):
        disk_interface = args.get('diskInterface')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'interface': disk_interface})

    if args.get('diskGuestOsFeatures'):
        disk_guest_os_features = args.get('diskGuestOsFeatures')
        disk_guest_os_features = parse_resource_ids(disk_guest_os_features)
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        config['disks'][0].update({'guestOsFeatures': []})
        for f in disk_guest_os_features:
            config['disks'][0]['guestOsFeatures'].append({'type': f})

    if args.get('diskEncryptionKeyRawKey'):
        disk_encryption_key_raw_key = args.get('diskEncryptionKeyRawKey')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'diskEncryptionKey' not in config['disks'][0].keys():
            config['disks'][0].update({'diskEncryptionKey': {}})
        config['disks'][0]['diskEncryptionKey'].update(
            {'rawKey': disk_encryption_key_raw_key}
        )

    if args.get('diskEncryptionKeyKmsKeyName'):
        disk_encryption_key_kms_key_name = args.get('diskEncryptionKeyKmsKeyName')
        if 'disks' not in config.keys():
            config.update({'disks': [{}]})
        if 'diskEncryptionKey' not in config['disks'][0].keys():
            config['disks'][0].update({'diskEncryptionKey': {}})
        config['disks'][0]['diskEncryptionKey'].update(
            {'kmsKeyName': disk_encryption_key_kms_key_name}
        )

    meta_data = {}
    if args.get('metadataItems'):
        meta_data.update({'items': parse_metadata_items(args.get('metadataItems'))})
        config.update({'metadata': meta_data})

    service_accounts = {}  # type: dict
    if (
            args.get('serviceAccountEmail') is not None
            and args.get('serviceAccountscopes') is not None
    ):
        service_accounts = {
            'serviceAccounts': [
                {
                    'email': args.get('serviceAccountEmail'),
                    'scopes': parse_resource_ids(args.get('serviceAccountscopes')),
                }
            ]
        }
        config.update({'serviceAccounts': service_accounts})

    if args.get('schedulingOnHostMaintenance'):
        scheduling_on_host_maintenance = args.get('schedulingOnHostMaintenance')
        if 'scheduling' not in config.keys():
            config.update({'scheduling': {}})
        config['scheduling'].update(
            {'onHostMaintenance': scheduling_on_host_maintenance}
        )

    if args.get('schedulingAutomaticRestart'):
        scheduling_automatic_restart = (
            args.get('schedulingAutomaticRestart') == 'true'
        )
        if 'scheduling' not in config.keys():
            config.update({'scheduling': {}})
        config['scheduling'].update({'automaticRestart': scheduling_automatic_restart})

    if args.get('schedulingPreemptible'):
        scheduling_preemptible = (
            args.get('schedulingPreemptible') == 'true'
        )
        if 'scheduling' not in config.keys():
            config.update({'scheduling': {}})
        config['scheduling'].update({'preemptible': scheduling_preemptible})

    if args.get('labels'):
        labels = args.get('labels')
        config.update({'labels': parse_labels(labels)})

    if args.get('labelFingerprint'):
        label_fingerprint = args.get('labelFingerprint')
        config.update({'labelFingerprint': label_fingerprint})

    if args.get('minCpuPlatform'):
        min_cpu_platform = args.get('minCpuPlatform')
        config.update({'minCpuPlatform': min_cpu_platform})

    if args.get('guestAcceleratorsAcceleratorType'):
        guest_accelerators_accelerator_type = args.get(
            'guestAcceleratorsAcceleratorType'
        )
        if 'guestAccelerators' not in config.keys():
            config.update({'guestAccelerators': [{}]})
        config['guestAccelerators'][0].update(
            {'acceleratorType': guest_accelerators_accelerator_type}
        )

    if args.get('guestAcceleratorsAcceleratorCount'):
        guest_accelerators_accelerator_count = args.get(
            'guestAcceleratorsAcceleratorCount'
        )
        if 'guestAccelerators' not in config.keys():
            config.update({'guestAccelerators': [{}]})
        config['guestAccelerators'][0].update(
            {'acceleratorCount': int(guest_accelerators_accelerator_count)}
        )

    if args.get('deletionProtection'):
        deletion_protection = (
            args.get('deletionProtection') == 'true'
        )
        config.update({'deletionProtection': deletion_protection})

    project = SERVICE_ACT_PROJECT_ID

    operation = (
        get_compute().instances().insert(project=project, zone=zone, body=config).execute()
    )

    data_res = {
        'status': operation.get('status'),
        'kind': operation.get('kind'),
        'name': operation.get('name'),
        'id': operation.get('id'),
        'progress': operation.get('progress'),
        'startTime': operation.get('startTime'),
        'operationType': operation.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': operation}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        operation,
    )


def list_instances(args):
    """
    Retrieves the list of instances contained within the specified zone.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (string) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name
    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    request = get_compute().instances().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    output = []
    data_res = []
    while request:
        response = request.execute()
        if 'items' in response:
            for instance in response['items']:
                output.append(instance)
                data_res_item = {
                    'id': instance.get('id'),
                    'name': instance.get('name'),
                    'machineType': instance.get('machineType'),
                    'zone': instance.get('zone'),
                }
                data_res.append(data_res_item)

        request = get_compute().instances().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Instances(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Instances', data_res, removeNull=True),
        ec,
        response,
    )


def aggregated_list_instances(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []

    request = get_compute().instances().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for _name, instances_scoped_list in response['items'].items():
                if 'warning' not in instances_scoped_list.keys():
                    for inst in instances_scoped_list.get('instances', []):
                        output.append(inst)
                        data_res_item = {
                            'id': inst.get('id'),
                            'name': inst.get('name'),
                            'machineType': inst.get('machineType'),
                            'zone': inst.get('zone'),
                        }
                        data_res.append(data_res_item)

        request = get_compute().instances().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Instances(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Instances', data_res, removeNull=True),
        ec,
        response,
    )


def set_instance_metadata(args):
    """
    Sets metadata for the specified instance to the data included in the request.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    instance = args.get('instance')

    meta_data = {}
    if args.get('metadataFingerprint'):
        meta_data.update({'fingerprint': args.get('metadataFingerprint')})
    if args.get('metadataItems'):
        meta_data.update({'items': parse_metadata_items(args.get('metadataItems'))})

    request = get_compute().instances().setMetadata(
        project=project, zone=zone, instance=instance, body=meta_data
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_instance(args):
    """
    Returns the specified Instance resource.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = args.get('project_id')
    if not project:
        project = SERVICE_ACT_PROJECT_ID

    instance = args.get('instance')
    zone = args.get('zone')

    request = get_compute().instances().get(project=project, zone=zone, instance=instance)
    response = request.execute()
    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'machineType': response.get('machineType'),
        'zone': response.get('zone'),
    }

    ec = {'GoogleCloudCompute.Instances(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Instances', data_res, removeNull=True),
        ec,
        response,
    )


def delete_instance(args):
    """
    Deletes the specified Instance resource

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')

    request = get_compute().instances().delete(project=project, zone=zone, instance=instance)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def start_instance(args):
    """
    Starts an instance that was stopped using the instances().stop method.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')

    request = get_compute().instances().start(project=project, zone=zone, instance=instance)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def stop_instance(args):
    """
    Stops a running instance, shutting it down cleanly, and allows you to restart the instance at a later time

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')

    request = get_compute().instances().stop(project=project, zone=zone, instance=instance)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def reset_instance(args):
    """
    Performs a reset on the instance.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')

    request = get_compute().instances().reset(project=project, zone=zone, instance=instance)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def set_instance_labels(args):
    """
    Sets labels on an instance

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    parameter: (dict) labels
        An object containing a list of 'key': value pairs
    parameter: (string) labelFingerprint
        Fingerprint of the previous set of labels for this resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')
    labels = args.get('labels')

    labels = parse_labels(labels)
    body = {'labels': labels}

    if args.get('labelFingerprint'):
        body.update({'labelFingerprint': args.get('labelFingerprint')})

    request = get_compute().instances().setLabels(
        project=project, zone=zone, instance=instance, body=body
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def set_instance_machine_type(args):
    """
    Changes the machine type for a stopped instance to the machine type specified in the request.

    parameter: (string) zone
        Name of the zone for request.
    parameter: (string) instance
        Name of the instance scoping this request.
    parameter: (string) machine_type
        Full or partial URL of the machine type resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')
    machine_type = args.get('machineType')

    body = {'machineType': machine_type}

    request = get_compute().instances().setMachineType(
        project=project, zone=zone, instance=instance, body=body
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


# images()
def get_image(args):
    """
    Returns the specified image.

    parameter: (string) project
        Project ID for this request.
    parameter: (string) image
        Name of the image resource to return.
    """
    if args.get('project') is not None:
        project = args.get('project')
    else:
        project = SERVICE_ACT_PROJECT_ID

    image = args.get('image')

    request = get_compute().images().get(project=project, image=image)
    response = request.execute()

    data_res = {'id': response.get('id'), 'name': response.get('name')}

    ec = {'GoogleCloudCompute.Images(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Images', data_res, removeNull=True),
        ec,
        response,
    )


def get_image_from_family(args):
    """
    Returns the latest image that is part of an image family and is not deprecated.

    parameter: (string) project
        Project ID for this request.
    parameter: (string) family
        Name of the image family to search for.
    """
    project = args.get('project')
    family = args.get('family')

    request = get_compute().images().getFromFamily(project=project, family=family)
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'family': response.get('family'),
    }

    ec = {'GoogleCloudCompute.Images(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Images', data_res, removeNull=True),
        ec,
        response,
    )


def list_images(args):
    """
    parameter: (string) project
        Project ID for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (string) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    return: demisto entry (list)

    """
    project = SERVICE_ACT_PROJECT_ID

    if args.get('project'):
        project = args.get('project')
    else:
        project = SERVICE_ACT_PROJECT_ID

    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().images().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for image in response['items']:
                output.append(image)
                data_res_item = {'id': image.get('id'), 'name': image.get('name')}
                data_res.append(data_res_item)

        request = get_compute().images().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Images(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Images', data_res, removeNull=True),
        ec,
        response,
    )


def delete_image(args):
    """
    Deletes the specified image.

    parameter: (string) image
        Name of the image resource to delete.
    """
    project = SERVICE_ACT_PROJECT_ID
    image = args.get('image')

    request = get_compute().images().delete(project=project, image=image)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def set_image_labels(args):
    """
    Sets the labels on an image.

    parameter: (string) image
        Name of the image resource to delete.
    parameter: (dict) labels
        A list of labels to apply for this resource.
    parameter: (string) labelFingerprint
        The fingerprint of the previous set of labels for this resource.
    """
    project = SERVICE_ACT_PROJECT_ID
    image = args.get('image')
    labels = args.get('labels')
    label_fingerprint = args.get('labelFingerprint')

    labels = parse_labels(labels)
    body = {'labels': labels, 'labelFingerprint': label_fingerprint}

    request = get_compute().images().setLabels(project=project, resource=image, body=body)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def insert_image(args):
    """
    Creates an image in the specified project using the data included in the request.
    """
    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    force_create = False
    if args.get('forceCreate'):
        force_create = args.get('forceCreate') == 'true'

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('rawDiskSource'):
        raw_disk_source = args.get('rawDiskSource')
        config.update({'rawDisk': {}})
        config['rawDisk'].update({'source': raw_disk_source})

    if args.get('rawDiskSha1Checksum'):
        raw_disk_sha1_checksum = args.get('rawDiskSha1Checksum')
        if 'rawDisk' not in config.keys():
            config.update({'rawDisk': {}})
        config['rawDisk'].update({'sha1Checksum': raw_disk_sha1_checksum})

    if args.get('rawDiskContainerType'):
        raw_disk_container_type = args.get('rawDiskContainerType')
        if 'rawDisk' not in config.keys():
            config.update({'rawDisk': {}})
        config['rawDisk'].update({'containerType': raw_disk_container_type})

    if args.get('deprecatedState'):
        deprecated_state = args.get('deprecatedState')
        config.update({'deprecated': {}})
        config['deprecated'].update({'state': deprecated_state})

    if args.get('deprecatedReplacement'):
        deprecated_replacement = args.get('deprecatedReplacement')
        if 'deprecated' not in config.keys():
            config.update({'deprecated': {}})
        config['deprecated'].update({'replacement': deprecated_replacement})

    if args.get('archiveSizeBytes'):
        archive_size_bytes = args.get('archiveSizeBytes')
        config.update({'archiveSizeBytes': int(archive_size_bytes)})

    if args.get('diskSizeGb'):
        disk_size_gb = args.get('diskSizeGb')
        config.update({'diskSizeGb': int(disk_size_gb)})

    if args.get('sourceDisk'):
        source_disk = args.get('sourceDisk')
        config.update({'sourceDisk': source_disk})

    if args.get('licenses'):
        licenses = args.get('licenses')
        config.update({'licenses': parse_resource_ids(licenses)})

    if args.get('family'):
        family = args.get('family')
        config.update({'family': family})

    if args.get('imageEncryptionKeyRawKey'):
        image_encryption_key_raw_key = args.get('imageEncryptionKeyRawKey')
        config.update({'imageEncryptionKey': {'rawKey': image_encryption_key_raw_key}})

    if args.get('imageEncryptionKeyKmsKeyName'):
        image_encryption_key_kms_key_name = args.get('imageEncryptionKeyKmsKeyName')
        if 'imageEncryptionKey' not in config.keys():
            config.update({'imageEncryptionKey': {}})
        config['imageEncryptionKey'].update(
            {'kmsKeyName': image_encryption_key_kms_key_name}
        )

    if args.get('sourceDiskEncryptionKeyRawKey'):
        source_disk_encryption_key_raw_key = args.get('sourceDiskEncryptionKeyRawKey')
        if 'sourceDiskEncryptionKey' not in config.keys():
            config.update({'sourceDiskEncryptionKey': {}})
        config['sourceDiskEncryptionKey'].update(
            {'rawKey': source_disk_encryption_key_raw_key}
        )

    if args.get('sourceDiskEncryptionKeyKmsKeyName'):
        source_disk_encryption_key_kms_key_name = args.get(
            'sourceDiskEncryptionKeyKmsKeyName'
        )
        if 'sourceDiskEncryptionKey' not in config.keys():
            config.update({'sourceDiskEncryptionKey': {}})
        config['sourceDiskEncryptionKey'].update(
            {'kmsKeyName': source_disk_encryption_key_kms_key_name}
        )

    if args.get('labels'):
        labels = args.get('labels')
        config.update({'labels': parse_labels(labels)})

    if args.get('labelFingerprint'):
        label_fingerprint = args.get('labelFingerprint')
        config.update({'labelFingerprint': label_fingerprint})

    if args.get('guestOsFeatures'):
        guest_os_features = args.get('guestOsFeatures')
        guest_os_features = parse_resource_ids(guest_os_features)
        config.update({'guestOsFeatures': []})
        for f in guest_os_features:
            config['guestOsFeatures'].append({'type': f})

    if args.get('licenseCodes'):
        license_codes = args.get('licenseCodes')
        config.update({'licenseCodes': parse_resource_ids(license_codes)})

    if args.get('sourceImage'):
        source_image = args.get('sourceImage')
        config.update({'sourceImage': source_image})

    if args.get('imageEncryptionKeyRawKey'):
        image_encryption_key_raw_key = args.get('imageEncryptionKeyRawKey')
        config.update({'imageEncryptionKey': {'rawKey': image_encryption_key_raw_key}})

    if args.get('sourceImageEncryptionKeyKmsKeyName'):
        source_image_encryption_key_kms_key_name = args.get(
            'sourceImageEncryptionKeyKmsKeyName'
        )
        if 'sourceImageEncryptionKey' not in config.keys():
            config.update({'sourceImageEncryptionKey': {}})
        config['sourceImageEncryptionKey'].update(
            {'kmsKeyName': source_image_encryption_key_kms_key_name}
        )

    if args.get('sourceSnapshot'):
        source_snapshot = args.get('sourceSnapshot')
        config.update({'sourceSnapshot': source_snapshot})

    if args.get('sourceSnapshotEncryptionKeyRawKey'):
        source_snapshot_encryption_key_raw_key = args.get(
            'sourceSnapshotEncryptionKeyRawKey'
        )
        if 'sourceSnapshotEncryptionKey' not in config.keys():
            config.update({'sourceSnapshotEncryptionKey': {}})
        config['sourceSnapshotEncryptionKey'].update(
            {'rawKey': source_snapshot_encryption_key_raw_key}
        )

    if args.get('sourceSnapshotEncryptionKeyKmsKeyName'):
        source_snapshot_encryption_key_kms_key_name = args.get(
            'sourceSnapshotEncryptionKeyKmsKeyName'
        )
        if 'sourceSnapshotEncryptionKey' not in config.keys():
            config.update({'sourceSnapshotEncryptionKey': {}})
        config['sourceSnapshotEncryptionKey'].update(
            {'kmsKeyName': source_snapshot_encryption_key_kms_key_name}
        )

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().images()
        .insert(project=project, forceCreate=force_create, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def networks_add_peering(args):
    """
    Adds a peering to the specified network.
    """
    config = {}
    network = args.get('network')

    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('peerNetwork'):
        peer_network = args.get('peerNetwork')
        config.update({'peerNetwork': peer_network})

    if args.get('autoCreateRoutes'):
        auto_create_routes = args.get('autoCreateRoutes') == 'true'
        config.update({'autoCreateRoutes': auto_create_routes})

    if args.get('networkPeeringName'):
        network_peering_name = args.get('networkPeeringName')
        config.update({'networkPeering': {}})
        config['networkPeering'].update({'name': network_peering_name})

    if args.get('networkPeeringNetwork'):
        network_peering_network = args.get('networkPeeringNetwork')
        if 'networkPeering' not in config.keys():
            config.update({'networkPeering': {}})
        config['networkPeering'].update({'network': network_peering_network})

    if args.get('networkPeeringExchangeSubnetRoutes'):
        network_peering_exchange_subnet_routes = (
            args.get('networkPeeringExchangeSubnetRoutes') == 'True'
        )
        if 'networkPeering' not in config.keys():
            config.update({'networkPeering': {}})
        config['networkPeering'].update(
            {'exchangeSubnetRoutes': network_peering_exchange_subnet_routes}
        )

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().networks()
        .addPeering(project=project, network=network, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def delete_network(args):
    """
    Deletes the specified network.

    parameter: (string) network
        Name of the network to delete.
    """
    project = SERVICE_ACT_PROJECT_ID
    network = args.get('network')

    request = get_compute().networks().delete(project=project, network=network)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_network(args):
    """
    Returns the specified network

    parameter: (string) network
        Name of the network to return.
    """
    project = SERVICE_ACT_PROJECT_ID
    network = args.get('network')

    request = get_compute().networks().get(project=project, network=network)
    response = request.execute()

    data_res = {'name': response.get('name'), 'id': response.get('id')}

    ec = {'GoogleCloudCompute.Networks(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Networks', data_res, removeNull=True),
        ec,
        response,
    )


def insert_network(args):
    """
    Creates a network in the specified project using the data included in the request.
    """
    config = {}

    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('autoCreateSubnetworks'):
        auto_create_sub_networks = (
            args.get('autoCreateSubnetworks') == 'true'
        )
        config.update({'autoCreateSubnetworks': auto_create_sub_networks})

    if args.get('routingConfigRoutingMode'):
        routing_config_routing_mode = args.get('routingConfigRoutingMode')
        config.update({'routingConfig': {'routingMode': routing_config_routing_mode}})

    project = SERVICE_ACT_PROJECT_ID
    response = get_compute().networks().insert(project=project, body=config).execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def list_networks(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().networks().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {'name': item.get('name'), 'id': item.get('id')}
                data_res.append(data_res_item)

        request = get_compute().networks().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Networks(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Networks', data_res, removeNull=True),
        ec,
        response,
    )


def networks_removepeering(args):
    """
    Removes a peering from the specified network.

    parameter: (string) network
        Name of the network resource to remove peering from.
    parameter: (string) name
        Name of the peering.
    """
    config = {}
    network = args.get('network')

    if args.get('name'):
        name = args.get('name', '')
        config.update({'name': name})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().networks()
        .removePeering(project=project, network=network, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_global_operation(args):
    """
    Retrieves the specified Operations resource.

    parameter: (string) name
        Name of the Operations resource to return.
    """
    project = SERVICE_ACT_PROJECT_ID
    operation = args.get('name')

    request = get_compute().globalOperations().get(project=project, operation=operation)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_zone_operation(args):
    """
    Retrieves the specified zone-specific Operations resource.

    parameter: (string) name
        Name of the Operations resource to return.
    parameter: (string) zone
        Name of the zone for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    zone = args.get('zone')

    request = get_compute().zoneOperations().get(project=project, zone=zone, operation=name)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_region_operation(args):
    """
    Retrieves the specified region-specific Operations resource.

    parameter: (string) name
        Name of the Operations resource to return.
    parameter: (string) region
        Name of the region for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    region = args.get('region')

    request = get_compute().regionOperations().get(
        project=project, region=region, operation=name
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def list_zone_operation(args):
    """
    parameter: (string) zone
        Name of the zone for request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().zoneOperations().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for operation in response['items']:
                output.append(operation)
                data_res_item = {
                    'status': operation.get('status'),
                    'kind': operation.get('kind'),
                    'name': operation.get('name'),
                    'id': operation.get('id'),
                    'progress': operation.get('progress'),
                    'startTime': operation.get('startTime'),
                    'operationType': operation.get('operationType'),
                }
                data_res.append(data_res_item)

        request = get_compute().zoneOperations().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def delete_zone_operation(args):
    """
    Deletes the specified zone-specific Operations resource.

    parameter: (string) name
        Name of the Operations resource to delete.
    parameter: (string) zone
        Name of the zone for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    zone = args.get('zone')

    request = get_compute().zoneOperations().delete(
        project=project, zone=zone, operation=name
    )
    request.execute()

    return 'success'


def list_region_operation(args):
    """
    parameter: (string) region
        Name of the region for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    region = args.get('region')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().regionOperations().list(
        project=project,
        region=region,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for operation in response['items']:
                output.append(operation)
                data_res_item = {
                    'status': operation.get('status'),
                    'kind': operation.get('kind'),
                    'name': operation.get('name'),
                    'id': operation.get('id'),
                    'progress': operation.get('progress'),
                    'startTime': operation.get('startTime'),
                    'operationType': operation.get('operationType'),
                }
                data_res.append(data_res_item)

        request = get_compute().regionOperations().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def delete_region_operation(args):
    """
    Deletes the specified region-specific Operations resource.

    parameter: (string) name
        Name of the Operations resource to delete.
    parameter: (string) region
        Name of the region for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    region = args.get('region')

    request = get_compute().regionOperations().delete(
        project=project, region=region, operation=name
    )
    request.execute()

    return 'success'


def list_global_operation(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().globalOperations().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for operation in response['items']:
                output.append(operation)
                data_res_item = {
                    'status': operation.get('status'),
                    'kind': operation.get('kind'),
                    'name': operation.get('name'),
                    'id': operation.get('id'),
                    'progress': operation.get('progress'),
                    'startTime': operation.get('startTime'),
                    'operationType': operation.get('operationType'),
                }
                data_res.append(data_res_item)

        request = get_compute().globalOperations().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def delete_global_operation(args):
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')

    request = get_compute().globalOperations().delete(project=project, operation=name)
    request.execute()

    return 'success'


def aggregated_list_addresses(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().addresses().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for _name, instances_scoped_list in response['items'].items():
                if 'warning' not in instances_scoped_list.keys():
                    for addr in instances_scoped_list.get('addresses'):
                        output.append(addr)
                        data_res_item = {
                            'id': addr.get('id'),
                            'name': addr.get('name'),
                            'address': addr.get('address'),
                        }
                        data_res.append(data_res_item)

        request = get_compute().addresses().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Addresses(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Addresses', data_res, removeNull=True),
        ec,
        response,
    )


def delete_address(args):
    """
    Deletes the specified address resource.

    parameter: (string) address
        Name of the address resource to delete.
    parameter: (string) region
        Name of the region for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    address = args.get('address')
    region = args.get('region')

    request = get_compute().addresses().delete(
        project=project, region=region, address=address
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_address(args):
    """
    Returns the specified address resource.

    parameter: (string) address
        Name of the address resource to return.
    parameter: (string) region
        Name of the region for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    address = args.get('address')
    region = args.get('region')

    request = get_compute().addresses().get(project=project, region=region, address=address)
    response = request.execute()
    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'address': response.get('address'),
    }
    ec = {'GoogleCloudCompute.Addresses(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Addresses', data_res, removeNull=True),
        ec,
        response,
    )


def insert_address(args):
    """
    Creates an address resource in the specified project using the data included in the request.
    """
    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    region = args.get('region')

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('address'):
        address = args.get('address')
        config.update({'address': address})

    if args.get('prefixLength'):
        prefix_length = args.get('prefixLength')
        config.update({'prefixLength': prefix_length})

    if args.get('networkTier'):
        network_tier = args.get('networkTier')
        config.update({'networkTier': network_tier})

    if args.get('addressType'):
        address_type = args.get('addressType')
        config.update({'addressType': address_type})

    if args.get('purpose'):
        purpose = args.get('purpose')
        config.update({'purpose': purpose})

    if args.get('subnetwork'):
        sub_network = args.get('subnetwork')
        config.update({'subnetwork': sub_network})

    if args.get('network'):
        network = args.get('network')
        config.update({'network': network})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().addresses()
        .insert(project=project, region=region, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def list_addresses(args):
    """
    parameter: (string) region
        Name of the region for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    region = args.get('region')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().addresses().list(
        project=project,
        region=region,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for address in response['items']:
                output.append(address)
                data_res_item = {
                    'id': address.get('id'),
                    'name': address.get('name'),
                    'address': address.get('address'),
                }
                data_res.append(data_res_item)

        request = get_compute().addresses().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Addresses(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Addresses', data_res, removeNull=True),
        ec,
        response,
    )


def delete_global_address(args):
    """
    Deletes the specified address resource.

    parameter: (string) address
        Name of the address resource to delete.
    """
    project = SERVICE_ACT_PROJECT_ID
    address = args.get('address')

    request = get_compute().globalAddresses().delete(project=project, address=address)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_global_address(args):
    """
    Returns the specified address resource

    parameter: (string) address
        Name of the address resource to return.
    """
    project = SERVICE_ACT_PROJECT_ID
    address = args.get('address')

    request = get_compute().globalAddresses().get(project=project, address=address)
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'address': response.get('address'),
    }

    ec = {'GoogleCloudCompute.Addresses(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Addresses', data_res, removeNull=True),
        ec,
        response,
    )


def insert_global_address(args):
    """
    Creates an address resource in the specified project using the data included in the request.
    """
    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('address'):
        address = args.get('address')
        config.update({'address': address})

    if args.get('prefixLength'):
        prefix_length = args.get('prefixLength')
        config.update({'prefixLength': prefix_length})

    if args.get('networkTier'):
        networkTier = args.get('networkTier')
        config.update({'networkTier': networkTier})

    if args.get('ipVersion'):
        ip_version = args.get('ipVersion')
        config.update({'ipVersion': ip_version})

    if args.get('addressType'):
        address_type = args.get('addressType')
        config.update({'addressType': address_type})

    if args.get('purpose'):
        purpose = args.get('purpose')
        config.update({'purpose': purpose})

    if args.get('subnetwork'):
        sub_network = args.get('subnetwork')
        config.update({'subnetwork': sub_network})

    if args.get('network'):
        network = args.get('network')
        config.update({'network': network})

    project = SERVICE_ACT_PROJECT_ID
    response = get_compute().globalAddresses().insert(project=project, body=config).execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def list_global_addresses(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().globalAddresses().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for address in response['items']:
                output.append(address)
                data_res_item = {
                    'id': address.get('id'),
                    'name': address.get('name'),
                    'address': address.get('address'),
                }
                data_res.append(data_res_item)

        request = get_compute().globalAddresses().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Addresses(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Addresses', data_res, removeNull=True),
        ec,
        response,
    )


# disks()
def aggregated_list_disks(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().disks().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for _name, instances_scoped_list in response['items'].items():
                if 'warning' not in instances_scoped_list.keys():
                    for disk in instances_scoped_list.get('disks', []):
                        output.append(disk)
                        data_res_item = {
                            'id': disk.get('id'),
                            'name': disk.get('name'),
                            'sizeGb': disk.get('sizeGb'),
                            'zone': disk.get('zone'),
                            'status': disk.get('status'),
                            'type': disk.get('type'),
                        }
                        data_res.append(data_res_item)

        request = get_compute().disks().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Disks(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Disks', data_res, removeNull=True),
        ec,
        response,
    )


def create_disk_snapshot(args):
    """
    Creates a snapshot of a specified persistent disk.

    parameter: (string) zone
        The name of the zone for this request.
    parameter: (string) disk
        Name of the persistent disk to snapshot.

    """

    zone = args.get('zone')
    disk = args.get('disk')

    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('snapshotEncryptionKeyRawKey'):
        raw_key = args.get('snapshotEncryptionKeyRawKey')
        if 'snapshotEncryptionKey' not in config.keys():
            config.update({'snapshotEncryptionKey': {}})
        config['snapshotEncryptionKey'].update({'rawKey': raw_key})

    if args.get('snapshotEncryptionKeyKmsKeyName'):
        kms_key_name = args.get('snapshotEncryptionKeyKmsKeyName')
        if 'snapshotEncryptionKey' not in config.keys():
            config.update({'snapshotEncryptionKey': {}})
        config['snapshotEncryptionKey'].update({'kmsKeyName': kms_key_name})

    if args.get('sourceDiskEncryptionKeyRawKey'):
        raw_key = args.get('sourceDiskEncryptionKeyRawKey')
        if 'sourceDiskEncryptionKey' not in config.keys():
            config.update({'sourceDiskEncryptionKey': {}})
        config['sourceDiskEncryptionKey'].update({'rawKey': raw_key})

    if args.get('sourceDiskEncryptionKeyKmsKeyName'):
        kms_key_name = args.get('sourceDiskEncryptionKeyKmsKeyName')
        if 'sourceDiskEncryptionKey' not in config.keys():
            config.update({'sourceDiskEncryptionKey': {}})
        config['sourceDiskEncryptionKey'].update({'kmsKeyName': kms_key_name})

    if args.get('labels'):
        labels = args.get('labels')
        config.update({'labels': parse_labels(labels)})

    if args.get('labelFingerprint'):
        label_fingerprint = args.get('labelFingerprint')
        config.update({'labelFingerprint': label_fingerprint})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().disks()
        .createSnapshot(project=project, zone=zone, disk=disk, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def delete_disk(args):
    """
    Deletes the specified persistent disk.

    parameter: (string) disk
        Name or id of the resource for this request.
    parameter: (string) zone
        Name of the zone for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    disk = args.get('disk')
    zone = args.get('zone')

    request = get_compute().disks().delete(project=project, zone=zone, disk=disk)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def get_disk(args):
    """
    Returns a specified persistent disk.

    parameter: (string) disk
        Name or id of the resource for this request.
    parameter: (string) zone
        Name of the zone for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    disk = args.get('disk')
    zone = args.get('zone')

    request = get_compute().disks().get(project=project, zone=zone, disk=disk)
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'sizeGb': response.get('sizeGb'),
        'zone': response.get('zone'),
        'status': response.get('status'),
        'type': response.get('type'),
    }

    ec = {'GoogleCloudCompute.Disks(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Disks', data_res, removeNull=True),
        ec,
        response,
    )


def insert_disk(args):
    """
    Creates a persistent disk in the specified project using the data in the request.
    """
    config = {}
    if args.get('name'):
        name = args.get('name', '')
        name = name.lower()
        config.update({'name': name})

    if args.get('zone'):
        zone = args.get('zone')
    else:
        zone = None
        demisto.debug(f"{args.get('zone')=}")

    if args.get('disktype'):
        disk_type = args.get('disktype')
        config.update({'type': disk_type})

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('sizeGb'):
        size_gb = args.get('sizeGb')
        config.update({'sizeGb': int(size_gb)})

    if args.get('sourceSnapshot'):
        sourceSnapshot = args.get('sourceSnapshot')
        config.update({'sourceSnapshot': sourceSnapshot})

    if args.get('sourceImage'):
        source_image = args.get('sourceImage')
        config.update({'sourceImage': source_image})

    if args.get('licenses'):
        licenses = args.get('licenses')
        config.update({'licenses': parse_resource_ids(licenses)})

    if args.get('guestOsFeatures'):
        guest_os_features = args.get('guestOsFeatures')
        guest_os_features = parse_resource_ids(guest_os_features)
        config.update({'guestOsFeatures': []})
        for f in guest_os_features:
            config['guestOsFeatures'].append({'type': f})

    if args.get('diskEncryptionKeyRawKey'):
        disk_encryption_key_raw_key = args.get('diskEncryptionKeyRawKey')
        config.update({'diskEncryptionKey': {}})
        config['diskEncryptionKey'].update({'rawKey': disk_encryption_key_raw_key})

    if args.get('diskEncryptionKeyKmsKeyName'):
        disk_encryption_key_kms_key_name = args.get('diskEncryptionKeyKmsKeyName')
        if 'diskEncryptionKey' not in config.keys():
            config.update({'diskEncryptionKey': {}})
        config['diskEncryptionKey'].update(
            {'kmsKeyName': disk_encryption_key_kms_key_name}
        )

    if args.get('imageEncryptionKeyRawKey'):
        image_encryption_key_raw_key = args.get('imageEncryptionKeyRawKey')
        config.update({'imageEncryptionKey': {'rawKey': image_encryption_key_raw_key}})

    if args.get('sourceImageEncryptionKeyKmsKeyName'):
        source_image_encryption_key_kms_key_name = args.get(
            'sourceImageEncryptionKeyKmsKeyName'
        )
        if 'sourceImageEncryptionKey' not in config.keys():
            config.update({'sourceImageEncryptionKey': {}})
        config['sourceImageEncryptionKey'].update(
            {'kmsKeyName': source_image_encryption_key_kms_key_name}
        )

    if args.get('sourceSnapshotEncryptionKeyRawKey'):
        source_snapshot_encryption_key_raw_key = args.get(
            'sourceSnapshotEncryptionKeyRawKey'
        )
        if 'sourceSnapshotEncryptionKey' not in config.keys():
            config.update({'sourceSnapshotEncryptionKey': {}})
        config['sourceSnapshotEncryptionKey'].update(
            {'rawKey': source_snapshot_encryption_key_raw_key}
        )

    if args.get('sourceSnapshotEncryptionKeyKmsKeyName'):
        source_snapshot_encryption_key_kms_key_name = args.get(
            'sourceSnapshotEncryptionKeyKmsKeyName'
        )
        if 'sourceSnapshotEncryptionKey' not in config.keys():
            config.update({'sourceSnapshotEncryptionKey': {}})
        config['sourceSnapshotEncryptionKey'].update(
            {'kmsKeyName': source_snapshot_encryption_key_kms_key_name}
        )

    if args.get('labels'):
        labels = args.get('labels')
        config.update({'labels': parse_labels(labels)})

    if args.get('labelFingerprint'):
        label_fingerprint = args.get('labelFingerprint')
        config.update({'labelFingerprint': label_fingerprint})

    if args.get('replicaZones'):
        replica_zones = args.get('replicaZones')
        config.update({'replicaZones': parse_resource_ids(replica_zones)})

    if args.get('licenseCodes'):
        license_codes = args.get('licenseCodes')
        config.update({'licenseCodes': parse_resource_ids(license_codes)})

    if args.get('physicalBlockSizeBytes'):
        physical_block_size_bytes = args.get('physicalBlockSizeBytes')
        config.update({'physicalBlockSizeBytes': int(physical_block_size_bytes)})

    project = SERVICE_ACT_PROJECT_ID
    response = get_compute().disks().insert(project=project, zone=zone, body=config).execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response,
    )


def list_disks(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().disks().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for disk in response['items']:
                output.append(disk)
                data_res_item = {
                    'id': disk.get('id'),
                    'name': disk.get('name'),
                    'sizeGb': disk.get('sizeGb'),
                    'zone': disk.get('zone'),
                    'status': disk.get('status'),
                    'type': disk.get('type')
                }
                data_res.append(data_res_item)

        request = get_compute().disks().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Disks(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Disks', data_res, removeNull=True),
        ec,
        response
    )


def resize_disk(args):
    """
    Resizes the specified persistent disk.

    parameter: (string) disk
        Name or id of the resource for this request.
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) sizeGb
        The new size of the persistent disk, which is specified in GB.
    """
    config = {}

    disk = args.get('disk')
    zone = args.get('zone')

    if args.get('sizeGb'):
        size_gb = args.get('sizeGb')
        config.update({'sizeGb': int(size_gb)})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().disks()
        .resize(project=project, zone=zone, disk=disk, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def set_disk_labels(args):
    """
    Sets the labels on a disk.

    parameter: (string) disk
        Name or id of the resource for this request.
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (dict) labels
        The labels to set for this resource.
    parameter: (string) labelFingerprint
        The fingerprint of the previous set of labels for this resource, used to detect conflicts.
    """
    project = SERVICE_ACT_PROJECT_ID
    disk = args.get('disk')
    zone = args.get('zone')
    labels = args.get('labels')

    labels = parse_labels(labels)
    body = {'labels': labels}

    if args.get('labelFingerprint'):
        label_fingerprint = args.get('labelFingerprint')
        if label_fingerprint is not None:
            body.update({'labelFingerprint': label_fingerprint})

    request = get_compute().disks().setLabels(
        project=project, zone=zone, resource=disk, body=body
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


# diskTypes()
def aggregated_list_disk_types(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().diskTypes().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for _name, instances_scoped_list in response['items'].items():
                if 'warning' not in instances_scoped_list.keys():
                    for disktype in instances_scoped_list.get('diskTypes', []):
                        output.append(disktype)
                        data_res_item = {
                            'name': disktype.get('name'),
                            'validDiskSize': disktype.get('validDiskSize')
                        }
                        data_res.append(data_res_item)

        request = get_compute().diskTypes().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.DiskTypes(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute DiskTypes', data_res, removeNull=True),
        ec,
        response
    )


def get_disk_type(args):
    """
    Returns the specified disk type.
    """
    project = SERVICE_ACT_PROJECT_ID
    disk_type = args.get('disktype')
    zone = args.get('zone')

    request = get_compute().diskTypes().get(project=project, zone=zone, diskType=disk_type)
    response = request.execute()

    data_res = {
        'name': response.get('name'),
        'validDiskSize': response.get('validDiskSize'),
        'zone': response.get('zone')
    }

    ec = {'GoogleCloudCompute.DiskTypes(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute DiskTypes', data_res, removeNull=True),
        ec,
        response
    )


def list_disks_types(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().diskTypes().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for disktype in response['items']:
                output.append(disktype)
                data_res_item = {
                    'name': disktype.get('name'),
                    'validDiskSize': disktype.get('validDiskSize')
                }
                data_res.append(data_res_item)

        request = get_compute().diskTypes().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.DiskTypes(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute DiskTypes', data_res, removeNull=True),
        ec,
        response
    )


# instanceGroups()
def instance_groups_add_instances(args):
    """
    Adds a list of instances to the specified instance group.
    All of the instances in the instance group must be in the same network/subnetwork.

    parameter: (dict) instances
        The list of instances to add to the instance group.
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) instance_group
        The name of the instance group

    """
    project = SERVICE_ACT_PROJECT_ID
    instance_group = args.get('instanceGroup')
    zone = args.get('zone')
    instances = args.get('instances')

    instances = parse_resource_ids(instances)
    instarry = []
    for inst in instances:
        instarry.append({'instance': inst})

    body = {}
    body.update({'instances': instarry})

    request = get_compute().instanceGroups().addInstances(
        project=project, zone=zone, instanceGroup=instance_group, body=body
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def aggregated_list_instance_groups(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (string) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().instanceGroups().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for _name, instances_scoped_list in response['items'].items():
                if 'warning' not in instances_scoped_list.keys():
                    for item in instances_scoped_list.get('instanceGroups', []):
                        output.append(item)
                        data_res_item = {
                            'id': item.get('id'),
                            'name': item.get('name'),
                            'zone': item.get('zone'),
                            'network': item.get('network')
                        }
                        data_res.append(data_res_item)

        request = get_compute().instanceGroups().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.InstanceGroups(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Instance Groups', data_res, removeNull=True
        ),
        ec,
        response
    )


def delete_instance_group(args):
    """
    Deletes the specified instance group. The instances in the group are not deleted.

    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) instance_group
        The name of the instance group
    """
    project = SERVICE_ACT_PROJECT_ID
    instance_group = args.get('instanceGroup')
    zone = args.get('zone')

    request = get_compute().instanceGroups().delete(
        project=project, zone=zone, instanceGroup=instance_group
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def get_instance_group(args):
    """
    Returns the specified instance group.

    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) instance_group
        The name of the instance group.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance_group = args.get('instanceGroup')
    zone = args.get('zone')

    request = get_compute().instanceGroups().get(
        project=project, zone=zone, instanceGroup=instance_group
    )
    response = request.execute()
    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'zone': response.get('zone'),
        'network': response.get('network')
    }

    ec = {'GoogleCloudCompute.InstanceGroups(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Instance Groups', data_res, removeNull=True
        ),
        ec,
        response
    )


def insert_instance_group(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (string) name
        The name of the instance group.
    parameter: (string) description
        An optional description of this resource. Provide this property when you create the resource.
    parameter: (object) namedPorts
        Assigns a name to a port number
    parameter: (string) network
        The URL of the network to which all instances in the instance group belong.

    """
    config = {}
    if args.get('name'):
        name = args.get('name')
        name = name.lower()
        config.update({'name': name})

    zone = args.get('zone')

    if args.get('description'):
        description = args.get('description')
        config.update({'description': description})

    if args.get('namedPorts'):
        named_ports = args.get('namedPorts')
        config.update({'namedPorts': parse_named_ports(named_ports)})

    if args.get('network'):
        network = args.get('network')
        config.update({'network': network})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().instanceGroups()
        .insert(project=project, zone=zone, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def list_instance_groups(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    request = get_compute().instanceGroups().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)

        request = get_compute().instanceGroups().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.InstanceGroups(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Instance Groups', output, removeNull=True
        ),
        ec,
        response
    )


def list_instance_groups_instances(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name
    parameter: (enum) instanceState
        A filter for the state of the instances in the instance group. Valid options are ALL or RUNNING
    """
    project = SERVICE_ACT_PROJECT_ID

    zone = args.get('zone')
    config = {}
    instance_group = args.get('instanceGroup')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    if args.get('instanceState'):
        instance_state = args.get('instanceState')
        config.update({'instanceState': instance_state})

    output = []
    data_res = []
    request = get_compute().instanceGroups().listInstances(
        project=project,
        zone=zone,
        instanceGroup=instance_group,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token,
        body=config
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'instance': item.get('instance'),
                    'status': item.get('status')
                }
                data_res.append(data_res_item)

        request = get_compute().instanceGroups().listInstances_next(
            previous_request=request, previous_response=response
        )
    output = {'Group': instance_group, 'Instances': output}

    ec = {'GoogleCloudCompute.InstanceGroupsInstances': output}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Instance Groups', data_res, removeNull=True
        ),
        ec,
        response
    )


def instance_groups_remove_instances(args):
    """
    Removes one or more instances from the specified instance group, but does not delete those instances.

    parameter: (string) zone
        The name of the zone for this request.
    parameter: (string) instanceGroup
        The name of the instance group where the named ports are updated.
    parameter: (list) instances
       The list of instances to remove from the instance group.
    """
    project = SERVICE_ACT_PROJECT_ID
    instance_group = args.get('instanceGroup')
    zone = args.get('zone')
    instances = args.get('instances')

    instances = parse_resource_ids(instances)
    instarry = []
    for inst in instances:
        instarry.append({'instance': inst})

    body = {'instances': instarry}

    request = get_compute().instanceGroups().removeInstances(
        project=project, zone=zone, instanceGroup=instance_group, body=body
    )
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def set_instance_group_named_ports(args):
    """
    Sets the named ports for the specified instance group.

    parameter: (string) zone
        The name of the zone for this request.
    parameter: (string) instanceGroup
        The name of the instance group where the named ports are updated.
    parameter: (list) namedPorts
        The list of named ports to set for this instance group.
    parameter: (string) fingerprint
        The fingerprint of the named ports information for this instance group.
    """
    config = {}
    instance_group = args.get('instanceGroup')

    zone = args.get('zone')

    if args.get('namedPorts'):
        named_ports = args.get('namedPorts')
        config.update({'namedPorts': parse_named_ports(named_ports)})

    if args.get('fingerprint'):
        fingerprint = args.get('fingerprint')
        config.update({'fingerprint': fingerprint})

    project = SERVICE_ACT_PROJECT_ID
    response = (
        get_compute().instanceGroups()
        .setNamedPorts(project=project, zone=zone, instanceGroup=instance_group, body=config)
        .execute()
    )

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


# regions()
def get_region(args):
    """
    Get a specified region resource.

    parameter: (string) region
        The name of the region for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    region = args.get('region')

    request = get_compute().regions().get(project=project, region=region)
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'status': response.get('status')
    }

    ec = {'GoogleCloudCompute.Regions(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Regions', data_res, removeNull=True),
        ec,
        response
    )


def list_regions(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().regions().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'id': item.get('id'),
                    'name': item.get('name'),
                    'status': item.get('status')
                }
                data_res.append(data_res_item)

        request = get_compute().regions().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Regions(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Regions', data_res, removeNull=True),
        ec,
        response
    )


def get_zone(args):
    """
    Get a specified zone resource.

    parameter: (string) zone
        The name of the zone for this request.
    """

    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')

    request = get_compute().zones().get(project=project, zone=zone)
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'status': response.get('status')
    }

    ec = {'GoogleCloudCompute.Zones(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Zones', data_res, removeNull=True),
        ec,
        response
    )


def list_zones(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """

    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().zones().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'id': item.get('id'),
                    'name': item.get('name'),
                    'status': item.get('status')
                }
                data_res.append(data_res_item)

        request = get_compute().zones().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Zones(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Zones', data_res, removeNull=True),
        ec,
        response
    )


def aggregated_list_machine_types(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """

    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().machineTypes().aggregatedList(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    response = request.execute()
    if 'items' in response:
        for _name, instances_scoped_list in response['items'].items():
            if 'warning' not in instances_scoped_list.keys():
                for item in instances_scoped_list.get('machineTypes', []):
                    output.append(item)
                    data_res_item = {
                        'id': item.get('id'),
                        'name': item.get('name'),
                        'memoryMb': item.get('memoryMb'),
                        'guestCpus': item.get('guestCpus')
                    }
                    data_res.append(data_res_item)

    ec = {'GoogleCloudCompute.MachineTypes(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Machine Types', data_res, removeNull=True
        ),
        ec,
        response
    )


def get_machine_type(args):
    """
    Get a specified machine type.

    parameter: (string) zone
        The name of the zone for this request.

    parameter: (string) machineType
        Name of the machine type to return.
    """

    project = SERVICE_ACT_PROJECT_ID
    machine_type = args.get('machineType')
    zone = args.get('zone')

    request = get_compute().machineTypes().get(
        project=project, zone=zone, machineType=machine_type
    )
    response = request.execute()

    data_res = {
        'id': response.get('id'),
        'name': response.get('name'),
        'memoryMb': response.get('memoryMb'),
        'guestCpus': response.get('guestCpus')
    }

    ec = {'GoogleCloudCompute.MachineTypes(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Machine Types', data_res, removeNull=True
        ),
        ec,
        response
    )


def list_machine_types(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """

    project = SERVICE_ACT_PROJECT_ID
    zone = args.get('zone')
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().machineTypes().list(
        project=project,
        zone=zone,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'id': item.get('id'),
                    'name': item.get('name'),
                    'memoryMb': item.get('memoryMb'),
                    'guestCpus': item.get('guestCpus')
                }
                data_res.append(data_res_item)

        request = get_compute().machineTypes().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.MachineTypes(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown(
            'Google Cloud Compute Machine Types', data_res, removeNull=True
        ),
        ec,
        response
    )


def insert_firewall(args):
    """
    Creates a firewall rule in the specified project using the data included in the request.
    """
    project = args.get('project_id')
    if not project:
        project = SERVICE_ACT_PROJECT_ID

    config = {}
    if args.get('name'):
        config.update({'name': args.get('name')})

    if args.get('description'):
        config.update({'description': args.get('description')})

    if args.get('network'):
        config.update({'network': args.get('network')})

    if args.get('priority'):
        config.update({'priority': int(args.get('priority'))})

    if args.get('sourceRanges'):
        config.update({'sourceRanges': parse_resource_ids(args.get('sourceRanges'))})

    if args.get('destinationRanges'):
        config.update(
            {'destinationRanges': parse_resource_ids(args.get('destinationRanges'))}
        )

    if args.get('sourceTags'):
        config.update({'sourceTags': parse_resource_ids(args.get('sourceTags'))})

    if args.get('targetTags'):
        config.update({'targetTags': parse_resource_ids(args.get('targetTags'))})

    if args.get('sourceServiceAccounts'):
        config.update(
            {
                'sourceServiceAccounts': parse_resource_ids(
                    args.get('sourceServiceAccounts')
                )
            }
        )

    if args.get('targetServiceAccounts'):
        config.update(
            {
                'targetServiceAccounts': parse_resource_ids(
                    args.get('targetServiceAccounts')
                )
            }
        )

    if args.get('allowed'):
        config.update({'allowed': parse_firewall_rule(args.get('allowed'))})

    if args.get('denied'):
        config.update({'denied': parse_firewall_rule(args.get('denied'))})

    if args.get('direction'):
        config.update({'direction': args.get('direction')})

    if args.get('logConfigEnable'):
        log_config_enable = args.get('logConfigEnable') == 'true'
        config.update({'logConfig': {'enable': log_config_enable}})

    if args.get('disabled'):
        disabled = args.get('disabled') == 'true'
        config.update({'disabled': disabled})

    request = get_compute().firewalls().insert(project=project, body=config)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def patch_firewall(args):
    """
    Updates the specified firewall rule with the data included in the request.
    """
    project = SERVICE_ACT_PROJECT_ID

    config = {}
    if args.get('name'):
        name = args.get('name')
        config.update({'name': args.get('name')})
    else:
        name = None
        demisto.debug(f"{args.get('name')=} -> {name=}")

    if args.get('description'):
        config.update({'description': args.get('description')})

    if args.get('network'):
        config.update({'network': args.get('network')})

    if args.get('priority'):
        config.update({'priority': int(args.get('priority'))})

    if args.get('sourceRanges'):
        config.update({'sourceRanges': parse_resource_ids(args.get('sourceRanges'))})

    if args.get('destinationRanges'):
        config.update(
            {'destinationRanges': parse_resource_ids(args.get('destinationRanges'))}
        )

    if args.get('sourceTags'):
        config.update({'sourceTags': parse_resource_ids(args.get('sourceTags'))})

    if args.get('targetTags'):
        config.update({'targetTags': parse_resource_ids(args.get('targetTags'))})

    if args.get('sourceServiceAccounts'):
        config.update(
            {
                'sourceServiceAccounts': parse_resource_ids(
                    args.get('sourceServiceAccounts')
                )
            }
        )

    if args.get('targetServiceAccounts'):
        config.update(
            {
                'targetServiceAccounts': parse_resource_ids(
                    args.get('targetServiceAccounts')
                )
            }
        )

    if args.get('allowed'):
        config.update({'allowed': parse_firewall_rule(args.get('allowed'))})

    if args.get('denied'):
        config.update({'denied': parse_firewall_rule(args.get('denied'))})

    if args.get('direction'):
        config.update({'direction': args.get('direction')})

    if args.get('logConfigEnable'):
        log_config_enable = args.get('logConfigEnable') == 'true'
        config.update({'logConfig': {'enable': log_config_enable}})

    if args.get('disabled'):
        disabled = args.get('disabled') == 'true'
        config.update({'disabled': disabled})

    request = get_compute().firewalls().patch(project=project, firewall=name, body=config)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def list_firewalls(args):
    """
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = args.get('project_id')
    if not project:
        project = SERVICE_ACT_PROJECT_ID

    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().firewalls().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'name': item.get('name'),
                    'network': item.get('network'),
                    'priority': item.get('priority')
                }
                data_res.append(data_res_item)

        request = get_compute().firewalls().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Firewalls(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Firewalls', data_res, removeNull=True),
        ec,
        response
    )


def get_firewall(args):
    """
    Get a specified firewall rule.

    parameter: (string) name
        Name of the firewall rule to return.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')

    request = get_compute().firewalls().get(project=project, firewall=name)
    response = request.execute()

    data_res = {
        'name': response.get('name'),
        'network': response.get('network'),
        'priority': response.get('priority')
    }

    ec = {'GoogleCloudCompute.Firewalls(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Firewalls', data_res, removeNull=True),
        ec,
        response
    )


def delete_firewall(args):
    """
    Delete a specified firewall.

    parameter: (string) name
        Name of the firewall rule to delete.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')

    request = get_compute().firewalls().delete(project=project, firewall=name)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


# snapshots()
def delete_snapshot(args):
    """
    Delete a specified snapshot.

    parameter: (string) name
        Name of the Snapshot resource to delete.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')

    request = get_compute().snapshots().delete(project=project, snapshot=name)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def get_snapshot(args):
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')

    request = get_compute().snapshots().get(project=project, snapshot=name)
    response = request.execute()

    data_res = {
        'name': response.get('name'),
        'status': response.get('status'),
        'creationTimestamp': response.get('creationTimestamp')
    }

    ec = {'GoogleCloudCompute.Snapshots(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Snapshots', data_res, removeNull=True),
        ec,
        response
    )


def list_snapshots(args):
    """
    parameter: (string) zone
        Name of the zone for this request.
    parameter: (number) maxResults
        The maximum number of results per page that should be returned (Default 500).
    parameter: (string) filters
        A filter expression that filters resources listed in the response
    parameter: (string) pageToken
        Specifies a page token to use
    parameter: (orderBy) orderBy
        Sorts list results by a certain order.
        By default, results are returned in alphanumerical order based on the resource name

    """
    project = SERVICE_ACT_PROJECT_ID
    max_results = int(args.get('maxResults'))
    filters = args.get('filters')
    order_by = args.get('orderBy')
    page_token = args.get('pageToken')

    output = []
    data_res = []
    request = get_compute().snapshots().list(
        project=project,
        filter=filters,
        maxResults=max_results,
        orderBy=order_by,
        pageToken=page_token
    )
    while request:
        response = request.execute()
        if 'items' in response:
            for item in response['items']:
                output.append(item)
                data_res_item = {
                    'name': response.get('name'),
                    'status': response.get('status'),
                    'creationTimestamp': response.get('creationTimestamp')
                }
                data_res.append(data_res_item)

        request = get_compute().snapshots().list_next(
            previous_request=request, previous_response=response
        )

    ec = {'GoogleCloudCompute.Snapshots(val.id === obj.id)': output}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Snapshots', data_res, removeNull=True),
        ec,
        response
    )


def set_snapshot_labels(args):
    """"
    parameter: (dict) labels
        A list of labels to apply for this resource.
    parameter: (number) labelFingerprint
        The fingerprint of the previous set of labels for this resource, used to detect conflicts.
    parameter: (string) name
        Name or ID of the resource for this request.
    """
    project = SERVICE_ACT_PROJECT_ID
    name = args.get('name')
    labels = args.get('labels')

    labels = parse_labels(labels)
    body = {'labels': labels}

    if args.get('labelFingerprint'):
        body.update({'labelFingerprint': args.get('labelFingerprint')})

    request = get_compute().snapshots().setLabels(project=project, resource=name, body=body)
    response = request.execute()

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType')
    }

    ec = {'GoogleCloudCompute.Operations(val.id === obj.id)': response}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        ec,
        response
    )


def add_project_info_metadata(metadata):
    """
    Add or update project wide metadata.
    :param metadata:  Each metadata entry is a key/value pair separated by ';' like so: key=abc,value=123;key=abc,value=123
    """
    project = SERVICE_ACT_PROJECT_ID
    project_instance = get_compute().projects().get(project=project).execute()
    fingerprint = project_instance.get('tags', {}).get('fingerprint')
    items = parse_metadata_items(metadata)
    body = assign_params(
        fingerprint=fingerprint,
        items=items,
        kind='compute#metadata'
    )
    raw_res = get_compute().projects().setCommonInstanceMetadata(project=project, body=body).execute()
    data_res = {
        'status': raw_res.get('status'),
        'kind': raw_res.get('kind'),
        'name': raw_res.get('name'),
        'id': raw_res.get('id'),
        'progress': raw_res.get('progress'),
        'operationType': raw_res.get('operationType')
    }
    ec = {'GoogleCloudCompute.ProjectMetadata(val.id === obj.id)': raw_res}
    return_outputs(
        tableToMarkdown('Google Cloud Compute Project Metadata Update Operation Started Successfully', data_res,
                        removeNull=True),
        ec,
        raw_res
    )


def aggregated_list_instances_ip(args: Dict[str, Any]) -> CommandResults:
    """
    gcp-compute-aggregated-list-instances-by-ip: Retrieves instance information based on public IP in your project
    across all regions and zones.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip']`` IP Address to search on.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains instance
        details.
    """
    ip = args.get('ip')
    default_search_scope = demisto.params().get('default_search_scope')
    # 'default_search_scope' param was set use it for scope, else use the project in the service account.
    # 'compute.googleapis.com/Instance' asset-type needed to find static and ephemeral public IPs.
    if default_search_scope:
        request_asset = get_asset().v1().searchAllResources(
            scope=default_search_scope,
            assetTypes='compute.googleapis.com/Instance',
            query=f"additionalAttributes.externalIPs={ip}"
        )

    else:
        request_asset = get_asset().v1().searchAllResources(
            scope=f"projects/{SERVICE_ACT_PROJECT_ID}",
            assetTypes='compute.googleapis.com/Instance',
            query=f"additionalAttributes.externalIPs={ip}"
        )
    response_asset = request_asset.execute()
    if response_asset:
        raw = response_asset.get('results')[0].get('parentFullResourceName')
        if raw:
            project = raw.split('/')[-1]
        else:
            raise ValueError("Unable to find project of the asset")

        output = []
        data_res = []

        request_comp = get_compute().instances().aggregatedList(
            project=project,
        )
        while request_comp:
            response_comp = request_comp.execute()
            if 'items' in response_comp:
                for _, instances_scoped_list in response_comp['items'].items():
                    if 'warning' not in instances_scoped_list.keys():
                        for inst in instances_scoped_list.get('instances', []):
                            for interface in inst.get('networkInterfaces', []):
                                for config in interface.get('accessConfigs', []):
                                    # only add if 'natIP' (public IP) matches.
                                    if config.get('natIP') == ip:
                                        output.append(inst)
                                        data_res_item = {
                                            'id': inst.get('id'),
                                            'name': inst.get('name'),
                                            'machineType': inst.get('machineType'),
                                            'zone': inst.get('zone'),
                                        }
                                        data_res.append(data_res_item)

            request_comp = get_compute().instances().aggregatedList_next(
                previous_request=request_comp, previous_response=response_comp
            )

        return CommandResults(
            readable_output=tableToMarkdown('Google Cloud Compute Instances', data_res, removeNull=True),
            raw_response=response_comp,
            outputs_prefix='GoogleCloudCompute.Instances',
            outputs_key_field='id',
            outputs=output
        )
    else:
        return CommandResults(
            readable_output='Unable to find asset with IP address.  If you are using an organization service account,'
            'please make sure the default_search_scope integration parameter is set.')


def add_networks_tag(args: Dict[str, Any]) -> CommandResults:
    """
    gcp-compute-add-network-tag: Add network tag for the specified instance.

    Args:
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['instance']`` Name of the instance scoping this request.
            ``args['zone']`` The name of the zone for this request.
            ``args['tag']`` Network tag to add.  Tag must be unique, 1-63 characters long, and comply with RFC1035.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains Compute
        action details.
    """
    project = args.get('project_id')
    if not project:
        project = SERVICE_ACT_PROJECT_ID
    instance = args.get('instance')
    zone = args.get('zone')
    tag = args.get('tag')

    # first request is to get info on instance (fingerprint and current tags)
    inst_obj = get_compute().instances().get(project=project, zone=zone, instance=instance)
    inst_resp = inst_obj.execute()
    finger = inst_resp.get('tags').get('fingerprint')
    all_tags = inst_resp.get('tags').get('items', [])
    all_tags.append(tag)

    if finger:
        body = {"fingerprint": finger, "items": all_tags}
        request = get_compute().instances().setTags(project=project, zone=zone, instance=instance, body=body)
        response = request.execute()
    else:
        raise ValueError("Unable to find tag fingerprint")

    data_res = {
        'status': response.get('status'),
        'kind': response.get('kind'),
        'name': response.get('name'),
        'id': response.get('id'),
        'progress': response.get('progress'),
        'operationType': response.get('operationType'),
    }

    return CommandResults(
        readable_output=tableToMarkdown('Google Cloud Compute Operations', data_res, removeNull=True),
        raw_response=response,
        outputs_prefix='GoogleCloudCompute.Operations',
        outputs_key_field='id',
        outputs=response
    )


"""
EXECUTION CODE
"""


def main():
    if not SERVICE_ACCOUNT_FILE:
        raise DemistoException('Service Account Private Key file contents must be provided.')
    try:
        build_and_authenticate(GSERVICE)
        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()

        elif command == 'gcp-compute-insert-instance':
            create_instance(demisto.args())

        elif command == 'gcp-compute-get-instance':
            get_instance(demisto.args())

        elif command == 'gcp-compute-delete-instance':
            delete_instance(demisto.args())

        elif command == 'gcp-compute-start-instance':
            start_instance(demisto.args())

        elif command == 'gcp-compute-stop-instance':
            stop_instance(demisto.args())

        elif command == 'gcp-compute-reset-instance':
            reset_instance(demisto.args())

        elif command == 'gcp-compute-list-instances':
            list_instances(demisto.args())

        elif command == 'gcp-compute-set-instance-labels':
            set_instance_labels(demisto.args())

        elif command == 'gcp-compute-set-instance-metadata':
            set_instance_metadata(demisto.args())

        elif command == 'gcp-compute-set-instance-machine-type':
            set_instance_machine_type(demisto.args())

        elif command == 'gcp-compute-aggregated-list-instances':
            aggregated_list_instances(demisto.args())

        elif command == 'gcp-compute-get-image-from-family':
            get_image_from_family(demisto.args())

        elif command == 'gcp-compute-get-image':
            get_image(demisto.args())

        elif command == 'gcp-compute-networks-add-peering':
            networks_add_peering(demisto.args())

        elif command == 'gcp-compute-delete-network':
            delete_network(demisto.args())

        elif command == 'gcp-compute-get-network':
            get_network(demisto.args())

        elif command == 'gcp-compute-insert-network':
            insert_network(demisto.args())

        elif command == 'gcp-compute-list-networks':
            list_networks(demisto.args())

        elif command == 'gcp-compute-networks-remove-peering':
            networks_removepeering(demisto.args())

        elif command == 'gcp-compute-get-global-operation':
            get_global_operation(demisto.args())

        elif command == 'gcp-compute-get-zone-operation':
            get_zone_operation(demisto.args())

        elif command == 'gcp-compute-get-region-operation':
            get_region_operation(demisto.args())

        elif command == 'gcp-compute-list-zone-operation':
            list_zone_operation(demisto.args())

        elif command == 'gcp-compute-list-global-operation':
            list_global_operation(demisto.args())

        elif command == 'gcp-compute-list-region-operation':
            list_region_operation(demisto.args())

        elif command == 'gcp-compute-delete-zone-operation':
            delete_zone_operation(demisto.args())

        elif command == 'gcp-compute-delete-global-operation':
            delete_global_operation(demisto.args())

        elif command == 'gcp-compute-delete-region-operation':
            delete_region_operation(demisto.args())

        elif command == 'gcp-compute-delete-address':
            delete_address(demisto.args())

        elif command == 'gcp-compute-get-address':
            get_address(demisto.args())

        elif command == 'gcp-compute-insert-address':
            insert_address(demisto.args())

        elif command == 'gcp-compute-list-addresses':
            list_addresses(demisto.args())

        elif command == 'gcp-compute-aggregated-list-addresses':
            aggregated_list_addresses(demisto.args())

        elif command == 'gcp-compute-delete-global-address':
            delete_global_address(demisto.args())

        elif command == 'gcp-compute-get-global-address':
            get_global_address(demisto.args())

        elif command == 'gcp-compute-insert-global-address':
            insert_global_address(demisto.args())

        elif command == 'gcp-compute-list-global-addresses':
            list_global_addresses(demisto.args())

        elif command == 'gcp-compute-aggregated-list-disks':
            aggregated_list_disks(demisto.args())

        elif command == 'gcp-compute-create-disk-snapshot':
            create_disk_snapshot(demisto.args())

        elif command == 'gcp-compute-delete-disk':
            delete_disk(demisto.args())

        elif command == 'gcp-compute-get-disk':
            get_disk(demisto.args())

        elif command == 'gcp-compute-insert-disk':
            insert_disk(demisto.args())

        elif command == 'gcp-compute-list-disks':
            list_disks(demisto.args())

        elif command == 'gcp-compute-resize-disk':
            resize_disk(demisto.args())

        elif command == 'gcp-compute-set-disk-labels':
            set_disk_labels(demisto.args())

        elif command == 'gcp-compute-aggregated-list-disk-types':
            aggregated_list_disk_types(demisto.args())

        elif command == 'gcp-compute-get-disk-type':
            get_disk_type(demisto.args())

        elif command == 'gcp-compute-list-disk-types':
            list_disks_types(demisto.args())

        elif command == 'gcp-compute-list-images':
            list_images(demisto.args())

        elif command == 'gcp-compute-delete-image':
            delete_image(demisto.args())

        elif command == 'gcp-compute-set-image-labels':
            set_image_labels(demisto.args())

        elif command == 'gcp-compute-insert-image':
            insert_image(demisto.args())

        elif command == 'gcp-compute-instance-groups-add-instances':
            instance_groups_add_instances(demisto.args())

        elif command == 'gcp-compute-aggregated-list-instance-groups':
            aggregated_list_instance_groups(demisto.args())

        elif command == 'gcp-compute-delete-instance-group':
            delete_instance_group(demisto.args())

        elif command == 'gcp-compute-get-instance-group':
            get_instance_group(demisto.args())

        elif command == 'gcp-compute-insert-instance-group':
            insert_instance_group(demisto.args())

        elif command == 'gcp-compute-list-instance-groups':
            list_instance_groups(demisto.args())

        elif command == 'gcp-compute-list-instance-group-instances':
            list_instance_groups_instances(demisto.args())

        elif command == 'gcp-compute-instance-groups-remove-instances':
            instance_groups_remove_instances(demisto.args())

        elif command == 'gcp-compute-set-group-instance-named-ports':
            set_instance_group_named_ports(demisto.args())

        elif command == 'gcp-compute-get-region':
            get_region(demisto.args())

        elif command == 'gcp-compute-list-regions':
            list_regions(demisto.args())

        elif command == 'gcp-compute-get-zone':
            get_zone(demisto.args())

        elif command == 'gcp-compute-list-zones':
            list_zones(demisto.args())

        elif command == 'gcp-compute-aggregated-list-machine-types':
            aggregated_list_machine_types(demisto.args())

        elif command == 'gcp-compute-get-machine-type':
            get_machine_type(demisto.args())

        elif command == 'gcp-compute-list-machine-types':
            list_machine_types(demisto.args())

        elif command == 'gcp-compute-wait-for-zone-operation':
            wait_for_zone_operation(demisto.args())

        elif command == 'gcp-compute-wait-for-region-operation':
            wait_for_region_operation(demisto.args())

        elif command == 'gcp-compute-wait-for-global-operation':
            wait_for_global_operation(demisto.args())

        elif command == 'gcp-compute-insert-firewall':
            insert_firewall(demisto.args())

        elif command == 'gcp-compute-patch-firewall':
            patch_firewall(demisto.args())

        elif command == 'gcp-compute-list-firewall':
            list_firewalls(demisto.args())

        elif command == 'gcp-compute-get-firewall':
            get_firewall(demisto.args())

        elif command == 'gcp-compute-delete-firewall':
            delete_firewall(demisto.args())

        elif command == 'gcp-compute-set-snapshot-labels':
            set_snapshot_labels(demisto.args())

        elif command == 'gcp-compute-list-snapshots':
            list_snapshots(demisto.args())

        elif command == 'gcp-compute-get-snapshot':
            get_snapshot(demisto.args())

        elif command == 'gcp-compute-delete-snapshot':
            delete_snapshot(demisto.args())

        elif command == 'gcp-compute-project-info-add-metadata':
            add_project_info_metadata(**demisto.args())

        elif command == 'gcp-compute-add-network-tag':
            return_results(add_networks_tag(demisto.args()))

        elif command == 'gcp-compute-aggregated-list-instances-by-ip':
            return_results(aggregated_list_instances_ip(demisto.args()))

    except Exception as e:
        LOG(e)
        try:
            response = json.loads(e.content)  # type: ignore
            response = response['error']
            status_code = response.get('code')
            err_message = response.get('message')
            full_err_msg = f'error code: {status_code}\n{err_message}'
            return_error(full_err_msg)
        except AttributeError:
            return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
