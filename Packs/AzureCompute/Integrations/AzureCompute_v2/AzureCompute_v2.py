import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402


'''GLOBAL VARS'''
API_VERSION = '2023-03-01'
APP_NAME = 'ms-azure-compute'
DEFAULT_LIMIT = 50

# Image options to be used in the create_vm_command
IMAGES = {
    'ubuntu server 14.04 lts': {
        'publisher': 'Canonical',
        'offer': 'UbuntuServer',
        'sku': '14.04-LTS',
        'version': 'latest'
    },
    'ubuntu server 16.04 lts': {
        'publisher': 'Canonical',
        'offer': 'UbuntuServer',
        'sku': '16.04-LTS',
        'version': 'latest'
    },
    'ubuntu server 18.04 lts': {
        'publisher': 'Canonical',
        'offer': 'UbuntuServer',
        'sku': '18.04-LTS',
        'version': 'latest'
    },
    'red hat enterprise linux 7.6': {
        'publisher': 'RedHat',
        'offer': 'RHEL',
        'sku': '7-RAW',
        'version': 'latest'
    },
    'centos-based 7.5': {
        'publisher': 'OpenLogic',
        'offer': 'CentOS',
        'sku': '7.5',
        'version': 'latest'
    },
    'windows server 2012 r2 datacenter': {
        'publisher': 'MicrosoftWindowsServer',
        'offer': 'WindowsServer',
        'sku': '2012-R2-Datacenter',
        'version': 'latest'
    },
    'windows server 2016 datacenter': {
        'publisher': 'MicrosoftWindowsServer',
        'offer': 'WindowsServer',
        'sku': '2016-Datacenter',
        'version': 'latest'
    },
    'windows 10 pro version 1803': {
        'publisher': 'MicrosoftWindowsDesktop',
        'offer': 'Windows-10',
        'sku': 'rs4-pro',
        'version': 'latest'
    },
    'windows 10 pro version 1809': {
        'publisher': 'MicrosoftWindowsDesktop',
        'offer': 'Windows-10',
        'sku': 'rs5-pro',
        'version': 'latest'
    }
}

# Error messages for different provisioning states
CREATING_OR_UPDATING_ERR = 'Please wait for the VM to finish being' \
                           ' {} before executing this command. To retrieve the ' \
                           'last known state of the VM, execute the ' \
                           '`azure-vm-get-instance-details` command. '
DELETING_ERR = 'You cannot execute this command because the VM is being deleted.'
FAILED_ERR = 'Unable to power-off or power-on \'{}\' virtual machine ' \
             'because the following provisioning failure occurred during ' \
             'the vm\'s creation.\ncode: "{}"\nmessage: "{}"\nVisit the ' \
             'Azure Web Portal to take care of this issue.'

# Error messages determined by the provisioning state of the VM
PROVISIONING_STATE_TO_ERRORS = {
    'creating': CREATING_OR_UPDATING_ERR.format('created'),
    'updating': CREATING_OR_UPDATING_ERR.format('updated'),
    'deleting': DELETING_ERR,
    'failed': FAILED_ERR
}

'''HELPER FUNCTIONS'''


def screen_errors(error_message, *args, **kwargs):
    """
    Make sure that the values passed as args and the keys in kwargs do not appear in error messages

    parameter: (string) error_message
        The error message that needs to be screened for the values in args and the keys
        in kwargs

    parameter: (list) *args
        Arguments that need to be screened from error outputs and that will be replaced
        by x's enclosed by a '<' symbol on the left, and a '>' symbol on the right

    parameter: (dict) **kwargs
        Key-value pairs for each of which the user wishes to screen the key identifier string
        from the error_message and replace it with its assigned value string. Useful for
        when the user wishes to replace sensitive data with a value of their choosing
        instead of the default x's enclosed by '<', and '>' symbols on the left and right respectively

    returns:
        The error message free of sensitive information as determined by the values of
        args and the keys of kwargs
    """
    if isinstance(error_message, Exception):
        # Format Exception object as String
        error_as_dict = vars(error_message)
        updated_error_message = ''
        for key, val in error_as_dict.items():
            if updated_error_message != '':
                updated_error_message += '\n' + str(key) + ': ' + str(val)
            else:
                updated_error_message += str(key) + ': ' + str(val)
    elif not isinstance(error_message, str):
        # If not an Exception or a String, try to cast to a string
        updated_error_message = str(error_message)
    else:
        updated_error_message = error_message

    for argument in args:
        if argument != '' and argument in updated_error_message:
            length = len(argument)
            placeholder = '<' + 'x' * length + '>'
            updated_error_message = updated_error_message.replace(argument, placeholder)

    for key, value in kwargs.items():
        if key != '' and key in updated_error_message:
            updated_error_message = updated_error_message.replace(key, value)

    return updated_error_message


def assign_image_attributes(image):
    """
    Retrieve image properties determined by the chosen image

    returns:
        Image Properties Tuple (sku, publisher, offer, version)
    """
    image = image.lower()
    image_properties = IMAGES.get(image)
    if not image_properties:
        err_msg = 'Invalid value entered for the \'os_image\' argument. '
        err_msg += 'Only values from the provided options are accepted.'
        raise Exception(err_msg)
    sku = image_properties.get('sku')
    publisher = image_properties.get('publisher')
    offer = image_properties.get('offer')
    version = image_properties.get('version')
    return sku, publisher, offer, version


def create_vm_parameters(args, subscription_id, resource_group):
    """
    Construct the VM object

    Use the actual parameters passed to the 'azure-vm-create-instance' command
    to build a vm object that will be sent in the body of the command's associated
    API call.

    parameter: (dict) args
        Dictionary that contains the actual parameters that were passed to the
        'azure-vm-create-instance' command

    returns:
        Virtual Machine Object
    """
    # Retrieve relevant command arguments
    location = args.get('virtual_machine_location')
    vm_size = args.get('vm_size')
    image = args.get('os_image')
    sku = args.get('sku')
    publisher = args.get('publisher')
    version = args.get('version')
    offer = args.get('offer')
    vm_name = args.get('virtual_machine_name')
    admin_username = args.get('admin_username')
    admin_password = args.get('admin_password')
    nic_name = args.get('nic_name')
    full_nic_id = f"/subscriptions/{subscription_id}/resourceGroups/"  # type: ignore
    full_nic_id += f"{resource_group}/providers/Microsoft.Network/networkInterfaces/{nic_name}"

    if not image and not (sku and publisher and version and offer):
        err_msg = 'You must enter a value for the \'os_image\' argument '
        err_msg += 'or the group of arguments, \'sku\', \'publisher\', \'version\', and \'offer\'.'
        raise Exception(err_msg)

    if image:
        sku, publisher, offer, version = assign_image_attributes(image)

    # Construct VM object
    vm = {
        'location': location,
        'properties': {
            'hardwareProfile': {
                'vmSize': vm_size
            },
            'storageProfile': {
                'imageReference': {
                    'sku': sku,
                    'publisher': publisher,
                    'version': version,
                    'offer': offer
                },
                'osDisk': {
                    'caching': 'ReadWrite',
                    'managedDisk': {
                        'storageAccountType': 'Standard_LRS'
                    },
                    'name': vm_name,
                    'createOption': 'FromImage'
                }
            },
            'osProfile': {
                'adminUsername': admin_username,
                'computerName': vm_name,
                'adminPassword': admin_password
            },
            'networkProfile': {
                'networkInterfaces': [
                    {
                        'id': full_nic_id,
                        'properties': {
                            'primary': 'true'
                        }
                    }
                ]
            }
        },
        'name': vm_name
    }

    return vm


def create_nic_parameters(resource_group, subscription_id, args):
    """
    Construct the NIC object

    Use the actual parameters passed to the 'azure-vm-create-nic' command
    to build a nic object that will be sent in the body of the command's associated
    API call.

    parameter: (dict) args
        Dictionary that contains the actual parameters that were passed to the
        'azure-vm-create-nic' command

    returns:
        NIC Object
    """
    # Retrieve relevant command arguments
    location = args.get('nic_location')
    address_assignment_method = args.get('address_assignment_method')
    private_ip_address = args.get('private_ip_address')
    network_security_group = args.get('network_security_group')
    vnet_name = args.get('vnet_name')
    subnet_name = args.get('subnet_name')
    ip_config_name = args.get('ip_config_name')
    subnet_id = (f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/"
                 f"virtualNetworks/{vnet_name}/subnets/{subnet_name}")

    # Construct NIC object
    nic = {
        'location': location,
        'properties': {
            'ipConfigurations': [
                {
                    'name': ip_config_name,
                    'properties': {
                        'privateIPAllocationMethod': address_assignment_method,
                        'subnet': {
                            'id': subnet_id
                        }
                    }
                }
            ]
        }
    }

    if address_assignment_method == "Static":
        if not private_ip_address:
            err_msg = 'You have chosen to assign a "Static" IP address value to the interface, ' \
                      'so you must enter a value for the "private_ip_address" argument.'
            raise Exception(err_msg)
        nic['properties']['ipConfigurations'][0]['properties']['privateIPAddress'] = private_ip_address

    if network_security_group:
        network_security_group_id = (f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers"
                                     f"/Microsoft.Network/networkSecurityGroups/{network_security_group}")
        nic['properties']['networkSecurityGroup']['id'] = network_security_group_id

    return nic


def get_single_ip_details_from_list_of_ip_details(list_of_ip_details: list, ip_address):
    """Finds the associated details of target IP Address from a list of PublicIPAddressListResult objects.

    Args:
        list_of_ip_details (list):  List of PublicIPAddressListResult objects.
        ip_address (list | dict): IP Address to search for in list of PublicIPAddressListResult objects.
    """
    def search_entry_for_ip(data, key, value):
        if isinstance(data, list):
            for item in data:
                result = search_entry_for_ip(item, key, value)
                if result:
                    return result
        elif isinstance(data, dict):
            if key in data and data[key] == value:
                return True
            for val in data.values():
                result = search_entry_for_ip(val, key, value)
                if result:
                    return result
        return None

    for entry in list_of_ip_details:
        result = search_entry_for_ip(entry, "ipAddress", ip_address)
        if result:
            return entry
    return None


class MsGraphClient:
    """
      Microsoft Graph Client enables authorized access to Create and Manage Azure Virtual Machines.
      """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed, ok_codes, server,
                 subscription_id, certificate_thumbprint, private_key):

        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name, base_url=base_url, verify=verify,
            proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes, scope=Scopes.management_azure,
            certificate_thumbprint=certificate_thumbprint, private_key=private_key,
            command_prefix="azure-vm",
        )

        self.server = server
        self.subscription_id = subscription_id
        self.default_params = {"api-version": API_VERSION}

    def list_resource_groups(self, limit: int, tag: str = '', full_url: Optional[str] = ''):
        filter_by_tag = azure_tag_formatter(tag) if tag else None
        parameters = {'$filter': filter_by_tag, '$top': limit, 'api-version': '2021-04-01'} if not full_url else {}
        return self.ms_client.http_request(method='GET', params=parameters, url_suffix='', full_url=full_url)

    def list_subscriptions(self):
        parameters = {'api-version': '2020-01-01'}
        url = self.server + '/subscriptions'
        return self.ms_client.http_request(method='GET', full_url=url, params=parameters, url_suffix='')

    def list_vms(self, resource_group):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines"

        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params=self.default_params)

    def get_vm(self, resource_group, vm_name, expand='instanceView'):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        parameters = {'$expand': expand} | self.default_params
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params=parameters)

    def create_vm(self, args, resource_group):
        # Retrieve relevant command argument
        vm_name = args.get('virtual_machine_name')

        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"

        # Construct VM object utilizing parameters passed as command arguments
        payload = create_vm_parameters(args, self.subscription_id, resource_group)
        return self.ms_client.http_request(method='PUT', url_suffix=url_suffix, params=self.default_params, json_data=payload)

    def delete_vm(self, resource_group, vm_name):
        # Construct endpoint URI suffix (for de-allocation of compute resources)
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/deallocate"

        # Call API to deallocate compute resources
        self.ms_client.http_request(method='POST', url_suffix=url_suffix, params=self.default_params, resp_type="response")

        # Construct endpoint URI suffix (for deletion)
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"

        # Call API to delete
        return self.ms_client.http_request(
            method='DELETE', url_suffix=url_suffix, params=self.default_params, resp_type="response")

    def start_vm(self, resource_group, vm_name):
        # Retrieve relevant command arguments
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/start"

        # Call API
        return self.ms_client.http_request(
            method='POST', url_suffix=url_suffix, params=self.default_params, resp_type="response")

    def poweroff_vm(self, resource_group, vm_name, skip_shutdown):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/powerOff"
        parameters = {'skipShutdown': skip_shutdown} | self.default_params

        return self.ms_client.http_request(
            method='POST', url_suffix=url_suffix, params=parameters, resp_type="response")

    def get_all_public_ip_details(self):
        """
        List all public IPs belonging to your Azure subscription

        Returns:
            List of PublicIPAddressListResult Objects

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/list-all?tabs=HTTP
        """
        url_suffix = "/providers/Microsoft.Network/publicIPAddresses"
        parameters = {'api-version': '2022-09-01'}
        base_url = f"{self.server}/subscriptions/{self.subscription_id}"
        self.ms_client._base_url = base_url
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params=parameters)

    def validate_provisioning_state(self, resource_group, vm_name):
        """
        Ensure that the provisioning state of a VM is 'Succeeded'

        For all provisioning states other than 'Succeeded', this method will raise an
        exception with an informative error message.

        parameter: (dict) args
            The command arguments passed to either the `azure-vm-start-instance` or
            `azure-vm-poweroff-instance` commands

        returns:
            None
        """
        response = self.get_vm(resource_group, vm_name)
        # Retrieve relevant properties for checking provisioning state and returning
        # informative error messages if necessary

        properties = response.get('properties')
        provisioning_state = properties.get('provisioningState')
        statuses = properties.get('instanceView', {}).get('statuses')

        # Check if the current ProvisioningState of the VM allows for executing this command
        if provisioning_state.lower() == 'failed':
            for status in statuses:
                status_code = status.get('code')
                if 'provisioningstate/failed' in status_code.lower():
                    message = status.get('message')
                    err_msg = PROVISIONING_STATE_TO_ERRORS.get('failed')
                    raise Exception(err_msg.format(vm_name, status_code, message))  # type: ignore
            # In the case that the microsoft API changes and the status code is no longer
            # relevant, preventing the above exception with its detailed error message from
            # being raised, then raise the below exception with a more general error message
            err_msg = 'Cannot execute this command because the ProvisioningState of the VM is \'Failed\'.'
            raise Exception(err_msg)
        elif provisioning_state.lower() in PROVISIONING_STATE_TO_ERRORS:
            err_msg = PROVISIONING_STATE_TO_ERRORS.get(provisioning_state.lower())
            raise Exception(err_msg)

    def get_network_interface(self, resource_group, interface_name):
        url_suffix = f"{resource_group}/providers/Microsoft.Network/networkInterfaces/{interface_name}"
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params={"api-version": '2023-05-01'})

    def get_public_ip_details(self, resource_group, address_name):
        url_suffix = f"{resource_group}/providers/Microsoft.Network/publicIPAddresses/{address_name}"
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params={"api-version": '2023-05-01'})

    def create_nic(self, resource_group, args):
        # Retrieve relevant command argument
        nic_name = args.get('nic_name')
        url_suffix = f"{resource_group}/providers/Microsoft.Network/networkInterfaces/{nic_name}"

        # Construct VM object utilizing parameters passed as command arguments
        payload = create_nic_parameters(resource_group, self.subscription_id, args)
        return self.ms_client.http_request(
            method='PUT',
            url_suffix=url_suffix,
            params={'api-version': '2023-05-01'},
            json_data=payload
        )


def test_module(client: MsGraphClient):
    # Implicitly will test tenant, enc_token and subscription_id
    client.list_resource_groups(1)
    return 'ok'


# <-------- Resource Groups --------> #

def list_resource_groups_command(client: MsGraphClient, args: dict):
    """
    List all Resource Groups belonging to your Azure subscription

    returns:
        Resource-Group Objects
    """
    tag = args.get('tag', '')
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT

    resource_groups: List[dict] = []

    next_link = True
    while next_link and len(resource_groups) < limit:
        full_url = next_link if isinstance(next_link, str) else None
        response = client.list_resource_groups(limit, tag, full_url=full_url)
        # Retrieve relevant properties to return to context
        value = response.get('value')
        next_link = response.get('nextLink')

        for resource_group in value:
            resource_group_context = {
                'Name': resource_group.get('name'),
                'ID': resource_group.get('id'),
                'Location': resource_group.get('location'),
                'ProvisioningState': resource_group.get('properties', {}).get('provisioningState')
            }
            resource_groups.append(resource_group_context)

    resource_groups = resource_groups[:limit]
    title = 'List of Resource Groups'
    human_readable = tableToMarkdown(title, resource_groups, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.ResourceGroup',
        outputs_key_field='Name',
        outputs=resource_groups,
        readable_output=human_readable,
        raw_response=response
    )


# <-------- Subscriptions --------> #

def list_subscriptions_command(client: MsGraphClient):
    """
    List all subscriptions for this application

    returns:
        Subscription Objects
    """
    response = client.list_subscriptions()
    # Retrieve relevant properties to return to context
    value = response.get('value')
    subscriptions = []
    for subscription in value:
        subscription_context = {
            'Name': subscription.get('displayName'),
            'ID': subscription.get('id'),
            'State': subscription.get('state')
        }
        subscriptions.append(subscription_context)

    title = 'List of Subscriptions'
    human_readable = tableToMarkdown(title, subscriptions, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Subscription',
        outputs_key_field='ID',
        outputs=subscriptions,
        readable_output=human_readable,
        raw_response=response
    )


# <-------- Virtual Machines --------> #

def list_vms_command(client: MsGraphClient, args: dict, params: dict):
    """
    List the VM instances in the specified Resource Group

    demisto parameter: (string) resource_group
        Resource Group of the VMs

    returns:
        Virtual Machine Objects
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    response = client.list_vms(resource_group)

    vm_objects_list = response.get('value')

    vms = []
    for vm_object in vm_objects_list:
        vm_name = vm_object.get('name').lower()
        location = vm_object.get('location')
        properties = vm_object.get('properties')
        provisioning_state = properties.get('provisioningState')
        os_disk = properties.get('storageProfile', {}).get('osDisk')
        datadisk = os_disk.get('diskSizeGB', 'NA')
        vm_id = properties.get('vmId')
        os_type = os_disk.get('osType')
        vm = {
            'Name': vm_name,
            'ID': vm_id,
            'Size': datadisk,
            'OS': os_type,
            'Location': location,
            'ProvisioningState': provisioning_state,
            'ResourceGroup': resource_group
        }
        vms.append(vm)

    title = f'Microsoft Azure - List of Virtual Machines in Resource Group "{resource_group}"'
    table_headers = ['Name', 'ID', 'Size', 'OS', 'Location', 'ProvisioningState', 'ResourceGroup']
    human_readable = tableToMarkdown(title, vms, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Compute',
        outputs_key_field='Name',
        outputs=vms,
        readable_output=human_readable,
        raw_response=response
    )


def get_vm_command(client: MsGraphClient, args: dict, params: dict):
    """
    Get the properties of a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine you wish to view the details of

    returns:
        Virtual Machine Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    vm_name = args.get('virtual_machine_name')
    expand = args.get('expand', '')
    response = client.get_vm(resource_group, vm_name, expand)
    # Retrieve relevant properties to return to context
    vm_name = vm_name.lower()  # type: ignore
    properties = response.get('properties')
    os_disk = properties.get('storageProfile', {}).get('osDisk')
    datadisk = os_disk.get('diskSizeGB', 'NA')
    vm_id = properties.get('vmId')
    os_type = os_disk.get('osType')
    provisioning_state = properties.get('provisioningState')
    location = response.get('location')
    user_data = properties.get('userData')
    tags = response.get('tags')
    network_interfaces = properties.get('networkProfile', {}).get('networkInterfaces')
    statuses = properties.get('instanceView', {}).get('statuses', [])
    power_state = None
    for status in statuses:
        status_code = status.get('code')
        status_code_prefix = status_code[:status_code.find('/')]
        if status_code_prefix == 'PowerState':
            power_state = status.get('displayStatus')

    vm = {
        'Name': vm_name,
        'ID': vm_id,
        'Size': datadisk,
        'OS': os_type,
        'ProvisioningState': provisioning_state,
        'Location': location,
        'PowerState': power_state,
        'ResourceGroup': resource_group,
        'NetworkInterfaces': network_interfaces,
        'UserData': user_data,
        'Tags': tags
    }

    title = f'Properties of VM "{vm_name}"'
    table_headers = ['Name', 'ID', 'Size', 'OS', 'ProvisioningState', 'Location', 'PowerState']
    human_readable = tableToMarkdown(title, vm, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Compute',
        outputs_key_field='Name',
        outputs=vm,
        readable_output=human_readable,
        raw_response=response
    )


def create_vm_command(client: MsGraphClient, args: dict, params: dict):
    """
    Create a virtual machine instance with the specified OS image

    demisto parameter: (string) resource_group
        Resource group to which the new VM will belong

    demisto parameter: (string) virtual_machine_name
        Name to assign to the new virtual machine

    demisto parameter: (string) virtual_machine_location
        Region in which the vm will be hosted

    demisto parameter: (string) nic_name
        The name of the Network Interface to link the VM with. This must be created from the Azure Portal

    demisto parameter: (string) vm_size
        The name of a VirtualMachineSize which determines the size of the deployed vm

    demisto parameter: (string) os_image
        Choose the base operating system image of the vm

    demisto parameter: (string) sku
        SKU of the image to be used

    demisto parameter: (string) publisher
        Name of the publisher of the image

    demisto parameter: (string) version
        Version of the image to use

    demisto parameter: (string) offer
        Specifies the offer of the platform image or marketplace image used
        to create the virtual machine

    demisto parameter: (string) admin_username
        Admin Username to be used when creating the VM

    demisto parameter: (string) admin_password
        Admin Password to be used when creating the VM

    returns:
        Virtual Machine Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    response = client.create_vm(args, resource_group)

    # Retrieve relevant properties to return to context
    vm_name = response.get('name').lower()
    properties = response.get('properties')
    os_disk = properties.get('storageProfile', {}).get('osDisk')
    datadisk = os_disk.get('diskSizeGB', 'NA')
    vm_id = properties.get('vmId')
    os_type = os_disk.get('osType')
    provisioning_state = properties.get('provisioningState')
    location = response.get('location')

    vm = {
        'Name': vm_name,
        'ID': vm_id,
        'Size': datadisk,
        'OS': os_type,
        'ProvisioningState': provisioning_state,
        'Location': location,
        'ResourceGroup': resource_group
    }

    title = f'Created Virtual Machine "{vm_name}"'
    human_readable = tableToMarkdown(title, vm, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Compute',
        outputs_key_field='Name',
        outputs=vm,
        readable_output=human_readable,
        raw_response=response
    )


def delete_vm_command(client: MsGraphClient, args: dict, params: dict):
    """
    Delete a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to delete

    returns:
        Success message to the war room
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    vm_name = args.get('virtual_machine_name')

    client.delete_vm(resource_group, vm_name)
    return f'"{vm_name}" VM Deletion Successfully Initiated'


def start_vm_command(client: MsGraphClient, args: dict, params: dict):
    """
    Power-on a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-on

    returns:
        Virtual Machine Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    vm_name = args.get('virtual_machine_name')

    # Raise an exception if the VM isn't in the proper provisioning state
    client.validate_provisioning_state(resource_group, vm_name)

    client.start_vm(resource_group, vm_name)
    vm_name = vm_name.lower()   # type: ignore
    vm = {
        'Name': vm_name,
        'ResourceGroup': resource_group,
        'PowerState': 'VM starting'
    }

    title = f'Power-on of Virtual Machine "{vm_name}" Successfully Initiated'
    human_readable = tableToMarkdown(title, vm, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Compute',
        outputs_key_field='Name',
        outputs=vm,
        readable_output=human_readable,
        raw_response=vm
    )


def poweroff_vm_command(client: MsGraphClient, args: dict, params: dict):
    """
    Power-off a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-off

    returns:
        Virtual Machine Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    vm_name = args.get('virtual_machine_name')
    skip_shutdown = argToBoolean(args.get('skip_shutdown', False))

    # Raise an exception if the VM isn't in the proper provisioning state
    client.validate_provisioning_state(resource_group, vm_name)

    client.poweroff_vm(resource_group, vm_name, skip_shutdown)

    vm_name = vm_name.lower()   # type: ignore
    vm = {
        'Name': vm_name,
        'ResourceGroup': resource_group,
        'PowerState': 'VM stopping'
    }

    title = f'Power-off of Virtual Machine "{vm_name}" Successfully Initiated'
    human_readable = tableToMarkdown(title, vm, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Compute',
        outputs_key_field='Name',
        outputs=vm,
        readable_output=human_readable,
        raw_response=vm
    )


def get_network_interface_command(client: MsGraphClient, args: dict, params: dict):
    """
    Get the properties of a specified Network Interface

    demisto parameter: (string) resource_group
        Resource Group to which the network interface belongs

    demisto parameter: (string) nic_name
        Name of the network interface you wish to view the details of

    returns:
        Network Interface Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    interface_name = args.get('nic_name')
    response = client.get_network_interface(resource_group, interface_name)
    interface_name = interface_name.lower()  # type: ignore
    properties = response.get('properties')
    interface_id = response.get('id')
    mac_address = properties.get('macAddress', 'NA')
    network_security_group = properties.get('networkSecurityGroup', 'NA')
    is_primay_interface = properties.get('primary', 'NA')
    attached_virtual_machine = properties.get('virtualMachine', {}).get('id', 'NA')
    nic_type = properties.get('nicType', 'NA')
    location = response.get('location')
    dns_suffix = properties.get('dnsSettings', {}).get('internalDomainNameSuffix')

    ip_configurations = properties.get('ipConfigurations', [])

    ip_configs = []

    for ip_configuration in ip_configurations:
        ip_configs.append({
            "ConfigName": ip_configuration.get('name', "NA"),
            "ConfigID": ip_configuration.get('id', "NA"),
            "PrivateIPAddress": ip_configuration.get('properties', {}).get('privateIPAddress', "NA"),
            "PublicIPAddressID": ip_configuration.get('properties', {}).get('publicIPAddress', {}).get('id')
        })

    network_config = {
        'Name': interface_name,
        'ID': interface_id,
        'MACAddress': mac_address,
        'NetworkSecurityGroup': network_security_group,
        'IsPrimaryInterface': is_primay_interface,
        'Location': location,
        'AttachedVirtualMachine': attached_virtual_machine,
        'ResourceGroup': resource_group,
        'NICType': nic_type,
        'DNSSuffix': dns_suffix,
        'IPConfigurations': ip_configs
    }

    human_readable_network_config = {
        'Name': interface_name,
        'ID': interface_id,
        'MACAddress': mac_address,
        'PrivateIPAddresses': [ip.get("PrivateIPAddress") for ip in ip_configs],
        'NetworkSecurityGroup': network_security_group,
        'Location': location,
        'NICType': nic_type,
        'AttachedVirtualMachine': attached_virtual_machine
    }

    title = f'Properties of Network Interface "{interface_name}"'
    table_headers = ['Name', 'ID', 'MACAddress', 'PrivateIPAddresses', 'NetworkSecurityGroup',
                     'Location', 'NICType', 'AttachedVirtualMachine']
    human_readable = tableToMarkdown(title, human_readable_network_config, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Network.Interfaces',
        outputs_key_field='ID',
        outputs=network_config,
        readable_output=human_readable,
        raw_response=response
    )


def get_public_ip_details_command(client: MsGraphClient, args: dict, params: dict):
    """
    Get the properties of a specified Public IP Address

    demisto parameter: (string) resource_group
        Resource Group to which the public IP address belongs

    demisto parameter: (string) address_name
        The IPv4 or Name of the public ip address you wish to view the details of.

    returns:
        Public IP Address Object
    """
    address_name = args.get('address_name')
    if resource_group := (args.get('resource_group') or params.get('resource_group')):
        response = client.get_public_ip_details(resource_group, address_name)
        address_id = response.get('id')
    else:
        response_for_all_ips = client.get_all_public_ip_details().get('value')
        response = get_single_ip_details_from_list_of_ip_details(response_for_all_ips, address_name)
        if not response:
            raise ValueError(f"'{address_name}' was not found. "
                             "Please try specifying the resource group the IP would be associated with.")
        address_id = response.get('id')
        resource_group = address_id.split('resourceGroups/')[1].split('/providers')[0]

    # Retrieve relevant properties to return to context
    properties = response.get('properties')
    config_id = properties.get('ipConfiguration', {}).get('id')
    ip_address = properties.get('ipAddress', 'NA')
    ip_address_version = properties.get('publicIPAddressVersion', 'NA')
    ip_address_allocation_method = properties.get('publicIPAllocationMethod', 'NA')
    address_domain_name = properties.get('dnsSettings', {}).get('domainNameLabel', 'NA')
    address_fqdn = properties.get('dnsSettings', {}).get('fqdn', 'NA')
    config_name = response.get('name')
    location = response.get('location')

    ip_config = {
        'PublicIPAddressID': address_id,
        'PublicConfigName': config_name,
        'Location': location,
        'PublicConfigID': config_id,
        'ResourceGroup': resource_group,
        'PublicIPAddress': ip_address,
        'PublicIPAddressVersion': ip_address_version,
        'PublicIPAddressAllocationMethod': ip_address_allocation_method,
        'PublicIPAddressDomainName': address_domain_name,
        'PublicIPAddressFQDN': address_fqdn,
    }

    human_readable_ip_config = {
        'PublicConfigName': config_name,
        'Location': location,
        'PublicIPAddress': ip_address,
        'PublicIPAddressVersion': ip_address_version,
        'PublicIPAddressAllocationMethod': ip_address_allocation_method,
        "ResourceGroup": resource_group
    }

    title = f'Properties of Public Address "{address_name}"'
    table_headers = ['PublicConfigName', 'Location', 'PublicIPAddress', 'PublicIPAddressVersion',
                     'PublicIPAddressAllocationMethod', 'ResourceGroup']
    human_readable = tableToMarkdown(title, human_readable_ip_config, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Network.IPConfigurations',
        outputs_key_field='PublicIPAddressID',
        outputs=ip_config,
        readable_output=human_readable,
        raw_response=response
    )


def get_all_public_ip_details_command(client: MsGraphClient):
    """
    Get the properties of all Public IP Addresses in the configured subscription

    returns:
        List of Public IP Address Objects
    """
    response = client.get_all_public_ip_details()

    ip_objects_list = response.get('value', [])

    ips = []

    for ip_object in ip_objects_list:
        # Retrieve relevant properties to return to context
        properties = ip_object.get('properties', {})
        address_id = ip_object.get('id', '')
        config_id = properties.get('ipConfiguration', {}).get('id', '')
        ip_address = properties.get('ipAddress', 'NA')
        ip_address_version = properties.get('publicIPAddressVersion', 'NA')
        ip_address_allocation_method = properties.get('publicIPAllocationMethod', 'NA')
        address_domain_name = properties.get('dnsSettings', {}).get('domainNameLabel', 'NA')
        address_fqdn = properties.get('dnsSettings', {}).get('fqdn', 'NA')
        config_name = ip_object.get('name')
        location = ip_object.get('location')
        resource_group = address_id.split('resourceGroups/')[1].split('/providers')[0]
        ip_config = {
            'PublicIPAddressID': address_id,
            'PublicConfigName': config_name,
            'Location': location,
            'PublicConfigID': config_id,
            'ResourceGroup': resource_group,
            'PublicIPAddress': ip_address,
            'PublicIPAddressVersion': ip_address_version,
            'PublicIPAddressAllocationMethod': ip_address_allocation_method,
            'PublicIPAddressDomainName': address_domain_name,
            'PublicIPAddressFQDN': address_fqdn,
        }
        ips.append(ip_config)

    title = f'Microsoft Azure - List of Virtual Machines in Subscription "{client.subscription_id}"'
    table_headers = ['PublicConfigName', 'Location', 'PublicIPAddress', 'PublicIPAddressVersion',
                     'PublicIPAddressAllocationMethod']
    human_readable = tableToMarkdown(title, ips, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Network.IPConfigurations',
        outputs_key_field='PublicIPAddressID',
        outputs=ips,
        readable_output=human_readable,
        raw_response=response
    )


def create_nic_command(client: MsGraphClient, args: dict, params: dict):
    """
    Create a Network Interface with the specified interface parameters

    demisto parameter: (string) resource_group
        The resource group to which the new network interface will belong.

    demisto parameter: (string) nic_name
        The network interface name.

    demisto parameter: (string) nic_location
        The location in which to create the network interface.

    demisto parameter: (string) vnet_name
        The virtual network name of the inteface.

    demisto parameter: (string) subnet_name
        The subnet name of the inteface.

    demisto parameter: (string) address_assignment_method
         The address assignment method, the default is Dynamic.

    demisto parameter: (string) private_ip_address
        The private ip address of the interface incase you chose to use the static assignment method.

    demisto parameter: (string) ip_config_name
        The ip address config name.

    demisto parameter: (string) network_security_group
        The network security group of the interface.

    returns:
        Network Interface Object
    """
    resource_group = get_from_args_or_params(args=args, params=params, key='resource_group')
    response = client.create_nic(resource_group, args)

    # Retrieve relevant properties to return to context
    nic_name = response.get('name').lower()
    nic_id = response.get('id')
    location = response.get('location')
    properties = response.get('properties')
    network_security_group = properties.get('networkSecurityGroup', {}).get('id', 'NA')
    provisioning_state = properties.get('provisioningState', "NA")
    ip_configurations = properties.get('ipConfigurations', [])
    dns_suffix = properties.get('dnsSettings', {}).get('internalDomainNameSuffix')

    ip_configs = []
    for ip_configuration in ip_configurations:
        ip_configs.append({
            "ConfigName": ip_configuration.get('name', "NA"),
            "ConfigID": ip_configuration.get('id', "NA"),
            "PrivateIPAddress": ip_configuration.get('properties', {}).get('privateIPAddress', "NA"),
            "PublicIPAddressID": ip_configuration.get('properties', {}).get('publicIPAddress', {}).get('id', "NA"),
            "SubNet": ip_configuration.get('properties', {}).get('subnet', {}).get('id', "NA"),
        })

    nic = {
        'Name': nic_name,
        'ID': nic_id,
        'IPConfigurations': ip_configs,
        'ProvisioningState': provisioning_state,
        'Location': location,
        'ResourceGroup': resource_group,
        'NetworkSecurityGroup': network_security_group,
        'DNSSuffix': dns_suffix
    }

    human_readable_nic = {
        'Name': nic_name,
        'ID': nic_id,
        'PrivateIPAddresses': [ip.get("PrivateIPAddress") for ip in ip_configs],
        'NetworkSecurityGroup': network_security_group,
        'Location': location
    }

    title = f'Created Network Interface "{nic_name}"'
    table_headers = ['Name', 'ID', 'PrivateIPAddresses', 'NetworkSecurityGroup', 'Location']
    human_readable = tableToMarkdown(title, human_readable_nic, headers=table_headers, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.Network.Interfaces',
        outputs_key_field=['ID', 'Name'],
        outputs=nic,
        readable_output=human_readable,
        raw_response=response
    )


def main():
    params: dict = demisto.params()
    args = demisto.args()
    server = params.get('host', 'https://management.azure.com').rstrip('/')
    tenant = params.get('cred_token', {}).get('password') or params.get('tenant_id')
    auth_and_token_url = params.get('cred_auth_id', {}).get('password') or params.get('auth_id')
    if not tenant or not auth_and_token_url:
        return_error('Token and ID must be provided.')
    enc_key = params.get('cred_enc_key', {}).get('password') or params.get('enc_key')
    certificate_thumbprint = params.get('cred_certificate_thumbprint', {}).get(
        'password') or params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    verify = not params.get('unsecure', False)
    subscription_id = args.get('subscription_id') or params.get(
        'cred_subscription_id', {}).get('password') or params.get('subscription_id')
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    if not self_deployed and not enc_key:
        raise DemistoException('Key must be provided. For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be providedFor further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
    ok_codes = (200, 201, 202, 204)

    commands_without_args = {
        'test-module': test_module,
        'azure-list-subscriptions': list_subscriptions_command,
        'azure-vm-get-all-public-ip-details': get_all_public_ip_details_command
    }

    commands_with_args = {
        'azure-list-resource-groups': list_resource_groups_command
    }

    commands_with_args_and_params = {
        'azure-vm-list-instances': list_vms_command,
        'azure-vm-get-instance-details': get_vm_command,
        'azure-vm-start-instance': start_vm_command,
        'azure-vm-poweroff-instance': poweroff_vm_command,
        'azure-vm-create-instance': create_vm_command,
        'azure-vm-delete-instance': delete_vm_command,
        'azure-vm-get-public-ip-details': get_public_ip_details_command,
        'azure-vm-create-nic': create_nic_command,
        'azure-vm-get-nic-details': get_network_interface_command
    }

    '''EXECUTION'''
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        # Initial setup
        if not subscription_id:
            return_error('A subscription ID must be provided.')
        base_url = f"{server}/subscriptions/{subscription_id}/resourceGroups/"

        client = MsGraphClient(
            base_url=base_url, tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key, app_name=APP_NAME,
            verify=verify, proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes, server=server,
            subscription_id=subscription_id, certificate_thumbprint=certificate_thumbprint,
            private_key=private_key)

        if command == 'azure-vm-auth-reset':
            return_results(reset_auth())

        elif command in commands_without_args:
            return_results(commands_without_args[command](client))

        elif command in commands_with_args:
            return_results(commands_with_args[command](client, args))

        elif command in commands_with_args_and_params:
            return_results(commands_with_args_and_params[command](client, args, params))

    except Exception as e:
        screened_error_message = screen_errors(str(e), tenant)
        return_error(screened_error_message)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
