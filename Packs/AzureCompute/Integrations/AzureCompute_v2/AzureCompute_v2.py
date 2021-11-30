import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''GLOBAL VARS'''
API_VERSION = '2018-06-01'
APP_NAME = 'ms-azure-compute'

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


def create_vm_parameters(args, subscription_id):
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
    resource_group = args.get('resource_group')
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


class MsGraphClient:
    """
      Microsoft Graph Client enables authorized access to Create and Manage Azure Virtual Machines.
      """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed, ok_codes, server,
                 subscription_id):

        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name, base_url=base_url, verify=verify,
            proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes, scope=Scopes.management_azure)
        self.server = server
        self.subscription_id = subscription_id

    def list_resource_groups(self):
        parameters = {'api-version': '2018-05-01'}
        return self.ms_client.http_request(method='GET', params=parameters, url_suffix='')

    def list_subscriptions(self):
        parameters = {'api-version': '2017-05-10'}
        url = self.server + '/subscriptions'
        return self.ms_client.http_request(method='GET', full_url=url, params=parameters, url_suffix='')

    def list_vms(self, resource_group):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines"

        parameters = {'api-version': API_VERSION}
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params=parameters)

    def get_vm(self, resource_group, vm_name):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        parameters = {'$expand': 'instanceView', 'api-version': API_VERSION}
        return self.ms_client.http_request(method='GET', url_suffix=url_suffix, params=parameters)

    def create_vm(self, args):
        # Retrieve relevant command argument
        resource_group = args.get('resource_group')
        vm_name = args.get('virtual_machine_name')

        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        parameters = {'api-version': API_VERSION}

        # Construct VM object utilizing parameters passed as command arguments
        payload = create_vm_parameters(args, self.subscription_id)
        return self.ms_client.http_request(method='PUT', url_suffix=url_suffix, params=parameters, json_data=payload)

    def delete_vm(self, resource_group, vm_name):
        # Construct endpoint URI suffix (for de-allocation of compute resources)
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/deallocate"
        parameters = {'api-version': API_VERSION}

        # Call API to deallocate compute resources
        self.ms_client.http_request(method='POST', url_suffix=url_suffix, params=parameters, resp_type="response")

        # Construct endpoint URI suffix (for deletion)
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        parameters = {'api-version': API_VERSION}

        # Call API to delete
        return self.ms_client.http_request(
            method='DELETE', url_suffix=url_suffix, params=parameters, resp_type="response")

    def start_vm(self, resource_group, vm_name):
        # Retrieve relevant command arguments
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/start"
        parameters = {'api-version': API_VERSION}

        # Call API
        return self.ms_client.http_request(
            method='POST', url_suffix=url_suffix, params=parameters, resp_type="response")

    def poweroff_vm(self, resource_group, vm_name):
        url_suffix = f"{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/powerOff"
        parameters = {'api-version': API_VERSION}

        return self.ms_client.http_request(
            method='POST', url_suffix=url_suffix, params=parameters, resp_type="response")

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
        elif provisioning_state.lower() in PROVISIONING_STATE_TO_ERRORS.keys():
            err_msg = PROVISIONING_STATE_TO_ERRORS.get(provisioning_state.lower())
            raise Exception(err_msg)


def test_module(client: MsGraphClient, args: dict):
    # Implicitly will test tenant, enc_token and subscription_id
    client.list_resource_groups()
    return 'ok', None, None


# <-------- Resource Groups --------> #

def list_resource_groups_command(client: MsGraphClient, args: dict):
    """
    List all Resource Groups belonging to your Azure subscription

    returns:
        Resource-Group Objects
    """
    response = client.list_resource_groups()
    # Retrieve relevant properties to return to context
    value = response.get('value')
    resource_groups = []
    for resource_group in value:
        resource_group_context = {
            'Name': resource_group.get('name'),
            'ID': resource_group.get('id'),
            'Location': resource_group.get('location'),
            'ProvisioningState': resource_group.get('properties', {}).get('provisioningState')
        }
        resource_groups.append(resource_group_context)

    title = 'List of Resource Groups'
    human_readable = tableToMarkdown(title, resource_groups, removeNull=True)
    entry_context = {'Azure.ResourceGroup(val.Name && val.Name === obj.Name)': resource_groups}
    return human_readable, entry_context, response


# <-------- Subscriptions --------> #

def list_subscriptions_command(client: MsGraphClient, args: dict):
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
    entry_context = {'Azure.Subscription(val.ID && val.ID === obj.ID)': subscriptions}
    return human_readable, entry_context, response


# <-------- Virtual Machines --------> #

def list_vms_command(client: MsGraphClient, args: dict):
    """
    List the VM instances in the specified Resource Group

    demisto parameter: (string) resource_group
        Resource Group of the VMs

    returns:
        Virtual Machine Objects
    """
    resource_group = args.get('resource_group')
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

    title = 'Microsoft Azure - List of Virtual Machines in Resource Group "{}"'.format(resource_group)
    table_headers = ['Name', 'ID', 'Size', 'OS', 'Location', 'ProvisioningState', 'ResourceGroup']
    human_readable = tableToMarkdown(title, vms, headers=table_headers, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vms}
    return human_readable, entry_context, response


def get_vm_command(client: MsGraphClient, args: dict):
    """
    Get the properties of a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine you wish to view the details of

    returns:
        Virtual Machine Object
    """
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    response = client.get_vm(resource_group, vm_name)

    # Retrieve relevant properties to return to context
    vm_name = vm_name.lower()  # type: ignore
    properties = response.get('properties')
    os_disk = properties.get('storageProfile', {}).get('osDisk')
    datadisk = os_disk.get('diskSizeGB', 'NA')
    vm_id = properties.get('vmId')
    os_type = os_disk.get('osType')
    provisioning_state = properties.get('provisioningState')
    location = response.get('location')
    statuses = properties.get('instanceView', {}).get('statuses')
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
        'ResourceGroup': args.get('resource_group')
    }

    title = 'Properties of VM "{}"'.format(vm_name)
    table_headers = ['Name', 'ID', 'Size', 'OS', 'ProvisioningState', 'Location', 'PowerState']
    human_readable = tableToMarkdown(title, vm, headers=table_headers, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}
    return human_readable, entry_context, response


def create_vm_command(client: MsGraphClient, args: dict):
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
    response = client.create_vm(args)

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
        'ResourceGroup': args.get('resource_group')
    }

    title = 'Created Virtual Machine "{}"'.format(vm_name)
    human_readable = tableToMarkdown(title, vm, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}
    return human_readable, entry_context, response


def delete_vm_command(client: MsGraphClient, args: dict):
    """
    Delete a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to delete

    returns:
        Success message to the war room
    """
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    client.delete_vm(resource_group, vm_name)
    success_msg = '"{}" VM Deletion Successfully Initiated'.format(vm_name)
    return success_msg, None, None


def start_vm_command(client: MsGraphClient, args: dict):
    """
    Power-on a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-on

    returns:
        Virtual Machine Object
    """
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Raise an exception if the VM isn't in the proper provisioning state
    client.validate_provisioning_state(resource_group, vm_name)

    client.start_vm(resource_group, vm_name)
    vm_name = vm_name.lower()   # type: ignore
    vm = {
        'Name': vm_name,
        'ResourceGroup': args.get('resource_group'),
        'PowerState': 'VM starting'
    }

    title = 'Power-on of Virtual Machine "{}" Successfully Initiated'.format(vm_name)
    human_readable = tableToMarkdown(title, vm, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}

    return human_readable, entry_context, vm


def poweroff_vm_command(client: MsGraphClient, args: dict):
    """
    Power-off a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-off

    returns:
        Virtual Machine Object
    """
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Raise an exception if the VM isn't in the proper provisioning state
    client.validate_provisioning_state(resource_group, vm_name)

    client.poweroff_vm(resource_group, vm_name)

    vm_name = vm_name.lower()   # type: ignore
    vm = {
        'Name': vm_name,
        'ResourceGroup': args.get('resource_group'),
        'PowerState': 'VM stopping'
    }

    title = 'Power-off of Virtual Machine "{}" Successfully Initiated'.format(vm_name)
    human_readable = tableToMarkdown(title, vm, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}

    return human_readable, entry_context, vm


def main():
    params: dict = demisto.params()
    server = params.get('host', 'https://management.azure.com').rstrip('/')
    tenant = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id')
    enc_key = params.get('enc_key')
    verify = not params.get('unsecure', False)
    subscription_id = demisto.args().get('subscription_id') or demisto.params().get('subscription_id')
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    ok_codes = (200, 201, 202, 204)

    commands = {
        'test-module': test_module,
        'azure-vm-list-instances': list_vms_command,
        'azure-vm-get-instance-details': get_vm_command,
        'azure-vm-start-instance': start_vm_command,
        'azure-vm-poweroff-instance': poweroff_vm_command,
        'azure-vm-create-instance': create_vm_command,
        'azure-vm-delete-instance': delete_vm_command,
        'azure-list-resource-groups': list_resource_groups_command,
        'azure-list-subscriptions': list_subscriptions_command
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
            subscription_id=subscription_id)

        human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
        return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as e:
        screened_error_message = screen_errors(str(e), tenant)
        return_error(screened_error_message)


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
