import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''

import base64
import os
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

'''GLOBAL VARS'''

PARAMS = demisto.params()
USE_SSL = not demisto.params().get('unsecure')
TENANT_ID = PARAMS.get('tenant_id')
AUTH_AND_TOKEN_URL = PARAMS.get('auth_id', '').split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = PARAMS.get('enc_key')
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
else:
    TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
HOST = PARAMS.get('host', 'https://management.azure.com')
SERVER = HOST[:-1] if HOST.endswith('/') else HOST
API_VERSION = '2018-06-01'
SUBSCRIPTION_ID = demisto.args().get('subscription_id') or demisto.params().get('subscription_id')
BASE_URL = None
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

'''SETUP'''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
handle_proxy()


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


def validate_provisioning_state(args):
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
    response = get_vm(args)
    # Retrieve relevant properties for checking provisioning state and returning
    # informative error messages if necessary
    vm_name = response.get('name')
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


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.

    parameter: (date) d
        The date to convert to seconds

    returns:
        The date in seconds
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """
    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)
    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    valid_until = integration_context.get('valid_until')
    calling_context = demisto.callingContext.get('context', {})  # type: ignore[attr-defined]
    brand_name = calling_context.get('IntegrationBrand', '')
    instance_name = calling_context.get('IntegrationInstance', '')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token
    headers = {'Accept': 'application/json'}
    headers['X-Content-Version'] = CONTENT_RELEASE_VERSION
    headers['X-Branch-Name'] = CONTENT_BRANCH_NAME
    headers['X-Content-Name'] = brand_name or instance_name or 'Name not found'

    dbot_response = requests.post(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        data=json.dumps({
            'app_name': APP_NAME,
            'registration_id': AUTH_ID,
            'encrypted_token': get_encrypted(TENANT_ID, ENC_KEY)
        }),
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response - Exception: {}'.format(ex))
        raise Exception(msg)
    try:
        gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
        demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)
    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    demisto.setIntegrationContext({
        'access_token': access_token,
        'valid_until': time_now + expires_in
    })
    return access_token


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


def create_vm_parameters(args):
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
    full_nic_id = '/subscriptions/' + SUBSCRIPTION_ID + '/resourceGroups/'  # type: ignore
    full_nic_id += resource_group + '/providers/Microsoft.Network/networkInterfaces/' + nic_name

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


def http_request(method, url_suffix=None, data=None, headers=None,
                 params=None, codes=None, full_url=None, j_son=None):
    """
    A wrapper for requests lib to send our requests and handle requests and responses better

    parameter: (string) method
        A string denoting the http request method to use.
        Can be 'GET', 'POST, 'PUT', 'DELETE', etc.

    parameter: (string) url_suffix
        The API endpoint that determines which data we are trying to access/create/update
        in our call to the API

    parameter: (dict) data
        The key/value pairs to be form-encoded

    parameter: (dict) headers
        The headers to use with the request

    parameter: (dict) params
        The parameters to use with this request

    parameter: (set) codes
        The set of status codes against which the status code of the response should be checked

    parameter: (string) full_url
        The full url to make a request to. Only necessary in the case that you need to make
        an API request to an endpoint which differs in its base url from the majority of
        the API calls in the integration

    parameter: (dict) j_son
        A JSON serializable Python object to send in the body of the request

    returns:
        JSON Response Object
    """
    token = get_access_token()
    if not headers:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    try:
        url = full_url if full_url else None
        if not url:
            url = BASE_URL + url_suffix if url_suffix else BASE_URL
        r = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            params=params,
            verify=USE_SSL,
            json=j_son
        )
        green_codes = codes if codes else {200, 201, 202, 204}
        if r.status_code not in green_codes:
            if r.status_code in {401, 403}:
                err_msg = ('Permission error in API call to Azure Compute Integration, make sure the application'
                           ' has access to the relevant resources.')
            else:
                err_msg = 'Error in API call to Azure Compute Integration [{}] - {}'.format(r.status_code, r.reason)
                err = r.json().get('error')
                if err:
                    err_msg1 = '\nError code: {}\nError message: {}'.format(err.get('code'), err.get('message'))
                    err_msg += err_msg1
            raise Exception(err_msg)
        response = json.loads(r.content)
    except ValueError:
        response = r.content

    return response


'''MAIN FUNCTIONS / API CALLS'''

# <---------- Test Module ----------> #


def test_module():
    # Implicitly will test TENANT_ID, TOKEN and SUBSCRIPTION_ID
    list_resource_groups()
    demisto.results('ok')

# <-------- Resource Groups --------> #


def list_resource_groups():
    parameters = {'api-version': '2018-05-01'}
    response = http_request('GET', params=parameters, codes={200})
    return response


def list_resource_groups_command():
    """
    List all Resource Groups belonging to your Azure subscription

    returns:
        Resource-Group Objects
    """
    response = list_resource_groups()
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
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


# <-------- Subscriptions --------> #


def list_subscriptions():
    parameters = {'api-version': '2017-05-10'}
    url = SERVER + '/subscriptions'
    response = http_request('GET', full_url=url, params=parameters, codes={200})
    return response


def list_subscriptions_command():
    """
    List all subscriptions for this application

    returns:
        Subscription Objects
    """
    response = list_subscriptions()
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
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


# <-------- Virtual Machines --------> #

def list_vms(resource_group):
    # Construct endpoint URI suffix
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines'
    parameters = {'api-version': API_VERSION}
    # Call API
    response = http_request('GET', url_endpoint, params=parameters, codes={200})
    return response


def list_vms_command():
    """
    List the VM instances in the specified Resource Group

    demisto parameter: (string) resource_group
        Resource Group of the VMs

    returns:
        Virtual Machine Objects
    """
    resource_group = demisto.args().get('resource_group')
    response = list_vms(resource_group)

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
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def get_vm(args):
    # Retrieve relevant command arguments
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Construct endpoint URI suffix
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name
    parameters = {'$expand': 'instanceView', 'api-version': API_VERSION}

    # Call API
    response = http_request('GET', url_endpoint, params=parameters, codes={200})

    return response


def get_vm_command():
    """
    Get the properties of a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine you wish to view the details of

    returns:
        Virtual Machine Object
    """
    args = demisto.args()
    response = get_vm(args)

    # Retrieve relevant properties to return to context
    vm_name = response.get('name').lower()
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
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def create_vm(args):
    # Retrieve relevant command arguments
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Construct endpoint URI suffix
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name
    parameters = {'api-version': API_VERSION}

    # Construct VM object utilizing parameters passed as command arguments
    payload = create_vm_parameters(args)

    # Call API
    response = http_request('PUT', url_endpoint, params=parameters, j_son=payload)

    return response


def create_vm_command():
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
    args = demisto.args()
    response = create_vm(args)

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
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def delete_vm(args):
    # Retrieve relevant command arguments
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Construct endpoint URI suffix (for de-allocation of compute resources)
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name + '/deallocate'
    parameters = {'api-version': API_VERSION}

    # Call API to deallocate compute resources
    http_request('POST', url_endpoint, params=parameters, codes={200, 202})

    # Construct endpoint URI suffix (for deletion)
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name
    parameters = {'api-version': API_VERSION}

    # Call API to delete
    response = http_request('DELETE', url_endpoint, params=parameters, codes={200, 202, 204})

    return response


def delete_vm_command():
    """
    Delete a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to delete

    returns:
        Success message to the war room
    """
    args = demisto.args()
    delete_vm(args)
    success_msg = '"{}" VM Deletion Successfully Initiated'.format(args.get('virtual_machine_name'))
    demisto.results(success_msg)


def start_vm(args):
    # Retrieve relevant command arguments
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Construct endpoint URI suffix
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name + '/start'
    parameters = {'api-version': API_VERSION}

    # Call API
    response = http_request('POST', url_endpoint, params=parameters, codes={202})

    return response


def start_vm_command():
    """
    Power-on a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-on

    returns:
        Virtual Machine Object
    """
    args = demisto.args()
    vm_name = args.get('virtual_machine_name').lower()

    # Raise an exception if the VM isn't in the proper provisioning state
    validate_provisioning_state(args)

    start_vm(args)

    vm = {
        'Name': vm_name,
        'ResourceGroup': args.get('resource_group'),
        'PowerState': 'VM starting'
    }

    title = 'Power-on of Virtual Machine "{}" Successfully Initiated'.format(vm_name)
    human_readable = tableToMarkdown(title, vm, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': vm,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


def poweroff_vm(args):
    # Retrieve relevant command arguments
    resource_group = args.get('resource_group')
    vm_name = args.get('virtual_machine_name')

    # Construct endpoint URI suffix
    url_endpoint = resource_group + '/providers/Microsoft.Compute/virtualMachines/' + vm_name + '/powerOff'
    parameters = {'api-version': API_VERSION}

    # Call API
    response = http_request('POST', url_endpoint, params=parameters, codes={202})

    return response


def poweroff_vm_command():
    """
    Power-off a specified Virtual Machine

    demisto parameter: (string) resource_group
        Resource Group to which the virtual machine belongs

    demisto parameter: (string) virtual_machine_name
        Name of the virtual machine to power-off

    returns:
        Virtual Machine Object
    """
    args = demisto.args()
    vm_name = args.get('virtual_machine_name').lower()

    # Raise an exception if the VM isn't in the proper provisioning state
    validate_provisioning_state(args)

    poweroff_vm(args)

    vm = {
        'Name': vm_name,
        'ResourceGroup': args.get('resource_group'),
        'PowerState': 'VM stopping'
    }

    title = 'Power-off of Virtual Machine "{}" Successfully Initiated'.format(vm_name)
    human_readable = tableToMarkdown(title, vm, removeNull=True)
    entry_context = {'Azure.Compute(val.Name && val.Name === obj.Name)': vm}
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': vm,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': entry_context
    })


'''COMMAND SWITCHBOARD'''

commands = {
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

try:
    # Initial setup
    if not SUBSCRIPTION_ID:
        return_error('A subscription ID must be provided.')
    BASE_URL = SERVER + '/subscriptions/' + SUBSCRIPTION_ID + '/resourceGroups/'

    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() in commands.keys():
        commands[demisto.command()]()

except Exception as e:
    screened_error_message = screen_errors(str(e), TENANT_ID)
    return_error(screened_error_message)
