import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import time
import urllib.parse
import httplib2

import googleapiclient
from oauth2client import service_account
from googleapiclient import discovery


''' IMPORTS '''


''' GLOBALS/PARAMS '''

# Params for assembling object of the Service Account Credentials File Contents
PARAMS = demisto.params()
SERVICE_ACT_PROJECT_ID = PARAMS.get('project_id')
PRIVATE_KEY_ID = PARAMS.get('private_key_id_creds', {}).get('password') or PARAMS.get('private_key_id')
PRIVATE_KEY = PARAMS.get('private_key_creds', {}).get('password') or PARAMS.get('private_key')
CLIENT_EMAIL = PARAMS.get('client_email_creds', {}).get('identifier') or PARAMS.get('client_email')
CLIENT_ID = PARAMS.get('client_email_creds', {}).get('password') or PARAMS.get('client_id')
CLIENT_X509_CERT_URL = PARAMS.get('client_x509_cert_url')
PROXY = PARAMS.get('proxy')
DISABLE_SSL = PARAMS.get('insecure')

AUTH_JSON = {
    'type': 'service_account',  # guardrails-disable-line
    'project_id': SERVICE_ACT_PROJECT_ID,
    'private_key_id': PRIVATE_KEY_ID,
    'private_key': PRIVATE_KEY.replace('\\n', '\n'),
    'client_email': CLIENT_EMAIL,
    'client_id': CLIENT_ID,
    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
    'token_uri': 'https://oauth2.googleapis.com/token',
    'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
    'client_x509_cert_url': CLIENT_X509_CERT_URL
}

# Params for constructing googleapiclient service object
API_VERSION = 'v1'
GRM = 'cloudresourcemanager'
SCOPE = ["https://www.googleapis.com/auth/cloud-platform"]


''' HELPER FUNCTIONS '''


# disable-secrets-detection-start
def get_http_client_with_proxy():
    proxies = handle_proxy()
    if not proxies or not proxies['https']:
        raise Exception('https proxy value is empty. Check Demisto server configuration')
    https_proxy = proxies['https']
    if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
        https_proxy = 'https://' + https_proxy
    parsed_proxy = urllib.parse.urlparse(https_proxy)
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
        proxy_host=parsed_proxy.hostname,
        proxy_port=parsed_proxy.port,
        proxy_user=parsed_proxy.username,
        proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=DISABLE_SSL)


# disable-secrets-detection-end


def get_credentials_obj():
    """Gets valid user credentials from storage.

    Returns:
        Credentials, the obtained credential.
    """
    cred = service_account.ServiceAccountCredentials.from_json_keyfile_dict(AUTH_JSON,
                                                                            scopes=SCOPE)  # type: ignore

    return cred.create_delegated(CLIENT_EMAIL)


def build_and_authenticate():
    """
    Return a service object via which can call GRM API.

    Use the service_account credential file generated in the Google Cloud
    Platform to build the Google Resource Manager API Service object.

    returns: service
        Google Resource Manager API Service object via which commands in the
        integration will make API calls
    """
    service_credentials = get_credentials_obj()

    if PROXY or DISABLE_SSL:
        http_client = service_credentials.authorize(get_http_client_with_proxy())
        return discovery.build(GRM, API_VERSION, http=http_client)
    else:
        handle_proxy()

    return discovery.build(GRM, API_VERSION, credentials=service_credentials)


def make_project_body(project_body):
    """
    Create and return the project body argument used when calling the GRM API
    to create or update a project.

    returns: (dict) body
        dict object formatted to be used in the create or update API call
    """
    keys = list(project_body.keys())
    body = {}
    if 'project_id' in keys:
        body['projectId'] = project_body['project_id']
    if 'parent_type' in keys and 'parent_id' in keys:
        body['parent'] = {
            'type': project_body['parent_type'],
            'id': project_body['parent_id']
        }
    if 'name' in keys:
        body['name'] = project_body['name']
    if 'label_keys' in keys and 'label_values' in keys:
        label_keys = argToList(project_body['label_keys'])
        label_values = argToList(project_body['label_values'])
        if len(label_keys) != len(label_values):
            err_msg = 'Label attrs array and Label values array do not match'\
                ' in length.\nThese arrays need to match in length because '\
                'each string in label_keys is assigned the value of the '\
                'string in the corresponding index in the label_values array.'
            return_error(err_msg)
        else:
            body['labels'] = {}
            for lbl_key, lbl_val in zip(label_keys, label_values):
                body['labels'][lbl_key] = lbl_val
    return body


def poll_operation(operation):
    """
    Query status of long running operation and return results if completed.

    parameter: (Operation) operation
        operation object returned from calls to the API that have a long
        execution time

    raises: Exception
        if long executing operation results in an error then raises an
        Exception that the operation was unsuccessful

    returns: (Project) response
        dict object representation of a Project Resource
    """
    name = operation.get('name')
    while not operation.get('done'):
        # delay 1 second and then retry and see if the operation finished
        time.sleep(1)
        service = build_and_authenticate()
        # get the latest state of the long-running operation
        operation = service.operations().get(name=name).execute()
    if not operation.get('error'):
        return operation.get('response')
    else:
        exc = operation.get('error')
        err_code = exc.get('code')
        err_msg = exc.get('message')
        full_err_msg = "error code: {}\nerror message: {}".format(err_code, err_msg)
        return_error(full_err_msg)


''' MAIN FUNCTIONS '''


def test_module():
    """If the list_projects_command executes successfully then the test completed and returns 'ok'"""
    build_and_authenticate()
    demisto.results('ok')


def create_project(service, project_body):
    """Build service object and return the result of calling the API 'create' function for the projects resource."""
    body = make_project_body(project_body)
    operation = service.projects().create(body=body).execute()
    # Get back result of long-running operation
    response = poll_operation(operation)
    return response


def create_project_command(service):
    """
    Create a project in the Google Cloud Platform.

    demisto parameter: (string) project_id
        The unique ID of the Project to create

    demisto parameter: (string) name
        The name to give the new Project

    demisto parameter: (string) parent_id
        The id of the parent resource

    demisto parameter: (string) parent_type
        The resource type the parent_id is for

    demisto parameter: (list) label_keys
        The label keys to associate with the new Project

    demisto parameter: (list) label_values
        The label values to associate with the new Project. The values are
        assigned to their corresponding indexed key in label_keys

    returns:
        The new Project resource object
    """
    args = demisto.args()
    response = create_project(service, args)
    # Parse response into context
    context = {
        'Name': response.get('name'),
        'ID': response.get('projectId'),
        'Number': response.get('projectNumber'),
        'State': response.get('lifecycleState'),
        'CreateTime': response.get('createTime'),
        'Parent': {
            'ID': response.get('parent').get('id'),
            'Type': response.get('parent').get('type')
        },
        'Label': response.get('labels')
    }
    md = tableToMarkdown('Google Cloud Project Successfully Created', context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Project(val.ID && val.ID === obj.ID)': context
        }
    })


def delete_project(service, project_id):
    """Build service object and return the result of calling the API 'delete' function for the projects resource."""
    operation = service.projects().delete(projectId=project_id).execute()
    return operation


def delete_project_command(service):
    """
    Deletes the specified project.

    Set the lifcycleState attribute of a specified project to DELETE_REQUESTED.

    demisto parameter: (string) project_id
        The unique ID of the Project to restore

    returns:
        Deleted project resource object
    """
    project_id = demisto.args()['project_id']
    response = delete_project(service, project_id)
    if not response:
        response = get_project(service, project_id)
        # Parse response into context
        context = {
            'Name': response.get('name'),
            'ID': response.get('projectId'),
            'Number': response.get('projectNumber'),
            'State': response.get('lifecycleState'),
            'CreateTime': response.get('createTime'),
            'Parent': {
                'ID': response.get('parent').get('id'),
                'Type': response.get('parent').get('type')
            },
            'Label': response.get('labels')
        }
        md = tableToMarkdown('Project State Successfully Set To DELETE_REQUESTED', context)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': {
                'GRM.Project(val.ID && val.ID === obj.ID)': context
            }
        })
    else:
        return_error('Unexpected return object from {} execution. Results uncertain.'.format(demisto.command()))


def undelete_project(service, project_id):
    """Build service object and return the result of calling the API 'undelete' function for the projects resource."""
    operation = service.projects().undelete(projectId=project_id).execute()
    return operation


def undelete_project_command(service):
    """
    Restores the specified project.

    Sets the lifcycleState attribute of a specified project back to ACTIVE.

    demisto parameter: (string) project_id
        The unique ID of the Project to restore

    returns:
        Restored project resource object
    """
    project_id = demisto.args()['project_id']
    response = undelete_project(service, project_id)
    if not response:
        response = get_project(service, project_id)
        # Parse response into context
        context = {
            'Name': response.get('name'),
            'ID': response.get('projectId'),
            'Number': response.get('projectNumber'),
            'State': response.get('lifecycleState'),
            'CreateTime': response.get('createTime'),
            'Parent': {
                'ID': response.get('parent').get('id'),
                'Type': response.get('parent').get('type')
            },
            'Label': response.get('labels')
        }
        md = tableToMarkdown('Project State Successfully Set To ACTIVE', context)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': {
                'GRM.Project(val.ID && val.ID === obj.ID)': context
            }
        })
    else:
        return_error('Unexpected return object from {} execution. Results uncertain.'.format(demisto.command()))


def get_project(service, project_id):
    """Build service object and return the result of calling the API 'get' function for the projects resource."""
    operation = service.projects().get(projectId=project_id).execute()
    return operation


def get_project_command(service):
    """
    Retrieves the Project identified by the specified project_id.

    demisto parameter: (string) project_id
        The unique ID of the Project to fetch

    returns:
        The project resource object specified by the project_id
    """
    project_id = demisto.args().get('project_id')
    response = get_project(service, project_id)
    # Parse response into context
    context = {
        'Name': response.get('name'),
        'ID': response.get('projectId'),
        'Number': response.get('projectNumber'),
        'State': response.get('lifecycleState'),
        'CreateTime': response.get('createTime'),
        'Parent': {
            'ID': response.get('parent').get('id'),
            'Type': response.get('parent').get('type')
        },
        'Label': response.get('labels')
    }
    md = tableToMarkdown('Details of Fetched Google Cloud Project', context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Project(val.ID && val.ID === obj.ID)': context
        }
    })


def list_projects(service, filter_list):
    """Build service object and return the result of calling the API 'list' function for the projects resource."""
    operation = service.projects().list(filter=filter_list).execute()
    return operation


def list_projects_command(service):
    """
    Lists Projects that are visible to the user and satisfy the specified
    filter if one is provided.

    demisto parameter: (string) filter -- optional
        An expression for filtering the results of the request

    returns:
        Project resource objects that are visible to the user and satisfy the specified filter
    """
    filter_list = demisto.args().get('filter') if 'filter' in demisto.args() else None
    response = list_projects(service, filter_list)
    contexts = []
    for project in response.get('projects', []):
        # Parse project into context
        context = {
            'Name': project.get('name'),
            'ID': project.get('projectId'),
            'Number': project.get('projectNumber'),
            'State': project.get('lifecycleState'),
            'CreateTime': project.get('createTime'),
            'Parent': {
                'ID': project.get('parent').get('id'),
                'Type': project.get('parent').get('type')
            },
            'Label': project.get('labels')
        }
        contexts.append(context)
    title = "Projects Filtered by '{}'".format(filter_list) if filter_list else "All Projects"
    md = tableToMarkdown(title, contexts)
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Project(val.ID && val.ID === obj.ID)': contexts
        }
    }
    demisto.results(entry)


def update_project(service, project_id, project_body):
    """Build service object and return the result of calling the API 'update' function for the projects resource."""
    operation = service.projects().update(projectId=project_id, body=project_body).execute()
    return operation


def update_project_command(service):
    """
    Updates the attributes of the Project identified by the specified project_id.

    demisto parameter: (string) project_id
        The unique ID of the Project to update

    demisto parameter: (string) name
        The string to update the Project name with

    demisto parameter: (string) parent_id
        The id of the parent resource

    demisto parameter: (string) parent_type
        The resource type the parent_id is for

    demisto parameter: (list) label_keys
        The label keys to associate with this Project

    demisto parameter: (list) label_values
        The label values to associate with this Project. The values are
        assigned to their corresponding indexed key in label_keys

    returns:
        The updated Project resource object
    """
    project_id = demisto.args().get('project_id')
    project_body = demisto.args()
    project_body = make_project_body(project_body)
    response = update_project(service, project_id, project_body)
    # Parse response into context
    context = {
        'Name': response.get('name'),
        'ID': response.get('projectId'),
        'Number': response.get('projectNumber'),
        'State': response.get('lifecycleState'),
        'CreateTime': response.get('createTime'),
        'Parent': {
            'ID': response.get('parent').get('id'),
            'Type': response.get('parent').get('type')
        },
        'Label': response.get('labels')
    }
    md = tableToMarkdown('Details of Updated Google Cloud Project', context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Project(val.ID && val.ID === obj.ID)': context
        }
    })


def search_organizations(service, req_body):
    """
    Build service object and return the result of calling the API 'search' function for the organizations resource.
    """
    operation = service.organizations().search(body=req_body).execute()
    return operation


def search_organizations_command(service):
    """
    Searches Organization resources that are visible to the user and satisfy
    the specified filter (if provided).

    demisto parameter: (number) pageSize -- optional
        The maximum number of Organizations to return in the response

    demisto parameter: (string) pageToken -- optional
        A pagination token returned from a previous call to organizations.search()
        that indicates from where listing should continue

    demisto parameter: (string) filter -- optional
        Used to filter the Organizations to return in the response

    returns:
        List of Organization resource objects that are visible to the user and satisfy the specified filter
    """
    args = demisto.args()
    # make request body
    req_body = {
        'pageSize': args.get('page_size') if 'page_size' in args else None,
        'pageToken': args.get('page_token') if 'page_token' in args else None,
        'filter': args.get('filter') if 'filter' in args else None
    }

    contexts = []
    contents = []
    next_page = True
    # continue calling the API with the appropriate pageToken argument while there are still results to be received
    # from the search organizations API call - this is useful in the case that a pageSize argument was given in this
    # command that was less than the total amount of results returned from the original call to the API
    while next_page:
        response = search_organizations(service, req_body)
        contents.append(response)
        for organization in response.get('organizations', []):
            # Parse organization into context
            context = {
                'Name': organization.get('name'),
                'State': organization.get('lifecycleState'),
                'CreateTime': organization.get('creationTime'),
                'Owner': {
                    'CustomerID': organization.get('owner').get('directoryCustomerId')
                },
            }
            contexts.append(context)
        if 'nextPageToken' not in response:
            next_page = False
        else:
            req_body['pageToken'] = response['nextPageToken']
    md = tableToMarkdown("Organizations", contexts)
    entry = {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Organization(val.Name && val.Name === obj.Name)': contexts
        }
    }
    demisto.results(entry)


def get_organization(service, name):
    """
    Build service object and return the result of calling the API 'get' function for the organizations resource.

    parameter: (string) name
        name of the Organization in format <type/number> e.g. 'organizations/1245345444'

    returns: (Organization) operation
        The response from calling the API that takes the form of a Organization object
    """
    operation = service.organizations().get(name=name).execute()
    return operation


def get_organization_command(service):
    """
    Fetches an Organization resource identified by the specified resource name.

    demisto parameter: (string) name
        name of the Organization in format <type/number> e.g. 'organizations/1245345444'

    returns:
        The organization object with its associated fields
    """
    name = demisto.args().get('name')
    response = get_organization(service, name)
    # Parse response into context
    context = {
        'Name': response.get('name'),
        'State': response.get('lifecycleState'),
        'CreateTime': response.get('creationTime'),
        'Owner': {
            'CustomerID': response.get('owner').get('directoryCustomerId')
        },
    }
    md = tableToMarkdown("Details of Fetched Organization", context)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'GRM.Organization(val.Name && val.Name === obj.Name)': context
        }
    })


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    # Command Switch Panel
    commands = {
        "grm-create-project": create_project_command,
        "grm-delete-project": delete_project_command,
        "grm-get-project": get_project_command,
        "grm-list-projects": list_projects_command,
        "grm-update-project": update_project_command,
        "grm-search-organizations": search_organizations_command,
        "grm-get-organization": get_organization_command,
        "grm-undelete-project": undelete_project_command,
    }

    LOG('Command being called is %s' % (demisto.command()))

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif demisto.command() in list(commands.keys()):
            service = build_and_authenticate()
            commands[demisto.command()](service)

    except Exception as exc:
        # Output HttpError errors from googleapiclient to the warroom nicely
        if isinstance(exc, googleapiclient.errors.HttpError):
            if exc.resp.get('content-type').startswith('application/json'):  # pylint: disable=no-member
                err_json = json.loads(exc.content.decode('utf-8'))  # pylint: disable=no-member
                error_code = dict_safe_get(err_json, ['error', 'code'])
                error_msg = dict_safe_get(err_json, ['error', 'message'])
                error_reason = dict_safe_get(err_json, ['error', 'errors', 0, 'reason'])
                error_status = dict_safe_get(err_json, ['error', 'status'])
                full_err_msg = "error code: {}\n{}\nreason: {}\nstatus: {}".format(error_code, error_msg,
                                                                                   error_reason, error_status)
                return_error(full_err_msg)
        else:
            return_error(str(exc))


if __name__ in ("__builtin__", "builtins"):
    main()
