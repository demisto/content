"""
Symantec Endpoint Detection and Response (EDR) integration with Symantec-EDR 4.6
"""
import requests.auth

from CommonServerPython import *
from requests.auth import HTTPBasicAuth
from typing import Dict, Any
import requests
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
handle_proxy()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TOKEN_ENDPOINT = '/atpapi/oauth2/tokens'
INTEGRATION_NAME = 'Symantec EDR'

''' CLIENT CLASS '''


class Client(BaseClient):

    """Client class to interact with the service API
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str,
                 client_id: str,
                 client_key: str,
                 verify=bool,
                 proxy=bool):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200,),
        )
        self.TokenUrl = f'{base_url}{TOKEN_ENDPOINT}'
        self.ClientID = client_id
        self.ClientSecret = client_key

    def access_token(self):
        """
        Generate Access token
        :return: access_token
        """
        # headers = {
        #     "Content-Type": "application/x-www-form-urlencoded",
        #     "Accept": "application/json"
        # }

        payload = {
            "grant_type": 'client_credentials'
        }

        token_response = requests.post(url=self.TokenUrl,
                                       auth=HTTPBasicAuth(self.ClientID, self.ClientSecret),
                                       data=payload,
                                       verify=self._verify)

        if token_response.status_code == 401:
            raise DemistoException(
                "Authorization Error: The provided credentials for "
                "Symantec EDR are invalid. Please provide "
                "a valid Client ID and Client Secret.")
        elif token_response.status_code >= 400:
            raise DemistoException("Error: Something went wrong, please try "
                                   "again")
        return token_response.json().get('access_token')

    def test_module(self) -> str:
        """
        Tests API connectivity and authentication return 'ok'
        Returning 'ok' indicates that connection to the service is successful.
        Raises exceptions if something goes wrong.
        """
        url = f'{self._base_url}/atpapi/v2/appliances'
        payload = {}
        param = {}

        try:
            token = self.access_token()
            headers = {
               'Accept': 'application/json',
               'content-type': 'application/json',
               'Authorization': f'Bearer {token}'
            }

            response = requests.get(
                        url=url,
                        headers=headers,
                        data=payload,
                        params=param,
                        verify=self._verify
                    )

            if response.status_code >= 400:
                error_message = response.json().get("message")
                raise DemistoException(error_message)

            return 'Success'

        except Exception as e:
            demisto.error(traceback.format_exc())
            errmsg = f'Failed to execute {demisto.command()} command'
            return_error("\n".join((errmsg, "Error:", str(e))))

    def fetch_data_from_symantec_api(self, end_point: str, payload: dict, reqtype: Optional[str] = 'post') -> Dict:
        """
        : param end_point: Symantec EDR endpoint data fetch
        : param params: Kwargs
        : return: return the raw api query response from Symantec EDR endpoint API.
        """
        return self.query(end_point, payload, reqtype)

    def query(self, end_point: str, payload: dict, reqtype: str) -> Dict:
        """
        : param end_point: Symantec EDR endpoint query
        : param payload: Kwargs
        : return: return the raw api response from Symantec EDR API.
        """

        result: Dict = {}
        url_path = f'{self._base_url}/{end_point}'
        access_token = self.access_token()
        # action = params.get('action')

        # payload = {}
        # Command
        # if action in ['isolate_endpoint', 'rejoin_endpoint', 'delete_endpoint_file']:
        #     payload = {
        #         'action': params.get('action'),
        #         'targets': list(params.get('targets').split(':'))
        #     }
        #
        # # Domain and FIle Associations
        # if action in ['domains-files', 'endpoints-domains', 'endpoints-files']:
        #     payload = {
        #         'verb': params.get('verb'),
        #         'limit': params.get('limit')
        #     }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.post(
            url_path,
            headers=headers,
            data=json.dumps(payload),
            verify=self._verify
        ) \
            if reqtype == 'post' \
            else \
            requests.get(url_path,
                         headers=headers,
                         verify=self._verify)

        # print(response.json())

        if response.status_code == 200:
            result = response.json()

        # In case of URL redirects set the Authorization Header
        # if response.status_code in range(300, 310):
        #     # payload = {}
        #     response = requests.post(
        #         response.headers['Location'],
        #         headers=headers,
        #         data=son.dumps(payload),
        #         verify = self._verify,
        #         allow_redirects=True)

        #     if response.ok:
        #         result = response.json()
        #
        if response.status_code >= 400:
            error_message = f'{response.json().get("error")}, {response.json().get("message")} !!'
            raise DemistoException(error_message)

        return result


# ALl functions with configuration
def get_edr_association_api_config(cmd: str) -> Dict:
    """
     get_edr_association_api_config: Get Association endpoints api

     Args:
         cmd: Demisto command
     Returns:
         Domain and files endpoint
     """
    association_command_detail = {
        "symantec-edr-domain-file-association-get": {
            "endpoint": "domains-files",
            "content_name": "DomainsAndFiles",
            "markdown_title": "Domain and File Associations"
        },
        "symantec-edr-endpoint-domain-association-get": {
            "endpoint": "endpoints-domains",
            "content_name": "EndpointAndDomain",
            "markdown_title": "Endpoint and Domains Associations"
        },
        "symantec-edr-endpoint-file-association-get": {
            "endpoint": "endpoints-files",
            "content_name": "EndpointAndFile",
            "markdown_title": "Endpoint and File Associations"
        }
    }

    return association_command_detail.get(cmd)


def get_edr_entities_api_config(cmd: str) -> Dict:
    """
     get_edr_entities_api_config: Get Association endpoints api

     Args:
         cmd: Demisto command
     Returns:
         Domain and files endpoint
     """
    args = demisto.args()
    file_endpoint = \
        f'/atpapi/v2/entities/files/{args.get("sha2")}/instances' \
        if args.get('sha2') \
        else '/atpapi/v2/entities/files/instances'

    file_markdown_title = \
        f'FIle Instance She2' \
        if args.get('sha2') \
        else 'File Instance'

    entities_command_detail = {
        "symantec-edr-domain-instance-get": {
            "endpoint": "/atpapi/v2/entities/domains/instances",
            "content_name": "DomainsInstances",
            "markdown_title": "Domain Instances"
        },
        "symantec-edr-endpoint-instance-get": {
            "endpoint": "/atpapi/v2/entities/endpoints/instances",
            "content_name": "EndpointInstances",
            "markdown_title": "Endpoint Instances"
        },
        "symantec-edr-file-instance-get": {
            "endpoint": file_endpoint,
            "content_name": "FileInstance",
            "markdown_title": file_markdown_title
        }
    }
    return entities_command_detail.get(cmd)


# All commands interface calling function
def get_edr_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get_edr_command: Issue a Command Action to the EDR endpoint(s) to internal and External networks
    based on endpoint Device/File IDs.
    Args:
        client: client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint_action = args.get('action')
    payload = {
        'action': args.get('action'),
        'targets': list(args.get('targets').split(':'))
    }
    endpoint = "atpapi/v2/commands"
    data_json = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} command Action"
    summary_data = {
            "Message": data_json.get('message'),
            "Command ID": data_json.get('command_id'),
            "Error Code": data_json.get('error_code')
        }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_NAME}.Command_{args.get("action")}',
        outputs_key_field='',
        outputs=data_json,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    )


def get_edr_association_command_wrapper(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
      get_edr_association_command_data: Get Association resource API data
        e.g. Domain and FIle,
             Endpoint and Domain,
             Endpoint and File

      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
      """
    command = demisto.command()
    cmd_dict = get_edr_association_api_config(command)
    endpoint = f'/atpapi/v2/associations/entities/{cmd_dict.get("endpoint")}'
    print(endpoint)
    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} {cmd_dict.get('markdown_title')}"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_association_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.{cmd_dict.get("content_name")}',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_domain_instance(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_domain_instance: Get Domain Instances

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/entities/domains/instances'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Domain Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_domain_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Entities.Domain.Instance',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_endpoint_instance(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_endpoint_instance: Get Endpoints Instances

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/entities/endpoints/instances'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Endpoint Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_endpoint_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Entities.Endpoints.Files',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_file_instance(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_file_instance: Get Endpoints Instances

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    # endpoint = '/atpapi/v2/entities/files/instances'

    endpoint = \
        f'/atpapi/v2/entities/files/{args.get("sha2")}/instances' \
        if args.get('sha2') \
        else '/atpapi/v2/entities/files/instances'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} File Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_file_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Entities.Files.Instances',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_system_activities(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_system_activities: Get System Activities

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/systemactivities'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} System Activities"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_system_activities_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.SystemActivities',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_audit_events(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_audit_events: Get Audit Events

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/auditevents'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Audit Events"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_audit_event_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.AuditEvents',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_event_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_event_list: Get Event List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/events'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Events List"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.EventsList',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_incident_event_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_incident_event_list: Get Incident Event List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/incidentevents'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Incident Events List"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.IncidentEventsList',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_incident_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_incident_list: Get Incident List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/incidents'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Incident List"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.IncidentList',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_incident_comment(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_incident_comment: Get Incident Comments
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    uuid = args.get('uuid')
    endpoint = f'/atpapi/v2/incidents/{uuid}/comments'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Incident Comments"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.IncidentList',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_deny_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_deny_list: Get Deny List Policies
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/policies/deny_list'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload, 'get')
    title = f"{INTEGRATION_NAME} Deny List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.DenyListPolicies',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_black_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_black_list: Get Black List Policies
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/policies/blacklist'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload, 'get')
    title = f"{INTEGRATION_NAME} Black List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.BlackListPolicies',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_allow_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_allow_list: Get Allow List Policies
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/policies/allow_list'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload, 'get')
    title = f"{INTEGRATION_NAME} Allow List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.AllowListPolicies',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_file_sandbox(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_file_sandbox: Issue File Sandbox command,
            Query file Sandbox command status,
            Get file Sandbox Verdict of specific SHA2
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    args = demisto.args()

    if args.get('type') == 'issue':
        if not args.get('action') or not args.get('targets'):
            raise DemistoException("For issue a File sandbox command both arguments Action and Target is required !!")

    if args.get('type') == 'status':
        if not args.get('command_id'):
            raise DemistoException("Argument command_id is required !!")

    if args.get('type') == 'verdict':
        if not args.get('sha2'):
            raise DemistoException("Argument sha2 is required !!")

    endpoint = \
        f'/atpapi/v2/sandbox/commands/{args.get("command_id")}' \
        if args.get('command_id') \
        else f'/atpapi/v2/sandbox/results/{args.get("sha2")}/verdict' \
        if args.get("sha2") \
        else '/atpapi/v2/sandbox/commands'

    # print(endpoint)

    payload = {
        'action': args.get('action'),
        'targets': list(args.get('targets').split(','))
    } if not args.get('command_id') and not args.get("sha2") else {}

    # print(payload)

    response_data = \
        client.fetch_data_from_symantec_api(endpoint, payload, 'get') \
        if args.get('command_id') or args.get("sha2") \
        else client.fetch_data_from_symantec_api(endpoint, payload)

    # Get Issue Sandbox Command
    if args.get('type') == 'issue':
        title = "Issue Sandbox Command"
        summary_data = {
            "Command ID": response_data.get('command_id')
        }
        headers = list(summary_data.keys())
        return CommandResults(
            outputs_prefix=f'{INTEGRATION_NAME}.SandboxCommand.Issue',
            outputs_key_field='',
            outputs=response_data,
            readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
        )

    # Get Sandbox Verdict of specific SHA2
    if args.get('type') == 'verdict':
        title = "Sandbox Verdict of specific SHA2"
        summary_data = {
            "VERDICT": response_data.get('verdict'),
            "VERDICT TYPE": response_data.get('verdict_type'),
            "SANDBOX SERVICE": response_data.get('sandbox_service'),
            "IS TARGETED": response_data.get('is_targeted'),
        }
        headers = list(summary_data.keys())
        return CommandResults(
            outputs_prefix=f'{INTEGRATION_NAME}.SandboxCommand.Verdict',
            outputs_key_field='',
            outputs=response_data,
            readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
        )

    if args.get('type') == 'status':
        # Query Sandbox Command Status
        datasets = response_data.get("status", [])
        title = "File status based on Command ID"
        if datasets:
            readable_output = fetch_data_to_markdown(datasets, title)
        else:
            readable_output = f'{title} does not have data to present. \n'

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'{INTEGRATION_NAME}.SandboxCommand.Status',
            outputs_key_field='',
            outputs=datasets
        )

    # If come to this point - which will never occur
    raise DemistoException("Error: Unknown Argument Type !!")


# Table Markdown functions below from here
def fetch_file_instance_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_file_instance_data_to_markdown: Parsing the Symantec EDR for file instances
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """
    summary_data = []
    for data in results:
        new = {
            'Name': data.get('name', ''),
            'First Seen': data.get('first_seen', ''),
            'Last Seen': data.get('last_seen', ''),
            'SHA2': data.get('sha2', ''),
            'Folder': data.get('folder', '')
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def fetch_endpoint_instance_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_endpoint_instance_data_to_markdown: Parsing the Symantec EDR for entities endpoints instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        ip_addresses = data.get("ip_addresses", [])
        new = {
            'Device UID': data.get('device_uid', ''),
            'Device Name': data.get('device_name', ''),
            'Device IP': data.get('device_ip', '0.0.0.0'),
            'Domain Or WorkGroup': data.get('domain_or_workgroup',''),
            'Time': data.get('time', '')
         }
        ips = {}
        for i in range(len(ip_addresses)):
            ips[f'IP ADDRESSES_{i}'] = ip_addresses[i]

        # Merge two dict worked python 3.5 or greater
        row_data = {**new, **ips}

        summary_data.append(row_data)

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def fetch_domain_instance_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_domain_instance_data_to_markdown: Parsing the Symantec EDR for entities Domains instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        new = {
            'Data Source URL Domain': data.get('data_source_url_domain', ''),
            'First Seen': data.get('first_seen', ''),
            'Last Seen': data.get('last_seen', ''),
            'External IP': data.get('external_ip', ''),
            'Data Source URL': data.get('data_source_url', ''),
            'Disposition': data.get('disposition', '')
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def fetch_association_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_association_data_to_markdown: Parsing the Symantec Association Domain or File  endpoints data
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        new = {
            'Device Name': data.get('device_name', ''),
            'Device IP': data.get('device_ip', '0.0.0.0'),
            'Device UID': data.get('device_uid', ''),
            'Signature Company Name': data.get('signature_company_name', ''),
            'Name': data.get('name', ''),
            'SHA2': data.get('sha2', ''),
            'Last Seen': data.get('last_seen', ''),
            'First Seen': data.get('first_seen', ''),
            'Data Source URL': data.get('data_source_url', ''),
            'Data Source URL Domain': data.get('data_source_url_domain', ''),
            'Folder': data.get('folder', '')
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def fetch_system_activities_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_system_activities_data_to_markdown: System Activities endpoint data lookup and Markdown to Table
    Args:
        results (list): System Activities Response results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        new = {
            'Device Name': data.get('device_name', ''),
            'Device IP': data.get('device_ip', '0.0.0.0'),
            'UUID': data.get('uuid', ''),
            'PID': data.get('process').get('pid', ''),
            'PRODUCT Name': data.get('product_name', ''),
            'PRODUCT VER': data.get('product_ver', ''),
            'STATUS ID': data.get('status_id', ''),
            'FEATURE NAME': data.get('feature_name', ''),
            'TYPE ID': data.get('type_id', ''),
            'TIMEZONE': data.get('timezone', ''),
            'ATP_NODE_ROLE': data.get('atp_node_role', ''),
            'DEVICE TIME': data.get('device_time', ''),
            'MESSAGE': data.get('message', ''),
            'LOG TIME': data.get('log_time', ''),
            'SEVERITY ID': data.get('severity_id', ''),
            'DEVICE CAP': data.get('device_cap', ''),
            'LOG NAME': data.get('log_name', ''),
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def fetch_audit_event_data_to_markdown(results: List[Dict], title: str) -> str:
    """
    fetch_system_activities_data_to_markdown: System Activities endpoint data lookup and Markdown to Table
    Args:
        results (list): System Activities Response results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        new = {
            'ID': data.get('id', ''),
            "USER NAME": data.get('user_name', ''),
            'USER UID': data.get('user_uid', ''),
            'DEVICE Name': data.get('device_name', ''),
            'DEVICE IP': data.get('device_ip', '0.0.0.0'),
            'USER AGENT IP': data.get('user_agent_ip', ''),
            'DEVICE UID': data.get('device_uid', ''),
            'STATUS DETAIL': data.get('status_detail', ''),
            'UUID': data.get('uuid', ''),
            'CATEGORY ID': data.get('category_id',''),
            'PRODUCT NAME': data.get('product_name', ''),
            'PRODUCT VER': data.get('product_ver', ''),
            'STATUS ID': data.get('status_id', ''),
            'FEATURE NAME': data.get('feature_name', ''),
            'TYPE ID': data.get('type_id', ''),
            'TIMEZONE': data.get('timezone', ''),
            'ATP NODE ROLE': data.get('atp_node_role', ''),
            'DEVICE TIME': data.get('device_time', ''),
            'MESSAGE': data.get('message', ''),
            'LOG TIME': data.get('log_time', ''),
            'SEVERITY ID': data.get('severity_id', ''),
            'DEVICE CAP': data.get('device_cap', ''),
            'LOG NAME': data.get('log_name', ''),
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def convert_to_field_name(key: str) -> str:
    """
     convert_string: Convert dict key to table field
       - Replace underscore with space
       - Convert string to upper
     Args:
         key (string): Passed any string
     Returns:
         A string in upper case
     """
    field_name = key.replace('_', ' ');
    return field_name.upper()


def mapping_endpoint_data(data: Dict, ignore_key: List, prefix: Optional[str] = None) -> Dict:
    """
     mapping_endpoint_data: Mapping endpoint data to table field and value
     Args:
         data (Dict): Endpoint Data
         ignore_key (List): Ignore Key List
         prefix optional[str] None:
     Returns:
         A string in upper case
     """
    # ignore_key = ['event_actor', 'process', 'enriched_data']
    dataset = {}
    for key, val in data.items():
        if key not in ignore_key:
            field = convert_to_field_name(key)
            field_name = f'{prefix}{field}' if prefix else f'{field}'
            dataset[field_name] = val

    return dataset


# def fetch_event_list_data_to_markdown(results: List[Dict], title: str) -> str:
#     """
#      fetch_event_list_data_to_markdown: Events data lookup and Markdown to Table
#      Args:
#          results (list): System Activities Response results data
#          title (str): Title string
#      Returns:
#          A string representation of the Markdown table
#      """
#     summary_data = []
#     for data in results:
#         ignore_key_list = []
#         prefix = ''
#         row = mapping_endpoint_data(data, ignore_key_list, prefix)
#         summary_data.append(row)
#
#     headers = summary_data[0] if summary_data else {}
#     headers = list(headers.keys())
#     markdown = tableToMarkdown(title, summary_data, headers=headers,
#                                removeNull=True)
#     return markdown
#
#
# def fetch_incident_event_list_data_to_markdown(results: List[Dict], title: str) -> str:
#     """
#      fetch_incident_event_list_data_to_markdown: Incident Events data lookup and Markdown to Table
#      Args:
#          results (list): System Activities Response results data
#          title (str): Title string
#      Returns:
#          A string representation of the Markdown table
#      """
#     summary_data = []
#     for data in results:
#         ignore_key_list = []
#         prefix = ''
#         row = mapping_endpoint_data(data, ignore_key_list, prefix)
#         summary_data.append(row)
#
#     headers = summary_data[0] if summary_data else {}
#     headers = list(headers.keys())
#     markdown = tableToMarkdown(title, summary_data, headers=headers,
#                                removeNull=True)
#     return markdown


def fetch_data_to_markdown(results: List[Dict], title: str) -> str:
    """
     fetch_data_to_markdown: Fetch Result data convert to Markdown Table
     Args:
         results (list): System Activities Response results data
         title (str): Title string
     Returns:
         A string representation of the Markdown table
     """
    summary_data = []
    for data in results:
        ignore_key_list = []
        prefix = ''
        row = mapping_endpoint_data(data, ignore_key_list, prefix)
        summary_data.append(row)

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_data, headers=headers,
                               removeNull=True)
    return markdown


def main():
    """
    main function, parses params and runs command functions

    :return: None
    :rtype: None
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Get Oath2.0 Client ID, Client Secret
    client_id = params.get('credentials').get('identifier')
    client_secret = params.get('credentials').get('password')

    # Get the Symantec-EDR API base URL
    base_url = params.get("api_url")
    proxy = params.get('proxy', False)
    verify_certificate = params.get('insecure', False)

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_key=client_secret,
            proxy=proxy,
            verify=verify_certificate
        )

        commands = {
                # Isolate Endpoint, Rejoin Endpoint and Delete Endpoint FIle
                "symantec-edr-endpoint-command": get_edr_command,

                # Domain File Associations
                "symantec-edr-domain-file-association-get": get_edr_association_command_wrapper,

                # Endpoint Domain Associations
                "symantec-edr-endpoint-domain-association-get": get_edr_association_command_wrapper,

                # Endpoint File Associations
                "symantec-edr-endpoint-file-association-get": get_edr_association_command_wrapper,

                # Get Incidents
                "symantec-edr-incident-list": get_edr_incident_list,

                # Get Incident Comments
                "symantec-edr-incident-comment-get": get_edr_incident_comment,

                # Patch Incidents Command to (Close Incidents, Update Resolution or Add Comments)
                "symantec-edr-incident-update": None,

                # File Sandbox Analysis, Command Status, and Verdict
                "file": get_edr_file_sandbox,

                # System Activities
                "symantec-edr-system-activity-get": get_edr_system_activities,

                # Audit Events
                "symantec-edr-audit-event-get": get_edr_audit_events,

                # Allow List Policies
                "symantec-edr-allow-list-policy-get": get_edr_allow_list,

                # BlackList Policies
                "symantec-edr-black-list-policy-get": get_edr_black_list,

                # Deny List Policies
                "symantec-edr-deny-list-policy-get": get_edr_deny_list,

                # Domain Instances
                "symantec-edr-domain-instance-get": get_edr_domain_instance,

                # Endpoint Instances
                "symantec-edr-endpoint-instance-get": get_edr_endpoint_instance,

                # File Instances
                "symantec-edr-file-instance-get": get_edr_file_instance,

                # Events
                "symantec-edr-event-list": get_edr_event_list,

                # Events For Incidents
                "symantec-edr-incident-event-list": get_edr_incident_event_list

        }
        if command == "test-module":
            return_results(client.test_module())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError

    # Log exceptions
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
