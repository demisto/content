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

    def fetch_data_from_symantec_api(self, end_point: str, payload: dict) -> Dict:
        """
        : param end_point: Symantec EDR endpoint data fetch
        : param params: Kwargs
        : return: return the raw api query response from Symantec EDR endpoint API.
        """
        return self.query(end_point, payload)

    def query(self, end_point: str, payload: dict) -> Dict:
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
        )

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
            "Command ID": data_json.get('command_id'),
            "Action": endpoint_action,
            "Message": data_json.get('message')
        }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_NAME}.commands.{args.get("action")}',
        outputs_key_field='',
        outputs=data_json,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    )


def get_edr_association_endpoint(cmd: str) -> str:
    """
     get_edr_association: Get Association endpoints api

     Args:
         cmd: Demisto command
     Returns:
         Domain and files endpoint
     """
    association_endpoint = {
        "symantec-edr-domain-file-association": "domains-files",
        "symantec-edr-endpoint-domain-association": "endpoints-domains",
        "symantec-edr-endpoint-file-association": "endpoints-files"
    }

    return association_endpoint.get(cmd)


def get_edr_domain_file_association(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_domain_file_association: Get Association between domains and files

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = f'/atpapi/v2/associations/entities/domains-files'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Domain File Associations"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_association_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Associations.Domains.Files',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_endpoint_domain_association(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_endpoint_domain_association: Get Association between endpoint and domains

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = f'/atpapi/v2/associations/entities/endpoints-domains'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Endpoint Domain Associations"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_association_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Associations.Endpoints.Domains',
        outputs_key_field='',
        outputs=datasets
    )


def get_edr_endpoint_file_association(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_edr_endpoint_file_association: Get Association between endpoints and files

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = f'/atpapi/v2/associations/entities/endpoints-files'

    payload = {
        'verb': args.get('verb'),
        'limit': args.get('limit')
    }

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{INTEGRATION_NAME} Endpoint File Associations"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_association_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Associations.Endpoints.Files',
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
        print(json.dumps(ip_addresses))
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
                "symantec-edr-domain-file-association-get": get_edr_domain_file_association,

                # Endpoint Domain Associations
                "symantec-edr-endpoint-domain-association-get": get_edr_endpoint_domain_association,

                # Endpoint File Associations
                "symantec-edr-endpoint-file-association-get": get_edr_endpoint_file_association,

                # Incident Comments
                "symantec-edr-incident-comment-get": None,

                # Patch Incident Command
                "symantec-edr-incident-update": None,

                # File Sandbox Analysis, Command Status, and Verdict
                "file": None,

                # System Activities
                "symantec-edr-system-activity-get": None,

                # Audit Events
                "symantec-edr-audit-event-get": None,

                # Allow List Policies
                "symantec-edr-allow-list-policy-get": None,

                # BlackList Policies
                "symantec-edr-black-list-policy-get": None,

                # Deny List Policies
                "symantec-edr-deny-list-policy-get": None,

                # Domain Instances
                "symantec-edr-domain-instance-get": get_edr_domain_instance,

                # Endpoint Instances
                "symantec-edr-endpoint-instance-get": get_edr_endpoint_instance,

                # File Instances
                "symantec-edr-file-instance-get": get_edr_file_instance,

                # Events
                "symantec-edr-event-list": None,

                # Incidents
                "symantec-edr-incident-list": None,

                # Events For Incidents
                "symantec-edr-incident-event-list": None
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
