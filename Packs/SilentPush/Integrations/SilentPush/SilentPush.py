import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import enum
import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, List, Optional, Union

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# API ENDPOINTS
JOB_STATUS = "explore/job"
NAMESERVER_REPUTATION = "explore/nsreputation/nameserver"
SUBNET_REPUTATION = "explore/ipreputation/history/subnet"
ASNS_DOMAIN = "explore/padns/lookup/domain/asns"

''' COMMANDS INPUTS '''

JOB_STATUS_INPUTS = [
                    InputArgument(name='job_id',  # option 1
                                      description='ID of the job returned by Silent Push actions.',
                                      required=True),
                    InputArgument(name='max_wait',
                                description='Number of seconds to wait for results (0-25 seconds).'),
                    InputArgument(name='result_type',
                                description='Type of result to include in the response.')
                    ]
NAMESERVER_REPUTATION_INPUTS = [
                    InputArgument(name='nameserver',
                                description='Nameserver name for which information needs to be retrieved',
                                required=True),
                    InputArgument(name='explain',
                                description='Show the information used to calculate the reputation score'),
                    InputArgument(name='limit',
                                description='The maximum number of reputation history to retrieve')
                ]
SUBNET_REPUTATION_INPUTS = [
                    InputArgument(
                        name='subnet',
                        description='IPv4 subnet for which reputation information needs to be retrieved.',
                        required=True
                    ),
                    InputArgument(
                        name='explain',
                        description='Show the detailed information used to calculate the reputation score.'
                    ),
                    InputArgument(
                        name='limit',
                        description='Maximum number of reputation history entries to retrieve.'
                    )
                ]
ASNS_DOMAIN_INPUTS = [
                    InputArgument(name='domain',  # option 1
                                description='Domain name to search ASNs for. Retrieves ASNs associated with A records for the specified domain and its subdomains in the last 30 days.',
                                required=True)
                    ]



''' COMMANDS OUTPUTS '''

JOB_STATUS_OUTPUTS = [
                        OutputArgument(name='get', output_type=str, description='URL to retrieve the job status.'),
                        OutputArgument(name='job_id', output_type=str, description='Unique identifier for the job.'),
                        OutputArgument(name='status', output_type=str, description='Current status of the job.')
                    ]

NAMESERVER_REPUTATION_OUTPUTS = [
                        OutputArgument(name='date', output_type=int, description='Date of the reputation history entry (in YYYYMMDD format).'),
                        OutputArgument(name='ns_server', output_type=str, description='Name of the nameserver associated with the reputation history entry.'),
                        OutputArgument(name='ns_server_reputation', output_type=int, description='Reputation score of the nameserver on the specified date.'),
                        OutputArgument(name='ns_server_reputation_explain', output_type=dict, description='Explanation of the reputation score, including domain density and listed domains.'),
                        OutputArgument(name='ns_server_domain_density', output_type=int, description='Number of domains associated with the nameserver.'),
                        OutputArgument(name='ns_server_domains_listed', output_type=int, description='Number of domains listed in reputation databases.')
                    ]
SUBNET_REPUTATION_OUTPUTS = [
                        OutputArgument(name='date', output_type=int, description='The date of the subnet reputation record.'),
                        OutputArgument(name='subnet', output_type=str, description='The subnet associated with the reputation record.'),
                        OutputArgument(name='subnet_reputation', output_type=int, description='The reputation score of the subnet.'),
                        OutputArgument(name='ips_in_subnet', output_type=int, description='Total number of IPs in the subnet.'),
                        OutputArgument(name='ips_num_active', output_type=int, description='Number of active IPs in the subnet.'),
                        OutputArgument(name='ips_num_listed', output_type=int, description='Number of listed IPs in the subnet.')
                    ]
ASNS_DOMAIN_OUTPUTS = [
                        OutputArgument(name='domain', output_type=str, description='The domain name for which ASNs are retrieved.'),
                        OutputArgument(name='domain_asns', output_type=dict, description='Dictionary of Autonomous System Numbers (ASNs) associated with the domain.')
                    ]



metadata_collector = YMLMetadataCollector(
    integration_name="SilentPush",
    description=(
        "The Silent Push Platform uses first-party data and a proprietary scanning engine to enrich global DNS data "
        "with risk and reputation scoring, giving security teams the ability to join the dots across the entire IPv4 and IPv6 range, "
        "and identify adversary infrastructure before an attack is launched. The content pack integrates with the Silent Push system "
        "to gain insights into domain/IP information, reputations, enrichment, and infratag-related details. It also provides "
        "functionality to live-scan URLs and take screenshots of them. Additionally, it allows fetching future attack feeds "
        "from the Silent Push system."
    ),
    display="SilentPush",
    category="Data Enrichment & Threat Intelligence",
    docker_image="demisto/python3:3.11.10.116949",
    is_fetch=False,
    long_running=False,
    long_running_port=False,
    is_runonce=False,
    integration_subtype="python3",
    integration_type="python",
    fromversion="5.0.0",
    conf=[
        ConfKey(
            name="url",
            display="Base URL",
            required=True,
            default_value="https://api.silentpush.com"
        ),
        ConfKey(
            name="credentials",
            display="API Key",
            required=False,
            key_type=ParameterTypes.TEXT_AREA_ENCRYPTED,
        ),
        ConfKey(
            name="insecure",
            display="Trust any certificate (not secure)",
            required=False,
            key_type=ParameterTypes.BOOLEAN
        ),
        ConfKey(
            name="proxy",
            display="Use system proxy settings",
            required=False,
            key_type=ParameterTypes.BOOLEAN
        )
    ]
)


''' CLIENT CLASS '''

class Client(BaseClient):
    """Client class to interact with the SilentPush API

    This Client implements API calls and does not contain any XSOAR logic.
    It should only perform requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initializes the client with the necessary parameters.

        Args:
            base_url (str): The base URL for the SilentPush API.
            api_key (str): The API key for authentication.
            verify (bool): Flag to determine whether to verify SSL certificates (default True).
            proxy (bool): Flag to determine whether to use a proxy (default False).
        """
        self.base_url = base_url.rstrip('/') + '/api/v1/merge-api/'
        self.api_key = api_key
        self.verify = verify
        self.proxy = proxy
        self._headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }

    def _http_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None) -> Any:
        """
        Perform an HTTP request to the SilentPush API.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST').
            url_suffix (str): The endpoint suffix to append to the base URL.
            params (dict, optional): Query parameters to include in the request. Defaults to None.
            data (dict, optional): JSON data to send in the request body. Defaults to None.

        Returns:
            Any: The JSON response from the API or text response if not JSON.

        Raises:
            DemistoException: If there's an error during the API call.
        """
        base_url = demisto.params().get('url', 'https://api.silentpush.com') if url_suffix.startswith("/api/v2/") else self.base_url
        full_url = f'{base_url}{url_suffix}'

        try:
            response = requests.request(
                method,
                full_url,
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data
            )
            if response.headers.get('Content-Type', '').startswith('application/json'):
                return response.json()
            else:
                return response.text
        except Exception as e:
            raise DemistoException(f'Error in API call: {str(e)}')


    def get_job_status(self, job_id: str, max_wait: Optional[int] = None, result_type: Optional[str] = None) -> Dict[str, Any]:
        """
            Retrieve the status of a specific job.

            Args:
                job_id (str): The unique identifier of the job to check.
                max_wait (int, optional): Maximum wait time in seconds. Must be between 0 and 25. Defaults to None.
                result_type (str, optional): Type of result to retrieve. Defaults to None.

            Returns:
                Dict[str, Any]: Job status information.

            Raises:
                ValueError: If max_wait is invalid or result_type is not in allowed values.
            """
        url_suffix = f"{JOB_STATUS}/{job_id}"
        params = {}

        if max_wait is not None:
            if not (0 <= max_wait <= 25):
                raise ValueError("max_wait must be an integer between 0 and 25")
        params['max_wait'] = max_wait

        valid_result_types = {'Status', 'Include Metadata', 'Exclude Metadata'}
        if result_type and result_type not in valid_result_types:
            raise ValueError(f"result_type must be one of {valid_result_types}")
        
        if result_type:
            params['result_type'] = result_type

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_nameserver_reputation(self, nameserver: str, explain: bool = False, limit: int = None):
        """
        Retrieve historical reputation data for the specified nameserver.

        Args:
            nameserver (str): The nameserver for which the reputation data is to be fetched.
            explain (bool): Whether to include detailed calculation explanations.
            limit (int): Maximum number of reputation entries to return.

        Returns:
            dict: Reputation history for the given nameserver.
        """

        url_suffix = f"{NAMESERVER_REPUTATION}/{nameserver}"

        params = filter_none_values({'explain': explain, 'limit': limit})

        response = self._http_request(method="GET", url_suffix=url_suffix, params=params)

        # Return the reputation history, or an empty list if not found
        return response.get('response', {}).get('ns_server_reputation', [])

    def get_subnet_reputation(self, subnet: str, explain: bool = False, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Retrieve reputation history for a specific subnet.

        Args:
            subnet (str): The subnet to query.
            explain (bool, optional): Whether to include detailed explanations. Defaults to False.
            limit (int, optional): Maximum number of results to return. Defaults to None.

        Returns:
            Dict[str, Any]: Subnet reputation history information.
        """
        url_suffix = f"/{subnet}"

        params = {
            "explain": str(explain).lower() if explain else None,
            "limit": limit
        }

        params = filter_none_values(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_asns_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Retrieve Autonomous System Numbers (ASNs) associated with the specified domain.

        Args:
            domain (str): The domain to retrieve ASNs for.

        Returns:
            Dict[str, Any]: A dictionary containing the ASN information for the domain.
        """
        url_suffix = f"{ASNS_DOMAIN}/{domain}"

        # Send the request and return the response directly
        return self._http_request(method="GET", url_suffix=url_suffix)


''' HELPER FUNCTIONS '''
def filter_none_values(params: Dict[str, Any]) -> Dict[str, Any]:
    """Removes None values from a dictionary."""
    return {k: v for k, v in params.items() if v is not None}


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: SilentPush client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e., auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return that is different than 'ok' as
    # an error.
    try:
        resp = client.get_job_status("job_id", "max_wait", "result_type")
        if resp.get("status_code") != 200:
            return f"Connection failed :- {resp.get('errors')}"
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise e


@metadata_collector.command(
    command_name="silentpush-get-job-status",
    inputs_list=JOB_STATUS_INPUTS,
    outputs_prefix="SilentPush.JobStatus",
    outputs_list=JOB_STATUS_OUTPUTS,
    description="This command retrieve status of running job or results from completed job.",
)
def get_job_status_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the status of a job based on the provided job ID and other optional parameters.

    Args:
        client (Client): The client instance that interacts with the service to fetch job status.
        args (dict): A dictionary of arguments, which should include:
            - 'job_id' (str): The unique identifier of the job for which status is being retrieved.
            - 'max_wait' (Optional[int]): The maximum wait time in seconds (default is None).
            - 'result_type' (Optional[str]): Type of result to retrieve. Valid options are 'Status', 
                                              'Include Metadata', or 'Exclude Metadata' (default is None).

    Returns:
        CommandResults: The command results containing:
            - 'outputs_prefix' (str): The prefix for the output context.
            - 'outputs_key_field' (str): The field used as the key in the outputs.
            - 'outputs' (dict): A dictionary with job ID and job status information.
            - 'readable_output' (str): A formatted string that represents the job status in a human-readable format.
            - 'raw_response' (dict): The raw response received from the service.

    Raises:
        DemistoException: If the 'job_id' parameter is missing or if no job status is found for the given job ID.
    """
    job_id = args.get('job_id')
    max_wait = arg_to_number(args.get('max_wait'))
    result_type = args.get('result_type')

    if not job_id:
        raise DemistoException("job_id is a required parameter")

    raw_response = client.get_job_status(job_id, max_wait, result_type)
    job_status = raw_response.get('response', {})

    if not job_status:
        raise DemistoException(f"No job status found for Job ID: {job_id}")

    readable_output = tableToMarkdown(
        f"Job Status for Job ID: {job_id}",
        [job_status],
        headers=list(job_status.keys()),
        removeNull=True
    )
    return CommandResults(
        outputs_prefix='SilentPush.JobStatus',
        outputs_key_field='job_id',
        outputs={'job_id': job_id, **job_status},
        readable_output=readable_output,
        raw_response=raw_response
    )


@metadata_collector.command(
    command_name="silentpush-get-nameserver-reputation",
    inputs_list=NAMESERVER_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.SubnetReputation",
    outputs_list=NAMESERVER_REPUTATION_OUTPUTS,
    description="This command retrieve historical reputation data for a specified nameserver, including reputation scores and optional detailed calculation information.",
)
def get_nameserver_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving nameserver reputation.

    Args:
        client (Client): The API client instance.
        args (dict): Command arguments.

    Returns:
        CommandResults: The command results containing nameserver reputation data.
    """
    nameserver = args.get("nameserver")
    explain = argToBoolean(args.get("explain", "false"))
    limit = arg_to_number(args.get("limit"))

    if not nameserver:
        raise ValueError("Nameserver is required.")

    # Fetch reputation data
    reputation_data = client.get_nameserver_reputation(nameserver, explain, limit)

    # Prepare the readable output
    if reputation_data:
        readable_output = tableToMarkdown(
            f"Nameserver Reputation for {nameserver}",
            reputation_data,
            headers=list(reputation_data[0].keys()),
            removeNull=True
        )
    else:
        readable_output = f"No reputation history found for nameserver: {nameserver}"

    # Return command results
    return CommandResults(
        outputs_prefix="SilentPush.NameserverReputation",
        outputs_key_field="ns_server",
        outputs={"nameserver": nameserver, "reputation_data": reputation_data},
        readable_output=readable_output,
        raw_response=reputation_data
    )

@metadata_collector.command(
    command_name="silentpush-get-subnet-reputation",
    inputs_list=SUBNET_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.NameserverReputation",
    outputs_list=SUBNET_REPUTATION_OUTPUTS,
    description="This command retrieves the reputation history for a specific subnet."
)
def get_subnet_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the reputation history of a given subnet.

    Args:
        client (Client): The API client instance.
        args (dict): Command arguments containing:
            - subnet (str): The subnet to query.
            - explain (bool, optional): Whether to include an explanation.
            - limit (int, optional): Limit the number of reputation records.

    Returns:
        CommandResults: The command result containing the subnet reputation data.
    """
    subnet = args.get('subnet')
    if not subnet:
        raise DemistoException("Subnet is a required parameter.")

    explain = argToBoolean(args.get('explain', False))
    limit = arg_to_number(args.get('limit'))

    raw_response = client.get_subnet_reputation(subnet, explain, limit)
    subnet_reputation = raw_response.get('response', {}).get('subnet_reputation_history', [])

    readable_output = (
        f"No reputation history found for subnet: {subnet}"
        if not subnet_reputation
        else tableToMarkdown(f"Subnet Reputation for {subnet}", subnet_reputation, removeNull=True)
    )

    return CommandResults(
        outputs_prefix='SilentPush.SubnetReputation',
        outputs_key_field='subnet',
        outputs={'subnet': subnet, 'reputation_history': subnet_reputation},
        readable_output=readable_output,
        raw_response=raw_response
    )


@metadata_collector.command(
    command_name="silentpush-get-asns-for-domain",
    inputs_list=ASNS_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.DomainASNs",
    outputs_list=ASNS_DOMAIN_OUTPUTS,
    description="This command retrieves Autonomous System Numbers (ASNs) associated with a domain."
)
def get_asns_for_domain_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves Autonomous System Numbers (ASNs) for the specified domain.

    Args:
        client (Client): The client object used to interact with the service.
        args (dict): Arguments passed to the command, including the domain.

    Returns:
        CommandResults: The results containing ASNs for the domain or an error message.
    """
    domain = args.get('domain')

    if not domain:
        raise DemistoException("Domain is a required parameter.")

    raw_response = client.get_asns_for_domain(domain)
    records = raw_response.get('response', {}).get('records', [])

    if not records or 'domain_asns' not in records[0]:
        readable_output = f"No ASNs found for domain: {domain}"
        asns = []
    else:
        domain_asns = records[0]['domain_asns']
        asns = [{'ASN': asn, 'Description': description}
                for asn, description in domain_asns.items()]

        readable_output = tableToMarkdown(
            f"ASNs for Domain: {domain}",
            asns,
            headers=['ASN', 'Description']
        )

    return CommandResults(
        outputs_prefix='SilentPush.DomainASNs',
        outputs_key_field='domain',
        outputs={
            'domain': domain,
            'asns': asns
        },
        readable_output=readable_output,
        raw_response=raw_response
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    try:
        params = demisto.params()
        api_key = params.get('credentials', {}).get('password')
        base_url = params.get('url', 'https://api.silentpush.com')
        verify_ssl = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_ssl,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module(client, demisto.args())
            return_results(result)

        elif demisto.command() == 'silentpush-get-job-status':
            return_results(get_job_status_command(client, demisto.args()))

        elif demisto.command() == 'silentpush-get-nameserver-reputation':
            return_results(get_nameserver_reputation_command(client, demisto.args()))

        elif demisto.command() == 'silentpush-get-subnet-reputation':
            return_results(get_subnet_reputation_command(client, demisto.args()))

        elif demisto.command() == 'silentpush-get-asns-for-domain':
            return_results(get_asns_for_domain_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
