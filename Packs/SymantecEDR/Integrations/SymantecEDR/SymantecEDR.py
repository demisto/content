"""
Symantec Endpoint Detection and Response (EDR) integration with Symantec-EDR 4.6
"""
import requests.auth

from CommonServerPython import *
from requests.auth import HTTPBasicAuth
from typing import Dict, Any
import requests
import json
import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
handle_proxy()

''' CONSTANTS '''
TOKEN_ENDPOINT = '/atpapi/oauth2/tokens'
INTEGRATION_CONTEXT_NAME = 'SymantecEDR'
# Limit for Page size as default as part of pagination
PAGE_LIMIT = 50
# Minimum and Maximum limit for API to retrieve -  Limit range is between 1 and 5000. Default 100
MIN_LIMIT = 100
MAX_LIMIT = 5000
# Go back in time from current date and time in days
# FROM_DAYS = 7
# Current date and time
TO_DATE = "now"
PAGE_NUMBER_ERROR_MSG = 'Invalid Input Error: page number should be greater ' \
                        'than zero.'
''' CLIENT CLASS '''
# # get current datetime
today = datetime.datetime.now(datetime.timezone.utc)


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

            return 'ok'

        except Exception as e:
            demisto.error(traceback.format_exc())
            errmsg = f'Failed to execute {demisto.command()} command'
            return_error("\n".join((errmsg, "Error:", str(e))))

    def fetch_data_from_symantec_api(self, end_point: str, payload: dict, req_type: Optional[str] = 'post') -> Dict:
        """
        : param end_point: Symantec EDR endpoint data fetch
        : param payload: Payload request data
        : param req_type: Request type post as Default
        : return: return the raw api query response from Symantec EDR endpoint API.
        """
        return self.query_patch(end_point, payload) \
            if req_type == 'patch' \
            else \
            self.query(end_point, payload, req_type)

    def query(self, end_point: str, payload: dict, req_type: str) -> Dict:
        """
        : param end_point: Symantec EDR endpoint query
        : param payload: Kwargs
        : param req_type
        : return: return the raw api response from Symantec EDR API.
        """

        result: Dict = {}
        url_path = f'{self._base_url}/{end_point}'
        access_token = self.access_token()

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
            if req_type == 'post' \
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

    def query_patch(self, end_point: str, payload: dict):
        """
        : param end_point: Symantec EDR endpoint resources operation add, update, delete
        : param payload: Kwargs
        : return: return response status code
        """

        result: Dict = {}
        url_path = f'{self._base_url}/{end_point}'
        access_token = self.access_token()

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.patch(
            url_path,
            headers=headers,
            data=json.dumps(payload),
            verify=self._verify
        )

        if response.status_code == 204:
            result['status'] = response.status_code
            result['message'] = 'Success'

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
        "symantec-edr-domain-file-association-list": {
            "endpoint": "domains-files",
            "content_name": "DomainsAndFiles",
            "markdown_title": "Domain and File Associations"
        },
        "symantec-edr-endpoint-domain-association-list": {
            "endpoint": "endpoints-domains",
            "content_name": "EndpointAndDomain",
            "markdown_title": "Endpoint and Domains Associations"
        },
        "symantec-edr-endpoint-file-association-list": {
            "endpoint": "endpoints-files",
            "content_name": "EndpointAndFile",
            "markdown_title": "Endpoint and File Associations"
        }
    }

    return association_command_detail.get(cmd)


# All commands interface functions
def get_endpoint_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get_endpoint_command: Issue a Command Action to the EDR endpoint(s) to internal and External networks
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
        'targets': argToList(args.get('targets'), ',')
    }
    endpoint = "atpapi/v2/commands"
    data_json = client.fetch_data_from_symantec_api(endpoint, payload)
    title = "command Action"
    summary_data = {
            "Message": data_json.get('message'),
            "Command ID": data_json.get('command_id'),
            "Error Code": data_json.get('error_code')
        }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Command_{args.get("action")}',
        outputs_key_field='',
        outputs=data_json,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    )


def get_association_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
      get_association_command: Get Association resource API data
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

    payload = {'verb': args.get('verb')}
    if args.get('limit'):
        payload['limit'] = args.get('limit')

    if args.get('query'):
        payload['query'] = args.get('query')

    demisto_print(payload)
    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = f"{cmd_dict.get('markdown_title')}"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_association_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{cmd_dict.get("content_name")}',
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
    title = "Domain Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_domain_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Entities.Domain.Instance',
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
    title = "Endpoint Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_endpoint_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Entities.Endpoints.Files',
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
    title = "File Instances"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_file_instance_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Entities.Files.Instances',
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
    title = "System Activities"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_system_activities_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SystemActivities',
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
    title = "Audit Events"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_audit_event_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AuditEvents',
        outputs_key_field='',
        outputs=datasets
    )


def pagination(page: Optional[int], page_size: Optional[int]):
    """
    Define pagination.
    Args:
        page: The page number.
        page_size: The number of requested results per page.
    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if (page and page <= 0) or (page_size and page_size <= 0):
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    page = 0 if not page else page - 1
    page_size = PAGE_LIMIT if not page_size else page_size
    limit = page_size
    offset = page * page_size
    return limit, offset


def get_iso_8601_timestamp(time_val: str, time_param: str) -> str:

    # -7days, -10mins, -2weeks, 2hours
    if not re.search(r"^-\d{1,3}(days|mins|weeks|hours)$", time_val):
        raise ValueError(
            f'Argument "{time_param}={time_val}" is invalid. '
            f'The maximum time range is 7 days between start and end time.'
            f'Only accepted similar type of value. '
            f'Example: {time_param}=-7days or {time_param}=-1weeks or {time_param}=-10mins or {time_param}=-2hours')

    r1 = re.match(r"(^-)(\d{1,3})(\w+)$", time_val)
    # print(f"Regular expression {time_val} : {r1}, {r1[0]}, {r1[1]}, {r1[2]}, {r1[3]}")

    if r1[3] == 'days':
        time_days_ago = today - datetime.timedelta(days=arg_to_number(r1[2]))
    elif r1[3] == 'mins':
        time_days_ago = today - datetime.timedelta(minutes=arg_to_number(r1[2]))
    elif r1[3] == 'weeks':
        time_days_ago = today - datetime.timedelta(weeks=arg_to_number(r1[2]))
    elif r1[3] == 'hours':
        time_days_ago = today - datetime.timedelta(hours=arg_to_number(r1[2]))
    else:
        raise DemistoException("Unable to handle either from time stamp parameter value, "
                               "It should be one of these formats -7days, -10mins, -2weeks, 2hours")
    # convert it to ISO 8601 standard
    conv_to_iso_date = time_days_ago.isoformat()[:23] + "Z"

    return conv_to_iso_date


def get_payload(args: Dict[str, Any]) -> Dict:

    payload = dict()

    payload['verb'] = args.get('verb') if args.get('verb') else 'query'
    payload['limit'] = args.get('limit') if args.get('limit') else MIN_LIMIT

    if args.get('query'):
        payload['query'] = args.get('query')

    # Start and end time arguments
    # # Get current ISO 8601 datetime in string format
    iso_date_now = today.isoformat()[:23] + "Z"

    # 7 days ago starting form current date as Default
    # week_ago = today - datetime.timedelta(days=from_days)
    # # Get current ISO 8601 datetime in string format
    # iso_date_week_ago = week_ago.isoformat()[:23] + "Z"

    if args.get('from'):
        payload['start_time'] = get_iso_8601_timestamp(args.get('from'), 'from')

    if args.get('to') == 'now':
        payload['end_time'] = iso_date_now
    elif args.get('to'):
        payload['end_time'] = get_iso_8601_timestamp(args.get('to'), 'to')

    return payload


def get_command_title_string(sub_context: str, page: Optional[int],
                             page_size: Optional[int]) -> str:
    """
    : param sub_context: Commands sub_context
    : param page: page_number
    : param page_size: page_size
    : return: returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        return f"{sub_context} List\nShowing page {page}\nCurrent page size:" \
               f" {page_size}"

    return f"{sub_context} List"


def page_validation(args: Dict[str, Any]):
    """
    Arguments Validation.
    Args:
        args: Kwargs
    Returns:
        page: The page number.
        page_size: The number of requested results per page.
    """
    # page validation
    page = arg_to_number(args.pop('page', 1), arg_name='page')
    if page <= 0:
        page = 1
        # demisto_print('Page number should start with 1 !!')

    # page size validation
    page_size = arg_to_number(args.pop('page_size', PAGE_LIMIT), arg_name='page_size')
    if page_size >= MIN_LIMIT or page_size <= 0:
        raise DemistoException(f'Page Size range is between 1 and {MIN_LIMIT}')

    return page, page_size


def fetch_incidents(client: Client):
    # demisto.getLastRun() will returns an obj with the previous run in it.

    last_run = demisto.getLastRun()

    # # 1 days ago starting form current date as Default
    day_ago = today - datetime.timedelta(days=1)
    # demisto_print(f"Day ago: {day_ago}, Last Run: {last_run.get('start_time')}")
    start_time = day_ago.isoformat()[:23] + "Z"

    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')
        #demisto_print(f"Start Time last run: {start_time}")

    now_iso = today.isoformat()[:23] + "Z"
    payload = {
        "verb": "query",
        "start_time": start_time
    }
    #
    #demisto_print(f"Payload: {payload}")
    #
    # # execute the query and get the events
    event_endpoint = '/atpapi/v2/events'
    events_response = client.query(event_endpoint, payload, 'post')

    datasets = events_response.get("result", [])
    # demisto_print(json.dumps(datasets))
    incidents = []

    if datasets:
        for event in datasets:
            event_actor = event.get('event_actor')
            #demisto_print(f"Name : {event_actor.get('file').get('name')}")
            incident = {
                'name': f"TestEvent_{event_actor.get('file').get('name')}",  # name is required field, must be set
                'occurred': event.get('device_time'),  # must be string of a format ISO8601
                'dbotMirrorId': str(event.get('uuid')),  # must be a string
                'rawJSON': json.dumps(event)
                # the original event, this will allow mapping of the event in the mapping stage.
                # Don't forget to `json.dumps`
            }
            incidents.append(incident)
    #
    # # demisto_print(json.dumps(incidents, indent=3))
    demisto.setLastRun({'start_time': now_iso})

    if incidents:
        # this command will create incidents in Cortex XSOAR
        return_results(demisto.incidents(incidents))
    else:
        return_results(demisto.incidents([]))


def get_event_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_event_list_command: Get Event List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/events'
    page, page_size = page_validation(args)
    payload = get_payload(args)
    limit, offset = pagination(page, page_size)
    title = get_command_title_string("Events", page, page_size)
    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    datasets = response_data.get("result", [])
    records = datasets[offset:(offset + limit)]
    if records:
        readable_output = fetch_data_to_markdown(records, title)
    else:
        readable_output = f'{title} Does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EventsList',
        outputs_key_field='',
        outputs=datasets
    )


def get_event_for_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_event_for_incident_command: Get Incident Event List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/incidentevents'
    page, page_size = page_validation(args)
    payload = get_payload(args)
    limit, offset = pagination(page, page_size)

    title = get_command_title_string("Events for Incidents", page, page_size)

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    datasets = response_data.get("result", [])
    records = datasets[offset:(offset + limit)]

    if records:
        readable_output = fetch_data_to_markdown(records, title)
    else:
        readable_output = f'{title} \n Does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentEvents',
        outputs_key_field='',
        outputs=records
    )


def get_incident_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_incident_list_command: Get Incident List

     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    endpoint = '/atpapi/v2/incidents'
    page, page_size = page_validation(args)
    payload = get_payload(args)
    limit, offset = pagination(page, page_size)

    title = get_command_title_string("Incident", page, page_size)

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)

    datasets = response_data.get("result", [])
    records = datasets[offset:(offset + limit)]
    if records:
        readable_output = fetch_data_to_markdown(records, title)
    else:
        readable_output = f'{title} Does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentList',
        outputs_key_field='atp_incident_id',
        outputs=datasets
    )


def get_incident_comments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_incident_comments_command: Get Incident Comments
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    if not re.search(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", args.get("uuid")):
        raise ValueError(
            f'UUID value {args.get("uuid")} is invalid')

    endpoint = f'/atpapi/v2/incidents/{args.pop("uuid")}/comments'
    page, page_size = page_validation(args)
    payload = get_payload(args)
    limit, offset = pagination(page, page_size)

    response_data = client.fetch_data_from_symantec_api(endpoint, payload)
    title = get_command_title_string("Incident Comments", page, page_size)
    datasets = response_data.get("result", [])

    records = datasets[offset:(offset + limit)]

    if records:
        readable_output = fetch_data_to_markdown(records, title)
    else:
        readable_output = f'{title} Does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentComment',
        outputs_key_field='',
        outputs=records
    )


def get_incident_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
      get_incident_update_command: Function is used to close, update resolution or add comments to incidents
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
      """
    endpoint = f'/atpapi/v2/incidents'

    if not re.search(r"\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(?=comments|state|resolution)", args.get("path")):
        raise ValueError(
            f'UUID and path value {args.get("uuid")} is invalid')

    payload = [
            {
                'op': args.get('operation'),
                "path": args.get('path'),
                "value": args.get('value')
            }
        ]

    response = client.fetch_data_from_symantec_api(endpoint, payload, 'patch')

    title = f"Incident Operation Add/Update"

    summary_data = {
        "Message": f'Successfully {args.get("operation")}ed',
    }
    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentCommentPatch',
        outputs_key_field='',
        outputs=response,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
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
    title = "Deny List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DenyListPolicies',
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
    title = "Black List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.BlackListPolicies',
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
    title = "Allow List Policies"

    datasets = response_data.get("result", [])

    if datasets:
        readable_output = fetch_data_to_markdown(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AllowListPolicies',
        outputs_key_field='',
        outputs=datasets
    )


def get_file_sandbox_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     get_file_sandbox_command: Issue File Sandbox command,
            Query file Sandbox command status,
            Get file Sandbox Verdict of specific SHA2
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """

    if args.get('type') == 'issue':
        if not args.get('action') or not args.get('targets'):
            raise DemistoException("For issue a File sandbox command both arguments Action and Target is required !!")

    if args.get('type') == 'status':
        if not args.get('command_id'):
            raise DemistoException("Argument command_id is required !!")

    if args.get('type') == 'verdict':
        if not args.get('sha2'):
            raise DemistoException("Argument sha2 is required !!")

    targets_list = argToList(args.get('targets'), ',')
    if args.get('targets'):
        for file_sha256 in targets_list:
            if not re.match(sha256Regex, file_sha256):
                raise ValueError(
                    f'SHA256 value {file_sha256} is invalid')
    file_sha2 = args.get('sha2')
    if args.get('sha2'):
        if not re.match(sha256Regex, file_sha2):
            raise ValueError(
                f'SHA-2 value {file_sha2} is invalid')

    endpoint = \
        f'/atpapi/v2/sandbox/commands/{args.get("command_id")}' \
        if args.get('command_id') \
        else f'/atpapi/v2/sandbox/results/{args.get("sha2")}/verdict' \
        if args.get("sha2") \
        else '/atpapi/v2/sandbox/commands'

    payload = {
        'action': args.get('action'),
        'targets': targets_list
    } if not args.get('command_id') and not args.get("sha2") else {}

    response_data = \
        client.fetch_data_from_symantec_api(endpoint, payload, 'get') \
        if args.get('command_id') or args.get("sha2") \
        else client.fetch_data_from_symantec_api(endpoint, payload)

    # Get Issue Sandbox Command
    if args.get('type') == 'issue':
        title = "Malicious File in a Sandbox"
        summary_data = {
            "Command ID": response_data.get('command_id')
        }
        headers = list(summary_data.keys())
        return CommandResults(
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxFile',
            outputs_key_field='',
            outputs=response_data,
            readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
        )

    # Get Sandbox Verdict of specific SHA2
    if args.get('type') == 'verdict':
        title = "File Sandbox Verdict"
        summary_data = {
            "VERDICT": response_data.get('verdict'),
            "VERDICT TYPE": response_data.get('verdict_type'),
            "SANDBOX SERVICE": response_data.get('sandbox_service'),
            "IS TARGETED": response_data.get('is_targeted'),
        }
        headers = list(summary_data.keys())
        return CommandResults(
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxFile.Verdict',
            outputs_key_field='',
            outputs=response_data,
            readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
        )

    if args.get('type') == 'status':
        # Query Sandbox Command Status
        datasets = response_data.get("status", [])
        title = "File Sandbox Status"
        if datasets:
            readable_output = fetch_data_to_markdown(datasets, title)
        else:
            readable_output = f'{title} does not have data to present. \n'

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxFile.Status',
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
         prefix (str): Optional
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
    # demisto_print(f"Parameters : {json.dumps(params)}")
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
                "symantec-edr-endpoint-command": get_endpoint_command,

                # Domain File Associations
                "symantec-edr-domain-file-association-list": get_association_command,

                # Endpoint Domain Associations
                "symantec-edr-endpoint-domain-association-list": get_association_command,

                # Endpoint File Associations
                "symantec-edr-endpoint-file-association-list": get_association_command,

                # Get Incidents
                "symantec-edr-incident-list": get_incident_list_command,

                # Get Incident Comments
                "symantec-edr-incident-comment-get": get_incident_comments_command,

                # Patch Incidents Command to (Close Incidents, Update Resolution or Add Comments)
                "symantec-edr-incident-update": get_incident_update_command,

                # File Sandbox Analysis, Command Status, and Verdict
                "file": get_file_sandbox_command,

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
                "symantec-edr-event-list": get_event_list_command,

                # Events For Incidents
                "symantec-edr-incident-event-list": get_event_for_incident_command

        }
        if command == "test-module":
            return_results(client.test_module())
        elif command == 'fetch-incidents':
            # demisto_print(json.dumps(args, indent=3))
            return_results(fetch_incidents(client))
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
