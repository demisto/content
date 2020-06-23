from typing import Dict, Optional, Tuple, Callable, Any, Union

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# key =  field of a ticket , val = dict of (name,id) of options
TICKETS_OBJECTS = {
    'impact': {
        '1 person cannot work': 1,
        'Many people cannot work': 2,
        '1 person inconvenienced': 3,
        'Many people inconvenienced': 4
    },
    'category': {
        "Network": 1,
        "Other": 2,
        "Software": 4,
        "Hardware": 3
    },
    'priority': {
        "Medium": 1,
        'High': 2,
        'Low': 3
    },
    'status': {
        'Opened': 1,
        'Closed': 2,
        'Need More Info': 3,
        'New': 4,
        'Reopened': 5,
        'Waiting Overdue': 6,
        'Waiting on Customer': 7,
        'Waiting on Third Party': 8
    }
}


def convert_snake_to_camel(snake_str: str) -> str:
    """Convert a specific string of snake case to camel case.
        Args:
            snake_str: The string that we would like to convert.
        Returns:
            converted string.
        """
    snake_split = snake_str.split("_")
    camel_string = "".join(map(str.capitalize, snake_split))
    camel_string = convert_specific_keys(camel_string)
    return camel_string


def convert_specific_keys(string: str):
    """
    Convert specific keys to demisto standard
    Args:
        string: the text to transform
    Returns:
        A Demisto output standard string
    """
    if string == 'OsName':
        return 'OSName'
    if string == 'OsNumber':
        return 'OSNumber'
    if string == 'Ram total':
        return 'RamTotal'
    if string == 'AssetDataId':
        return 'AssetDataID'
    if string == 'AssetClassId':
        return 'AssetClassID'
    if string == 'AssetStatusId':
        return 'AssetStatusID'
    if string == 'AssetTypeId':
        return 'AssetTypeID'
    if string == 'MappedId':
        return 'MappedID'
    if string == 'OwnerId':
        return 'OwnerID'
    if string == 'HdQueueId':
        return 'HdQueueID'
    if string == 'Ip':
        return 'IP'
    return string


def convert_dict_snake_to_camel(dic: dict) -> dict:
    """Convert a dictionary of snake case to camel case.
        Args:
            dic: The dictionary that we would like to convert.
        Returns:
            converted dictionary.
        """
    context_dict = {}
    for snake_str in dic:
        if type(dic[snake_str]) is dict:
            inner_dict = convert_dict_snake_to_camel(dic[snake_str])
            camel = convert_snake_to_camel(snake_str)
            context_dict[camel] = inner_dict
        elif type(dic[snake_str]) is list:
            inner_dict = parse_response(dic[snake_str])
            camel = convert_snake_to_camel(snake_str)
            context_dict[camel] = inner_dict
        elif snake_str in ['id', 'Id']:
            context_dict['ID'] = dic.get(snake_str, '')
        else:
            camel = convert_snake_to_camel(snake_str)
            context_dict[camel] = dic.get(snake_str, '')
    return context_dict


def parse_response(lst: list):
    """Convert a Api response to wanted format.
        Args:
            lst: A list of dictionaries that return from api call.
        Returns:
            converted list of dictionaries from snake case to camel case.
        """
    list_res = []
    for dic in lst:
        context_dict = convert_dict_snake_to_camel(dic)
        list_res.append(context_dict)
    return list_res


class Client(BaseClient):
    """
    Client to use in the integration, overrides BaseClient.
    Used for communication with the api.
    """

    def __init__(self, url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=f"{url}/api", verify=verify, proxy=proxy)
        self._url = url
        self._username = username
        self._password = password
        self._token, self._cookie = self.get_token()

    def get_token(self) -> Tuple[str, str]:
        """Get a token for the connection.
            Returns:
                token , cookie for the connection.
        """
        token = ''
        cookie = ''
        data = {
            "userName": self._username,
            "password": self._password
        }
        login_url = f"{self._url}/ams/shared/api/security/login"
        body = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        response = self.token_request(login_url, headers=headers, data=body)
        # Extracting Token
        response_cookies = response.get('cookies').__dict__.get('_cookies')
        if response_cookies:
            cookie_key = list(response_cookies.keys())[0]
            if cookie_key:
                ret_cookie = response_cookies.get(cookie_key).get("/")
                cookie = self.get_cookie(ret_cookie)
                token = ret_cookie.get("KACE_CSRF_TOKEN").__dict__.get('value')
        if not token:
            raise DemistoException("Could not get token")
        if not cookie:
            raise DemistoException("Could not get cookie")
        return token, cookie

    def update_token(self):
        """Update cookie and token.
            Returns:
                Tuple of token and cookie.
        """
        self._token, self._cookie = self.get_token()

    def get_cookie(self, res_cookie: dict) -> str:
        """Get a cookie from an cookie object in the needed format for the requests.
            Args:
                res_cookie: part of the response that the cookie is inside it.
            Returns:
                string that will be sent in the requests which represents the cookie in the header.
        """
        KACE_CSRF_TOKEN = res_cookie.get("KACE_CSRF_TOKEN").__dict__.get('value')
        x_dell_auth_jwt = res_cookie.get("x-dell-auth-jwt").__dict__.get('value')
        kboxid = res_cookie.get("kboxid").__dict__.get('value')
        KACE_LAST_USER_SECURE = res_cookie.get("KACE_LAST_USER_SECURE").__dict__.get('value')
        KACE_LAST_ORG_SECURE = res_cookie.get("KACE_LAST_ORG_SECURE").__dict__.get('value')

        cookie = f'KACE_LAST_USER_SECURE={KACE_LAST_USER_SECURE}; KACE_LAST_ORG_SECURE={KACE_LAST_ORG_SECURE};' \
                 f' kboxid={kboxid}; x-dell-auth-jwt={x_dell_auth_jwt}; KACE_CSRF_TOKEN={KACE_CSRF_TOKEN}'
        return cookie

    def token_request(self, url: str, headers: Optional[dict] = None, data: Optional[str] = None) -> dict:
        """login request for initiating a connection with the product.
        Args:
            url: full url that the request will be sent to.
            headers: headers of the request.
            data: data of the request which includes username and password.
        Returns:
            Dictionary of the response from the product.
        """
        try:
            response = requests.request("POST", url, headers=headers, data=data, verify=self._verify)
        except requests.exceptions.SSLError:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg)
        except requests.exceptions.ConnectionError:
            raise DemistoException("Invalid url , Failed to establish a connection")
        if response.status_code == 401:
            raise DemistoException("Error Code 401 - Invalid user or password")
        return response.__dict__

    def machines_list_request(self, filter_fields: Optional[str] = None):
        """List of machines.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        url_suffix = '/inventory/machines'
        if filter_fields:
            url_suffix += f'?filtering={filter_fields}'
        return self._http_request("GET", url_suffix=url_suffix, headers=headers)

    def assets_list_request(self, filter_fields: Optional[str] = None) -> dict:
        """List of assets.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        url_suffix = '/asset/assets'
        if filter_fields:
            url_suffix += f'?filtering={filter_fields}'
        return self._http_request("GET", url_suffix=url_suffix, headers=headers)

    def queues_list_request(self, filter_fields: Optional[str] = None) -> dict:
        """List of queues.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        url_suffix = '/service_desk/queues?shaping=fields all'
        if filter_fields:
            url_suffix += f'&filtering={filter_fields}'
        return self._http_request("GET", url_suffix=url_suffix, headers=headers)

    def queues_list_fields_request(self, queue_number: str) -> dict:
        """List of fields in specific queue.
            Args:
                queue_number: queue nubmer for the request.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        return self._http_request("GET", url_suffix=f"/service_desk/queues/{queue_number}/fields", headers=headers)

    def tickets_list_request(self, shaping_fields: str = None, filter_fields: str = None) -> dict:
        """List of Tickets.
            Args:
                shaping_fields: str of the shaping that will be sent in the request.
                filter_fields: str of filter that will be sent in the request.
           Returns:
               Response from API.
        """
        if not shaping_fields:
            shaping_fields = set_shaping(self)
        self.update_token()
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        url_suffix = f"/service_desk/tickets?shaping={shaping_fields}"
        if filter_fields:
            url_suffix += f'&filtering={filter_fields}'
        return self._http_request("GET", url_suffix=url_suffix, headers=headers)

    def create_ticket_request(self, data: str) -> dict:
        """Create Ticket
            Args:
                data (str): the body of the request.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie,
            'Content-Type': 'application/json'
        }
        return self._http_request("POST", url_suffix="/service_desk/tickets", headers=headers, data=data)

    def update_ticket_request(self, ticket_id: str, data: str) -> dict:
        """Update Ticket.
           Args:
            ticket_id (str): ticket id that will be updated.
            data (str): the body of the request.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie,
            'Content-Type': 'application/json'
        }
        return self._http_request("POST", url_suffix=f"/service_desk/tickets/{ticket_id}", headers=headers, data=data)

    def delete_ticket_request(self, ticket_id: str) -> dict:
        """Delete Ticket.
            Args:
                ticket_id (str): ticket id that will be deleted.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie,
            'Content-Type': 'application/json'
        }
        return self._http_request("DELETE", url_suffix=f"/service_desk/tickets/{ticket_id}", headers=headers)

    def ticket_by_id_request(self, filtering_id: int) -> dict:
        """Specific ticket details by ID.
            Args:
                filtering_id: id for filtering by it.
           Returns:
               Response from API.
        """
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        filter_fields = f"id eq {filtering_id}"
        return self._http_request("GET", url_suffix=f"/service_desk/tickets?filtering={filter_fields}", headers=headers)


def test_module(client: Client, *_) -> Tuple[str, dict, dict]:
    """Function which checks if there is a connection with the api.
        Args:
            client : Integration client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    _ = client.machines_list_request()
    client.update_token()
    response = client.tickets_list_request()
    list_tickets_res = response.get('Tickets')
    if list_tickets_res and demisto.params().get('isFetch'):
        parse_date_range(demisto.params().get('fetch_time'), date_format='%Y-%m-%dT%H:%M:%SZ')
        parsed_time = (datetime.utcnow() - timedelta(days=20))
        incidents, _ = parse_incidents(list_tickets_res, "1", '%Y-%m-%dT%H:%M:%SZ', parsed_time)
    return 'ok', {}, {}


def get_machines_list_command(client, args) -> Tuple[str, dict, dict]:
    """Function which returns all machines in the system.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    limit = int(args.get('limit', 50))
    filter_fields = args.get('custom_filter')
    response = client.machines_list_request(filter_fields)
    raw_response = response.get('Machines')[:limit]
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Machines', context, removeNull=True, headers=['ID', 'Name',
                                                                                                        'IP', 'Created',
                                                                                                        'Modified',
                                                                                                        'LastInventory',
                                                                                                        'LastSync',
                                                                                                        'ManualEntry',
                                                                                                        'PagefileMaxSize',
                                                                                                        'PagefileSize',
                                                                                                        'RamTotal',
                                                                                                        'RamUsed'])
    context = {
        'QuestKace.Machine(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def get_assets_list_command(client, args) -> Tuple[str, dict, dict]:
    """Function which returns all assets in the system.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    limit = int(args.get('limit', 50))
    filter_fields = args.get('custom_filter')
    response = client.assets_list_request(filter_fields)
    raw_response = response.get('Assets')[:limit]
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Assets', context, removeNull=True,
                                              headers=['ID', 'Name', 'Created', 'Modified', 'OwnerID', 'MappedID',
                                                       'AssetClassID', 'AssetDataID', 'AssetStatusID', 'AssetTypeID',
                                                       'AssetTypeName'])
    context = {
        'QuestKace.Asset(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def get_queues_list_command(client, args) -> Tuple[str, dict, dict]:
    """Function which returns all queues in the system.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    filter_fields = args.get('custom_filter')
    limit = int(args.get('limit', 50))
    response = client.queues_list_request(filter_fields)
    raw_response = response.get('Queues')[:limit]
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Queues', context, removeNull=True,
                                              headers=['ID', 'Name', 'Fields'])
    context = {
        'QuestKace.Queue(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def get_tickets_list_command(client, args) -> Tuple[str, dict, dict]:
    """Function which returns all tickets in the system.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    limit = int(args.get('limit', 50))
    custom_shaping = args.get("custom_shaping")
    custom_filter = args.get("custom_filter")
    response = client.tickets_list_request(custom_shaping, custom_filter)
    raw_response = response.get('Tickets')[:limit]
    context = parse_response(raw_response)
    for response in context:
        response['IsDeleted'] = False
    human_readable_markdown = tableToMarkdown(f'Quest Kace Tickets', context, removeNull=True,
                                              headers=['ID', 'Title', 'Created', 'Modified', 'HdQueueID', 'DueDate'])
    context = {
        'QuestKace.Ticket(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def create_ticket_command(client, args) -> Tuple[str, dict, dict]:
    """Function which creates a new ticket to the system according to users arguments.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    impact = None
    category = None
    status = None
    priority = None
    hd_queue_id = args.get('queue_id')
    custom_fields = args.get('custom_fields')
    if (custom_fields and "hd_queue_id" not in custom_fields) and (not hd_queue_id):
        raise DemistoException("hd_queue_id is a mandatory value, please add it.")
    title = args.get("title")
    summary = args.get('summary')
    if args.get('impact'):
        dict_of_obj = TICKETS_OBJECTS.get('impact')
        impact = args.get('impact')
        if dict_of_obj:
            impact = dict_of_obj.get(args.get('impact'), args.get('impact'))
    if args.get('category'):
        dict_of_obj = TICKETS_OBJECTS.get('category')
        impact = args.get('category')
        if dict_of_obj:
            impact = dict_of_obj.get(args.get('category'), args.get('category'))
    if args.get('status'):
        dict_of_obj = TICKETS_OBJECTS.get('status')
        impact = args.get('status')
        if dict_of_obj:
            impact = dict_of_obj.get(args.get('status'), args.get('status'))
    if args.get('priority'):
        dict_of_obj = TICKETS_OBJECTS.get('priority')
        impact = args.get('priority')
        if dict_of_obj:
            impact = dict_of_obj.get(args.get('priority'), args.get('priority'))
    machine = args.get('machine')
    asset = args.get('asset')
    body_from_args = create_body_from_args(hd_queue_id, title, summary, impact, category, status, priority, machine,
                                           asset)
    if custom_fields:
        splited = split_fields(custom_fields)
        body_from_args.update(splited)
    temp_data = {'Tickets': [body_from_args]}
    data = json.dumps(temp_data)
    response = client.create_ticket_request(data)
    if response.get('Result') != 'Success':
        raise DemistoException(f'Error while adding a new ticket.')
    try:
        id = response.get('IDs')[0]
    except Exception as e:
        raise DemistoException(e)
    client.update_token()
    res = client.ticket_by_id_request(id)
    ticket = res.get('Tickets')
    ticket_view = tableToMarkdown(f'New ticket was added successfully, ticket number {id}.\n', ticket)
    return ticket_view, {}, {}


def create_body_from_args(hd_queue_id: Union[str, int] = None, title: Union[str, int] = None,
                          summary: Union[str, int] = None, impact: Union[str, int] = None,
                          category: Union[str, int] = None, status: Union[str, int] = None,
                          priority: Union[str, int] = None, machine: Union[str, int] = None,
                          asset: Union[str, int] = None) -> dict:
    """Function which creates the body of the request from user arguments.
        Args:
           hd_queue_id: the queue number to insert the ticket to.
           title: title of the ticket.
           summary: summary of the ticket.
           impact: impact of the ticket.
           category: category of the ticket.
           status: status of the ticket.
           priority: priority of the ticket.
           machine: machine of the ticket.
           asset: asset of the ticket.
       Returns:
           body of the request as a dict.
    """
    body = {}
    if hd_queue_id:
        body.update({'hd_queue_id': hd_queue_id})
    if title:
        body.update({'title': title})
    if summary:
        body.update({'summary': summary})
    if impact:
        body.update({'impact': impact})
    if category:
        body.update({'category': category})
    if status:
        body.update({'status': status})
    if priority:
        body.update({'priority': priority})
    if machine:
        body.update({'machine': machine})
    if asset:
        body.update({'asset': asset})
    return body


def update_ticket_command(client, args) -> Tuple[str, dict, dict]:
    """Function which updates the body of the request from user arguments.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    impact = None
    category = None
    status = None
    priority = None
    ticket_id = args.get('ticket_id')
    title = args.get("title")
    summary = args.get('summary')
    if args.get('impact'):
        impact = TICKETS_OBJECTS['impact'][args.get('impact')]
    if args.get('category'):
        category = TICKETS_OBJECTS['category'][args.get('category')]
    if args.get('status'):
        status = TICKETS_OBJECTS['status'][args.get('status')]
    if args.get('priority'):
        priority = TICKETS_OBJECTS['priority'][args.get('priority')]
    machine = args.get('machine')
    asset = args.get('asset')
    custom_fields = args.get('custom_fields')

    body_from_args = create_body_from_args(title=title, summary=summary, impact=impact, category=category,
                                           status=status,
                                           priority=priority, machine=machine, asset=asset)
    if custom_fields:
        splited = split_fields(custom_fields)
        body_from_args.update(splited)
    temp_data = {'Tickets': [body_from_args]}
    data = json.dumps(temp_data)

    response = client.update_ticket_request(ticket_id, data)
    if response.get('Result') != 'Success':
        raise DemistoException(f'Error while updating the ticket.')
    client.update_token()
    res = client.ticket_by_id_request(ticket_id)
    ticket = res.get('Tickets')
    ticket_view = tableToMarkdown(f'Ticket number {ticket_id} was updated successfully.\n', ticket)
    return ticket_view, {}, {}


def delete_ticket_command(client, args) -> Tuple[str, dict, dict]:
    """Function which deleted a specific ticket by ticket id.
        Args:
            client : Integretion client which communicates with the api.
            args: Users arguments of the command.
       Returns:
           human readable, context, raw response of this command.
    """
    ticket_id = args.get('ticket_id')
    try:
        response = client.delete_ticket_request(ticket_id)
    except Exception as e:
        raise DemistoException(e)
    if response.get('Result') == 'Success':
        context = {}
        old_context = demisto.dt(demisto.context(), f'QuestKace.Ticket(val.ID === {ticket_id})')
        if old_context:
            if isinstance(old_context, list):
                old_context = old_context[0]
            old_context['IsDeleted'] = True
            context = {
                f'QuestKace.Ticket(val.ID === obj.ID)': old_context
            }
        return f'Ticket was deleted successfully. Ticket number {ticket_id}', context, {}
    else:
        raise DemistoException(f'Error while deleting the ticket.')


def fetch_incidents(client: Client, fetch_time: str, fetch_shaping: str, last_run: Dict, fetch_limit: str,
                    fetch_queue_id: Optional[list] = None, fetch_filter: Optional[str] = None) -> list:
    """
    This function will execute each interval (default is 1 minute).
    Args:
        client (Client): Quest Kace Client
        fetch_time: time interval for fetch incidents.
        fetch_shaping: shaping for the request.
        fetch_filter: custom filters for the request.
        fetch_limit: limit for number of fetch incidents per fetch.
        fetch_queue_id: queue id for fetch, if not given then fetch runs on all tickets in the system
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
    Returns:
        incidents: Incidents that will be created in Demisto
    """
    if not fetch_queue_id or fetch_queue_id[0] == 'All':
        fetch_queue_id = get_queue_ids(client)
    time_format = '%Y-%m-%dT%H:%M:%SZ'
    if not last_run:  # if first time running
        new_last_run = {'last_fetch': parse_date_range(fetch_time, date_format=time_format)[0]}
    else:
        new_last_run = last_run

    if not fetch_shaping:
        fetch_shaping = shaping_fetch(client, fetch_queue_id)

    parsed_last_time = datetime.strptime(new_last_run.get('last_fetch', ''), time_format)
    fetch_filter_for_query = f'created gt {parsed_last_time}'
    if fetch_queue_id:
        queue_id_str = ';'.join(fetch_queue_id)
        filter_by_queue_id = f'hd_queue_id in {queue_id_str}'
        fetch_filter_for_query = f'{fetch_filter_for_query},{filter_by_queue_id}'
    if fetch_filter:
        fetch_filter_for_query = f'{fetch_filter_for_query},{fetch_filter}'
    demisto.info(f"Fetching Incident has Started,\n"
                 f"Fetch filter is {fetch_filter_for_query}\n"
                 f"Last fetch was on {str(parsed_last_time)}")
    client.update_token()
    items: dict = client.tickets_list_request(fetch_shaping, fetch_filter_for_query)
    items: list = items.get('Tickets', [])
    incidents, last_incident_time = parse_incidents(items, fetch_limit, time_format, parsed_last_time)
    last_incident_time = last_incident_time.strftime(time_format)
    demisto.info(f"Fetching Incident has Finished\n"
                 f"Fetch limit was {fetch_limit}"
                 f"Last fetch was on {str(last_incident_time)}\n"
                 f"Number of incidents was {len(incidents)}")
    demisto.setLastRun({'last_fetch': last_incident_time})
    return incidents


def shaping_fetch(client: Client, fetch_queue_id: list) -> str:
    """
    Create and Update shaping fields once a day and saves them in integration context.
    Args:
        client: Client for the api.
        fetch_queue_id:
    Returns:
        the current shaping.
    """
    integration_context = demisto.getIntegrationContext()
    if integration_context:
        valid_until = integration_context.get('valid_until')
        time_now = int(time.time())
        if time_now < valid_until:
            fetch_shaping = integration_context.get('shaping_fields')
        else:
            fetch_shaping = set_shaping(client, fetch_queue_id)
            integration_context = {
                'shaping_fields': fetch_shaping,
                'valid_until': int(time.time()) + 3600 * 24
            }
            demisto.setIntegrationContext(integration_context)
    else:
        fetch_shaping = set_shaping(client, fetch_queue_id)
        integration_context = {
            'shaping_fields': fetch_shaping,
            'valid_until': int(time.time()) + 3600 * 24
        }
        demisto.setIntegrationContext(integration_context)
    return fetch_shaping


def get_fields_by_queue(client, queue: Optional[list]) -> list:
    """
    Creating a list of all queue ids that are in the system.
    Args:
        client: Client for the api.
    Returns:
        list of queue ids.
    """
    if queue:
        queues_id = queue
    else:
        queues_id = get_queue_ids(client)
    fields: list = []
    for q in queues_id:
        client.update_token()
        fields_by_queue = client.queues_list_fields_request(queue_number=str(q))
        fields_by_queue = fields_by_queue.get('Fields', [])
        for field in fields_by_queue:
            if field.get('jsonKey') not in fields:
                # get internal error 500 from server with related tickets
                if field.get('jsonKey') != 'related_tickets' and field.get('jsonKey') != 'referring_tickets':
                    fields.append(field.get('jsonKey'))
    return fields


def get_queue_ids(client: Client) -> list:
    """
    Creating a list of all queue ids that are in the system.
    Args:
        client: Client for the api.
    Returns:
        list of queue ids.
    """
    queues = client.queues_list_request()
    queues = queues.get('Queues', [])
    queues_id = []
    for q in queues:
        queues_id.append(str(q.get('id')))
    return queues_id


def shaping_by_fields(fields: list) -> str:
    """
    Creating a shaping for the request which is from the fields and seperated by comma's
    Args:
        fields: List of fields that would be part of the shaping.
    Returns:
        str of the shaping.
    """
    shaping = 'hd_ticket all'
    for field in fields:
        shaping += f',{field} limited'
    return shaping


def set_shaping(client, queue: Optional[list] = None) -> str:
    """
    Creating a shaping for the request.
    Args:
        client: Client in order to get the queue fields.
        queue: If specific queue is given for the shaping.
    Returns:
        str of the shaping.
    """
    fields = get_fields_by_queue(client, queue)
    shaping = shaping_by_fields(fields)
    return shaping


def parse_incidents(items: list, fetch_limit: str, time_format: str, parsed_last_time: datetime) \
        -> Tuple[list, Any]:
    """
    This function will create a list of incidents
    Args:
        items : List of tickets of the api response.
        fetch_limit: Limit for incidents of fetch cycle.
        time_format: Time format of the integration.
        parsed_last_time: limit for number of fetch incidents per fetch.
    Returns:
        incidents: List of incidents.
        parsed_last_time: Time of last incident.
    """
    count = 0
    incidents = []
    for item in items:
        if count >= int(fetch_limit):
            break

        incident_created_time = dateparser.parse(item['created'])

        incident = {
            'name': item['title'],
            'occurred': incident_created_time.strftime(time_format),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)
        count += 1
        parsed_last_time = incident_created_time
    return incidents, parsed_last_time


def split_fields(fields: str = '') -> dict:
    """Split str fields of Demisto arguments to request fields by the char ';'.
    Args:
        fields: fields in a string representation.
    Returns:
        dic_fields object for request.
    """
    dic_fields = {}
    if fields:
        if '=' not in fields:
            raise Exception(
                f"The argument: {fields}.\nmust contain a '=' to specify the keys and values. e.g: key=val.")
        arr_fields = fields.split(';')
        for f in arr_fields:
            field = f.split('=', 1)  # a field might include a '=' sign in the value. thus, splitting only once.
            if len(field) > 1:
                dic_fields[field[0]] = field[1]
    return dic_fields


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get("identifier")
    password = params.get('credentials').get('password')
    base_url = params.get('url')
    proxy = demisto.params().get('proxy', False)
    verify_certificate = not params.get('insecure', False)

    # fetch incidents params
    fetch_limit = params.get('fetch_limit', 10)
    fetch_time = params.get('fetch_time', '1 day')
    fetch_shaping = params.get('fetch_shaping')
    fetch_filter = params.get('fetch_filter')
    fetch_queue_id = argToList(params.get('fetch_queue_id'))
    try:
        client = Client(
            url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy)
        command = demisto.command()
        LOG(f'Command being called is {command}')
        # Commands dict
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, dict, dict]]] = {
            'test-module': test_module,
            'kace-machines-list': get_machines_list_command,
            'kace-assets-list': get_assets_list_command,
            'kace-queues-list': get_queues_list_command,
            'kace-tickets-list': get_tickets_list_command,
            'kace-ticket-create': create_ticket_command,
            'kace-ticket-update': update_ticket_command,
            'kace-ticket-delete': delete_ticket_command,
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client, fetch_time=fetch_time, fetch_shaping=fetch_shaping,
                                        fetch_filter=fetch_filter, fetch_limit=fetch_limit,
                                        fetch_queue_id=fetch_queue_id, last_run=demisto.getLastRun())
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f'{command} is not an existing QuestKace command')
    except Exception as e:
        return_error(f'Error from QuestKace Integration.\n'
                     f'Failed to execute {demisto.command()} command.\n\n Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
