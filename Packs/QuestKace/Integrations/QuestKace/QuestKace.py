from typing import Dict, Optional

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
# IMPORTS
import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def convert_snake_to_camel(snake_str):
    snake_split = snake_str.split("_")
    camel_string = "".join(map(str.capitalize, snake_split))
    return camel_string


def convert_dict_snake_to_camel(dic):
    context_dict = {}
    for snake_str in dic:
        if type(dic[snake_str]) is dict:
            inner_dict = convert_dict_snake_to_camel(dic[snake_str])
            camel = convert_snake_to_camel(snake_str)
            context_dict[camel] = inner_dict
        elif snake_str == 'id' or snake_str == "Id":
            context_dict['ID'] = dic.get(snake_str)
        else:
            camel = convert_snake_to_camel(snake_str)
            context_dict[camel] = dic.get(snake_str)
    return context_dict


def parse_response(lst):
    print(lst)
    list_res = []
    for dic in lst:
        context_dict = convert_dict_snake_to_camel(dic)
        list_res.append(context_dict)
    print(list_res)
    return list_res


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, username: str, password: str, verify: bool,
                 proxy: bool):
        super().__init__(base_url=(url + "/api"), verify=verify, proxy=proxy)
        self._url = url
        self._username = username
        self._password = password
        self._token, self._cookie = self.get_token()

    def get_token(self):
        data = {
            "userName": self._username,
            "password": self._password
        }
        login_url = self._url + '/ams/shared/api/security/login'
        body = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        response = self.token_request("Post", login_url, headers=headers, data=body)
        # Extracting Token
        response_cookies = response.cookies._cookies
        cookie_key = list(response_cookies.keys())[0]
        ret_cookie = response_cookies.get(cookie_key).get("/")
        cookie = self.get_cookie(ret_cookie)
        token = ret_cookie.get("KACE_CSRF_TOKEN").__dict__.get('value')
        return token, cookie

    def get_cookie(self, res_cookie):
        KACE_CSRF_TOKEN = res_cookie.get("KACE_CSRF_TOKEN").__dict__.get('value')
        x_dell_auth_jwt = res_cookie.get("x-dell-auth-jwt").__dict__.get('value')
        kboxid = res_cookie.get("kboxid").__dict__.get('value')
        KACE_LAST_USER_SECURE = res_cookie.get("KACE_LAST_USER_SECURE").__dict__.get('value')
        KACE_LAST_ORG_SECURE = res_cookie.get("KACE_LAST_ORG_SECURE").__dict__.get('value')

        cookie = f'KACE_LAST_USER_SECURE={KACE_LAST_USER_SECURE}; KACE_LAST_ORG_SECURE={KACE_LAST_ORG_SECURE};' \
                 f' kboxid={kboxid}; x-dell-auth-jwt={x_dell_auth_jwt}; KACE_CSRF_TOKEN={KACE_CSRF_TOKEN}'
        return cookie

    def token_request(self, method, url, headers=None, data=None):
        try:
            response = requests.request(method, url, headers=headers, data=data, verify=self._verify)
        except requests.exceptions.SSLError:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg)
        except requests.exceptions.ConnectionError:
            raise DemistoException("Invalid url , Failed to establish a connection")
        if response.status_code == 401:
            raise DemistoException("Error Code 401 - Invalid user or password")
        return response

    def machines_list_request(self):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        return self._http_request("GET", url_suffix="/inventory/machines", headers=headers)

    def assets_list_request(self):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        return self._http_request("GET", url_suffix="/asset/assets", headers=headers)

    def queues_list_request(self):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        return self._http_request("GET", url_suffix="/service_desk/queues", headers=headers)

    def queues_list_fields_request(self, queue_number):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        return self._http_request("GET", url_suffix=f"/service_desk/queues/{queue_number}/fields", headers=headers)

    def tickets_list_request(self, shaping_fields, filter_fields=None):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie
        }
        if filter_fields:
            return self._http_request("GET", url_suffix=f"/service_desk/tickets?filtering={filter_fields}&"
                                                        f"shaping={shaping_fields}", headers=headers)
        else:
            return self._http_request("GET", url_suffix=f"/service_desk/tickets?shaping={shaping_fields}",
                                      headers=headers)

    def update_ticket_request(self, ticket_id, data):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie,
            'Content-Type': 'application/json'
        }
        return self._http_request("POST", url_suffix=f"/service_desk/tickets/{ticket_id}", headers=headers, data=data)

    def delete_ticket_request(self, ticket_id):
        headers = {
            'Accept': 'application/json',
            'x-dell-csrf-token': self._token,
            'x-dell-api-version': '5',
            'Cookie': self._cookie,
            'Content-Type': 'application/json'
        }
        return self._http_request("DELETE", url_suffix=f"/service_desk/tickets/{ticket_id}", headers=headers)


def test_module(client, args=None):
    response = client.machines_list_request()
    list_machines_res = response.get('Machines')
    if list_machines_res:
        return 'ok', {}, {}
    else:
        return 'Test failed', {}, {}


def get_machines_list_command(client, args):
    response = client.machines_list_request()
    raw_response = response.get('Machines')
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Machines', context, removeNull=True)
    context = {
        'QuestKace.Machines(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def get_assets_list_command(client, args):
    response = client.assets_list_request()
    raw_response = response.get('Assets')
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Assets', context, removeNull=True)
    context = {
        'QuestKace.Assets(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def get_queues_list_command(client, args):
    response = client.queues_list_request()
    raw_response = response.get('Queues')
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown('Quest Kace Queues', context, removeNull=True)
    context = {
        'QuestKace.Queues(val.ID === obj.ID)': context
    }
    print(context)
    print(raw_response)
    return human_readable_markdown, context, raw_response


def get_queues_fields_list_command(client, args):
    queue_number = args.get('queue_number')
    response = client.queues_list_fields_request(queue_number)
    raw_response = response.get('Fields')
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown(f'Quest Kace Queue {queue_number} Fields', context, removeNull=True)
    context = {
        'QuestKace.Queues.Fields(val.JsonKey === obj.JsonKey)': context
    }
    return human_readable_markdown, context, raw_response


def get_tickets_list_command(client, args):
    shaping_fields = args.get("custom_fields")
    response = client.tickets_list_request(shaping_fields)
    raw_response = response.get('Tickets')
    context = parse_response(raw_response)
    human_readable_markdown = tableToMarkdown(f'Quest Kace Tickets', context, removeNull=True)
    context = {
        'QuestKace.Tickets(val.ID === obj.ID)': context
    }
    return human_readable_markdown, context, raw_response


def create_ticket_command(client, args):
    hd_queue_id = args.get('queue_id')
    custom_fields = args.get('custom_fields')
    if not hd_queue_id and not custom_fields:
        raise DemistoException("queue id is a mandatory value, please add it to your request")
    title = args.get("title")
    summary = args.get('summary')
    impact = args.get('impact')
    category = args.get('category')
    status = args.get('status')
    priority = args.get('priority')
    machine = args.get('machine')
    asset = args.get('asset')
    # owner = "for now" #??????
    if not custom_fields:
        data = create_body_from_args(hd_queue_id, title, summary, impact, category, status, priority, machine, asset)
        data = {'Tickets': [data]}
    else:

        data = {'Tickets': [json.loads(custom_fields)]}
    data = json.dumps(data)
    demisto.log(data)

    headers = {
        'Accept': 'application/json',
        'x-dell-csrf-token': client._token,
        'x-dell-api-version': '5',
        'Cookie': client._cookie,
        'Content-Type': 'application/json'
    }
    response = client._http_request("POST", url_suffix="/service_desk/tickets", headers=headers, data=data)
    if response.get('Result') == 'Success':
        id = response.get('IDs')[0]
        return f'New ticket was added successfully, ticket number {id}.', {}, {}
    else:
        return f'Error while adding a new ticket.', {}, {}


def create_body_from_args(hd_queue_id=None, title=None, summary=None, impact=None, category=None, status=None,
                          priority=None, machine=None, asset=None):
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


def update_ticket_command(client, args):
    ticket_id = args.get('ticket_id')
    title = args.get("title")
    summary = args.get('summary')
    impact = args.get('impact')
    category = args.get('category')
    status = args.get('status')
    priority = args.get('priority')
    machine = args.get('machine')
    asset = args.get('asset')
    owner = "for now"  # ??????
    custom_fields = args.get('custom_fields')

    if not custom_fields:
        data = create_body_from_args(title=title, summary=summary, impact=impact, category=category, status=status,
                                     priority=priority, machine=machine, asset=asset)
        data = {'Tickets': [{'change': data}]}
    else:
        data = {'Tickets': [{'change': json.loads(custom_fields)}]}
    data = json.dumps(data)

    response = client.update_ticket_request(ticket_id, data)
    if response.get('Result') == 'Success':
        return f'Ticket was updated successfully.', {}, {}
    else:
        return f'Error while updating the ticket.', {}, {}


def delete_ticket_command(client, args):
    ticket_id = args.get('ticket_id')
    response = client.delete_ticket_request(ticket_id)
    if response.get('Result') == 'Success':
        return f'Ticket was updated successfully.', {}, {}
    else:
        return f'Error while updating the ticket.', {}, {}


def fetch_incidents(client: Client, fetch_time: str, fetch_shaping: str, last_run: Dict, fetch_limit: str,
                    fetch_filter: Optional[str] = None):
    """
    This function will execute each interval (default is 1 minute).
    Args:
        client (Client): Quest Kace Client
        fetch_time:
        fetch_shaping:
        fetch_filter:
        fetch_limit
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    time_format = '%Y-%m-%dT%H:%M:%SZ'
    count = 1
    if not last_run:  # if first time running
        new_last_run = {'last_fetch': parse_date_range(fetch_time, date_format=time_format)[0]}
    else:
        new_last_run = last_run

    parsed_last_time = datetime.strptime(new_last_run.get('last_fetch'), time_format)
    filter_after_last_run = f'created gt {parsed_last_time}'
    if fetch_filter:
        fetch_filter = fetch_filter + f',{filter_after_last_run}'
    else:
        fetch_filter = filter_after_last_run

    incidents = []

    items = client.tickets_list_request(fetch_shaping, fetch_filter)
    items = items.get('Tickets')
    for item in items:
        if count > int(fetch_limit):
            break

        incident_created_time = dateparser.parse(item['created'])
        demisto.info(f"Fetching Incident for number {count} out of {int(fetch_limit)} ,"
                     f" of name: {item['title']} and creation time {incident_created_time} and"
                     f" rawJson: {json.dumps(item)}")

        incident = {
            'name': item['title'],
            'occurred': incident_created_time.strftime(time_format),
            'rawJSON': json.dumps(item)
        }
        demisto.info(f"incident after one run {str(incident)}")

        incidents.append(incident)
        count += 1
        parsed_last_time = incident_created_time
    parsed_last_time = parsed_last_time.strftime(time_format)
    demisto.setLastRun({'last_fetch': parsed_last_time})
    return incidents


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
    fetch_time = params.get('fetch_time', '1 hour')
    fetch_shaping = params.get('fetch_shaping', "hd_ticket all,submitter limited,owner limited,"
                                                " asset limited,machine limited,"
                                                " priority limited,category limited, impact limited,"
                                                "status limited, related_tickets limited")
    fetch_filter = params.get('fetch_filter')

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
        commands = {
            'test-module': test_module,
            'kace-machines-list': get_machines_list_command,
            'kace-assets-list': get_assets_list_command,
            'kace-queues-list': get_queues_list_command,
            'kace-queues-fields-list': get_queues_fields_list_command,
            'kace-tickets-list': get_tickets_list_command,
            'kace-ticket-create': create_ticket_command,
            'kace-ticket-update': update_ticket_command,
            'kace-ticket-delete': delete_ticket_command,
        }
        try:
            if command in commands:
                return_outputs(*commands[command](client, demisto.args()))
            elif command == 'fetch-incidents':
                incidents = fetch_incidents(client, fetch_time=fetch_time, fetch_shaping=fetch_shaping,
                                            fetch_filter=fetch_filter, fetch_limit=fetch_limit,
                                            last_run=demisto.getLastRun())
                demisto.incidents(incidents)
            else:
                raise NotImplementedError(f'{command} is not an existing QuestKace command')

        except Exception as err:
            return_error(f'Error from QuestKace Integration \n\n {err} \n', err)
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\n\n Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
