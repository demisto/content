import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
TOKEN = demisto.params().get('token')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TICKET_HEADERS = ['RecId', 'Subject','CreatedDateTime','Status','Symptom','Urgency','OwnerTeam','IncidentNumber'
                  'Priority', 'Email', 'TypeOfIncident', 'ClosedDateTime','ActualCategory','SocialTextHeader']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def do_request(self, method, url_suffix, params=None, data=None, json_data=None, resp_type='json', files=None):

        res = self._http_request(method, url_suffix, params=params, data=data, json_data=json_data, files=files,
                                 resp_type=resp_type, ok_codes=[200, 204], return_empty_response=True)

        if resp_type == 'other' or isinstance(res, dict) or isinstance(res, list):
            return res
        return {}


def test_module(client):
    client.do_request('GET', 'odata/businessobject/incidents')
    return 'ok'


def add_ticket_filter(curr_filter, new_filter):
    if curr_filter:
        return f'{curr_filter} and {new_filter}'
    return new_filter


def generate_filter_param(ticket_type, rec_id, from_date, to_date):
    if rec_id:
        return f'recId eq \'{rec_id}\''

    filter = ''
    if ticket_type:
        filter = add_ticket_filter(filter, f'TypeOfIncident eq \'{ticket_type}\'')
    if from_date:
        filter = add_ticket_filter(filter, f'CreatedDateTime gt {from_date}')
    if to_date:
        filter = add_ticket_filter(filter, f'CreatedDateTime lt {to_date}')
    return filter


@logger
def tickets_list_command(client, args):
    ticket_type = args.get('ticket-type')
    rec_id = args.get('rec-id')
    from_date = args.get('from')
    to_date = args.get('to')

    limit = args.get('limit')
    offset = args.get('offset')
    query = args.get('search-query')
    params = {'$orderby': 'CreatedDateTime desc'}
    filter_txt = generate_filter_param(ticket_type, rec_id, from_date, to_date)
    if filter_txt:
        params['$filter'] = filter_txt
    if limit:
        params['$top'] = limit
    if offset:
        params['$skip'] = offset
    if query:
        params['$search'] = query

    raw_res = client.do_request('GET', 'odata/businessobject/incidents', params=params)
    if raw_res.get('value'):
        human_readable = tableToMarkdown('Tickets results', t=raw_res.get('value'), headers=TICKET_HEADERS,
                                         removeNull=True)

        entry_context = {'ivantiHeat.Ticket(val.RecId===obj.RecId)': raw_res.get('value')}
        return human_readable, entry_context, raw_res

    return 'No tickets found', {}, raw_res


@logger
def update_ticket_command(client, args):
    rec_id = args.get('rec-id')
    fields = args.get('fields')

    body = {}
    fields = fields.split(';')
    for field in fields:
        field_data = field.split('=')
        body[field_data[0]] = field_data[1]


    raw_res = client.do_request('PUT', f'odata/businessobject/incidents(\'{rec_id}\')', json_data=body)
    human_readable = tableToMarkdown('Tickets results', t=raw_res, headers=TICKET_HEADERS, removeNull=True)
    entry_context = {'ivantiHeat.Ticket(val.RecId===obj.RecId)': raw_res}
    return human_readable, entry_context, raw_res


@logger
def delete_ticket_command(client, args):
    rec_id = args.get('rec-id')
    raw_res = client.do_request('DELETE', f'odata/businessobject/incidents(\'{rec_id}\')')
    return f'Ticket {rec_id} deleted successfully', {}, raw_res


@logger
def get_attachment_command(client, args):
    attachment_id = args.get('attachment-id')
    raw_res = client.do_request('Get', f'rest/Attachment?ID={attachment_id}', resp_type='other')

    filename_header = raw_res.headers.get('content-disposition')

    f_attr = 'filename='

    if filename_header and f_attr in filename_header:
        filename = filename_header[filename_header.index(f_attr) + len(f_attr):]
        return fileResult(filename, raw_res.content)


@logger
def upload_attachment_command(client, args):
    entry_id = args.get('entry-id')
    rec_id = args.get('rec-id')

    body = {'ObjectID': rec_id, 'ObjectType': 'incident#'}
    raw_res = client.do_request('POST', 'rest/Attachment', data=body, files={'file': get_file(entry_id)})
    if raw_res:
        attachment = raw_res[0]
        attachment_id = attachment.get('Message')
        file_name =attachment.get('FileName')
        entry_context = {'ivantiHeat.TicketAttachment':
                        {'RecId': rec_id, 'AttachmentId':attachment_id, 'FileName': file_name}}
        return f'{file_name} uploaded successfully, attachment ID: {attachment_id}', entry_context, raw_res


def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as fopen:
        file_bytes = fopen.read()
    return file_name, file_bytes


@logger
def fetch_incidents(client, last_run, first_fetch_time):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    incidents = []

    params = {'$orderby': 'CreatedDateTime asc'}
    params['$filter'] = f'CreatedDateTime gt {last_fetch.strftime(DATE_FORMAT)}'
    raw_res = client.do_request('GET', 'odata/businessobject/incidents', params=params)
    if raw_res.get('value'):
        for item in raw_res['value']:
            incident_created_time = dateparser.parse(item.get('CreatedDateTime'))
            incident = {
                'name': item.get('Subject'),
                'details': json.dumps(item),
                'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'rawJSON': json.dumps(item)
            }
            incidents.append(incident)
            last_fetch = incident_created_time

    next_run = {'last_fetch': last_fetch.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    commands = {
        'ivanti-heat-tickets-list': tickets_list_command,
        'ivanti-heat-ticket-update': update_ticket_command,
        'ivanti-heat-ticket-delete': delete_ticket_command,
        'ivanti-heat-ticket-attachment-upload': upload_attachment_command
    }

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'rest_api_key={TOKEN}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'ivanti-heat-ticket-attachment-get':
            demisto.results(get_attachment_command(client, demisto.args()))
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            hr, outputs, raw = commands[demisto.command()](client, demisto.args())
            return_outputs(hr, outputs, raw)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
