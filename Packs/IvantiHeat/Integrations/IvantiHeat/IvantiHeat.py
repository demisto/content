import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import dateparser
import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
OBJECT_HEADERS = ['RecId', 'Subject', 'Name', 'Status', 'CreatedDateTime', 'Symptom', 'Urgency', 'OwnerTeam',
                  'IncidentNumber', 'CreatedBy', 'Details', 'Owner', 'Category', 'Description', 'Priority',
                  'Email', 'TypeOfIncident', 'ClosedDateTime', 'ActualCategory', 'SocialTextHeader']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def do_request(self, method, url_suffix, params=None, data=None, json_data=None, resp_type='json', files=None):

        res = self._http_request(method, url_suffix, params=params, data=data, json_data=json_data, files=files,
                                 resp_type=resp_type, ok_codes=(200, 201, 204), return_empty_response=True)

        if isinstance(res, (dict, list)) or resp_type == 'other':
            return res
        return {}


def test_module(client):
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()
    if demisto.params().get('isFetch', False):
        # Validate fetch_time parameter is valid (if not, parse_date_range will raise the error message)
        parse_date_range(first_fetch_time, '%Y-%m-%d %H:%M:%S')

    client.do_request('GET', 'odata/businessobject/incidents')
    return 'ok'


def generate_filter_param(rec_id, from_date, to_date):
    if rec_id:
        return f'recId eq \'{rec_id}\''

    if not from_date and not to_date:
        return ''
    if from_date and not to_date:
        return f'CreatedDateTime gt {from_date}'
    if to_date and not from_date:
        return f'CreatedDateTime lt {to_date}'
    return f'CreatedDateTime gt {from_date} and CreatedDateTime lt {to_date}'


@logger
def objects_list_command(client, args):
    object_type = args.get('object-type')
    rec_id = args.get('rec-id')
    from_date = args.get('from')
    to_date = args.get('to')
    limit = args.get('limit')
    offset = args.get('offset')
    query = args.get('search-query')

    params = {'$orderby': 'CreatedDateTime desc'}
    filter_txt = generate_filter_param(rec_id, from_date, to_date)

    if filter_txt:
        params['$filter'] = filter_txt
    if limit:
        params['$top'] = limit
    if offset:
        params['$skip'] = offset
    if query:
        params['$search'] = query

    raw_res = client.do_request('GET', f'odata/businessobject/{object_type}', params=params)
    if raw_res.get('value'):
        human_readable = tableToMarkdown(f'{object_type} results', t=raw_res.get('value'), headers=OBJECT_HEADERS,
                                         removeNull=True)

        entry_context = {f'IvantiHeat.{object_type}(val.RecId && val.RecId===obj.RecId)': raw_res.get('value')}
        return human_readable, entry_context, raw_res

    return 'No records found', {}, raw_res


@logger
def update_object_command(client, args):
    object_type = args.get('object-type')
    rec_id = args.get('rec-id')
    fields = args.get('fields')

    try:
        fields = json.loads(fields)
    except Exception:
        raise Exception(f'Failed to parse fields as JSON data, received object:\n{fields}')

    raw_res = client.do_request('PUT', f'odata/businessobject/{object_type}(\'{rec_id}\')', json_data=fields)

    human_readable = tableToMarkdown(f'{rec_id} updated successfully', t=raw_res, headers=OBJECT_HEADERS,
                                     removeNull=True)
    entry_context = {f'IvantiHeat.{object_type}(val.RecId===obj.RecId)': raw_res}
    return human_readable, entry_context, raw_res


@logger
def delete_object_command(client, args):
    object_type = args.get('object-type')
    rec_id = args.get('rec-id')
    raw_res = client.do_request('DELETE', f'odata/businessobject/{object_type}(\'{rec_id}\')')
    return f'Record {rec_id} deleted successfully', {}, raw_res


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
    object_type = args.get('object-type')
    entry_id = args.get('entry-id')
    rec_id = args.get('rec-id')

    body = {'ObjectID': rec_id, 'ObjectType': f'{object_type}#'}
    raw_res = client.do_request('POST', 'rest/Attachment', data=body, files={'file': get_file(entry_id)})
    if raw_res:
        attachment = raw_res[0]
        attachment_id = attachment.get('Message')
        file_name = attachment.get('FileName')
        entry_context = {'IvantiHeat.Attachment':
                         {'RecId': rec_id, 'AttachmentId': attachment_id, 'FileName': file_name}}
        return f'{file_name} uploaded successfully, attachment ID: {attachment_id}', entry_context, raw_res
    raise Exception(f'Upload attachment {rec_id} failed')


@logger
def perform_action_command(client, args):
    object_type = args.get('object-type')
    object_id = args.get('object-id')
    action = args.get('action')
    request_data = args.get('request-data')

    try:
        request_data = json.loads(request_data)
    except Exception:
        raise Exception(f'Failed to parse request-data as JSON data, received object:\n{request_data}')

    raw_res = client.do_request('POST', f'odata/businessobject/{object_type}(\'{object_id}\')/{action}',
                                json_data=request_data, resp_type='other')

    return f'{action} action success', {}, raw_res.content


@logger
def create_object_command(client, args):
    object_type = args.get('object-type')
    fields = args.get('fields')

    body = {}

    try:
        fields = json.loads(fields)
    except Exception:
        raise Exception(f'Failed to parse additional-fields as JSON data, received object:\n{fields}')

    for key in fields.keys():
        body[key] = fields[key]

    raw_res = client.do_request('POST', f'odata/businessobject/{object_type}', json_data=body)

    human_readable = tableToMarkdown(f'{object_type} object created successfully', t=raw_res, headers=OBJECT_HEADERS,
                                     removeNull=True)

    entry_context = {f'IvantiHeat.{object_type}(val.RecId===obj.RecId)': raw_res}
    return human_readable, entry_context, raw_res


def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as fopen:
        file_bytes = fopen.read()
    return file_name, file_bytes


@logger
def fetch_incidents(client, last_run, first_fetch_time, name_field):
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
    for item in raw_res.get('value', []):
        incident_created_time = dateparser.parse(item.get('CreatedDateTime'))
        assert incident_created_time is not None
        incident_name = item.get(name_field, item.get('RecId'))
        incident = {
            'name': incident_name,
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
    token = demisto.params().get('token_creds', {}).get('password') or demisto.params().get('token')
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    commands = {
        'ivanti-heat-objects-list': objects_list_command,
        'ivanti-heat-object-update': update_object_command,
        'ivanti-heat-object-delete': delete_object_command,
        'ivanti-heat-object-attachment-upload': upload_attachment_command,
        'ivanti-heat-object-create': create_object_command,
        'ivanti-heat-object-perform-action': perform_action_command
    }

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'rest_api_key={token}'},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'ivanti-heat-object-attachment-download':
            demisto.results(get_attachment_command(client, demisto.args()))
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                name_field=demisto.params().get('incident_name_field'))

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
