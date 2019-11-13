import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
FILTER_DICT = {'Contains': '1',
               'Excludes': '2',
               'Starts With': '3',
               'Ends With': '4',
               'Equals': '5',
               'Not Equals': '6',
               'Greater Than': '7',
               'Less Than': '8',
               'Greater Equals Than': '9',
               'Less Equals Than': '10',
               'Between': '11',
               'Not Between': '12',
               'Is Null': '15',
               'Is Not Null': '16'}

'''CLIENT'''


class Client(BaseClient):
    def _http_request(self, method, url_suffix, full_url=None, headers=None,
                      auth=None, json_data=None, params=None, data=None, files=None,
                      timeout=10, resp_type='json', ok_codes=None, **kwargs):
        '''
        Overides _http_request in order to log the http method.
        '''
        if json_data and json_data.get('password'):
            json_print_data = '***Credentials***'
        else:
            json_print_data = json_data

        # TODO Change to LOG
        log = f'KeyLight is attempting {method} request sent to {self._base_url + url_suffix}'
        if params:
            log += f' with params:\n{json.dumps(params, indent=4)}'
        if json_data:
            log += f'\njson_data:\n{json.dumps(json_print_data, indent=4)}'
        print(log)

        # The instance isn't always stable so trying to send http request twice.
        # Not ideal, I know..
        try:
            # TODO: Remove print
            print("first try")
            res = super()._http_request(method, url_suffix, full_url, headers,
                                        auth, json_data, params, data, files,
                                        timeout, resp_type, ok_codes, **kwargs)
            return res
        # TODO Remove second try
        except Exception as e:
            # TODO: Remove print
            print(str(e))
            print('second try')
            return super()._http_request(method, url_suffix, full_url, headers,
                                         auth, json_data, params, data, files,
                                         timeout, resp_type, ok_codes, **kwargs)

    def login(self, username: str, password: str) -> bool:
        '''
        Returns:
            Logs in to the server and keeps the cookie as header.
            Returns if connection was successful.
        '''
        body = {
            'username': username,
            'password': password
        }
        res = self._http_request('POST', '/SecurityService/Login', resp_type='response', json_data=body)
        successful = True if res.content == b'true' else False

        return successful

    def logout(self):
        self._http_request('GET', '/SecurityService/Logout')

    def return_components(self, link: str, params: dict = None) -> None:
        res = self._http_request('GET', link, params=params)
        if type(res) == dict:
            res['ID'] = res.pop('Id')
        else:
            for comp in res:
                comp['ID'] = comp.pop('Id')
        ec = {'Keylight.Component(val.ID && val.ID==obj.ID))': res}
        hr = tableToMarkdown("Keylight Components", res)
        return_outputs(hr, ec, res)

    def return_fields(self, suffix: str, params: dict = None, title: str = None) -> None:
        res = self._http_request('GET', suffix, params=params)
        if type(res) == dict:
            res['ID'] = res.pop('Id')
        else:
            for field in res:
                field['ID'] = field.pop('Id')
        ec = {'Keylight.Field(val.ID && val.ID==obj.ID))': res}
        hr = tableToMarkdown(title,
                             res, ['ID', 'Name', 'SystemName', 'ShortName', 'ReadOnly', 'Required'])
        return_outputs(hr, ec, res)

    def return_records(self, component_id: str, record_id: str, field_ids: str,
                       suffix: str) -> None:
        params = {'componentID': component_id,
                  'recordId': record_id}
        res = self._http_request('GET', suffix, params=params)
        field_ids = argToList(field_ids)
        fields = []
        for field in res.get('FieldValues', []):
            if str(field.get('Key', '')) in field_ids:
                fields.append(field)
        if not field_ids:
            fields = res.get('FieldValues', [])
        record = {'ID': res.get('Id'),
                  'Fields': fields,
                  'ComponentID': component_id,
                  'DisplayName': res.get('DisplayName', '')
                  }
        ec = {'Keylight.Record(val.ID && val.ID==obj.ID))': record}
        hr = tableToMarkdown(f'Details for record {record.get("DisplayName")}:', record)
        return_outputs(hr, ec, res)

    def return_filtered_records(self, component_id: str, page_size: str, page_index: str, suffix: str,
                                filter_type: str = None, filter_field_id: str = None, filter_value: str = None) -> dict:
        data = {'componentId': component_id,
                'pageIndex': page_index,
                'pageSize': page_size}
        if filter_type:
            data['filters'] = [create_filter(filter_type, filter_value, filter_field_id)]  # type: ignore
        res = self._http_request('POST', suffix, json_data=data)
        for result in res:
            result['ID'] = result.pop('Id')
            result['ComponentID'] = component_id
        return res

    def component_id_from_name(self, name: str) -> str:
        component_list = self._http_request('GET', '/ComponentService/GetComponentList')
        component = {}  # type: dict
        for comp in component_list:
            if comp.get('Name') == name:
                component = comp
        return str(component.get('Id'))

    def field_id_from_name(self, name: str, component_id: str) -> str:
        params = {'componentId': component_id}
        field_list = self._http_request('GET', '/ComponentService/GetFieldList', params=params)
        field_id = ''
        for field in field_list:
            if field.get('Name') == name:
                field_id = field.get('Id')
        return field_id


'''HELPER FUNCTIONS'''


def create_filter(filter_type: str, filter_value: str, filter_field_id: str) -> dict:
    # adding filter if exists
    if not FILTER_DICT.get(filter_type):
        raise ValueError('Filter Type is invalid.')
    filter = {
        "FieldPath": [int(filter_field_id)],
        "FilterType": FILTER_DICT.get(filter_type),
        'Value': filter_value
    }
    return filter


'''COMMAND FUNCTIONS'''


def get_component_list_command(client: Client, args: dict) -> None:
    '''
    Args:
        client: The client
        args: Demisto.args()

    Returns:
        A list of all components.
    '''
    client.return_components('/ComponentService/GetComponentList')


def get_component_command(client: Client, args: dict) -> None:
    '''
    Args:
        client: The client
        args: Demisto.args()

    Returns:
        A list of all components.
    '''
    params = {'id': args.get('component_id')}
    client.return_components('/ComponentService/GetComponent', params)


def get_component_by_alias_command(client: Client, args: dict) -> None:
    '''

    Args:
        client:
        args: {alias: ...}

    Returns:
        Returns the component by its alias
    '''
    params = {'alias': args.get('alias')}
    client.return_components('/ComponentService/GetComponentByAlias', params)


def get_field_list_command(client: Client, args: dict) -> None:
    params = {'componentId': args.get('component_id')}
    client.return_fields('/ComponentService/GetFieldList', params,
                         f"Keylight fields for component {params.get('componentId')}:")


def get_field_command(client: Client, args: dict) -> None:
    params = {'id': args.get('field_id')}
    client.return_fields('/ComponentService/GetField', params,
                         f"Keylight field {params.get('id')}:")


def get_record_command(client: Client, args: dict) -> None:
    path = '/ComponentService/GetDetailRecord' if args.get('detailed', "False") == "True" \
        else '/ComponentService/GetRecord'
    client.return_records(args.get('component_id', ''), args.get('record_id', ''), args.get('field_ids', ''), path)


def get_filtered_records_command(client: Client, args: dict) -> None:
    page_size = str(min(int(args.get('page_size', '10')), 100))
    component_id = args.get('component_id', '')
    page_index = args.get('page_index', "0")
    filter_type = args.get('filter_type')
    filter_value = args.get('filter_value', '')
    filter_field_id = args.get('filter_field_id', '')
    detailed = '/ComponentService/GetDetailRecords' if args.get('detailed', "False") == "True" \
        else '/ComponentService/GetRecords'
    res = client.return_filtered_records(component_id, page_size, page_index, detailed,
                                         filter_type, filter_field_id, filter_value)
    ec = {'Keylight.Record(val.ID == obj.ID)': res}
    title = f'Records for component {component_id}'
    if filter_type:
        title += f' with filter: "{filter_type} {filter_value}" on field {filter_field_id}'
    hr = tableToMarkdown(title, res)
    return_outputs(hr, ec, res)


def get_record_count_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    filter_type = args.get('filter_type', '')
    filter_value = args.get('filter_value', '')
    filter_field_id = args.get('filter_field_id', '')
    data = {'componentId': component_id}
    data['filters'] = [create_filter(filter_type, filter_value, filter_field_id)]
    res = client._http_request('POST', '/ComponentService/GetRecordCount', json_data=data)
    title = f'## There are __**{res}**__ records with filter:' \
        f' "{filter_type} {filter_value}" on field {filter_field_id} in component {component_id}'
    return_outputs(title)


def get_record_attachments_command(client: Client, args: dict) -> None:
    field_id = args.get('record_id', '')
    record_id = args.get('record_id', '')
    params = {'componentID': args.get('component_id', ''),
              'recordId': record_id,
              'fieldId': field_id
              }
    res = client._http_request('GET', '/ComponentService/GetRecordAttachments', params=params)
    for doc in res:
        doc['FieldID'] = doc.pop("FieldId")
        doc['DocumentID'] = doc.pop('DocumentId')
    hr = tableToMarkdown(f'Field {field_id} in record {record_id} has the following attachments:', res)
    ec = {'Keylight.Attachment(val.FieldID == obj.FieldID && val.DocumentID == obj.DocumentID)': res}
    return_outputs(hr, ec, res)


def get_record_attachment_command(client: Client, args: dict) -> None:
    field_id = args.get('record_id', '')
    record_id = args.get('record_id', '')
    doc_id = args.get('document_id', '')
    params = {'componentID': args.get('component_id', ''),
              'recordId': record_id,
              'fieldId': field_id,
              'documentId': doc_id
              }
    res = client._http_request('GET', '/ComponentService/GetRecordAttachment', params=params)
    hr = f'## File {res.get("FileName", "")}:\n{res.get("FileData")}'
    return_outputs(hr)


def fetch_incidents(client: Client, args: dict) -> None:
    name = demisto.params().get('component_name', '')
    filter_field = demisto.params().get('filter_field', '')
    page_size = str(min(int(demisto.params().get('fetch_limit', '100')), 100))
    if not name or not filter_field:
        raise ValueError("No component alias or field to filter by specified.")
    last_fetch_time = demisto.getLastRun().get('last_fetch_time')
    if not last_fetch_time:
        now = datetime.now()
        last_fetch = now - timedelta(days=20)
        last_fetch_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S")
    # Find component ID
    component_id = demisto.getLastRun().get('component', {}).get(filter_field)
    if not component_id:
        component_id = client.component_id_from_name(name)
    if not component_id:
        raise ValueError("Could not find component name.")
    field_id = demisto.getLastRun().get('field', {}).get(name)
    field_id = client.field_id_from_name(filter_field, component_id)
    if not field_id:
        raise ValueError("Could not find field name.")
    res = client.return_filtered_records(component_id, page_size, '0', '/ComponentService/GetDetailRecords',
                                         '>=', field_id, last_fetch_time)
    incidents = []
    max_fetch_time = last_fetch_time
    for record in res:
        occurred_at = ''
        for field in record.get('FieldValues', []):
            if field.get('Key') == field_id:
                occurred_at = field.get('Value')
                break
        incident = {'name': f'Keylight record {record.get("DisplayName")}',
                    'occurred': occurred_at,
                    'rawJSON': record
                    }
        if parse_date_string(occurred_at) > parse_date_string(max_fetch_time):
            max_fetch_time = occurred_at
        incidents.append(incident)
    print({'last_fetch_time': max_fetch_time,
           'component': {name: component_id},
           'field': {filter_field: field_id}})
    demisto.setLastRun({'last_fetch_time': max_fetch_time,
                        'component': {name: component_id},
                        'field': {filter_field: field_id}})
    demisto.incidents(incidents)


def main():
    proxy = demisto.params().get('proxy')
    verify = not demisto.params().get('insecure')
    address = demisto.params().get('server', '')
    address = address.rstrip('/') + ":" + demisto.params().get('port', '4443')
    username = demisto.params().get('credentials', {}).get('identifier', '')
    password = demisto.params().get('credentials', {}).get('password', '')
    client = Client(address, verify, proxy, headers={'Accept': 'application/json'})

    commands = {
        'kl-get-component-list': get_component_list_command,
        'kl-get-component': get_component_command,
        'kl-get-component-by-alias': get_component_by_alias_command,
        'kl-get-field-list': get_field_list_command,
        'kl-get-field': get_field_command,
        'kl-get-record-count': get_record_count_command,
        'kl-get-record': get_record_command,
        'kl-get-filtered-records': get_filtered_records_command,
        # 'kl-delete-record': 'ComponentService/DeleteRecord',
        # 'kl-create-record': 'ComponentService/CreateRecord',
        # 'kl-update-record': 'ComponentService/UpdateRecord',
        # 'kl-get-lookup-report-column-fields': 'ComponentService/GetLookupReportColumnFields',
        'kl-get-record-attachment': get_record_attachment_command,
        'kl-get-record-attachments': get_record_attachments_command,
        # 'kl-delete-record-attachments': 'ComponentService/DeleteRecordAttachments',
        'fetch-incidents': fetch_incidents
    }

    LOG(f'Command being called is {demisto.command()}')
    logged_in = False
    try:
        if demisto.command() == 'test-module':
            client.login(username, password)
            demisto.results('ok')

        logged_in = client.login(username, password)
        if logged_in:
            # TODO: add detailed exceptions: No records returned, no such component and so on.
            commands[demisto.command()](client, demisto.args())
            client.logout()
    except Exception as e:
        if demisto.command() == 'test-module':
            # TODO change to return_error
            print(f'Could not connect to instance. Error: {str(e)}')
            # return_error(f'Could not connect to instance. Error: {str(e)}')
        else:
            # TODO change to return_error
            print(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
            # return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
