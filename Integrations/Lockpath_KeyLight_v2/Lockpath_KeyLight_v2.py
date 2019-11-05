import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
FILTER_DICT = {'Contains': '1',
               'Excludes': '2',
               'Starts With': '3',
               'Ends With': '4',
               '=': '5',
               '<>': '6',
               '>': '7',
               '<': '8',
               '>=': '9',
               '<=': '10',
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
            json_print_data='***Credentials***'
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
            #TODO: Remove print
            print("first try")
            res = super()._http_request(method, url_suffix, full_url, headers,
                                  auth, json_data, params, data, files,
                                  timeout, resp_type, ok_codes, **kwargs)
            return res
        #TODO Remove second try
        except Exception as e:
            #TODO: Remove print
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
        res = self._http_request('POST', '/SecurityService/Login',resp_type='response', json_data=body)
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
        hr = tableToMarkdown(f'Details for record {record.get("ID")}:', record)
        return_outputs(hr, ec, res)


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
    client.return_records(args.get('component_id'), args.get('record_id'), args.get('field_ids', ''),
                          '/ComponentService/GetRecord')


def get_records_command(client: Client, args: dict) -> None:
    page_size = min(int(args.get('page_size', '10')), 100)
    component_id = args.get('component_id', '')
    data = {'componentId': component_id,
            'pageIndex': args.get('page_index', '0'),
            'pageSize': str(page_size)}
    if args.get('filter_type'):
        data['filters'] = [create_filter(args.get('filter_type', ''), args.get('filter_value', ''),
                                        args.get('filter_field_id', ''))]
    res = client._http_request('POST', '/ComponentService/GetRecords', json_data=data)
    for result in res:
        result['ID'] = result.pop('Id')
        result['ComponentID'] = component_id
    ec = {'Keylight.Record(val.ID == obj.ID)': res}
    title = f'Records for component {component_id}'
    if args.get('filter_type'):
        title += f' with filter: "{args.get("filter_type")} {args.get("filter_value", "")} "' \
            f'on field {args.get("filter_field_id", "")}'
    hr = tableToMarkdown(title, res)
    return_outputs(hr, ec, res)


def get_detail_record_command(client: Client, args: dict):
    client.return_records(args.get('component_id', ''), args.get('record_id', ''), args.get('field_ids', ''),
                          '/ComponentService/GetDetailRecord')


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
        'kl-get-record-count': 'ComponentService/GetRecordCount',
        'kl-get-record': get_record_command,
        'kl-get-records': get_records_command,
        'kl-delete-record': 'ComponentService/DeleteRecord',
        'kl-create-record': 'ComponentService/CreateRecord',
        'kl-update-record': 'ComponentService/UpdateRecord',
        'kl-get-detail-record': get_detail_record_command,
        'kl-get-lookup-report-column-fields': 'ComponentService/GetLookupReportColumnFields',
        'kl-get-detail-records': 'ComponentService/GetDetailRecords',
        'kl-get-record-attachment': 'ComponentService/GetRecordAttachment',
        'kl-get-record-attachments': 'ComponentService/GetRecordAttachments',
        'kl-delete-record-attachments': 'ComponentService/DeleteRecordAttachments'
    }

    LOG(f'Command being called is {demisto.command()}')
    logged_in = False
    try:
        if demisto.command() == 'test-module':
            client.login(username, password)
            demisto.results('ok')

        logged_in = client.login(username, password)
        if logged_in:
            commands[demisto.command()](client, demisto.args())
            client.logout()
    except Exception as e:
        if demisto.command() == 'test-module':
            #TODO change to return_error
            print(f'Could not connect to instance. Error: {str(e)}')
            #return_error(f'Could not connect to instance. Error: {str(e)}')
        else:
            #TODO change to return_error
            print(f'Failed to execute {demisto.command()} command. Error: {str(e)}')
            #return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
