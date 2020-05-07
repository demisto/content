import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from datetime import datetime, timedelta
from typing import Union
import traceback

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

INTEGRATION_CONTEXT_SIZE = 15

'''CLIENT'''


class Client(BaseClient):
    @logger
    def _http_request(self, method, url_suffix, full_url=None, headers=None,
                      auth=None, json_data=None, params=None, data=None, files=None,
                      timeout=10, resp_type='json', ok_codes=None, **kwargs):
        res = super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                    auth=auth, json_data=json_data, params=params, data=data, files=files,
                                    timeout=timeout, resp_type=resp_type, ok_codes=ok_codes, **kwargs)
        return res

    def login(self, username: str, password: str) -> bool:
        """
        Logs in to the server and keeps the cookie as header.

        Args:
            username:
            password:

        Returns:
            Returns if connection was successful.
        """
        body = {
            'username': username,
            'password': password
        }
        res = self._http_request('POST', '/SecurityService/Login', resp_type='response', json_data=body)
        successful = res.content == b'true'

        return successful

    def logout(self):
        """
        Logs out of the connection.

        """
        self._http_request('GET', '/SecurityService/Logout')

    def return_components(self, link: str, params: dict = None) -> None:
        res = self._http_request('GET', link, params=params)
        if isinstance(res, dict):
            res['ID'] = res.pop('Id')
        else:
            for comp in res:
                comp['ID'] = comp.pop('Id')
        ec = {'Keylight.Component(val.ID && val.ID==obj.ID))': res}
        hr = tableToMarkdown("Keylight Components", res)
        return_outputs(hr, ec, res)

    def return_fields(self, suffix: str, params: dict = None, title: str = None) -> None:
        """
        Runs and returns field commands according to the suffix .
        Args:
            suffix: which api call to make
            params: if the command neads a params this are them
            title: The title for the table to markdown

        Returns:

        """
        res = self._http_request('GET', suffix, params=params)
        if isinstance(res, dict):
            res['ID'] = res.pop('Id')
        else:
            for field in res:
                field['ID'] = field.pop('Id')
        ec = {'Keylight.Field(val.ID && val.ID==obj.ID))': res}
        hr = tableToMarkdown(title,
                             res, ['ID', 'Name', 'SystemName', 'ShortName', 'ReadOnly', 'Required'])
        return_outputs(hr, ec, res)

    def return_records(self, component_id: str, record_id: str, field_names: str,
                       suffix: str) -> None:
        """
        Returns to demisto record calls according to suffix
        Args:
            component_id: The component IF
            record_id: which record to return
            field_names: what fields to return
            suffix: The suffix for the API request

        Returns:
            None
        """
        params = {'componentID': component_id,
                  'recordId': record_id}
        res = self._http_request('GET', suffix, params=params)
        field_names = argToList(field_names)
        all_fields = self.field_output_to_hr_fields(res.get('FieldValues', []), component_id, field_names)
        record = {'ID': res.get('Id'),
                  'ComponentID': component_id,
                  'DisplayName': res.get('DisplayName', '')
                  }
        hr = tableToMarkdown(f'Details for record {record.get("DisplayName")}:', record)
        hr += tableToMarkdown('With the following fields:', all_fields)
        record['Fields'] = all_fields
        ec = {'Keylight.Record(val.ID && val.ID==obj.ID))': record}

        return_outputs(hr, ec, res)

    def return_filtered_records(self, component_id: str, page_size: str, page_index: str, suffix: str,
                                filter_type: str = None, filter_field_id: str = None, filter_value: str = None) -> dict:
        """

        Args:
            component_id: component id
            page_size: how many results to return per page
            page_index: what page number
            suffix: API suffix
            filter_type: What filter to apply (out of FILTER_DICT
            filter_field_id: which field to apply the filter on
            filter_value: the filter value

        Returns:
            number of records according to a certain query made up of filter_type, filter_value and filter_field_id
        """
        data = {'componentId': component_id,
                'pageIndex': page_index,
                'pageSize': page_size}
        if filter_type:
            data['filters'] = [create_filter(filter_type, filter_value, filter_field_id)]  # type: ignore
        else:
            data['filters'] = []  # type: ignore
        res = self._http_request('POST', suffix, json_data=data)
        for result in res:
            result['ID'] = result.pop('Id')
            result['ComponentID'] = component_id
        return res

    def change_record(self, component_id: str, record_id: Union[str, None] = None,
                      record_json: dict = None) -> None:
        json_data = {
            'componentId': component_id,
            'dynamicRecord': {
                'FieldValues': self.string_to_FieldValues(record_json, component_id)
            }
        }
        suffix = '/ComponentService/CreateRecord'
        if record_id:
            json_data['dynamicRecord']['Id'] = record_id  # type: ignore
            suffix = '/ComponentService/UpdateRecord'
        res = self._http_request('POST', suffix, json_data=json_data)
        fields = self.field_output_to_hr_fields(res.get('FieldValues', []), component_id)
        record = {'ID': res.get('Id'),
                  'ComponentID': component_id,
                  'DisplayName': res.get('DisplayName', '')
                  }
        hr = tableToMarkdown(f'Task "{record.get("DisplayName")}":', record)
        hr += tableToMarkdown('With the following fields:', fields)
        record['Fields'] = fields
        ec = {'Keylight.Record(val.ID && val.ID==obj.ID))': record}

        return_outputs(hr, ec, res)

    '''HELPER CLIENT FUNCTIONS'''

    def component_id_from_name(self, name: str) -> str:
        """

        Args:
            name: Name of component

        Returns:
            The component ID
        """
        component_list = self._http_request('GET', '/ComponentService/GetComponentList')
        component = {}  # type: dict
        for comp in component_list:
            if comp.get('Name') == name:
                component = comp
        return str(component.get('Id'))

    def field_id_from_name(self, name: str, component_id: str) -> Union[str, None]:
        """

        Args:
            name: The field's name
            component_id:

        Returns:
            The field_id if it exists
        """
        field_map = demisto.getIntegrationContext().get(str(component_id))
        if not field_map:
            self.update_field_integration_context(component_id)
            field_map = demisto.getIntegrationContext().get(str(component_id))
        fields = field_map.get('fields')
        for field_key, field_name in fields.items():
            if field_name == name:
                return field_key
        return None

    @logger
    def update_field_integration_context(self, component_id: str) -> None:
        """
        update integration context to include the component_id and have at most 7 tables stored
        Update policy : FIFO

        Integration context will look: {
                                        component_id: {
                                            last_update: $date
                                            fields: {field_key: field_name.
                                                    field_key, field_name,
                                                    ...,
                                                    }
                                            }
                                        }

        Args:
            component_id: The id of the component we want to add to the integration context

        Returns: None

        """
        field_map = demisto.getIntegrationContext()
        if field_map.get(str(component_id)):
            field_map.pop(str(component_id))
        params = {'componentId': component_id}
        fields = self._http_request('GET', '/ComponentService/GetFieldList', params=params)
        field_names = {}
        for field in fields:
            field_names[str(field.get('Id'))] = field.get('Name')
        update = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        if len(field_map) == INTEGRATION_CONTEXT_SIZE:
            min_time = update
            min_component = ''
            for component in field_map.keys():
                updated = field_map.get(component).get('updated')
                if parse_date_string(updated) < parse_date_string(min_time):
                    min_time = updated
                    min_component = component
            field_map.pop(min_component)
        field_map[str(component_id)] = {'fields': field_names,
                                        'updated': update
                                        }
        demisto.setIntegrationContext(field_map)

    @logger
    def field_output_to_hr_fields(self, field_output: dict, component_id: str, returned_fields: list = None) -> dict:
        '''

        Args:
            field_output: a dictionary of key,values that is the output of FieldValue field
            component_id: What component the fields are from
            returned_fields: A list of field names to return. If None - all fields returned

        Returns:
        '''
        field_map = demisto.getIntegrationContext().get(str(component_id))
        final_fields = {}
        if not field_map:
            self.update_field_integration_context(component_id)
            field_map = demisto.getIntegrationContext().get(str(component_id))
        fields = field_map.get('fields')
        for field_dict in field_output:
            field_key = field_dict.get('Key')
            field_val = field_dict.get('Value')
            if not fields.get(str(field_key)):
                self.update_field_integration_context(component_id)
                fields = demisto.getIntegrationContext().get(str(component_id)).get('fields')
            field_name = fields.get(str(field_key))
            if isinstance(field_val, dict) and field_val.get('DisplayName'):
                field_val = {'Value': field_val.get('DisplayName'),
                             'ID': field_val.get('Id', -1)}
            if not returned_fields or field_name in returned_fields:
                final_fields[field_name] = field_val
        return final_fields

    @logger
    def string_to_FieldValues(self, fields_json: Union[dict, list], component_id: str) -> list:
        """
        Args:
            field_json in the format:
            [{
                "fieldName": "Task ID",
                "value": "1",
                "isLookup": false
                },
                ...
            ]

        Returns:
            returns the for right format (dynamicRecord) for creating and updating a record.
        """
        key_val_return = []
        for field in fields_json:
            field_id = self.field_id_from_name(field.get('fieldName', ''), component_id)
            value = field.get('value', '')
            if not field_id:
                raise ValueError(f'Could not find the field "{field.get("fieldName", "")}" in component {component_id}.')
            if field.get('isLookup', ''):
                key_val_return.append(
                    {
                        'Key': field_id,
                        'Value': {
                            'Id': value
                        }
                    }
                )
            else:
                key_val_return.append({'Key': field_id, 'Value': value})
        return key_val_return


'''HELPER FUNCTIONS'''


@logger
def create_filter(filter_type: str, filter_value: str, filter_field_id: str) -> dict:
    """

    Args:
        filter_type: What type of filter to apply on the field. out of FILTER_DICT
        filter_value:
        filter_field_id:

    Returns:
        A filter made from the arguments in the format keylight needs.
    """
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


def get_component_command(client: Client, args: dict) -> None:
    '''
    Args:
        client: The client
        args: Demisto.args()

    Returns:
        A list of all components.
    '''
    if args.get('component_id'):
        params = {'id': args.get('component_id')}
        client.return_components('/ComponentService/GetComponent', params)
    elif args.get('alias'):
        params = {'alias': args.get('alias')}
        client.return_components('/ComponentService/GetComponentByAlias', params)
    else:
        client.return_components('/ComponentService/GetComponentList')


def get_field_list_command(client: Client, args: dict) -> None:
    params = {'componentId': args.get('component_id')}
    client.return_fields('/ComponentService/GetFieldList', params,
                         f"Keylight fields for component {params.get('componentId')}:")


def get_field_command(client: Client, args: dict) -> None:
    field_id = client.field_id_from_name(args.get('field_name', ''), args.get('component_id', ''))
    params = {'id': field_id}
    client.return_fields('/ComponentService/GetField', params,
                         f"Keylight field {params.get('id')}:")


def get_record_command(client: Client, args: dict) -> None:
    path = '/ComponentService/GetDetailRecord' if args.get('detailed', "False") == "True" \
        else '/ComponentService/GetRecord'
    client.return_records(args.get('component_id', ''), args.get('record_id', ''), args.get('field_names', ''), path)


def get_records_command(client: Client, args: dict) -> None:
    page_size = str(min(int(args.get('page_size', '10')), 100))
    component_id = args.get('component_id', '')
    page_index = args.get('page_index', "0")
    filter_type = args.get('filter_type')
    filter_value = args.get('filter_value', '')
    field_name = args.get('filter_field_name', '')
    returned_fields = argToList(args.get('returned_fields', ''))
    filter_field_id = None
    if filter_type and filter_value and field_name:
        filter_field_id = client.field_id_from_name(field_name, component_id)
        if not filter_field_id:
            raise ValueError(f'Could not find the field "{field_name}" in component {component_id}.')
    detailed = '/ComponentService/GetDetailRecords' if args.get('detailed', "False") == "True" \
        else '/ComponentService/GetRecords'
    res = client.return_filtered_records(component_id, page_size, page_index, detailed,
                                         filter_type, filter_field_id, filter_value)
    for record in res:
        record['Fields'] = client.field_output_to_hr_fields(record.pop('FieldValues'), component_id, returned_fields)
    ec = {'Keylight.Record(val.ID == obj.ID)': res}
    title = f'Records for component {component_id}'
    if filter_type:
        title += f' \n### with filter "{filter_type}: {filter_value}" on field "{field_name}"'
    records = []
    for record in res:
        temp_dict = record.get('Fields').copy()
        for key in temp_dict.keys():
            if isinstance(temp_dict[key], dict):
                temp_dict[key] = temp_dict[key].get('Value')
        temp_dict['Id'] = record.get("ID")
        temp_dict['DisplayName'] = record.get('DisplayName')
        records.append(temp_dict)
    hr = tableToMarkdown(title, records)
    # hr = f'# {title}\n'
    # for record in res:
    #     hr += tableToMarkdown(f'Record {record.get("DisplayName", "")} (ID: {record.get("ID", "")}):',
    #                           record.get("Fields"))
    return_outputs(hr, ec, res)


def get_record_count_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    filter_type = args.get('filter_type', '')
    filter_value = args.get('filter_value', '')
    filter_field_name = args.get('filter_field_name', '')
    data = {'componentId': component_id}

    if not filter_type or not filter_value or not filter_field_name:
        data['filters'] = []
    else:
        filter_field_id = client.field_id_from_name(filter_field_name, component_id)
        if not filter_field_id:
            raise ValueError('Could not find the field name.')
        data['filters'] = [create_filter(filter_type, filter_value, filter_field_id)]
    res = client._http_request('POST', '/ComponentService/GetRecordCount', json_data=data)
    title = f'## There are **{res}** records in component {component_id}.\n'
    if filter_type:
        title += f'### with filter: "{filter_type} {filter_value}" on field `{filter_field_name}`'
    return_outputs(title)


def get_record_attachments_command(client: Client, args: dict) -> None:
    field_name = args.get('field_name', '')
    record_id = args.get('record_id', '')
    component_id = args.get('component_id', '')
    field_id = client.field_id_from_name(field_name, component_id)
    params = {'componentID': component_id,
              'recordId': record_id,
              'fieldId': field_id
              }
    res = client._http_request('GET', '/ComponentService/GetRecordAttachments', params=params)
    for doc in res:
        doc['FieldID'] = doc.pop("FieldId")
        doc['DocumentID'] = doc.pop('DocumentId')
        doc['RecordID'] = record_id
        doc['ComponentID'] = component_id
    if not res:
        hr = f'## Field {field_id} in record {record_id} has no attachments.'
        return_outputs(hr)
        return
    hr = tableToMarkdown(f'Field {field_name} in record {record_id} has the following attachments:', res)
    ec = {'Keylight.Attachment(val.FieldID == obj.FieldID && val.DocumentID == obj.DocumentID)': res}
    return_outputs(hr, ec, res)


def get_record_attachment_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    field_name = args.get('field_name', '')
    record_id = args.get('record_id', '')
    doc_id = args.get('document_id', '')
    field_id = client.field_id_from_name(field_name, component_id)
    params = {'componentID': component_id,
              'recordId': record_id,
              'fieldId': field_id,
              'documentId': doc_id
              }
    res = client._http_request('GET', '/ComponentService/GetRecordAttachment', params=params)
    demisto.results(fileResult(res.get("FileName", ""), base64.b64decode(res.get("FileData"))))


def delete_record_attachment_command(client: Client, args: dict) -> None:
    field_id = args.get('field_id', '')
    record_id = args.get('record_id', '')
    doc_id = args.get('document_id', '')
    component_id = args.get('component_id', '')
    json_data = {
        "componentId": component_id,
        "dynamicRecord": {
            "Id": record_id,
            "FieldValues": [
                {
                    "Key": field_id,
                    "value": [
                        {
                            "Id": doc_id
                        }
                    ]
                }
            ]
        }
    }
    client._http_request('POST', '/ComponentService/DeleteRecordAttachments', json_data=json_data)
    return_outputs("### Attachment was successfully deleted from the Documents field.")


def delete_record_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    record_id = args.get('record_id', '')
    json_data = {
        'componentId': component_id,
        'recordId': record_id
    }
    client._http_request('DELETE', '/ComponentService/DeleteRecord', json_data=json_data)
    return_outputs(f'### Record {record_id} of component {component_id} was deleted successfully.')


def get_lookup_report_column_fields_command(client: Client, args: dict) -> None:
    field_path_id = args.get('field_path_id', '')
    lookup_field_id = args.get('lookup_field_id', '')
    params = {
        'lookupFieldId': lookup_field_id,
        'fieldPathId': field_path_id
    }
    res = client._http_request('GET', '/ComponentService/GetLookupReportColumnFields', params=params)
    for rec in res:
        rec['ID'] = rec.pop("Id")
        rec['ComponentID'] = rec.pop("ComponentId")
    ec = {'Keylight.LookupField(val.ID === obj.ID)': res}
    hr = tableToMarkdown(f'Here is more information about field path {field_path_id}, lookup field {lookup_field_id}:',
                         res)
    return_outputs(hr, ec, res)


def create_record_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    record_json = args.get('record_json', '{}').replace("'", '"')
    record_json = json.loads(record_json)
    client.change_record(component_id, record_json=record_json)


def update_record_command(client: Client, args: dict) -> None:
    component_id = args.get('component_id', '')
    record_id = args.get('record_id', '')
    record_json = args.get('record_json', '{}').replace("'", '"')
    record_json = json.loads(record_json)
    client.change_record(component_id, record_id, record_json)


def get_user_by_id_command(client: Client, args: dict) -> None:
    user_id = args.get('user_id', '')
    res = client._http_request('GET', f'/SecurityService/GetUser?id={user_id}')
    hr = tableToMarkdown(f'Keylight user {user_id}', res)
    ec = {'Keylight.User(val.Id && val.Id==obj.Id)': res}
    return_outputs(hr, ec, res)


def fetch_incidents(client: Client, args: dict) -> None:
    name = demisto.params().get('component_name', '')
    filter_field = demisto.params().get('filter_field', '')
    page_size = str(min(int(demisto.params().get('fetch_limit', '50')), 50))
    if not name or not filter_field:
        raise ValueError("No component alias or field to filter by specified.")
    last_fetch_time = demisto.getLastRun().get('last_fetch_time')
    if not last_fetch_time:
        now = datetime.now()
        last_fetch = now - timedelta(days=120)
        last_fetch_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S")

    # Find component ID
    component_id = demisto.getLastRun().get('component', {}).get(name)
    if not component_id:
        component_id = client.component_id_from_name(name)
    if component_id == 'None':
        raise ValueError("Could not find component name.")
    field_id = demisto.getLastRun().get('field', {}).get(filter_field)
    if not field_id:
        field_id = client.field_id_from_name(filter_field, component_id)
    if not field_id:
        raise ValueError("Could not find field name.")
    res = client.return_filtered_records(component_id, page_size, '0', '/ComponentService/GetDetailRecords',
                                         'Greater Than', field_id, last_fetch_time)
    incidents = []
    max_fetch_time = last_fetch_time
    for record in res:
        record['Fields'] = client.field_output_to_hr_fields(record.pop('FieldValues'), component_id)
        occurred_at = record.get('Fields', {}).get(filter_field, datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        incident = {'name': f'Keylight record {record.get("DisplayName")}',
                    'occurred': occurred_at.split('.')[0] + 'Z',
                    'rawJSON': json.dumps(record)
                    }
        if datetime.strptime(occurred_at.split('.')[0], "%Y-%m-%dT%H:%M:%S") > \
                datetime.strptime(max_fetch_time.split('.')[0], "%Y-%m-%dT%H:%M:%S"):
            max_fetch_time = occurred_at
        incidents.append(incident)
    demisto.setLastRun({'last_fetch_time': max_fetch_time,
                        'component': {name: component_id},
                        'field': {filter_field: field_id}})
    demisto.incidents(incidents)


def main():
    params = demisto.params()
    proxy = params.get('proxy')
    verify = not params.get('insecure')
    address = params.get('server', '').rstrip('/')
    username = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    client = Client(address, verify, proxy, headers={'Accept': 'application/json'})
    commands = {
        'kl-get-component': get_component_command,
        'kl-get-field-list': get_field_list_command,
        'kl-get-field': get_field_command,
        'kl-get-record-count': get_record_count_command,
        'kl-get-record': get_record_command,
        'kl-get-records': get_records_command,
        'kl-delete-record': delete_record_command,
        'kl-create-record': create_record_command,
        'kl-update-record': update_record_command,
        'kl-get-lookup-report-column-fields': get_lookup_report_column_fields_command,
        'kl-get-record-attachment': get_record_attachment_command,
        'kl-get-record-attachments': get_record_attachments_command,
        'kl-delete-record-attachment': delete_record_attachment_command,
        'kl-get-user-by-id': get_user_by_id_command,
        'fetch-incidents': fetch_incidents,
    }

    LOG(f'Command being called is {demisto.command()}')
    logged_in = False
    try:
        logged_in = client.login(username, password)
        if logged_in:
            if demisto.command() == 'test-module':
                demisto.results('ok')
            else:
                commands[demisto.command()](client, demisto.args())
    except Exception as e:
        if demisto.command() == 'test-module':
            return_error(f'Could not connect to instance. Error: {str(e)}')
        else:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}',
                         error=traceback.format_exc())
    finally:
        if logged_in:
            client.logout()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
