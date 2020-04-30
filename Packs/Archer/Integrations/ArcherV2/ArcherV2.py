import demistomock as demisto
from CommonServerPython import *
import traceback
from CommonServerUserPython import *
from typing import Tuple, Dict, Any
''' IMPORTS '''


REQUEST_HEADERS = {'Accept': 'application/json,text/html,application/xhtml +xml,application/xml;q=0.9,*/*;q=0.8',
                   'Content-Type': 'application/json'}


def get_token_soap_request(user, password, instance):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <CreateUserSessionFromInstance xmlns="http://archer-tech.com/webservices/">' + \
           f'            <userName>{user}</userName>' + \
           f'            <instanceName>{instance}</instanceName>' + \
           f'            <password>{password}</password>' + \
           '        </CreateUserSessionFromInstance>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def terminate_session_soap_request(token):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <TerminateSession xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           '        </TerminateSession>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_reports_soap_request(token):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <GetReports xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           '        </GetReports>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_statistic_search_report_soap_request(token, report_guid, max_results):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <ExecuteStatisticSearchByReport xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <reportIdOrGuid>{report_guid}</reportIdOrGuid>' + \
           f'            <pageNumber>{max_results}</pageNumber>' + \
           '        </ExecuteStatisticSearchByReport>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_search_options_soap_request(token, report_guid):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <GetSearchOptionsByGuid xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <searchReportGuid>{report_guid}</searchReportGuid>' + \
           '        </GetSearchOptionsByGuid>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_value_list_soap_request(token, field_id):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <GetValueListForField xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <fieldId>{field_id}</fieldId>' + \
           '        </GetValueListForField>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_user_info_soap_request(token, username, domain):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <LookupDomainUserId xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <username>{username}</username>' + \
           f'            <usersDomain>{domain}</usersDomain>' + \
           '        </LookupDomainUserId>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


SOAP_COMMANDS = {'archer-get-reports':
                 {'soapAction': 'http://archer-tech.com/webservices/GetReports',
                  'urlSuffix': 'rsaarcher/ws/search.asmx',
                  'soapBody': get_reports_soap_request,
                  'outputPath': 'Envelope.Body.GetReportsResponse.GetReportsResult'},
                 'archer-execute-statistic-search-by-report':
                     {'soapAction': 'http://archer-tech.com/webservices/ExecuteStatisticSearchByReport',
                      'urlSuffix': 'rsaarcher/ws/search.asmx',
                      'soapBody': get_statistic_search_report_soap_request,
                      'outputPath': 'Envelope.Body.ExecuteStatisticSearchByReportResponse.ExecuteStatisticSearchByReportResult'},
                 'archer-get-search-options-by-guid':
                     {'soapAction': 'http://archer-tech.com/webservices/GetSearchOptionsByGuid',
                      'urlSuffix': 'rsaarcher/ws/search.asmx',
                      'soapBody': get_search_options_soap_request,
                      'outputPath': 'Envelope.Body.GetSearchOptionsByGuidResponse.GetSearchOptionsByGuidResult'},
                 'archer-get-valuelist':
                     {'soapAction': 'http://archer-tech.com/webservices/GetValueListForField',
                      'urlSuffix': 'rsaarcher/ws/field.asmx',
                      'soapBody': get_value_list_soap_request,
                      'outputPath': 'Envelope.Body.GetValueListForFieldResponse.GetValueListForFieldResult'},
                 'archer-get-user-id':
                     {'soapAction': 'http://archer-tech.com/webservices/LookupDomainUserId',
                      'urlSuffix': 'rsaarcher/ws/accesscontrol.asmx',
                      'soapBody': get_user_info_soap_request,
                      'outputPath': 'response.Envelope.Body.LookupDomainUserIdResponse.LookupDomainUserIdResult'}
                 }


def extract_from_xml(xml, path):
    xml = json.loads(xml2json(xml))
    path = path.split('.')

    for item in path:
        if xml.get(item):
            xml = xml[item]
            continue
        return ''
    return xml


class Client(BaseClient):
    def __init__(self, base_url, username, password, instance_name, domain, **kwargs):
        self.username = username
        self.password = password
        self.instance_name = instance_name
        self.domain = domain
        super(Client, self).__init__(base_url=base_url, headers=REQUEST_HEADERS, **kwargs)

    def do_request(self, method, url_suffix, data=None):
        if not REQUEST_HEADERS.get('Authorization'):
            self.update_session()

        res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data,
                                 resp_type='response', ok_codes=[200, 401])

        if res.status_code == 401:
            self.update_session()
            res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data,
                                     resp_type='response', ok_codes=[200, 401])
            return res

        return res.json()

    def update_session(self):
        body = {
            'InstanceName': self.instance_name,
            'Username': self.username,
            'UserDomain': self.domain,
            'Password': self.password
        }

        res = self._http_request('Post', '/rsaarcher/api/core/security/login', json_data=body, ok_codes=[200])

        session = res.get('RequestedObject').get('SessionToken')
        REQUEST_HEADERS['Authorization'] = f'Archer session-id={session}'

    def get_token(self):
        body = get_token_soap_request(self.username, self.password, self.instance_name)
        headers = {'SOAPAction': 'http://archer-tech.com/webservices/CreateUserSessionFromInstance',
                   'Content-Type': 'text/xml; charset=utf-8'}
        res = self._http_request('Post', 'rsaarcher/ws/general.asmx', headers=headers, data=body, ok_codes=[200], resp_type='content')

        return extract_from_xml(res, 'Envelope.Body.CreateUserSessionFromInstanceResponse.CreateUserSessionFromInstanceResult')

    def destroy_token(self, token):
        body = terminate_session_soap_request(token)
        headers = {'SOAPAction': 'http://archer-tech.com/webservices/TerminateSession',
                   'Content-Type': 'text/xml; charset=utf-8'}
        self._http_request('Post', 'rsaarcher/ws/general.asmx', headers=headers, data=body, ok_codes=[200], resp_type='content')

    def do_soap_request(self, command, **kwargs):
        req_data = SOAP_COMMANDS[command]
        headers = {'SOAPAction': req_data['soapAction'], 'Content-Type': 'text/xml; charset=utf-8'}
        token = self.get_token()
        body = req_data['soapBody'](token, **kwargs)

        res = self._http_request('Post', req_data['urlSuffix'], headers=headers,
                                  data=body, ok_codes=[200], resp_type='content')
        return extract_from_xml(res, req_data['outputPath'])

    def get_level_by_app_id(self, app_id):
        cache = demisto.getIntegrationContext()
        if cache.get(app_id):
            return cache[app_id]

        levels = []
        res = self.do_request('GET', f'rsaarcher/api/core/system/level/module/{app_id}')
        for level in res:
            if level.get('RequestedObject') and level.get('IsSuccessful'):
                level_id = level.get('RequestedObject').get('Id')

                fields = {}
                res = self.do_request('GET', f'rsaarcher/api/core/system/fielddefinition/level/{level_id}')
                for field in res:
                    if field.get('RequestedObject') and field.get('IsSuccessful'):
                        field_item = field.get('RequestedObject')
                        fields[field_item.get('Id')] = {'Type': field_item.get('Type'),
                                                        'Name': field_item.get('Name'),
                                                        'IsRequired': field_item.get('IsRequired', False)}

                levels.append({'level': level_id, 'mapping': fields})

        if levels:
            cache[app_id] = levels
            demisto.setIntegrationContext(cache)
        return levels

    def generate_field_contents(self, fields_values, level_fields):
        fields_values = json.loads(fields_values)

        field_content = {}
        for field_name in fields_values.keys():
            field_data = None
            for _id, field in level_fields.items():
                if field.get('Name') == field_name:
                    field_data = field
                    break

            if field_data:
                field_content[_id] = {'Type': field_data['Type'],
                                      'Value': fields_values[field_name],
                                      'FieldId': _id}
        return field_content

    def get_sub_form_id(self, app_id, field_id, value_for_sub_form):
        level_data = self.get_level_by_app_id(app_id)[0]
        body = {'Content': {'LevelId': level_data['level'],
                'FieldContents': {'29906': {'Type': 1, 'FieldId': 29906, 'Value': value_for_sub_form}}},
                'SubformFieldId': field_id}

        res = self.do_request('Post', f'rsaarcher/api/core/content', data=body)

def test_module(client: Client) -> str:
    return 'ok' if client.do_request('GET', 'rsaarcher/api/core/system/application') else 'Connection failed.'


def search_applications_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    app_id = args.get('application-id')
    endpoint_url = 'rsaarcher/api/core/system/application/'

    if app_id:
         endpoint_url = f'rsaarcher/api/core/system/application/{app_id}'

    res = client.do_request('GET', endpoint_url)

    if isinstance(res, dict):
        res = [res]

    applications = []
    for app in res:
        if app.get('RequestedObject') and app.get('IsSuccessful'):
            app_obj = app['RequestedObject']
            applications.append({'Id': app_obj.get('Id'),
                                 'Type': app_obj.get('Type'),
                                 'Name': app_obj.get('Name'),
                                 'LanguageId': app_obj.get('LanguageId'),
                                 'Status': app_obj.get('Status'),
                                 'Guid': app_obj.get('Guid')})

    markdown = tableToMarkdown('archer-search-applications', applications)
    context: dict = {
            f'Archer.Applications(val.Id && val.Id == obj.Id)':
            applications
        }
    return markdown, context, res


def get_application_fields_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    app_id = args.get('application-id')

    res = client.do_request('GET', f'rsaarcher/api/core/system/fielddefinition/application/{app_id}')

    fields = []
    for field in res:
        if field.get('RequestedObject') and field.get('IsSuccessful'):
            field_obj = field['RequestedObject']
            fields.append({'FieldId': field_obj.get('Id'),
                           'FieldType': field_obj.get('Type'),
                           'FieldName': field_obj.get('Name'),
                           'LevelID': field_obj.get('LevelId')})

    markdown = tableToMarkdown('archer-get-application-fields', fields)
    context: dict = {
            f'Archer.ApplicationFields(val.FieldId && val.FieldId == obj.FieldId)':
            fields
        }
    return markdown, context, res


def get_field_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    field_id = args.get('field-id')

    res = client.do_request('GET', f'core/system/fielddefinition/{field_id}')
    field = {}
    if res.get('RequestedObject') and res.get('IsSuccessful'):
        field_obj = res['RequestedObject']
        field = {'FieldId': field_obj.get('Id'),
                       'FieldType': field_obj.get('Type'),
                       'FieldName': field_obj.get('Name'),
                       'LevelID': field_obj.get('LevelId')}

    markdown = tableToMarkdown('archer-get-application-field', field)
    context: dict = {
        f'Archer.ApplicationFields(val.FieldId && val.FieldId == obj.FieldId)':
            field
    }
    return markdown, context, res


def get_mapping_by_level_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    level = args.get('level')

    res = client.do_request('GET', f'core/system/fielddefinition/level/{level}')

    items = []
    for item in res:
        if item.get('RequestedObject') and item.get('IsSuccessful'):
            item_obj = item['RequestedObject']
            items.append({'Name': item_obj.get('Id'),
                          'Type': item_obj.get('Type'),
                          'levelId': item_obj.get('LevelId')})

    markdown = tableToMarkdown('archer-get-mapping-by-level', items)
    context: dict = {
            f'Archer.ApplicationFields(val.FieldId && val.FieldId == obj.FieldId)':
            items
        }
    return markdown, context, res


def get_record_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    record_id = args.get('record-id')
    app_id = args.get('application-id')
    res = client.do_request('GET', f'rsaarcher/api/core/content/{record_id}')

    if res.get('ValidationMessages'):
        messages = []
        for message in res.get('ValidationMessages'):
            messages.append(message.get('ResourcedMessage'))
        return messages, {}, res

    if res.get('RequestedObject') and res.get('IsSuccessful'):
        content_obj = res.get('RequestedObject')
        level_id = content_obj.get('LevelId')
        levels = client.get_level_by_app_id(app_id)
        level_fields = list(filter(lambda m: m['level'] == level_id, levels))
        if level_fields:
            level_fields = level_fields[0]['mapping']

        record_fields = {}
        for _id, field in content_obj.get('FieldContents').items():
            field_data = level_fields.get(int(_id))
            field_value = field.get('Value')
            if isinstance(field_value, dict):
                if field_data.get('Type') == 4:
                    field_value = str(field_value.get('ValuesListIds'))
                if field_data.get('Type') == 8:
                    field_value = str(field_value.get('UserList'))
            if field_value and field_data.get('Name'):
                record_fields[field_data.get('Name')] = field_value

        record = {'Id': content_obj.get('Id'),'Record': record_fields}
        markdown = tableToMarkdown('archer-get-record', record)
        context: dict = {
            f'Archer.Record(val.Id && val.Id == obj.Id)':
                record
        }
        return markdown, context, res


def create_record_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    app_id = args.get('application-id')
    fields_values = args.get('fields-to-values')

    level_data = client.get_level_by_app_id(app_id)[0]
    field_contents = client.generate_field_contents(fields_values, level_data['mapping'])

    body = {'Content': {'LevelId': level_data['level'], 'FieldContents': field_contents}}

    res = client.do_request('Post', f'rsaarcher/api/core/content', data=body)

    if res.get('ValidationMessages'):
        messages = []
        for message in res.get('ValidationMessages'):
            messages.append(message.get('ResourcedMessage'))
        return messages, {}, res

    if res.get('RequestedObject') and res.get('IsSuccessful'):
        return res, {}, res


def delete_record_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    record_id = args.get('record-id')
    res = client.do_request('Delete', f'rsaarcher/api/core/content/{record_id}')
    if res.get('IsSuccessful'):
        return 'succesfully deleted', {}, res

    return 'delete record failed', {}, res


def update_record_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    app_id = args.get('application-id')
    record_id = args.get('record-id')
    fields_values = args.get('fields-to-values')
    level_data = client.get_level_by_app_id(app_id)[0]
    field_contents = client.generate_field_contents(fields_values,  level_data['mapping'])

    body = {'Content': {'Id': record_id, 'LevelId':  level_data['level'], 'FieldContents': field_contents}}
    res = client.do_request('Put', f'rsaarcher/api/core/content', data=body)

    if res.get('IsSuccessful'):
        return 'succesfully updated', {}, res
    else:
        return 'update failed', {}, res


def execute_statistics_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    report_guid = args.get('report-guid')
    max_results = args.get('max-results')
    raw_res = client.do_soap_request('archer-execute-statistic-search-by-report',
                                 report_guid=report_guid, max_results=max_results)
    res = json.loads(xml2json(raw_res))
    return res, {}, res


def get_reports(client: Client) -> Tuple[str, dict, Any]:
    raw_res = client.do_soap_request('archer-get-reports')
    res = json.loads(xml2json(raw_res))
    ec = res.get('ReportValues').get('ReportValue')

    context: dict = {
        f'Archer.Report(val.ReportGUID && val.ReportGUID == obj.ReportGUID)': ec
    }
    return ec, context, raw_res


def search_options(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    report_guid = args.get('report-guid')
    raw_res = client.do_soap_request('archer-get-search-options-by-guid', report_guid=report_guid)
    try:
        res = json.loads(xml2json(raw_res))
    except Exception as e:
        print('')
    return res, {}, raw_res


def reset_cache(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    demisto.setIntegrationContext({})
    return '', {}, ''


def get_value_list(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    field_id = args.get('field-id')
    raw_res = client.do_soap_request('archer-get-valuelist', field_id=field_id)
    try:
        res = json.loads(xml2json(raw_res))
    except Exception as e:
        print('')
    return res, {}, raw_res


def get_user_id(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    user_info = args.get('user-info')
    user_info = user_info.split('/')
    raw_res = client.do_soap_request('archer-get-user-id',
                                     domain=user_info[0].lower(), username=user_info[1].lower())
    try:
        res = json.loads(xml2json(raw_res))
    except Exception as e:
        print('')
    return res, {}, raw_res


def main():
    params = demisto.params()
    credentials = params.get('credentials')
    base_url = params.get('url').strip('/')
    client = Client(base_url,
                    credentials.get('identifier'), credentials.get('password'),
                    params.get('instanceName'),
                    params.get('domain'),
                    verify=not params.get('insecure', False),
                    proxy=params.get('proxy', False))
    commands = {
        'archer-search-applications': search_applications_command,
        'archer-get-application-fields': get_application_fields_command,
        'archer-get-field': get_field_command,
        'archer-get-mapping-by-level': get_mapping_by_level_command,
        'archer-get-record': get_record_command,
        'archer-create-record': create_record_command,
        'archer-delete-record': delete_record_command,
        'archer-update-record': update_record_command,
        'archer-execute-statistic-search-by-report': execute_statistics_command,
        'archer-get-reports': get_reports,
        'archer-get-search-options-by-guid': search_options,
        'archer-reset-cache': reset_cache,
        'archer-get-valuelist': get_value_list,
        'archer-get-user-id': get_user_id
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
