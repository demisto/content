from datetime import timezone
from typing import Dict, Tuple

import dateparser
import urllib3

from CommonServerPython import *

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

REQUEST_HEADERS = {
    'Accept': 'application/json,text/html,application/xhtml +xml,application/xml;q=0.9,*/*;q=0.8',
    'Content-Type': 'application/json'
}

FIELD_TYPE_DICT = {
    1: 'Text', 2: 'Numeric', 3: 'Date', 4: 'Values List', 6: 'TrackingID', 7: 'External Links',
    8: 'Users/Groups List', 9: 'Cross-Reference', 11: 'Attachment', 12: 'Image',
    14: 'Cross-Application Status Tracking (CAST)', 16: 'Matrix', 19: 'IP Address', 20: 'Record Status',
    21: 'First Published', 22: 'Last Updated Field', 23: 'Related Records', 24: 'Sub-Form',
    25: 'History Log', 26: 'Discussion', 27: 'Multiple Reference Display Control',
    28: 'Questionnaire Reference', 29: 'Access History', 30: 'V oting', 31: 'Scheduler',
    1001: 'Cross-Application Status Tracking Field Value'
}

ACCOUNT_STATUS_DICT = {1: 'Active', 2: 'Inactive', 3: 'Locked'}


def format_time(datetime_object: datetime, use_european_time: bool) -> str:
    """Transform datetime to string, handles european time.

    Arguments:
        datetime_object: object to transform
        use_european_time: Whatever the day position should be first or second

    Returns:
        A string formatted:
        7/22/2017 3:58 PM (American) or 22/7/2017 3:58 PM (European)
    """
    time_format = '%d/%m/%Y %I:%M:%S %p' if use_european_time else '%m/%d/%Y %I:%M:%S %p'
    return datetime_object.strftime(time_format)


def parse_date_to_datetime(date: str, day_first: bool = False) -> datetime:
    """Return a datetime object from given date.
    Format of "1/1/2020 04:00 PM".

    Arguments:
        date: a date string
        day_first: is the day first in the string (European)

    Returns:
        a datetime object
    """
    date_obj = parser(date)
    if date_obj.tzinfo is None or date_obj.tzinfo.utcoffset(date_obj) is None:  # if no timezone provided
        date_order = {'DATE_ORDER': 'DMY' if day_first else 'MDY'}
        date_obj = parser(date, settings=date_order)  # Could throw `AssertionError` if could not parse the timestamp
    return date_obj


def parser(date_str, date_formats=None, languages=None, locales=None, region=None, settings=None) -> datetime:
    """Wrapper of dateparser.parse to support return type value
    """
    date_obj = dateparser.parse(
        date_str, date_formats=date_formats, languages=languages, locales=locales, region=region, settings=settings
    )
    assert isinstance(date_obj, datetime), f'Could not parse date {date_str}'  # MYPY Fix
    return date_obj


def get_token_soap_request(user, password, instance):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.orecord_to_incidentrg/2001/XMLSchema-instance" ' \
           'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
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
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
           ' xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <TerminateSession xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           '        </TerminateSession>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_reports_soap_request(token):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
           'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <GetReports xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           '        </GetReports>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def get_statistic_search_report_soap_request(token, report_guid, max_results):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
           ' xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
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
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
           'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <GetSearchOptionsByGuid xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <searchReportGuid>{report_guid}</searchReportGuid>' + \
           '        </GetSearchOptionsByGuid>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def search_records_by_report_soap_request(token, report_guid):
    return '<?xml version="1.0" encoding="utf-8"?>' + \
           '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
           'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' + \
           '    <soap:Body>' + \
           '        <SearchRecordsByReport xmlns="http://archer-tech.com/webservices/">' + \
           f'            <sessionToken>{token}</sessionToken>' + \
           f'            <reportIdOrGuid>{report_guid}</reportIdOrGuid>' + \
           '            <pageNumber>1</pageNumber>' + \
           '        </SearchRecordsByReport>' + \
           '    </soap:Body>' + \
           '</soap:Envelope>'


def search_records_soap_request(
        token, app_id, display_fields, field_id, field_name, search_value, date_operator='',
        numeric_operator='', max_results=10
):
    request_body = '<?xml version="1.0" encoding="UTF-8"?>' + \
                   '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' \
                   'xmlns:xsd="http://www.w3.org/2001/XMLSchema"' \
                   ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' + \
                   '    <soap:Body>' + \
                   '        <ExecuteSearch xmlns="http://archer-tech.com/webservices/">' + \
                   f'            <sessionToken>{token}</sessionToken>' + \
                   '            <searchOptions>' + \
                   '                <![CDATA[<SearchReport>' + \
                   '                <PageSize>100</PageSize>' + \
                   '                <PageNumber>1</PageNumber>' + \
                   f'                <MaxRecordCount>{max_results}</MaxRecordCount>' + \
                   '                <ShowStatSummaries>false</ShowStatSummaries>' + \
                   f'                <DisplayFields>{display_fields}</DisplayFields>' + \
                   f'             <Criteria><ModuleCriteria><Module name="appname">{app_id}</Module></ModuleCriteria>'

    if search_value:
        request_body += '<Filter><Conditions>'

        if date_operator:
            request_body += '<DateComparisonFilterCondition>' + \
                            f'        <Operator>{date_operator}</Operator>' + \
                            f'        <Field name="{field_name}">{field_id}</Field>' + \
                            f'        <Value>{search_value}</Value>' + \
                            '        <TimeZoneId>UTC Standard Time</TimeZoneId>' + \
                            '        <IsTimeIncluded>TRUE</IsTimeIncluded>' + \
                            '</DateComparisonFilterCondition >'
        elif numeric_operator:
            request_body += '<NumericFilterCondition>' + \
                            f'        <Operator>{numeric_operator}</Operator>' + \
                            f'        <Field name="{field_name}">{field_id}</Field>' + \
                            f'        <Value>{search_value}</Value>' + \
                            '</NumericFilterCondition >'
        else:
            request_body += '<TextFilterCondition>' + \
                            '        <Operator>Contains</Operator>' + \
                            f'        <Field name="{field_name}">{field_id}</Field>' + \
                            f'        <Value>{search_value}</Value>' + \
                            '</TextFilterCondition >'

        request_body += '</Conditions></Filter>'

    if date_operator:  # Fetch incidents must present date_operator
        request_body += '<Filter>' + \
                        '<Conditions>' + \
                        '    <DateComparisonFilterCondition>' + \
                        f'        <Operator>{date_operator}</Operator>' + \
                        f'        <Field name="{field_name}">{field_id}</Field>' + \
                        f'        <Value>{search_value}</Value>' + \
                        '        <TimeZoneId>UTC Standard Time</TimeZoneId>' + \
                        '        <IsTimeIncluded>TRUE</IsTimeIncluded>' + \
                        '    </DateComparisonFilterCondition >' + \
                        '</Conditions>' + \
                        '</Filter>'

    request_body += ' </Criteria></SearchReport>]]>' + \
                    '</searchOptions>' + \
                    '<pageNumber>1</pageNumber>' + \
                    '</ExecuteSearch>' + \
                    '</soap:Body>' + \
                    '</soap:Envelope>'

    return request_body


SOAP_COMMANDS = {
    'archer-get-reports': {'soapAction': 'http://archer-tech.com/webservices/GetReports', 'urlSuffix': 'ws/search.asmx',
                           'soapBody': get_reports_soap_request,
                           'outputPath': 'Envelope.Body.GetReportsResponse.GetReportsResult'},
    'archer-execute-statistic-search-by-report': {
        'soapAction': 'http://archer-tech.com/webservices/ExecuteStatisticSearchByReport',
        'urlSuffix': 'ws/search.asmx',
        'soapBody': get_statistic_search_report_soap_request,
        'outputPath': 'Envelope.Body.ExecuteStatisticSearchByReportResponse.ExecuteStatistic'
                      'SearchByReportResult'
    },
    'archer-get-search-options-by-guid':
        {'soapAction': 'http://archer-tech.com/webservices/GetSearchOptionsByGuid',
         'urlSuffix': 'ws/search.asmx',
         'soapBody': get_search_options_soap_request,
         'outputPath': 'Envelope.Body.GetSearchOptionsByGuidResponse.GetSearchOptionsByGuidResult'
         },
    'archer-search-records':
        {'soapAction': 'http://archer-tech.com/webservices/ExecuteSearch',
         'urlSuffix': 'ws/search.asmx',
         'soapBody': search_records_soap_request,
         'outputPath': 'Envelope.Body.ExecuteSearchResponse.ExecuteSearchResult'},
    'archer-search-records-by-report': {
        'soapAction': 'http://archer-tech.com/webservices/SearchRecordsByReport',
        'urlSuffix': 'ws/search.asmx',
        'soapBody': search_records_by_report_soap_request,
        'outputPath': 'Envelope.Body.SearchRecordsByReportResponse.SearchRecordsByReportResult'
    }
}


class Client(BaseClient):
    def __init__(self, base_url, username, password, instance_name, domain, **kwargs):
        self.username = username
        self.password = password
        self.instance_name = instance_name
        self.domain = domain
        super(Client, self).__init__(base_url=base_url, headers=REQUEST_HEADERS, **kwargs)

    def do_request(self, method, url_suffix, data=None, params=None):
        if not REQUEST_HEADERS.get('Authorization'):
            self.update_session()

        res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data, params=params,
                                 resp_type='response', ok_codes=(200, 401))

        if res.status_code == 401:
            self.update_session()
            res = self._http_request(method, url_suffix, headers=REQUEST_HEADERS, json_data=data,
                                     resp_type='response', ok_codes=(200, 401))

        return res.json()

    def update_session(self):
        body = {
            'InstanceName': self.instance_name,
            'Username': self.username,
            'UserDomain': self.domain,
            'Password': self.password
        }

        res = self._http_request('POST', '/api/core/security/login', json_data=body)
        is_successful_response = res.get('IsSuccessful')
        if not is_successful_response:
            return_error(res.get('ValidationMessages'))
        session = res.get('RequestedObject', {}).get('SessionToken')
        REQUEST_HEADERS['Authorization'] = f'Archer session-id={session}'

    def get_token(self):
        body = get_token_soap_request(self.username, self.password, self.instance_name)
        headers = {'SOAPAction': 'http://archer-tech.com/webservices/CreateUserSessionFromInstance',
                   'Content-Type': 'text/xml; charset=utf-8'}
        res = self._http_request('POST'
                                 '', 'ws/general.asmx', headers=headers, data=body, resp_type='content')

        return extract_from_xml(res,
                                'Envelope.Body.CreateUserSessionFromInstanceResponse.'
                                'CreateUserSessionFromInstanceResult')

    def destroy_token(self, token):
        body = terminate_session_soap_request(token)
        headers = {'SOAPAction': 'http://archer-tech.com/webservices/TerminateSession',
                   'Content-Type': 'text/xml; charset=utf-8'}
        self._http_request('POST', 'ws/general.asmx', headers=headers, data=body, resp_type='content')

    def do_soap_request(self, command, **kwargs):
        req_data = SOAP_COMMANDS[command]
        headers = {'SOAPAction': req_data['soapAction'], 'Content-Type': 'text/xml; charset=utf-8'}
        token = self.get_token()
        body = req_data['soapBody'](token, **kwargs)  # type: ignore
        res = self._http_request('POST', req_data['urlSuffix'], headers=headers, data=body, resp_type='content')
        self.destroy_token(token)
        return extract_from_xml(res, req_data['outputPath']), res

    def get_level_by_app_id(self, app_id):
        cache = demisto.getIntegrationContext()
        if cache.get(app_id):
            return cache[app_id]

        levels = []
        all_levels_res = self.do_request('GET', f'/api/core/system/level/module/{app_id}')
        for level in all_levels_res:
            if level.get('RequestedObject') and level.get('IsSuccessful'):
                level_id = level.get('RequestedObject').get('Id')

                fields = {}
                level_res = self.do_request('GET', f'/api/core/system/fielddefinition/level/{level_id}')
                for field in level_res:
                    if field.get('RequestedObject') and field.get('IsSuccessful'):
                        field_item = field.get('RequestedObject')
                        field_id = str(field_item.get('Id'))
                        fields[field_id] = {'Type': field_item.get('Type'),
                                            'Name': field_item.get('Name'),
                                            'FieldId': field_id,
                                            'IsRequired': field_item.get('IsRequired', False),
                                            'RelatedValuesListId': field_item.get('RelatedValuesListId')}

                levels.append({'level': level_id, 'mapping': fields})

        if levels:
            cache[int(app_id)] = levels
            demisto.setIntegrationContext(cache)
            return levels
        return []

    def get_record(self, app_id, record_id):
        res = self.do_request('GET', f'/api/core/content/{record_id}')

        if not isinstance(res, dict):
            res = res.json()

        errors = get_errors_from_res(res)
        record = {}
        if res.get('RequestedObject') and res.get('IsSuccessful'):
            content_obj = res.get('RequestedObject')
            level_id = content_obj.get('LevelId')
            levels = self.get_level_by_app_id(app_id)
            level_fields = list(filter(lambda m: m['level'] == level_id, levels))
            if level_fields:
                level_fields = level_fields[0]['mapping']
            else:
                return {}, res, errors

            for _id, field in content_obj.get('FieldContents').items():
                field_data = level_fields.get(str(_id))  # type: ignore
                field_type = field_data.get('Type')

                # when field type is IP Address
                if field_type == 19:
                    field_value = field.get('IpAddressBytes')
                # when field type is Values List
                elif field_type == 4 and field.get('Value') and field['Value'].get('ValuesListIds'):
                    list_data = self.get_field_value_list(_id)
                    list_ids = field['Value']['ValuesListIds']
                    list_ids = list(filter(lambda x: x['Id'] in list_ids, list_data['ValuesList']))
                    field_value = list(map(lambda x: x['Name'], list_ids))
                else:
                    field_value = field.get('Value')

                if field_value:
                    record[field_data.get('Name')] = field_value

            record['Id'] = content_obj.get('Id')
        return record, res, errors

    def record_to_incident(
            self, record_item, app_id, date_field, day_first: bool = False, offset: int = 0
    ) -> Tuple[dict, datetime]:
        """Transform a recotrd to incident

        Args:
            record_item: The record item dict
            app_id: IF of the app
            date_field: what is the date field
            day_first: should the day be first in the day field (european date)
            offset: what is the offset to the server

        Returns:
            incident, incident created time (in Archer's local time)
        """
        labels = []
        raw_record = record_item['raw']
        record_item = record_item['record']
        incident_created_time = datetime(1, 1, 1)
        occurred_time = incident_created_time
        if date_field := record_item.get(date_field):
            incident_created_time = parse_date_to_datetime(
                date_field, day_first=day_first
            ).replace(tzinfo=timezone.utc)
            # fix ocurred time. if the offset is -120 minutes (Archer is two hours behind
            # Cortex XSOAR, we should add 120 minutes to the occurred. So negative the incident_created_time
            occurred_time = incident_created_time - timedelta(minutes=offset)

        # Will convert value to strs
        for k, v in record_item.items():
            if isinstance(v, str):
                labels.append({
                    'type': k,
                    'value': v
                })
            else:
                labels.append({
                    'type': k,
                    'value': json.dumps(v)
                })

        labels.append({'type': 'ModuleId', 'value': app_id})
        labels.append({'type': 'ContentId', 'value': record_item.get("Id")})
        labels.append({'type': 'rawJSON', 'value': json.dumps(raw_record)})
        incident = {
            'name': f'RSA Archer Incident: {record_item.get("Id")}',
            'details': json.dumps(record_item),
            'occurred': occurred_time.strftime(OCCURRED_FORMAT),
            'labels': labels,
            'rawJSON': json.dumps(raw_record)
        }
        return incident, incident_created_time

    def search_records(
            self, app_id, fields_to_display=None, field_to_search='', search_value='',
            numeric_operator='', date_operator='', max_results=10,
    ):
        demisto.debug(f'searching for records {field_to_search}:{search_value}')
        if fields_to_display is None:
            fields_to_display = []
        try:
            level_data = self.get_level_by_app_id(app_id)[0]
        except IndexError as exc:
            raise DemistoException(
                'Could not find a level data. You might be using the wrong application id'
            ) from exc
        # Building request fields
        fields_xml = ''
        search_field_name = ''
        search_field_id = ''
        fields_mapping = level_data['mapping']
        for field in fields_mapping.keys():
            field_name = fields_mapping[field]['Name']
            if field_name in fields_to_display:
                fields_xml += f'<DisplayField name="{field_name}">{field}</DisplayField>'
            if field_name == field_to_search:
                search_field_name = field_name
                search_field_id = field

        res, raw_res = self.do_soap_request(
            'archer-search-records',
            app_id=app_id, display_fields=fields_xml,
            field_id=search_field_id, field_name=search_field_name,
            numeric_operator=numeric_operator,
            date_operator=date_operator, search_value=search_value,
            max_results=max_results
        )

        if not res:
            return [], raw_res

        records = self.xml_to_records(res, fields_mapping)
        return records, raw_res

    def xml_to_records(self, xml_response, fields_mapping):
        res = json.loads(xml2json(xml_response))
        records = []
        if res.get('Records') and res['Records'].get('Record'):
            records_data = res['Records']['Record']
            if isinstance(records_data, dict):
                records_data = [records_data]

            for item in records_data:
                record = {'Id': item.get('@contentId')}
                record_fields = item.get('Field')

                if isinstance(record_fields, dict):
                    record_fields = [record_fields]

                for field in record_fields:
                    field_name = fields_mapping[field.get('@id')]['Name']
                    field_type = field.get('@type')
                    field_value = ''
                    if field_type == '3':
                        field_value = field.get('@xmlConvertedValue')
                    elif field_type == '4':
                        if field.get('ListValues'):
                            field_value = field['ListValues']['ListValue']['@displayName']
                    elif field_type == '8':
                        field_value = json.dumps(field)
                    else:
                        field_value = field.get('#text')

                    record[field_name] = field_value
                records.append({'record': record, 'raw': item})
        return records

    def get_field_value_list(self, field_id):
        cache = demisto.getIntegrationContext()

        if cache['fieldValueList'].get(field_id):
            return cache.get('fieldValueList').get(field_id)

        res = self.do_request('GET', f'/api/core/system/fielddefinition/{field_id}')

        errors = get_errors_from_res(res)
        if errors:
            return_error(errors)

        if res.get('RequestedObject') and res.get('IsSuccessful'):
            list_id = res['RequestedObject']['RelatedValuesListId']
            values_list_res = self.do_request('GET', f'/api/core/system/valueslistvalue/valueslist/{list_id}')
            if values_list_res.get('RequestedObject') and values_list_res.get('IsSuccessful'):
                values_list = []
                for value in values_list_res['RequestedObject'].get('Children'):
                    values_list.append({'Id': value['Data']['Id'],
                                        'Name': value['Data']['Name'],
                                        'IsSelectable': value['Data']['IsSelectable']})
                field_data = {'FieldId': field_id, 'ValuesList': values_list}

                cache['fieldValueList'][field_id] = field_data
                demisto.setIntegrationContext(cache)
                return field_data
        return {}


def extract_from_xml(xml, path):
    xml = json.loads(xml2json(xml))
    path = path.split('.')

    for item in path:
        if xml.get(item):
            xml = xml[item]
            continue
        return ''
    return xml


def generate_field_contents(client, fields_values, level_fields):
    if fields_values and not isinstance(fields_values, dict):
        try:
            fields_values = json.loads(fields_values)
        except Exception:
            raise Exception('Failed to parese fields-values argument')

    field_content = {}
    for field_name in fields_values.keys():
        field_data = None

        for _id, field in level_fields.items():
            if field.get('Name') == field_name:
                field_data = field
                break

        if field_data:
            field_key, field_value = generate_field_value(client, field_name, field_data, fields_values[field_name])

            field_content[_id] = {'Type': field_data['Type'],
                                  field_key: field_value,
                                  'FieldId': _id}
    return field_content


def generate_field_value(client, field_name, field_data, field_val):
    field_type = field_data['Type']

    # when field type is Values List, call get_field_value_list method to get the value ID
    # for example: {"Type":["Switch"], fieldname:[value1, value2]}
    if field_type == 4:
        field_data = client.get_field_value_list(field_data['FieldId'])
        list_ids = []
        if not isinstance(field_val, list):
            field_val = [field_val]
        for item in field_val:
            tmp_id = next(f for f in field_data['ValuesList'] if f['Name'] == item)
            if tmp_id:
                list_ids.append(tmp_id['Id'])
            else:
                raise Exception(f'Failed to create field {field_name} with the value {field_data}')
        return 'Value', {'ValuesListIds': list_ids}

    # when field type is External Links
    # for example: {"Patch URL":[{"value":"github", "link": "https://github.com"}]}
    elif field_type == 7:
        list_urls = []
        for item in field_val:
            list_urls.append({'Name': item.get('value'), 'URL': item.get('link')})
        return 'Value', list_urls

    # when field type is Users/Groups List
    # for example: {"Policy Owner":{"users":[20],"groups":[30]}}
    elif field_type == 8:
        users = field_val.get('users')
        groups = field_val.get('groups')
        field_val = {'UserList': [], 'GroupList': []}
        if users:
            for user in users:
                field_val['UserList'].append({'ID': user})
        if groups:
            for group in groups:
                field_val['GroupList'].append({'ID': group})
        return 'Value', field_val

    # when field type is Cross- Reference
    # for example: {"Area Reference(s)":[20]}
    elif field_type == 9:
        list_cross_reference = []
        if isinstance(field_val, list):
            for content in field_val:
                list_cross_reference.append({'ContentID': content})

        else:
            list_cross_reference = [{'ContentID': field_val}]
        return 'Value', list_cross_reference

    elif field_type == 19:
        return 'IpAddressBytes', field_val

    else:
        return 'Value', field_val


def get_errors_from_res(res):
    if isinstance(res, dict) and res.get('ValidationMessages'):
        messages = []
        for message in res.get('ValidationMessages'):  # type: ignore
            messages.append(message.get('ResourcedMessage'))
        return '\n'.join(messages)


def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as fopen:
        file_bytes = fopen.read()

    file_bytes = base64.b64encode(file_bytes)
    return file_name, file_bytes.decode('utf-8')


def test_module(client: Client, params: dict) -> str:
    if params.get('isFetch', False):
        offset_in_minutes = int(params['time_zone'])
        last_fetch = get_fetch_time(
            {}, params.get('fetch_time', '3 days'),
            offset_in_minutes
        )
        fetch_incidents(client, params, last_fetch)

        return 'ok'

    return 'ok' if client.do_request('GET', '/api/core/system/application') else 'Connection failed.'


def search_applications_command(client: Client, args: Dict[str, str]):
    app_id = args.get('applicationId')
    limit = args.get('limit')
    endpoint_url = '/api/core/system/application/'

    if app_id:
        endpoint_url = f'/api/core/system/application/{app_id}'
        res = client.do_request('GET', endpoint_url)
    elif limit:
        res = client.do_request('GET', endpoint_url, params={"$top": limit})

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

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

    markdown = tableToMarkdown('Search applications results', applications)
    context: dict = {
        'Archer.Application(val.Id && val.Id == obj.Id)': applications}
    return_outputs(markdown, context, res)


def get_application_fields_command(client: Client, args: Dict[str, str]):
    app_id = args.get('applicationId')

    res = client.do_request('GET', f'/api/core/system/fielddefinition/application/{app_id}')

    fields = []
    for field in res:
        if field.get('RequestedObject') and field.get('IsSuccessful'):
            field_obj = field['RequestedObject']
            field_type = field_obj.get('Type')
            fields.append({'FieldId': field_obj.get('Id'),
                           'FieldType': FIELD_TYPE_DICT.get(field_type, 'Unknown'),
                           'FieldName': field_obj.get('Name'),
                           'LevelID': field_obj.get('LevelId')})
        else:
            errors = get_errors_from_res(field)
            if errors:
                return_error(errors)

    markdown = tableToMarkdown('Application fields', fields)
    context: dict = {'Archer.ApplicationField(val.FieldId && val.FieldId == obj.FieldId)': fields}
    return_outputs(markdown, context, res)


def get_field_command(client: Client, args: Dict[str, str]):
    field_id = args.get('fieldID')

    res = client.do_request('GET', f'/api/core/system/fielddefinition/{field_id}')

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    field = {}
    if res.get('RequestedObject') and res.get('IsSuccessful'):
        field_obj = res['RequestedObject']
        item_type = field_obj.get('Type')
        item_type = FIELD_TYPE_DICT.get(item_type, 'Unknown')
        field = {'FieldId': field_obj.get('Id'),
                 'FieldType': item_type,
                 'FieldName': field_obj.get('Name'),
                 'LevelID': field_obj.get('LevelId')}

    markdown = tableToMarkdown('Application field', field)
    context: dict = {
        'Archer.ApplicationField(val.FieldId && val.FieldId == obj.FieldId)':
            field
    }
    return_outputs(markdown, context, res)


def get_mapping_by_level_command(client: Client, args: Dict[str, str]):
    level = args.get('level')

    res = client.do_request('GET', f'/api/core/system/fielddefinition/level/{level}')

    items = []
    for item in res:
        if item.get('RequestedObject') and item.get('IsSuccessful'):
            item_obj = item['RequestedObject']
            item_type = item_obj.get('Type')
            if item_type:
                item_type = FIELD_TYPE_DICT.get(item_type, 'Unknown')
            else:
                item_type = 'Unknown'
            items.append({'Id': item_obj.get('Id'),
                          'Name': item_obj.get('Name'),
                          'Type': item_type,
                          'LevelId': item_obj.get('LevelId')})
        else:
            errors = get_errors_from_res(item)
            if errors:
                return_error(errors)

    markdown = tableToMarkdown(f'Level mapping for level {level}', items)
    context: dict = {'Archer.LevelMapping(val.Id && val.Id == obj.Id)': items}
    return_outputs(markdown, context, res)


def get_record_command(client: Client, args: Dict[str, str]):
    record_id = args.get('contentId')
    app_id = args.get('applicationId')

    record, res, errors = client.get_record(app_id, record_id)
    if errors:
        return_error(errors)

    markdown = tableToMarkdown('Record details', record)
    context: dict = {
        'Archer.Record(val.Id && val.Id == obj.Id)':
            record
    }
    return_outputs(markdown, context, res)


def create_record_command(client: Client, args: Dict[str, str]):
    app_id = args.get('applicationId')
    fields_values = args.get('fieldsToValues')
    try:
        level_data = client.get_level_by_app_id(app_id)[0]
    except IndexError as exc:
        raise DemistoException(
            'Got no level by app id. You might be using the wrong application id'
        ) from exc
    field_contents = generate_field_contents(client, fields_values, level_data['mapping'])

    body = {'Content': {'LevelId': level_data['level'], 'FieldContents': field_contents}}

    res = client.do_request('Post', '/api/core/content', data=body)

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    if res.get('RequestedObject') and res.get('IsSuccessful'):
        rec_id = res['RequestedObject']['Id']
        return_outputs(f'Record created successfully, record id: {rec_id}', {'Archer.Record.Id': rec_id}, res)


def delete_record_command(client: Client, args: Dict[str, str]):
    record_id = args.get('contentId')
    res = client.do_request('Delete', f'/api/core/content/{record_id}')

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)
    return_outputs(f'Record {record_id} deleted successfully', {}, res)


def update_record_command(client: Client, args: Dict[str, str]):
    app_id = args.get('applicationId')
    record_id = args.get('contentId')
    fields_values = args.get('fieldsToValues')
    level_data = client.get_level_by_app_id(app_id)[0]
    field_contents = generate_field_contents(client, fields_values, level_data['mapping'])

    body = {'Content': {'Id': record_id, 'LevelId': level_data['level'], 'FieldContents': field_contents}}
    res = client.do_request('Put', '/api/core/content', data=body)

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    if res.get('IsSuccessful'):
        return_outputs(f'Record {record_id} updated successfully', {}, res)
    else:
        raise DemistoException('Update record failed')


def execute_statistics_command(client: Client, args: Dict[str, str]):
    report_guid = args.get('reportGuid')
    max_results = args.get('maxResults')
    res, raw_res = client.do_soap_request('archer-execute-statistic-search-by-report',
                                          report_guid=report_guid, max_results=max_results)
    if res:
        res = json.loads(xml2json(res))
    return_outputs(res, {}, {})


def get_reports_command(client: Client, args: Dict[str, str]):
    res, raw_res = client.do_soap_request('archer-get-reports')
    res = json.loads(xml2json(res))
    ec = res.get('ReportValues').get('ReportValue')

    context: dict = {
        'Archer.Report(val.ReportGUID && val.ReportGUID == obj.ReportGUID)': ec
    }
    return_outputs(ec, context, {})


def search_options_command(client: Client, args: Dict[str, str]):
    report_guid = args.get('reportGuid')
    res, raw_res = client.do_soap_request('archer-get-search-options-by-guid', report_guid=report_guid)
    if res.startswith('<'):
        res = json.loads(xml2json(res))
    return_outputs(res, {}, {})


def reset_cache_command(client: Client, args: Dict[str, str]):
    demisto.setIntegrationContext({})
    return_outputs('', {}, '')


def get_value_list_command(client: Client, args: Dict[str, str]):
    field_id = args.get('fieldID')
    field_data = client.get_field_value_list(field_id)

    markdown = tableToMarkdown(f'Value list for field {field_id}', field_data['ValuesList'])

    context: dict = {
        'Archer.ApplicationField(val.FieldId && val.FieldId == obj.FieldId)':
            field_data
    }
    return_outputs(markdown, context, {})


def upload_file_command(client: Client, args: Dict[str, str]) -> str:
    """Uploading a file to archer as an attachment

    Arguments:
        client: A client to use in order to send the api callarcher-get-file
        args: demisto args

    Returns:
        An attachment id from Archer
    """
    entry_id = args.get('entryId')
    file_name, file_bytes = get_file(entry_id)
    body = {'AttachmentName': file_name, 'AttachmentBytes': file_bytes}

    res = client.do_request('POST', '/api/core/content/attachment', data=body)

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    if res.get('RequestedObject') and res.get('IsSuccessful'):
        attachment_id = res['RequestedObject'].get('Id')
    else:
        raise DemistoException('Upload file failed')

    return_outputs(f'File uploaded successfully, attachment ID: {attachment_id}', {}, res)
    return attachment_id


def upload_and_associate_command(client: Client, args: Dict[str, str]):
    """Uploading an entry to archer. than, if needed, associate it to a record.
    """
    app_id = args.get('applicationId')
    content_id = args.get('contentId')
    associate_field = args.get('associatedField')

    should_associate_to_record = app_id and content_id
    if not should_associate_to_record:  # If both app_id and content_id
        if app_id or content_id:  # If one of them, raise error. User's mistake
            raise DemistoException(
                'Found arguments to associate an attachment to a record, but not all required arguments supplied'
            )

    attachment_id = upload_file_command(client, args)
    if should_associate_to_record:
        args['fieldsToValues'] = json.dumps({associate_field: [attachment_id]})
        update_record_command(client, args)


def download_file_command(client: Client, args: Dict[str, str]):
    attachment_id = args.get('fileId')
    res = client.do_request('GET', f'/api/core/content/attachment/{attachment_id}')

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    if res.get('RequestedObject') and res.get('IsSuccessful'):
        content = base64.b64decode(res['RequestedObject'].get('AttachmentBytes'))
        filename = res['RequestedObject'].get('AttachmentName')
        return demisto.results(fileResult(filename, content))
    else:
        return_error('File downloading failed', outputs=res)


def list_users_command(client: Client, args: Dict[str, str]):
    user_id = args.get('userId')
    if user_id:
        res = client.do_request('GET', f'/api/core/system/user/{user_id}')
    else:
        res = client.do_request('GET', '/api/core/system/user')

    errors = get_errors_from_res(res)
    if errors:
        return_error(errors)

    if isinstance(res, dict):
        res = [res]

    users = []
    for user in res:
        if user.get('RequestedObject') and user.get('IsSuccessful'):
            user_obj = user['RequestedObject']
            users.append({'Id': user_obj.get('Id'),
                          'DisplayName': user_obj.get('DisplayName'),
                          'FirstName': user_obj.get('FirstName'),
                          'MiddleName': user_obj.get('MiddleName'),
                          'LastName': user_obj.get('LastName'),
                          'AccountStatus': ACCOUNT_STATUS_DICT[user_obj.get('AccountStatus')],
                          'LastLoginDate': user_obj.get('LastLoginDate'),
                          'UserName': user_obj.get('UserName')})

    markdown = tableToMarkdown('Users list', users)
    context: dict = {
        'Archer.User(val.Id && val.Id == obj.Id)':
            users
    }
    return_outputs(markdown, context, res)


def search_records_command(client: Client, args: Dict[str, str]):
    app_id = args.get('applicationId')
    field_to_search = args.get('fieldToSearchOn')
    search_value = args.get('searchValue')
    max_results = args.get('maxResults', 10)
    date_operator = args.get('dateOperator')
    numeric_operator = args.get('numeric-operator')
    fields_to_display = argToList(args.get('fieldsToDisplay'))
    fields_to_get = argToList(args.get('fieldsToGet'))
    full_data = args.get('fullData', 'true') == 'true'

    if fields_to_get and 'Id' not in fields_to_get:
        fields_to_get.append('Id')

    if not all(f in fields_to_get for f in fields_to_display):
        return_error('fields-to-display param should have only values from fields-to-get')

    if full_data:
        level_data = client.get_level_by_app_id(app_id)[0]
        fields_mapping = level_data['mapping']
        fields_to_get = [fields_mapping[next(iter(fields_mapping))]['Name']]

    records, raw_res = client.search_records(
        app_id, fields_to_get, field_to_search, search_value,
        numeric_operator, date_operator, max_results=max_results
    )

    records = list(map(lambda x: x['record'], records))

    if full_data:
        records_full = []
        for rec in records:
            record_item, _, errors = client.get_record(app_id, rec['Id'])
            if not errors:
                records_full.append(record_item)
        records = records_full

    hr = []

    if full_data:
        hr = records
    else:
        for record in records:
            hr.append({f: record[f] for f in fields_to_display})

    markdown = tableToMarkdown('Search records results', hr)
    context: dict = {'Archer.Record(val.Id && val.Id == obj.Id)': records}
    return_outputs(markdown, context, {})


def search_records_by_report_command(client: Client, args: Dict[str, str]):
    report_guid = args.get('reportGuid')
    res, raw_res = client.do_soap_request('archer-search-records-by-report', report_guid=report_guid)
    if not res:
        return_outputs(f'No records found for report {report_guid}', {}, json.loads(xml2json(raw_res)))
        return

    raw_records = json.loads(xml2json(res))
    records = []
    ec = {}
    if raw_records.get('Records') and raw_records['Records'].get('Record'):
        level_id = raw_records['Records']['Record'][0]['@levelId']

        level_res = client.do_request('GET', f'/api/core/system/fielddefinition/level/{level_id}')
        fields = {}
        for field in level_res:
            if field.get('RequestedObject') and field.get('IsSuccessful'):
                field_item = field.get('RequestedObject')
                field_id = str(field_item.get('Id'))
                fields[field_id] = {'Type': field_item.get('Type'),
                                    'Name': field_item.get('Name')}

        records = client.xml_to_records(res, fields)
        records = list(map(lambda x: x['record'], records))

        ec = {'Record': records, 'RecordsAmount': len(records), 'ReportGUID': report_guid}

    markdown = tableToMarkdown('Search records by report results', records)
    context: dict = {'Archer.SearchByReport(val.ReportGUID && val.ReportGUID == obj.ReportGUID)': ec}

    return_outputs(markdown, context, json.loads(xml2json(raw_res)))


def print_cache_command(client: Client, args: Dict[str, str]):
    cache = demisto.getIntegrationContext()
    return_outputs(cache, {}, {})


def fetch_incidents(
        client: Client, params: dict, from_time: datetime
) -> Tuple[list, datetime]:
    """Fetches incidents.

    Args:
        client: Client derived from BaseClient
        params: demisto.params dict.
        from_time: Time to start the fetch from

    Returns:
        incidents, next_run datetime in archer's local time
    """
    # Not using get method as those params are a must
    app_id = params['applicationId']
    date_field = params['applicationDateField']
    max_results = params.get('fetch_limit', 10)
    offset = int(params.get('time_zone', '0'))
    fields_to_display = argToList(params.get('fields_to_fetch'))
    fields_to_display.append(date_field)
    day_first = argToBoolean(params.get('useEuropeanTime', False))
    from_time_utc = format_time(from_time, day_first)
    # API Call
    records, raw_res = client.search_records(
        app_id, fields_to_display, date_field,
        from_time_utc,
        date_operator='GreaterThan',
        max_results=max_results
    )

    # Build incidents
    incidents = list()
    next_fetch = from_time
    for record in records:
        incident, incident_created_time = client.record_to_incident(
            record, app_id, date_field, day_first=day_first, offset=offset
        )
        if incident_created_time > next_fetch:
            next_fetch = incident_created_time
        incidents.append(incident)

    return incidents, next_fetch


def get_fetch_time(last_fetch: dict, first_fetch_time: str, offset: int = 0) -> datetime:
    """Gets lastRun object and first fetch time (str, 3 days) and returns
    a datetime object of the last run if exists, else datetime of the first fetch time

    Args:
        last_fetch: a dict that may contain 'last_fetch'
        first_fetch_time: time back in simple format (3 days)
        offset: time difference between CortexXSOAR machine and Archer, in minutes.

    Returns:
        Time to start fetch from

    """
    if next_run := last_fetch.get('last_fetch'):
        start_fetch = parser(next_run)
    else:
        start_fetch, _ = parse_date_range(first_fetch_time)
        start_fetch += timedelta(minutes=offset)
    start_fetch = start_fetch.replace(tzinfo=timezone.utc)
    return start_fetch


def main():
    params = demisto.params()
    credentials = params.get('credentials')
    base_url = params.get('url').strip('/')

    cache = demisto.getIntegrationContext()
    if not cache.get('fieldValueList'):
        cache['fieldValueList'] = {}
        demisto.setIntegrationContext(cache)

    client = Client(
        base_url,
        credentials.get('identifier'), credentials.get('password'),
        params.get('instanceName'),
        params.get('userDomain'),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy', False)
    )
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
        'archer-get-reports': get_reports_command,
        'archer-get-search-options-by-guid': search_options_command,
        'archer-reset-cache': reset_cache_command,
        'archer-get-valuelist': get_value_list_command,
        'archer-upload-file': upload_and_associate_command,
        'archer-get-file': download_file_command,
        'archer-list-users': list_users_command,
        'archer-search-records': search_records_command,
        'archer-search-records-by-report': search_records_by_report_command,
        'archer-print-cache': print_cache_command,
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if command == 'fetch-incidents':
            offset = int(params['time_zone'])
            from_time = get_fetch_time(
                demisto.getLastRun(), params.get('fetch_time', '3 days'), offset
            )

            incidents, next_fetch = fetch_incidents(
                client=client,
                params=params,
                from_time=from_time
            )
            demisto.debug(f'Setting next run to {next_fetch}')
            demisto.setLastRun({'last_fetch': next_fetch.strftime(OCCURRED_FORMAT)})
            demisto.incidents(incidents)
        elif command == 'test-module':
            demisto.results(test_module(client, params))
        elif command in commands:
            return commands[command](client, demisto.args())
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}')


if __name__ in ('__builtin__', 'builtins'):
    main()
