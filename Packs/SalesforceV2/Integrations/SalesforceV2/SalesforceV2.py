import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

import urllib3
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

''' CLIENT CLASS '''


class Client(BaseClient):
    SESSION_DATA = ''
    URI_PREFIX = '/services/data/v39.0/'

    def getNewToken(self):

        response = self._http_request(
            method='POST',
            url_suffix='/services/oauth2/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            params={
                "grant_type": "password",
                "client_id": demisto.params().get("clientID"),
                "client_secret": demisto.params().get("clientSecret"),
                "username": demisto.params()["credentials"].get("identifier"),
                "password": demisto.params()["credentials"].get("password")
            }
        )

        if response.get("access_token"):
            self.SESSION_DATA = response
            self._base_url = self.SESSION_DATA.get('instance_url')  # type: ignore
            self._headers = {
                'Authorization': f'Bearer {self.SESSION_DATA.get("access_token")}',  # type: ignore
                'Content-Type': 'application/json'
            }

        return response

    def sendRequestInSession(self, method, uri='', body={}, params={}, full_url=None):

        if not full_url:
            response = self._http_request(
                method=method, url_suffix=f"{self.URI_PREFIX}{uri}", headers=self._headers, json_data=body,
                params=params, resp_type='response')
            if response.status_code == 401:
                # get a new token and re-run the request
                self.SESSION_DATA = self.getNewToken()
                response = self._http_request(
                    method=method, url_suffix=f"{self.URI_PREFIX}{uri}", headers=self._headers, json_data=body,
                    params=params, resp_type='response')
        else:
            response = self._http_request(method=method, full_url=full_url, headers=self._headers,
                                          json_data=body, params=params, resp_type='response')
            if response.status_code == 401:
                # get a new token and re-run the request
                self.SESSION_DATA = self.getNewToken()
                response = self._http_request(method=method, full_url=full_url, headers=self._headers,
                                              json_data=body, params=params, resp_type='response')

        try:
            return response.json()
        except ValueError:
            return response.text

    def getCaseFiles(self, oid, caseNumber):

        if oid:
            p = "cid={oid}"
        else:
            p = f"cno={caseNumber}"

        response = self.sendRequestInSession(method='GET', full_url=f'{self._base_url}/services/apexrest/TACCaseFileAPI?{p}')

        return response

    def getCaseFileById(self, caseNumber, caseFileId):

        case_files = self.getCaseFiles(None, caseNumber).get('fileInfo')
        for cf in case_files:
            if cf.get('id') == caseFileId:
                response = requests.get(cf.get('url')).content
                return fileResult(cf.get('fileName'), response)

        raise Exception(f"Cannot find {caseFileId} in {caseNumber}")

    def getObjectTypes(self):

        sobjects = {}
        response = self.sendRequestInSession('GET', 'sobjects').get('sobjects', None)

        if len(response) > 0:
            for item in response:
                if key_prefix := item.get('keyPrefix'):
                    sobjects[key_prefix] = item.get('label')
            # set the integration object with object prefix
            demisto.setIntegrationContext({'sobjects': sobjects})

    def identifyObjectType(self, oid):
        # identify object type based on the first 3 chars of oid
        return demisto.getIntegrationContext()['sobjects'].get(str(oid[0:3]), 'Unknown')

    def queryRaw(self, query):

        url = 'query/'
        params = {"q": query}
        records = []
        response = self.sendRequestInSession('GET', url, '', params)
        records += response.get('records')

        while response.get('done') is False:
            response = self.sendRequestInSession('GET', url + response.get('nextRecordsUrl').split("/")[5], '', {})
            records += response.get('records')

        response['records'] = records

        return response

    def queryObjects(self, fields, table, condition=None):

        query = f"SELECT {','.join(fields)} FROM {table}"
        if condition:
            query += f" WHERE {condition}"

        return self.queryRaw(query)

    def getObject(self, path):

        if "/" in path:
            # if full path provided
            response = self.sendRequestInSession('GET', 'sobjects/' + path, '')
        else:
            # otherwise only oid provided
            obj_type = self.identifyObjectType(path).replace(" ", "")
            response = self.sendRequestInSession('GET', f'sobjects/{obj_type}/{path}', '')

        return response

    def createObject(self, path, json_obj):

        return self.sendRequestInSession('POST', 'sobjects/' + path, json_obj)

    def updateObject(self, path, json_obj):

        return self.sendRequestInSession('PATCH', 'sobjects/' + path, json_obj)

    def deleteObject(self, path):

        return self.sendRequestInSession('DELETE', 'sobjects/' + path)

    # Add the capability to get all comments in a specific case

    def getCaseComment(self, oid, caseNumber):

        if caseNumber:
            condition = f"CaseNumber='{caseNumber}'"
            cases = self.queryObjects(['Id', 'CaseNumber'], 'Case', condition).get("records")
            comments = self.sendRequestInSession("GET", f"sobjects/Case/{cases[0]['Id']}/CaseComments")
        elif oid:
            comments = self.sendRequestInSession("GET", f"sobjects/Case/{oid}/CaseComments")
        else:
            comments = ""

        return comments

    def getUser(self, oid, caseNumber):

        if caseNumber:
            condition = f"CaseNumber='{caseNumber}'"
            cases = self.queryObjects(['Id', 'CaseNumber', 'OwnerId'], 'Case', condition).get("records", [])
            if len(cases) == 1:
                # retrieve object type based on OwnerId
                obj_type = self.identifyObjectType(cases[0].get('OwnerId'))
                users = self.getObject(f"{obj_type}/{cases[0].get('OwnerId')}")
            else:
                users = ""
                demisto.debug(f"{len(cases)=} != 1. {users=}")
        elif oid:
            users = self.getObject(f"User/{oid}")
        else:
            users = ""
            demisto.debug(f"not caseNumber and not oid. {users=}")

        return users

    # Add the capability to post comment in specific case
    def postCaseComment(self, public, oid, caseNumber, text):

        # retrieve oid based on case number

        if caseNumber:
            condition = f"CaseNumber='{caseNumber}'"
            cases = self.queryObjects(['Id', 'CaseNumber', 'OwnerId'], 'Case', condition).get("records", [])
            if len(cases) == 1:
                oid = cases[0].get('Id')
            else:
                return_error('Invalid Case Number Provided.')

        data = {
            "CommentBody": text,
            "ParentId": oid,
            "IsPublished": public
        }

        response = self.sendRequestInSession('POST', 'sobjects/CaseComment', data)

        return response

    def pushComment(self, oid, text, linkUrl):
        data = {
            "body": {
                "messageSegments": [{
                    "type": 'Text',
                    "text": text
                }],
            },
            "feedElementType": 'FeedItem',
            "subjectId": oid
        }

        if linkUrl:
            data['body']['messageSegments'].append({
                "type": 'Link',
                "url": linkUrl})

        response = self.sendRequestInSession('POST', 'chatter/feed-elements', data)

        return response

    def pushCommentThread(self, id, text):
        data = {
            "body": {
                "messageSegments": [{
                    "type": 'Text',
                    "text": text
                }]
            }
        }

        return self.sendRequestInSession('POST', f'chatter/feed-elements/{id}/capabilities/comments/items', data)


''' HELPER FUNCTIONS '''


def getUserNames(client):
    res = client.queryObjects(['Id', 'Name'], 'User', None)
    users = {}
    for item in res.get('records'):
        users[item.get('Id')] = item.get('Name')

    return users


def searchToEntry(client, searchRecords):
    if len(searchRecords) == 0:
        raise Exception('No records matched the search.')

    case_ids = []
    contact_ids = []
    lead_ids = []
    task_ids = []
    user_ids = []
    general = []
    case_comment = []
    get_org = []

    for record in searchRecords:
        record_type = record.get('attributes', {}).get('type')
        if record_type == 'CaseComment':
            case_comment.append(record.get('Id'))
            break
        elif record_type == 'getOrgName':  # noqa: RET508
            get_org.append(record.get('Id'))
            break
        elif record_type == 'Case':
            case_ids.append(record.get('Id'))
            break
        elif record_type == 'Contact':
            contact_ids.append(record.get('id'))
            break
        elif record_type == 'Lead':
            lead_ids.append(record.get('Id'))
            break
        elif record_type == 'Task':
            task_ids.append(record.get('Id'))
            break
        elif record_type == 'User':
            user_ids.append(record.get('Id'))
            break
        else:
            # in case we don't know how to parse the object
            general.append(record)
            break

    condition = None
    properties = None
    entries = []
    # var userMapping = getUserNames();

    if len(get_org) > 0:
        condition = "ID IN ('" + "','".join(get_org) + "')"
        properties = ['ID', 'Name']
        # cases = client.queryObjects(properties, "Account", condition).get('records')
        # entries.append(client.orgToEntry(cases, 'Account:', userMapping))

    if len(case_ids) > 0:
        condition = "ID IN ('" + "','".join(case_ids) + "')"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate',
                      'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason',
                      'IsEscalated', 'SuppliedPhone', 'SuppliedCompany', 'SuppliedEmail', 'ContactEmail',
                      'ContactId', 'AccountId']
        cases = client.queryObjects(properties, "Case", condition).get('records')
        entries.append(objectToEntry(client, cases))

    if len(case_comment) > 0:
        condition = "ID IN ('" + "','".join(case_comment) + "')"
        properties = ['ID', 'CommentBody', 'CreatedDate', 'CreatedById',
                      'IsPublished', 'SystemModstamp', 'LastModifiedById', 'LastModifiedDate']
        cases_comment = client.queryObjects(properties, "CaseComment", condition).get('records')
        entries.append(objectToEntry(client, cases_comment))

    if len(contact_ids) > 0:
        condition = "ID IN ('" + "','".join(contact_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'AccountId', 'Phone', 'MobilePhone', 'Email', 'OwnerId']
        contacts = client.queryObjects(properties, "Contact", condition).get('records')
        entries.append(objectToEntry(client, contacts))

    if len(lead_ids) > 0:
        condition = "ID IN ('" + "','".join(lead_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'Company', 'Phone', 'MobilePhone', 'Email', 'Status', 'OwnerId']
        leads = client.queryObjects(properties, "Lead", condition).get('records')
        entries.append(objectToEntry(client, leads))

    if len(task_ids) > 0:
        condition = "ID IN ('" + "','".join(task_ids) + "')"
        properties = ['ID', 'Subject', 'WhoId', 'ActivityDate']
        tasks = client.queryObjects(properties, "Task", condition).get('records')
        entries.append(objectToEntry(client, tasks))

    if len(user_ids) > 0:
        condition = "ID IN ('" + "','".join(user_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'Phone', 'Email']
        users = client.queryObjects(properties, "User", condition).get('records')
        entries.append(objectToEntry(client, users))

    if len(general) > 0:
        entries.append({'unparsed': general})

    return entries


def queryToEntry(client, args):

    query = client.queryRaw(args.get('query'))

    results = CommandResults(
        outputs_prefix='SalesForce.QueryResults',
        outputs_key_field='',
        readable_output=tableToMarkdown('Query Results', query.get("records")),
        outputs=query.get("records"))

    return results


def commentToEntry(raw_info, title, userMapping):
    # fix owner field
    if userMapping:
        for i in range(raw_info):
            # use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].get(
                'OwnerId')] if userMapping[raw_info[i].get('OwnerId')] else raw_info[i].get('OwnerId')

    results = CommandResults(
        outputs_prefix='SalesForceV2.CaseComment',
        outputs_key_field='ID',
        readable_output=tableToMarkdown(title, raw_info),
        outputs=raw_info)

    return results


def objectToEntry(client, raw_info):
    title = ""
    if isinstance(raw_info, dict):
        obj_id = raw_info.get('Id')
        obj_type = client.identifyObjectType(obj_id)
        title = f"{obj_type} #{obj_id}:"
    elif isinstance(raw_info, list):
        obj_type = client.identifyObjectType(raw_info[0].get("Id"))
        title = f"{obj_type}"
    else:
        return_error('Cannot Identify Object Type')

    if obj_type == 'CaseComment':

        headers = ['ID', 'ParentId', 'IsPublished', 'CommentBody', 'CreatedById', 'CreatedDate',
                   'SystemModstamp', 'LastModifiedDate', 'LastModifiedById', 'IsDeleted']
        outputs_prefix = 'SalesForceV2.CaseComment'
        outputs_key_field = 'ID'

    elif obj_type == 'Case':

        headers = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerId', 'Priority',
                   'Origin', 'Status', 'Reason', 'IsEscalated', 'SuppliedPhone', 'SuppliedCompany', 'SuppliedEmail',
                   'ContactEmail', 'ContactId', 'AccountId']
        outputs_prefix = 'SalesForceV2.Case'
        outputs_key_field = 'ID'

    elif obj_type == 'Contact':

        headers = ['ID', 'Name', 'Account', 'Title', 'Phone', 'Mobile', 'Email', 'Owner']
        outputs_prefix = 'SalesForceV2.Contact'
        outputs_key_field = 'ID'

    elif obj_type == 'Lead':

        headers = ['ID', 'Name', 'Title', 'Company', 'Phone', 'MobilePhone', 'Email', 'OwnerId', 'Status']
        outputs_prefix = 'SalesForceV2.Lead'
        outputs_key_field = 'ID'

    elif obj_type == 'Task':

        headers = ['ID', 'Subject', 'WhoId', 'RelatedTo', 'ActivityDate']
        outputs_prefix = 'SalesForceV2.Task'
        outputs_key_field = 'ID'

    elif obj_type == 'User':

        headers = ['ID', 'Name', 'Alias', 'CommunityNickname', 'Title', 'Phone', 'Email', 'FirstName', 'Username']
        outputs_prefix = 'SalesForceV2.GetUsers'
        outputs_key_field = 'ID'

    else:

        headers = []
        outputs_prefix = 'SalesForceV2.Result'
        outputs_key_field = ''

    # backward compatibility --> capitalize ID
    if isinstance(raw_info, dict):
        raw_info['ID'] = raw_info.pop('Id')
    elif isinstance(raw_info, list):
        for index, _item in enumerate(raw_info):
            raw_info[index]['ID'] = raw_info[index]['Id']
            del raw_info[index]['Id']

    results = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        readable_output=tableToMarkdown(title, raw_info, headers=headers),
        outputs=raw_info)

    return results


def get_object_command(client: Client, args: dict[str, Any]) -> CommandResults:

    if path := args.get('path'):
        result = client.getObject(path)
    elif oid := args.get('oid'):
        result = client.getObject(oid)
    else:
        result = ""
        demisto.debug(f"no path or oid. {result=}")

    return objectToEntry(client, result)


def update_object_command(client: Client, args: dict[str, Any]) -> CommandResults:

    client.updateObject(args.get('path'), args.get('json'))
    # return updated object
    return get_object_command(client, args)


def create_object_command(client: Client) -> CommandResults:

    result = client.createObject(demisto.args().get('path'), demisto.args().get('json'))

    return result


def get_case_command(client: Client, args: dict[str, Any]) -> CommandResults:

    if args.get('caseNumber'):
        condition = f"CaseNumber='{args.get('caseNumber')}"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate',
                      'OwnerID', 'Priority', 'Origin', 'Status', 'Reason', 'IsEscalated', 'SuppliedPhone',
                      'SuppliedCompany', 'SuppliedEmail', 'ContactEmail', 'ContactId', 'AccountId']
        cases = client.queryObjects(properties, 'Case', condition).get('records')
        return objectToEntry(client, cases)

    elif args.get('oid'):
        cases = client.getObject(f"Case/{args.get('oid')}")
        return objectToEntry(client, cases)

    else:
        raise Exception('You must specify object ID or a Case Number')


def get_user_command(client: Client, args: dict[str, Any]) -> CommandResults:

    response = client.getUser(args.get('oid'), args.get('caseNumber'))
    return objectToEntry(client, response)


def get_case_comment_command(client: Client, args: dict[str, Any]) -> CommandResults:

    result = client.getCaseComment(args.get('oid'), args.get('caseNumber'))

    return objectToEntry(client, result.get('records', []))


def get_org_name_command(client: Client, args: dict[str, Any]) -> CommandResults:

    if case_number := args.get('caseNumber'):
        condition = f"CaseNumber='{case_number}'"
        properties = ['ID', 'CaseNumber', 'AccountId']
        cases = client.queryObjects(properties, 'Case', condition).get("records")
        condition_a = f"Id='{cases[0].get('AccountId')}'"
        properties_a = ['Id', 'Name']
        users_a = client.queryObjects(properties_a, "Account", condition_a).get("records")
    else:
        raise Exception('You must specify a Case Number')
    return objectToEntry(client, users_a)


def post_case_comment_command(client: Client, args: dict[str, Any]) -> CommandResults:

    results = client.postCaseComment(args.get('public'), args.get(
        'oid'), args.get('caseNumber'), args.get('text'))
    if results.get('success'):
        case_comment = client.getObject(f"{results.get('id')}")
    else:
        raise Exception(f"Unable to post case comment. Error Encountered was:{json.dumps(results.get('errors'))}")

    return objectToEntry(client, case_comment)


def create_case_command(client: Client, args: dict[str, Any]) -> CommandResults:

    data = {
        "Subject": args.get('subject'),
        "Description": args.get('description'),
        "Status": args.get('status'),
        "Origin": args.get('origin'),
        "Priority": args.get('priority'),
        "Type": args.get('caseType')
    }

    results = client.createObject('Case', data)
    if results.get('success'):
        case = client.getObject(f"{results.get('id')}")
    else:
        raise Exception(f"Unable to create case. Error Encountered was:{json.dumps(results.get('errors'))}")

    return objectToEntry(client, case)


def update_case_command(client: Client, args: dict[str, Any]) -> CommandResults:

    case_number = args.get('caseNumber')
    oid = args.get('oid')
    if oid and case_number:
        raise Exception('You must specify an object ID or a Case Number (not both)')

    if case_number:
        condition = f"CaseNumber='{case_number}'"
        cases = client.queryObjects(['Id'], 'Case', condition).get('records')
        if len(cases) > 0:
            oid = cases[0].get('Id')
        else:
            raise Exception('Unable to update case -> Invalid Case Number provided')

    data = {}

    if subject := args.get('subject'):
        data['Subject'] = subject

    if description := args.get('description'):
        data['Description'] = description

    if status := args.get('status'):
        data['Status'] = status

    if origin := args.get('origin'):
        data['Origin'] = origin

    if priority := args.get('priority'):
        data['Priority'] = priority

    if case_type := args.get('caseType'):
        data['Type'] = case_type

    client.updateObject(f'Case/{oid}', data)

    return get_case_command(client, {'oid': oid})


def get_cases_command(client: Client) -> CommandResults:

    properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate',
                  'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason']
    cases = client.queryObjects(properties, 'Case', '').get('records')
    return objectToEntry(client, cases)


def close_case_command(client: Client, args: dict[str, Any]) -> CommandResults:

    args['status'] = 'Closed'
    return update_case_command(client, args)


def delete_case_command(client: Client, args: dict[str, Any]) -> CommandResults:

    case_number = args.get('caseNumber')
    if args.get('oid') and case_number:
        raise Exception('You must specify object ID or a Case Number')

    if case_number:
        condition = f"CaseNumber='{case_number}'"
        cases = client.queryObjects(['Id'], 'Case', condition).get('records')
        if len(cases) > 0:
            oid = cases[0].get('Id')
        else:
            raise Exception('Unable to update case -> Invalid Case Number provided')
    else:
        oid = args.get('oid')

    return client.deleteObject(f'Case/{oid}')


def push_comment_command(client: Client, args: dict[str, Any]) -> CommandResults:

    return client.pushComment(args.get('oid'), args.get('text'), args.get('linkUrl'))


def push_comment_thread_command(client: Client, args: dict[str, Any]) -> CommandResults:

    results = client.pushCommentThread(args.get('id'), args.get('text'))

    return results


def search_command(client: Client, args: dict[str, Any]) -> CommandResults:

    search_records = client.sendRequestInSession(
        'GET', f"search/?q=FIND+%7B{args.get('pattern')}%7D", '').get('searchRecords')
    return searchToEntry(client, search_records)


def list_case_files_command(client: Client, args: dict[str, Any]) -> CommandResults:

    case_oid = args.get('caseoId')
    case_number = args.get('caseNumber')
    file_info = client.getCaseFiles(case_oid, case_number).get('fileInfo', [])

    results = CommandResults(
        outputs_prefix='SalesforceV2.Files',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f"Case Files {case_oid or case_number}", file_info),
        outputs=file_info,
        ignore_auto_extract=True)

    return results


def get_case_file_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:

    return client.getCaseFileById(args.get('caseNumber'), args.get('caseFileId'))


def describe_sobject_field_command(client: Client, args: dict[str, Any]):

    response = client.sendRequestInSession('GET', 'sobjects/Case/describe/')

    if field_to_search := args.get('field'):
        fields = response.get('fields')
        for field in fields:
            if field.get('name') == field_to_search:
                return field

        raise Exception(f'The field: {field_to_search} cannot be found in the sobject.'
                        f' Perhaps wrong field name or object name.')
    return None


def get_mapping_fields_command(client):

    case_incident_type_scheme = SchemeTypeMapping(type_name='Salesforce Case')

    fields = client.sendRequestInSession('GET', 'sobjects/Case/describe/').get('fields')

    for field in fields:
        case_incident_type_scheme.add_field(name=field.get('name'), description='N/A')

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(case_incident_type_scheme)

    return mapping_response


def update_remote_system_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client:  XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system
            args['entries']: the entries to send to the remote system
            args['incident_changed']: boolean telling us if the local incident indeed changed or not
            args['remote_incident_id']: the remote incident id
        params:
            entry_tags: the tags to pass to the entries (to separate between comments and work_notes)

    Returns: The remote incident id - ticket_id

    """
    parsed_args = UpdateRemoteSystemArgs(args)
    object_id = parsed_args.remote_incident_id
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    if parsed_args.incident_changed:
        demisto.debug(f'Incident changed: {parsed_args.incident_changed}')

        # close case in Salesforce when incident is closed in XSOAR
        if parsed_args.inc_status == IncidentStatus.DONE and params.get('close_case'):
            parsed_args.data['status'] = 'Closed'

        demisto.debug(f'Sending update request to server {parsed_args.data}')
        updated_fields = parsed_args.data
        if 'Id' in updated_fields:
            del updated_fields['Id']
        result = client.updateObject(f'Case/{object_id}', parsed_args.data)

        demisto.info(f'Case Update result {result}')

    entries = parsed_args.entries
    if entries:
        demisto.debug(f'New entries {entries}')

        for entry in entries:
            demisto.debug(f'Sending entry {entry.get("id")}, type: {entry.get("type")}')
            # Mirroring files as entries
            if entry.get('type', 0) != 3:
                # Mirroring comment and work notes as entries
                tags = entry.get('tags', [])
                user = entry.get('user', 'dbot')
                text = f"({user}): {str(entry.get('contents', ''))}\n\n Mirrored from Cortex XSOAR"
                public = 'true' if 'public' in tags else 'false'
                client.postCaseComment(public, object_id, None, text)

    return object_id


def get_data(client, remote_incident_id, last_update, params):
    case = {}
    if len(params.get('fetchFields', [])) > 1:
        properties = params.get('fetchFields', []).split(",")
    else:
        properties = []
    properties += ['Id', 'CaseNumber', 'Subject', 'Description', 'CreatedDate',
                   'ClosedDate', 'OwnerId', 'Priority', 'Origin', 'Status',
                   'Reason', 'LastModifiedDate', 'MilestoneStatus', 'isEscalated']
    cases = client.queryObjects(
        list(set(properties)), 'Case', f"LastModifiedDate >= {last_update} AND Id='{remote_incident_id}'").get('records')
    comments = []
    if len(cases) == 1:
        case = cases[0]
        case['OwnerDetails'] = client.getObject(case.get('OwnerId'))
        del case['attributes']  # remove attributes
        condition = f"LastModifiedDate >= {last_update} AND ParentId='{case.get('Id')}' ORDER BY LastModifiedDate DESC"
        properties = ['ID', 'CommentBody', 'CreatedDate', 'CreatedById',
                      'IsPublished', 'SystemModstamp', 'LastModifiedById', 'LastModifiedDate']
        comments = client.queryObjects(properties, "CaseComment", condition).get('records')
        if isinstance(comments, dict):
            comments = [comments]

        for index, comment in enumerate(comments):
            comments[index]['Owner'] = client.getObject(comment.get('CreatedById'))

    else:  # we have more that 1 case or none
        raise Exception('Invalid remote incident ID provided.')

    return case, comments


def get_modified_remote_data_command(client, args, params):
    modified_records_ids = []
    remote_args = GetModifiedRemoteDataArgs(args)
    last_upadte_parsed = parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
    if last_upadte_parsed:
        last_update = last_upadte_parsed.isoformat().split(".")[0] + "Z"
        demisto.debug(f'SalesforcePy : * START * Performing get-modified-remote-data command. Last update is:'
                      f' {last_update}')

    cases = client.queryObjects(['Id'], 'Case',
                                f"{params.get('mirroring_condition')}".replace("AND ", "")).get('records')

    for item in cases:
        modified_records_ids.append(item['Id'])

    demisto.debug(
        f"SalesforcePy : * END * Performing get-modified-remote-data command."
        f" Results: {','.join(modified_records_ids)}")

    return GetModifiedRemoteDataResponse(modified_records_ids)


def get_remote_data_command(client, args, params):
    parsed_args = GetRemoteDataArgs(args)
    new_incident_data = {}
    entries = []
    lastcomment_date = []
    last_update_sfdc_parsed = parse(parsed_args.last_update, settings={'TIMEZONE': 'UTC'})
    last_update_sfdc = last_update_sfdc_parsed.isoformat().split(".")[0] + "Z" if last_update_sfdc_parsed else ''
    try:
        new_incident_data, case_comments = get_data(client, parsed_args.remote_incident_id, last_update_sfdc, params)
        new_incident_data['id'] = parsed_args.remote_incident_id
        new_incident_data['in_mirror_error'] = ''

        if len(case_comments) > 0:
            for cc in case_comments:
                owner = cc.get('Owner', '')
                lastcomment_date.append(cc.get('LastModifiedDate', '').split(".")[0] + "Z")
                entries.append({
                    'Type': EntryType.NOTE,
                    'Contents': f"# Case Comment From Salesforce on {cc.get('LastModifiedDate', '')}\n*Created By*:"
                                f" {owner.get('FirstName', '')} {owner.get('LastName', '')}"
                                f" ({owner.get('Username', '')})\n\n{cc.get('CommentBody', '')}",
                    'ContentsFormat': EntryFormat.MARKDOWN,
                    'Tags': ['Salesforce Case Comment'],  # the list of tags to add to the entry
                    'Note': True,
                    'IgnoreAutoExtract': True
                })
        # setup last comment date to track tickets
        if len(lastcomment_date) > 0:
            new_incident_data['lastcomment_date'] = max(lastcomment_date)
        # end
        # close xsoar incident when SFDC case is closed
        if new_incident_data.get('Status') == 'Closed' and demisto.params().get('close_incident'):
            demisto.debug(f'case is closed: {new_incident_data}')
            entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeReason': f'Case closed in Salesforce on {new_incident_data.get("LastModifiedDate")}'
                },
                'ContentsFormat': EntryFormat.JSON
            })

        return GetRemoteDataResponse(mirrored_object=new_incident_data, entries=entries)

    except Exception as e:

        if new_incident_data:
            new_incident_data['in_mirror_error'] = str(e)
        else:
            new_incident_data = {
                'id': parsed_args.remote_incident_id,
                'in_mirror_error': str(e)
            }
        return GetRemoteDataResponse(
            mirrored_object=new_incident_data,
            entries=[]
        )


def fetchIncident(client, params):
    fetchType = params.get("fetchType")

    lastRun = demisto.getLastRun()
    if not lastRun.get("last_case_time"):
        lastRun = {}
        first_fetch_time = params.get('firstFetchTime', '3 days').strip()
        first_fetch_time_parsed = parse(f'{first_fetch_time} UTC')
        if first_fetch_time_parsed:
            lastRun['last_case_time'] = first_fetch_time_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
        demisto.setLastRun(lastRun)

    incidents = []

    if len(params.get('fetchFields', [])) > 1:
        properties = params.get('fetchFields', []).split(",")
    else:
        properties = []

    if fetchType == 'cases':
        # query cases from last time
        condition = f"CreatedDate>{lastRun.get('last_case_time')} {params.get('condition','')} ORDER BY CreatedDate DESC"
        properties += ['Id', 'CaseNumber', 'Subject', 'Description', 'CreatedDate',
                       'ClosedDate', 'OwnerId', 'Priority', 'Origin', 'Status',
                       'Reason', 'LastModifiedDate', 'MilestoneStatus', 'isEscalated']
        cases = client.queryObjects(list(set(properties)), "Case", condition).get("records")

        if len(cases) > 0:
            last_case_time_parsed = parse(cases[0].get("CreatedDate"))
            if last_case_time_parsed:
                lastRun['last_case_time'] = last_case_time_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
            demisto.setLastRun(lastRun)
            for index, item in enumerate(cases):
                del item['attributes']  # remove attributes
                # retrieve owner info
                cases[index]['OwnerDetails'] = client.getObject(item.get('OwnerId'))
                last_modified_date_parsed = parse(item.get('LastModifiedDate'))
                if last_modified_date_parsed:
                    cases[index]['LastModifiedDate'] = last_modified_date_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
                created_dated_parsed = parse(item.get('CreatedDate'))
                if created_dated_parsed:
                    cases[index]['CreatedDate'] = created_dated_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
                incidents.append({
                    "name": f"{item.get('Id')} {item.get('Subject')}",
                    "details": item.get('Description'),
                    "owner": cases[index]['OwnerDetails'].get("Email"),
                    "occurred": created_dated_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
                    if created_dated_parsed else '',
                    "rawJSON": json.dumps(item),
                    'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction')),
                    'mirror_tags': [params.get('comment_tag'), params.get('file_tag')],
                    'mirror_instance': demisto.integrationInstance()
                })

    else:
        # Fetch comment replies

        properties += ['Id', 'CommentBody', 'CreatedDate']
        condition = f"CreatedDate> {lastRun.get('last_case_time')} {params.get('condition','')}" \
                    f" ORDER BY CreatedDate DESC LIMIT 10"
        replies = client.queryObjects(list(set(properties)), "FeedComment", condition).get("records")

        if len(replies) > 0:
            last_case_time_parsed = parse(replies[0].get("CreatedDate"))
            if last_case_time_parsed:
                lastRun['last_case_time'] = last_case_time_parsed.isoformat().split("+")[0].split(".")[0] + "Z"
            demisto.setLastRun(lastRun)

            for reply in replies:
                # Get reply details
                replyDetails = client.sendRequestInSession('GET', f'chatter/comments/{reply.get("Id")}')
                feedElement = replyDetails.get("feedElement")
                parentID = feedElement.get("id")

                # get parent details
                parentDetails = client.getObject(f'CaseFeed/{parentID}')
                parentText = parentDetails

                # if (parentText.indexOf('DemistoID') !== -1) {
                messageSegments = replyDetails.get("body").get("messageSegments")

                for ms in messageSegments:
                    if ms.get('type') == 'Text':
                        created_date_parsed = parse(parentText.get('CreatedDate'))
                        # Found the relevant comment (there's only one), so we return it
                        incidents.append({
                            "name": f"{parentText['attributes']['type']} {parentText['Id']}",
                            "details": ms.get("text"),
                            "occurred": created_date_parsed.isoformat().split("+")[0].split(".")[0] + "Z" if
                            created_date_parsed else '',
                            "rawJSON": json.dumps(parentText)
                        })

    return incidents


def test_module(client):
    token = client.getNewToken()
    if token.get("access_token"):
        return 'ok'
    return None


''' MAIN FUNCTION '''


def main() -> None:
    """
        main function, parses params and runs command functions
    """

    # get the service API url
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('InstanceURL')
    verify_certificate = params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={},
            proxy=proxy)

        # obtain the token
        client.getNewToken()
        # set the integration context if not already
        if 'sobjects' not in demisto.getIntegrationContext():
            client.getObjectTypes()

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            incidents = fetchIncident(client, params)
            demisto.incidents(incidents)
        elif command == 'salesforce-search':
            return_results(search_command(client, args))
        elif command == 'salesforce-query':
            return_results(queryToEntry(client, args))
        elif command == 'salesforce-get-object':
            return_results(get_object_command(client, args))
        elif command == 'salesforce-update-object':
            return_results(update_object_command(client, args))
        elif command == 'salesforce-create-object':
            return_results(create_object_command(client))
        elif command == 'salesforce-get-case':
            return_results(get_case_command(client, args))
        elif command == 'salesforce-get-user':
            return_results(get_user_command(client, args))
        elif command == 'salesforce-get-casecomment':
            return_results(get_case_comment_command(client, args))
        elif command == 'salesforce-get-org':
            return_results(get_org_name_command(client, args))
        elif command == 'salesforce-post-casecomment':
            return_results(post_case_comment_command(client, args))
        elif command == 'salesforce-create-case':
            return_results(create_case_command(client, args))
        elif command == 'salesforce-update-case':
            return_results(update_case_command(client, args))
        elif command == 'salesforce-get-cases':
            return_results(get_cases_command(client))
        elif command == 'salesforce-close-case':
            return_results(close_case_command(client, args))
        elif command == 'salesforce-delete-case':
            return_results(delete_case_command(client, args))
        elif command == 'salesforce-push-comment':
            return_results(push_comment_command(client, args))
        elif command == 'salesforce-push-comment-threads':
            return_results(push_comment_thread_command(client, args))
        elif command == 'salesforce-describe-sobject-field':
            return_results(describe_sobject_field_command(client, args))
        elif command == 'salesforce-list-case-files':
            return_results(list_case_files_command(client, args))
        elif command == 'salesforce-get-case-file-by-id':
            return_results(get_case_file_by_id_command(client, args))
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, args, params))
        elif command == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args, params))
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args, params))
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
