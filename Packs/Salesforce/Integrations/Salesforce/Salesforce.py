import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
import json
from urllib.parse import urlencode
from datetime import datetime, timedelta

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings()

URI_PREFIX = '/services/data/v63.0/'
SESSION_DATA = ''


def get_nested(obj, path):
    """Helper to get nested field using dot notation like 'body.text'"""
    keys = path.split('.')
    result = obj
    for key in keys:
        if result is None:
            return None
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return None
    return result


def dot_to_space(header):
    """Header transform function that replaces dots with spaces"""
    return header.replace('.', ' ')


def create_entry(raw_info, options):
    """
    Replicates the JS createEntry function.
    Maps raw_info using the data mapping and creates an entry dict.
    """
    context_path = options.get('contextPath', '')
    title = options.get('title', '')
    data_mapping = options.get('data', [])

    # Handle single object case - wrap in list
    if not isinstance(raw_info, list):
        raw_info = [raw_info]

    mapped_list = []
    hr_list = []
    for item in raw_info:
        mapped = {}
        hr_item = {}
        for field in data_mapping:
            to_field = field['to']
            from_field = field['from']
            # Handle nested field access (e.g., 'body.text')
            if '.' in from_field:
                value = get_nested(item, from_field)
            else:
                value = item.get(from_field) if isinstance(item, dict) else None
            mapped[to_field] = value
            if field.get('humanReadable') is not False:
                hr_item[to_field] = value
        mapped_list.append(mapped)
        hr_list.append(hr_item)

    entry = {
        'Type': EntryType.NOTE,
        'Contents': raw_info,
        'ContentsFormat': EntryFormat.JSON,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown(title, hr_list),
        'EntryContext': {
            context_path: mapped_list if len(mapped_list) > 1 else mapped_list[0]
        }
    }
    return entry


def get_new_token():
    params = demisto.params()
    credentials_client_secret = params.get('credentials_client_secret')
    if credentials_client_secret is not None:
        client_id = credentials_client_secret.get('identifier')
        client_secret = credentials_client_secret.get('password')
    else:
        client_id = params.get('clientID')
        client_secret = params.get('clientSecret')

    if client_id is None or client_secret is None:
        return 'Consumer Key and Consumer Secret must be provided.'

    request_data = {
        'grant_type': 'password',
        'client_id': client_id,
        'client_secret': client_secret,
        'username': params['credentials']['identifier'],
        'password': params['credentials']['password']
    }

    body = urlencode(request_data)
    verify = not params.get('insecure', False)
    proxies = handle_proxy() if params.get('useproxy') else {}

    response = requests.request(
        method='POST',
        url=params['InstanceURL'] + '/services/oauth2/token',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data=body,
        verify=verify,
        proxies=proxies
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise Exception('Failed to get new token, request status code: ' + str(response.status_code) + ' and Body: ' + response.text + '.')

    return response.json()


def send_request(method, url, body, token=None):
    params = demisto.params()
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if method == 'POST' or method == 'PATCH':
        headers['Content-Type'] = 'application/json'

    verify = not params.get('insecure', False)
    proxies = handle_proxy() if params.get('useproxy') else {}

    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        data=body,
        verify=verify,
        proxies=proxies
    )

    return response


def send_request_in_session(method, uri, body=''):
    global SESSION_DATA
    if not SESSION_DATA or not SESSION_DATA.get('access_token'):
        raise Exception("Faield to get access token for Salesforce integration.")

    response = send_request(method, SESSION_DATA['instance_url'] + URI_PREFIX + uri, body, SESSION_DATA['access_token'])

    if response.status_code == 401:
        SESSION_DATA = get_new_token()
        response = send_request(method, SESSION_DATA['instance_url'] + URI_PREFIX + uri, body, SESSION_DATA['access_token'])

    if response.status_code < 200 or response.status_code >= 300:
        raise Exception('Failed to run command uri: ' + uri + ', request status code: ' + str(response.status_code) + ' and Body: ' + response.text + '.')

    return response


def get_user_names():
    res = query_objects(['Id', 'Name'], 'User')
    users = {}
    for record in res.get('records', []):
        users[record['Id']] = record['Name']
    return users


def comment_to_entry(raw_info, title, user_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.CaseComment(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'ParentId', 'from': 'ParentId'},
            {'to': 'IsPublished', 'from': 'IsPublished'},
            {'to': 'CommentBody', 'from': 'CommentBody'},
            {'to': 'CreatedById', 'from': 'CreatedById'},
            {'to': 'CreatedDate', 'from': 'CreatedDate'},
            {'to': 'SystemModstamp', 'from': 'SystemModstamp'},
            {'to': 'LastModifiedDate', 'from': 'LastModifiedDate'},
            {'to': 'LastModifiedById', 'from': 'LastModifiedById'},
            {'to': 'IsDeleted', 'from': 'IsDeleted'}
        ]
    })


def user_to_entry(raw_info, title, user_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.User(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Alias', 'from': 'Alias'},
            {'to': 'CommunityNickname', 'from': 'CommunityNickname'},
            {'to': 'CreatedById', 'from': 'CreatedById'},
            {'to': 'Email', 'from': 'Email'},
            {'to': 'LastLoginDate', 'from': 'LastLoginDate'},
            {'to': 'LastModifiedDate', 'from': 'LastModifiedDate'},
            {'to': 'LastName', 'from': 'LastName'},
            {'to': 'Name', 'from': 'Name'},
            {'to': 'Username', 'from': 'Username'},
            {'to': 'UserRoleId', 'from': 'UserRoleId'}
        ]
    })


def org_to_entry(raw_info, title, user_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.GetOrg(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Name', 'from': 'Name'}
        ]
    })


def cases_to_entry(raw_info, title, user_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.Case(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'CaseNumber', 'from': 'CaseNumber'},
            {'to': 'Subject', 'from': 'Subject'},
            {'to': 'Description', 'from': 'Description'},
            {'to': 'CreatedDate', 'from': 'CreatedDate'},
            {'to': 'ClosedDate', 'from': 'ClosedDate'},
            {'to': 'Owner', 'from': 'OwnerId'},
            {'to': 'Priority', 'from': 'Priority'},
            {'to': 'Origin', 'from': 'Origin'},
            {'to': 'Status', 'from': 'Status'},
            {'to': 'Reason', 'from': 'Reason'},
            {'to': 'IsEscalated', 'from': 'IsEscalated'},
            {'to': 'SuppliedPhone', 'from': 'SuppliedPhone'},
            {'to': 'SuppliedCompany', 'from': 'SuppliedCompany'},
            {'to': 'SuppliedEmail', 'from': 'SuppliedEmail'},
            {'to': 'ContactEmail', 'from': 'ContactEmail'},
            {'to': 'ContactId', 'from': 'ContactId'},
            {'to': 'AccountId', 'from': 'AccountId'},
            {'to': 'Id', 'from': 'Id'}
        ]
    })


def contacts_to_entry(raw_info, title, user_mapping, account_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    if account_mapping:
        for i in range(len(raw_info)):
            # use AccountId if no account was found
            raw_info[i]['AccountId'] = account_mapping.get(raw_info[i].get('AccountId')) or raw_info[i].get('AccountId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.Contact(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Name', 'from': 'Name'},
            {'to': 'Account', 'from': 'AccountId'},
            {'to': 'Title', 'from': 'Title'},
            {'to': 'Phone', 'from': 'Phone'},
            {'to': 'Mobile', 'from': 'MobilePhone'},
            {'to': 'Email', 'from': 'Email'},
            {'to': 'Owner', 'from': 'OwnerId'},
        ]
    })


def leads_to_entry(raw_info, title, user_mapping):
    # fix owner field
    if user_mapping:
        for i in range(len(raw_info)):
            # use OwnerId if no user was found
            raw_info[i]['OwnerId'] = user_mapping.get(raw_info[i].get('OwnerId')) or raw_info[i].get('OwnerId')

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.Lead(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Name', 'from': 'Name'},
            {'to': 'Title', 'from': 'Title'},
            {'to': 'Company', 'from': 'Company'},
            {'to': 'Phone', 'from': 'Phone'},
            {'to': 'Mobile', 'from': 'MobilePhone'},
            {'to': 'Email', 'from': 'Email'},
            {'to': 'Owner', 'from': 'OwnerId'},
            {'to': 'Status', 'from': 'Status'}
        ]
    })


def tasks_to_entry(raw_info, title, lead_dict):
    # fix owner field
    # BUG PRESERVED: Original JS uses 'leadMapping' (undefined global) instead of 'lead_dict' parameter
    if leadMapping:  # noqa: F821
        for i in range(len(raw_info)):
            # use WhoId if no lead was found
            raw_info[i]['WhoId'] = leadMapping.get(raw_info[i].get('WhoId')) or raw_info[i].get('WhoId')  # noqa: F821

    return create_entry(raw_info, {
        'contextPath': 'SalesForce.Task(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Subject', 'from': 'Subject'},
            {'to': 'Lead', 'from': 'WhoId'},
            {'to': 'RelatedTo', 'from': 'RelatedTo'},
            {'to': 'DueDate', 'from': 'ActivityDate'}
        ]
    })


def users_to_entry(raw_info, title):
    return create_entry(raw_info, {
        'contextPath': 'SalesForce.GetUsers(val.ID && val.ID == obj.ID)',
        'title': title,
        'data': [
            {'to': 'ID', 'from': 'Id', 'humanReadable': False},
            {'to': 'Name', 'from': 'Name'},
            {'to': 'Alias', 'from': 'Alias'},
            {'to': 'CommunityNickname', 'from': 'CommunityNickname'},
            {'to': 'Title', 'from': 'Title'},
            {'to': 'Phone', 'from': 'Phone'},
            {'to': 'Email', 'from': 'Email'},
            {'to': 'FirstName', 'from': 'FirstName'},
            {'to': 'Username', 'from': 'Username'}
        ]
    })


def object_to_entry(obj_type, obj):
    user_mapping = get_user_names()
    if obj_type == 'CaseComment':
        return comment_to_entry([obj], 'CaseComment:', user_mapping)
    elif obj_type == 'getOrgName':
        return org_to_entry([obj], 'getOrgName:', user_mapping)
    elif obj_type == 'userToEntry':
        return user_to_entry([obj], 'getUser', user_mapping)
    elif obj_type == 'Case':
        return cases_to_entry([obj], 'Case:', user_mapping)
    elif obj_type == 'Contact':
        account_mapping = None  # TODO: implement
        return contacts_to_entry([obj], 'Contact:', user_mapping, account_mapping)
    elif obj_type == 'Lead':
        return leads_to_entry([obj], 'Lead:', user_mapping)
    elif obj_type == 'Task':
        # BUG PRESERVED: Original JS uses undefined 'leadMapping' variable
        leadMapping = None  # noqa: F841
        return tasks_to_entry([obj], 'Lead:', leadMapping)  # noqa: F821
    elif obj_type == 'User':
        return users_to_entry([obj], 'User:')
    else:
        return obj


def query_to_entry(query):
    return {
        'Type': EntryType.NOTE,
        'Contents': query.get('records'),
        'ContentsFormat': EntryFormat.JSON,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Query Results', query.get('records'))
    }


def search_to_entry(search_records):
    if len(search_records) == 0:
        return {
            'Type': EntryType.NOTE,
            'Contents': 'No records matched the search.',
            'ReadableContentsFormat': EntryFormat.MARKDOWN
        }

    case_ids = []
    contact_ids = []
    lead_ids = []
    task_ids = []
    user_ids = []
    general = []
    case_comment = []
    get_org = []

    for record in search_records:
        record_type = record.get('attributes', {}).get('type')
        if record_type == 'CaseComment':
            case_comment.append(record['Id'])
        elif record_type == 'getOrgName':
            get_org.append(record['Id'])
        elif record_type == 'Case':
            case_ids.append(record['Id'])
        elif record_type == 'Contact':
            contact_ids.append(record['Id'])
        elif record_type == 'Lead':
            lead_ids.append(record['Id'])
        elif record_type == 'Task':
            task_ids.append(record['Id'])
        elif record_type == 'User':
            user_ids.append(record['Id'])
        else:
            # in case we don't know how to parse the object
            general.append(record)

    entries = []
    user_mapping = get_user_names()

    if len(get_org) > 0:
        condition = "ID IN ('" + "','".join(get_org) + "')"
        properties = ['ID', 'Name']
        cases = query_objects(properties, "Account", condition).get('records', [])
        entries.append(org_to_entry(cases, 'Account:', user_mapping))

    if len(case_ids) > 0:
        condition = "ID IN ('" + "','".join(case_ids) + "')"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason', 'IsEscalated', 'SuppliedPhone', 'SuppliedCompany', 'SuppliedEmail', 'ContactEmail', 'ContactId', 'AccountId']
        cases = query_objects(properties, "Case", condition).get('records', [])
        entries.append(cases_to_entry(cases, 'Cases:', user_mapping))

    if len(case_comment) > 0:
        condition = "ID IN ('" + "','".join(case_comment) + "')"
        properties = ['ID', 'CommentBody', 'CreatedDate', 'CreatedById', 'IsPublished', 'SystemModstamp', 'LastModifiedById', 'LastModifiedDate']
        cases_comment = query_objects(properties, "CaseComment", condition).get('records', [])
        entries.append(comment_to_entry(cases_comment, 'CaseComment:', user_mapping))

    if len(contact_ids) > 0:
        condition = "ID IN ('" + "','".join(contact_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'AccountId', 'Phone', 'MobilePhone', 'Email', 'OwnerId']
        contacts = query_objects(properties, "Contact", condition).get('records', [])
        entries.append(contacts_to_entry(contacts, 'Contacts:', user_mapping, None))

    if len(lead_ids) > 0:
        condition = "ID IN ('" + "','".join(lead_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'Company', 'Phone', 'MobilePhone', 'Email', 'Status', 'OwnerId']
        leads = query_objects(properties, "Lead", condition).get('records', [])
        entries.append(leads_to_entry(leads, 'Leads:', user_mapping))

    if len(task_ids) > 0:
        condition = "ID IN ('" + "','".join(task_ids) + "')"
        properties = ['ID', 'Subject', 'WhoId', 'ActivityDate']
        tasks = query_objects(properties, "Task", condition).get('records', [])
        entries.append(tasks_to_entry(tasks, 'Tasks:', None))

    if len(user_ids) > 0:
        condition = "ID IN ('" + "','".join(user_ids) + "')"
        properties = ['ID', 'Name', 'Title', 'Phone', 'Email']
        users = query_objects(properties, "User", condition).get('records', [])
        entries.append(users_to_entry(users, 'Users:'))

    if len(general) > 0:
        entries.append({'unparsed': general})

    return entries


def query_raw(query):
    url = 'query/?' + urlencode({'q': query})
    response = send_request_in_session('GET', url, '')
    return response.json()


def query_objects(fields, table, condition=None):
    query = 'SELECT ' + ','.join(fields) + ' FROM ' + table
    if condition is not None:
        query += ' WHERE ' + condition

    return query_raw(query)


def get_object(path):
    response = send_request_in_session('GET', 'sobjects/' + path, '')
    return object_to_entry(path.split('/')[0], response.json())


def create_object(path, json_obj):
    response = send_request_in_session('POST', 'sobjects/' + path, json_obj)
    response_data = response.json()

    if response_data.get('success') is not True:
        return {
            'Type': EntryType.NOTE,
            'Contents': response_data,
            'ContentsFormat': EntryFormat.JSON,
            'ReadableContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': tableToMarkdown('Request failed with errors', response_data.get('errors'), headerTransform=dot_to_space)
        }

    return get_object(path + '/' + response_data['id'])


def update_object(path, json_obj):
    response = send_request_in_session('PATCH', 'sobjects/' + path, json_obj)
    if response.status_code != 204:
        raise Exception('object ' + path + ' update failed with status code: ' + str(response.status_code))

    return get_object(path)


def delete_object(path):
    response = send_request_in_session('DELETE', 'sobjects/' + path)
    if response.status_code != 204:
        raise Exception('object ' + path + ' delete failed with status code: ' + str(response.status_code))

    # BUG PRESERVED: Missing space before "was" in original JS
    return 'object ' + path + 'was successfully deleted.'


def get_case(oid, case_number):
    if case_number is not None:
        condition = "CaseNumber='" + case_number + "'"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason', 'IsEscalated', 'SuppliedPhone', 'SuppliedCompany', 'SuppliedEmail', 'ContactEmail', 'ContactId', 'AccountId']
        cases = query_objects(properties, 'Case', condition).get('records', [])
        return cases_to_entry(cases, 'Case #' + case_number + ':', get_user_names())

    if oid is not None:
        return get_object('Case/' + oid)

    return {
        'Type': EntryType.ERROR,
        'Contents': 'You must specify object ID or a Case Number',
        'ReadableContentsFormat': EntryFormat.MARKDOWN
    }


# Add the capability to get all comment in specific case
def get_case_comment(oid, case_number):
    if case_number is not None:
        condition = "CaseNumber='" + case_number + "'"
        cases = query_objects(['Id', 'CaseNumber'], 'Case', condition).get('records', [])
        comments = send_request_in_session('GET', 'sobjects/Case/' + cases[0]['Id'] + '/CaseComments').json()
        return comment_to_entry(comments.get('records', []), 'CaseComment #' + cases[0]['CaseNumber'] + ':', get_user_names())

    if oid is not None:
        comments = send_request_in_session('GET', 'sobjects/Case/' + oid + '/CaseComments').json()
        return comment_to_entry(comments.get('records', []), 'CaseComment #' + oid + ':', get_user_names())

    return {
        'Type': EntryType.ERROR,
        'Contents': 'You must specify object ID or a Case Number',
        'ReadableContentsFormat': EntryFormat.MARKDOWN
    }


def get_user(oid, case_number):
    if case_number is not None:
        condition = "CaseNumber='" + case_number + "'"
        cases = query_objects(['Id', 'CaseNumber', 'OwnerId'], 'Case', condition).get('records', [])
        condition_a = "Id='" + cases[0]['OwnerId'] + "'"
        properties = ['Id', 'Name', 'Alias', 'CommunityNickname', 'Email', 'FirstName', 'Username']
        users = query_objects(properties, "User", condition_a).get('records', [])
        return users_to_entry(users, 'User #' + cases[0]['OwnerId'] + ':', get_user_names())

    if oid is not None:
        users_oid = send_request_in_session('GET', 'sobjects/' + 'User').json()
        # BUG PRESERVED: Original JS uses 'usersToEntry.records' (function reference) instead of 'usersOid.records'
        return users_to_entry(users_to_entry.records, 'User #' + str(users_oid) + ':', get_user_names())  # noqa: E501

    return {
        'Type': EntryType.ERROR,
        'Contents': 'You must specify object ID or a Case Number',
        'ReadableContentsFormat': EntryFormat.MARKDOWN
    }


def get_org_name(case_number):
    if case_number is not None:
        condition = "CaseNumber='" + case_number + "'"
        properties = ['ID', 'CaseNumber', 'AccountId']
        cases = query_objects(properties, 'Case', condition).get('records', [])
        condition_a = "Id='" + cases[0]['AccountId'] + "'"
        properties_a = ['Id', 'Name']
        users_a = query_objects(properties_a, "Account", condition_a).get('records', [])
        return org_to_entry(users_a, 'Account #' + cases[0]['AccountId'] + ':', get_user_names())

    return {
        'Type': EntryType.ERROR,
        'Contents': 'You must specify a Case Number',
        'ReadableContentsFormat': EntryFormat.MARKDOWN
    }


# Add the capability to post comment in specific case
def post_case_comment(oid, case_number, text):
    data = {
        'CommentBody': text,
        'ParentId': case_number
    }

    response = send_request_in_session('POST', 'sobjects/CaseComment', json.dumps(data))
    message = response.json()
    message['body'] = text
    return {
        'Type': EntryType.NOTE,
        'Contents': message,
        'ContentsFormat': EntryFormat.JSON,
        'HumanReadable': tableToMarkdown('comment', message)
    }


def create_case(subject, description, status, origin, priority, case_type):
    data = {
        'Subject': subject,
        'Description': description,
        'Status': status,
        'Origin': origin,
        'Priority': priority,
        'Type': case_type
    }

    return create_object('Case', json.dumps(data))


def update_case(oid, case_number, subject, description, status, origin, priority, case_type):
    if oid is None and case_number is None:
        return {
            'Type': EntryType.ERROR,
            'Contents': 'You must specify object ID or a Case Number',
            'ReadableContentsFormat': EntryFormat.MARKDOWN
        }

    if oid is None:
        condition = "CaseNumber='" + case_number + "'"
        cases = query_objects(['ID'], 'Case', condition).get('records', [])
        oid = cases[0]['Id'] if len(cases) == 1 else None

    data = {
        'Subject': subject,
        'Description': description,
        'Status': status,
        # BUG PRESERVED: Original JS has typo 'Origion' instead of 'Origin'
        'Origion': origin,
        'Priority': priority,
        'Type': case_type
    }

    return update_object('Case/' + oid, json.dumps(data))


def get_cases():
    properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason']
    cases = query_objects(properties, 'Case').get('records', [])
    return cases_to_entry(cases, 'Cases:', get_user_names())


def close_case(oid, case_number):
    return update_case(oid, case_number, None, None, 'Closed', None, None, None)


def delete_case(oid, case_number):
    if oid is None and case_number is None:
        return {
            'Type': EntryType.ERROR,
            'Contents': 'You must specify object ID or a Case Number',
            'ReadableContentsFormat': EntryFormat.MARKDOWN
        }

    if oid is None:
        condition = "CaseNumber='" + case_number + "'"
        cases = query_objects(['ID'], 'Case', condition).get('records', [])
        oid = cases[0]['Id'] if len(cases) == 1 else None

    return delete_object('Case/' + oid)


def push_comment(oid, text, link_url):
    data = {
        'body': {
            'messageSegments': [{
                'type': 'Text',
                'text': text
            }],
        },
        'feedElementType': 'FeedItem',
        'subjectId': oid
    }

    if link_url is not None:
        data['body']['messageSegments'].append({
            'type': 'Link',
            'url': link_url
        })

    response = send_request_in_session('POST', 'chatter/feed-elements', json.dumps(data))
    message = response.json()

    return create_entry(message, {
        'title': 'New Message',
        'contextPath': 'SalesForce.Comment(val.URL && val.URL == obj.URL)',
        'data': [
            {'to': 'Body', 'from': 'body.text'},
            {'to': 'CreatedDate', 'from': 'createdDate'},
            {'to': 'Title', 'from': 'header.text'},
            {'to': 'ParentType', 'from': 'parent.type'},
            {'to': 'ParentName', 'from': 'parent.name'},
            {'to': 'URL', 'from': 'url'},
            {'to': 'Visibility', 'from': 'visibility'}
        ]
    })


def push_comment_thread(id, text):
    data = {
        'body': {
            'messageSegments': [{
                'type': 'Text',
                'text': text
            }]
        }
    }

    response = send_request_in_session('POST', 'chatter/feed-elements/' + id + '/capabilities/comments/items', json.dumps(data))
    message = response.json()
    output = {
        'Body': message.get('body', {}).get('text'),
        'CreatedDate': message.get('createdDate'),
        'URL': message.get('url')
    }

    ec = {
        'SalesForce.Comment(val.URL && val.URL == obj.URL)': {
            'URL': URI_PREFIX + 'chatter/feed-elements/' + id,
            'Reply': output
        }
    }

    return {
        'Type': EntryType.NOTE,
        'Contents': message,
        'ContentsFormat': EntryFormat.JSON,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('New Reply', output),
        'EntryContext': ec
    }


def cases_to_incidents(raw_info, user_mapping):
    cases = []
    for item in raw_info:
        cases.append({
            'name': item.get('Id', '') + " " + (item.get('Subject') or ''),
            'details': item.get('Description'),
            'rawJSON': json.dumps(item),
            'Reason': item.get('Reason')
        })
    return cases


def fetch_incident():
    params = demisto.params()
    fetch_type = params.get('fetchType')

    last_run = demisto.getLastRun()
    if last_run.get('last_case_time') is None:
        current_time = datetime.utcnow()
        current_time = current_time - timedelta(days=30)  # TODO - remove this line (equivalent to setMonth(-1))
        last_run['last_case_time'] = current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        demisto.setLastRun(last_run)

    incidents = []

    if fetch_type == 'cases':
        # query cases from last time
        condition = "CreatedDate>" + last_run['last_case_time'] + " ORDER BY CreatedDate DESC"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason']

        cases = query_objects(properties, "Case", condition).get('records', [])

        if len(cases) > 0:
            # Parse the date and format it back
            new_time = datetime.strptime(cases[0]['CreatedDate'], "%Y-%m-%dT%H:%M:%S.%f%z")
            last_run['last_case_time'] = new_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'

            demisto.setLastRun(last_run)
            user_mapping = get_user_names()
            incidents = cases_to_incidents(cases, user_mapping)

    else:  # fetchType === 'comment'
        # query comments from last time

        # Fetch comment replies
        properties = ['Id', 'CommentBody', 'CreatedDate']
        condition = "CreatedDate>" + last_run['last_case_time'] + " ORDER BY CreatedDate DESC LIMIT 10"
        replies = query_objects(properties, "FeedComment", condition).get('records', [])

        if len(replies) > 0:
            new_time = datetime.strptime(replies[0]['CreatedDate'], "%Y-%m-%dT%H:%M:%S.%f%z")
            last_run['last_case_time'] = new_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
            demisto.setLastRun(last_run)

            for i in range(len(replies)):
                # Get reply details
                reply_details = send_request_in_session('GET', 'chatter/comments/' + replies[i]['Id'])
                data = reply_details.json()
                feed_element = data.get('feedElement', {})
                parent_id = feed_element.get('id')

                # Get parent details
                parent_details = get_object('CaseFeed/' + parent_id)
                parent_text = parent_details.get('Body')

                if parent_text is not None and 'DemistoID' in parent_text:
                    message_segments = data.get('body', {}).get('messageSegments', [])
                    for j in range(len(message_segments)):
                        if message_segments[j].get('type') == 'Text':
                            # Found the relevant comment (there's only one), so we return it
                            return [{
                                'name': parent_text,
                                'details': message_segments[j].get('text')
                            }]

    return incidents


def main():
    global SESSION_DATA
    SESSION_DATA = get_new_token()

    command = demisto.command()
    args = demisto.args()

    try:
        if command == 'fetch-incidents':
            incidents = fetch_incident()
            demisto.incidents(incidents)
        elif command == 'test-module':
            try:
                send_request_in_session('GET', '', '')
            except Exception as err:
                demisto.results('Connection test failed with error: ' + str(err) + '.')
                return
            demisto.results('ok')
        elif command == 'salesforce-search':
            response = send_request_in_session('GET', 'search/?q=FIND+%7B' + args['pattern'] + '%7D', '')
            demisto.results(search_to_entry(response.json().get('searchRecords', [])))
        elif command == 'salesforce-query':
            demisto.results(query_to_entry(query_raw(args['query'])))
        elif command == 'salesforce-get-object':
            demisto.results(get_object(args['path']))
        elif command == 'salesforce-update-object':
            demisto.results(update_object(args['path'], args['json']))
        elif command == 'salesforce-create-object':
            demisto.results(create_object(args['path'], args['json']))
        elif command == 'salesforce-get-case':
            demisto.results(get_case(args.get('oid'), args.get('caseNumber')))
        elif command == 'salesforce-get-user':
            demisto.results(get_user(args.get('oid'), args.get('caseNumber')))
        elif command == 'salesforce-get-casecomment':
            demisto.results(get_case_comment(args.get('oid'), args.get('caseNumber')))
        elif command == 'salesforce-get-org':
            demisto.results(get_org_name(args.get('caseNumber')))
        elif command == 'salesforce-post-casecomment':
            demisto.results(post_case_comment(args.get('oid'), args.get('caseNumber'), args.get('text')))
        elif command == 'salesforce-create-case':
            demisto.results(create_case(args.get('subject'), args.get('description'), args.get('status'), args.get('origin'), args.get('priority'), args.get('type')))
        elif command == 'salesforce-update-case':
            demisto.results(update_case(args.get('oid'), args.get('caseNumber'), args.get('subject'), args.get('description'), args.get('status'), args.get('origin'), args.get('priority'), args.get('type')))
        elif command == 'salesforce-get-cases':
            demisto.results(get_cases())
        elif command == 'salesforce-close-case':
            demisto.results(close_case(args.get('oid'), args.get('caseNumber')))
        elif command == 'salesforce-delete-case':
            demisto.results(delete_case(args.get('oid'), args.get('caseNumber')))
        elif command == 'salesforce-push-comment':
            demisto.results(push_comment(args['oid'], args['text'], args.get('link')))
        elif command == 'salesforce-push-comment-threads':
            demisto.results(push_comment_thread(args['id'], args['text']))
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
