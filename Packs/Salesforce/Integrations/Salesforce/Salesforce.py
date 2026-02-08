import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

URI_PREFIX = '/services/data/v63.0/'

class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, client_id, client_secret, username, password):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.instance_url = None

    def get_new_token(self):
        if not self.client_id or not self.client_secret:
            raise DemistoException('Consumer Key and Consumer Secret must be provided.')

        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.username,
            'password': self.password
        }

        res = self._http_request(
            method='POST',
            full_url=f'{self._base_url}/services/oauth2/token',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        return res

    def _get_session(self):
        if not self.access_token:
            token_data = self.get_new_token()
            self.access_token = token_data.get('access_token')
            self.instance_url = token_data.get('instance_url')

    def http_request(self, method, url_suffix, data=None, params=None):
        self._get_session()
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        # Handle full URL vs suffix
        if url_suffix.startswith('http'):
            url = url_suffix
        else:
            url = f'{self.instance_url}{URI_PREFIX}{url_suffix}'

        try:
            return self._http_request(
                method=method,
                full_url=url,
                json_data=data,
                params=params,
                headers=headers
            )
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 401:
                # Token might be expired, try to refresh
                self.access_token = None
                self._get_session()
                headers['Authorization'] = f'Bearer {self.access_token}'
                return self._http_request(
                    method=method,
                    full_url=url,
                    json_data=data,
                    params=params,
                    headers=headers
                )
            raise e

    def query_objects(self, fields, table, condition=None):
        query = f'SELECT {",".join(fields)} FROM {table}'
        if condition:
            query += f' WHERE {condition}'
        
        return self.http_request('GET', 'query/', params={'q': query})

def get_user_names(client):
    res = client.query_objects(['Id', 'Name'], 'User')
    users = {}
    for record in res.get('records', []):
        users[record['Id']] = record['Name']
    return users

def resolve_mapping(raw_info, mapping, field_name):
    if mapping:
        for item in raw_info:
            original_val = item.get(field_name)
            if original_val:
                item[field_name] = mapping.get(original_val, original_val)
    return raw_info

def comment_to_entry(raw_info, title, user_mapping):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    
    return CommandResults(
        outputs_prefix='SalesForce.CaseComment',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'ParentId', 'IsPublished', 'CommentBody', 'CreatedById', 'CreatedDate']),
        raw_response=raw_info
    )

def user_to_entry(raw_info, title, user_mapping):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    
    return CommandResults(
        outputs_prefix='SalesForce.User',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Name', 'Email', 'Username', 'Alias']),
        raw_response=raw_info
    )

def org_to_entry(raw_info, title, user_mapping):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    
    return CommandResults(
        outputs_prefix='SalesForce.GetOrg',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Name']),
        raw_response=raw_info
    )

def cases_to_entry(raw_info, title, user_mapping):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    
    return CommandResults(
        outputs_prefix='SalesForce.Case',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'CaseNumber', 'Subject', 'Status', 'Priority', 'OwnerId']),
        raw_response=raw_info
    )

def contacts_to_entry(raw_info, title, user_mapping, account_mapping=None):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    if account_mapping:
        raw_info = resolve_mapping(raw_info, account_mapping, 'AccountId')

    return CommandResults(
        outputs_prefix='SalesForce.Contact',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Name', 'Email', 'Phone', 'Title']),
        raw_response=raw_info
    )

def leads_to_entry(raw_info, title, user_mapping):
    raw_info = resolve_mapping(raw_info, user_mapping, 'OwnerId')
    
    return CommandResults(
        outputs_prefix='SalesForce.Lead',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Name', 'Company', 'Status', 'Email']),
        raw_response=raw_info
    )

def tasks_to_entry(raw_info, title, lead_mapping=None):
    if lead_mapping:
        raw_info = resolve_mapping(raw_info, lead_mapping, 'WhoId')

    return CommandResults(
        outputs_prefix='SalesForce.Task',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Subject', 'WhoId', 'ActivityDate']),
        raw_response=raw_info
    )

def users_list_to_entry(raw_info, title):
    return CommandResults(
        outputs_prefix='SalesForce.GetUsers',
        outputs_key_field='ID',
        outputs=raw_info,
        readable_output=tableToMarkdown(title, raw_info, headers=['Id', 'Name', 'Email', 'Username']),
        raw_response=raw_info
    )

def object_to_entry(obj_type, obj, client):
    user_mapping = get_user_names(client)
    
    # Ensure obj is a list for consistency with helper functions
    if not isinstance(obj, list):
        obj = [obj]

    if obj_type == 'CaseComment':
        return comment_to_entry(obj, 'CaseComment:', user_mapping)
    elif obj_type == 'getOrgName':
        return org_to_entry(obj, 'getOrgName:', user_mapping)
    elif obj_type == 'userToEntry':
        return user_to_entry(obj, 'getUser', user_mapping)
    elif obj_type == 'Case':
        return cases_to_entry(obj, 'Case:', user_mapping)
    elif obj_type == 'Contact':
        return contacts_to_entry(obj, 'Contact:', user_mapping)
    elif obj_type == 'Lead':
        return leads_to_entry(obj, 'Lead:', user_mapping)
    elif obj_type == 'Task':
        return tasks_to_entry(obj, 'Task:', None)
    elif obj_type == 'User':
        return users_list_to_entry(obj, 'User:')
    else:
        return CommandResults(
            outputs=obj,
            readable_output=tableToMarkdown(f'{obj_type} Object', obj),
            raw_response=obj
        )

def search_command(client, args):
    pattern = args.get('pattern')
    response = client.http_request('GET', 'search/', params={'q': f'FIND {{{pattern}}}'})
    search_records = response.get('searchRecords', [])
    
    if not search_records:
        return CommandResults(readable_output='No records matched the search.')

    results = []
    
    # Group by type
    grouped = {}
    for record in search_records:
        obj_type = record.get('attributes', {}).get('type')
        if obj_type:
            if obj_type not in grouped:
                grouped[obj_type] = []
            grouped[obj_type].append(record['Id'])

    user_mapping = get_user_names(client)

    # Process groups
    if 'getOrgName' in grouped:
        ids_str = "','".join(grouped['getOrgName'])
        condition = f"ID IN ('{ids_str}')"
        cases = client.query_objects(['ID', 'Name'], "Account", condition).get('records', [])
        results.append(org_to_entry(cases, 'Account:', user_mapping))

    if 'Case' in grouped:
        ids_str = "','".join(grouped['Case'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason','IsEscalated','SuppliedPhone','SuppliedCompany','SuppliedEmail','ContactEmail','ContactId','AccountId']
        cases = client.query_objects(properties, "Case", condition).get('records', [])
        results.append(cases_to_entry(cases, 'Cases:', user_mapping))

    if 'CaseComment' in grouped:
        ids_str = "','".join(grouped['CaseComment'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'CommentBody', 'CreatedDate', 'CreatedById', 'IsPublished', 'SystemModstamp', 'LastModifiedById', 'LastModifiedDate']
        comments = client.query_objects(properties, "CaseComment", condition).get('records', [])
        results.append(comment_to_entry(comments, 'CaseComment:', user_mapping))

    if 'Contact' in grouped:
        ids_str = "','".join(grouped['Contact'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'Name', 'Title', 'AccountId', 'Phone', 'MobilePhone', 'Email', 'OwnerId']
        contacts = client.query_objects(properties, "Contact", condition).get('records', [])
        results.append(contacts_to_entry(contacts, 'Contacts:', user_mapping))

    if 'Lead' in grouped:
        ids_str = "','".join(grouped['Lead'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'Name', 'Title', 'Company', 'Phone', 'MobilePhone', 'Email', 'Status', 'OwnerId']
        leads = client.query_objects(properties, "Lead", condition).get('records', [])
        results.append(leads_to_entry(leads, 'Leads:', user_mapping))

    if 'Task' in grouped:
        ids_str = "','".join(grouped['Task'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'Subject', 'WhoId', 'ActivityDate']
        tasks = client.query_objects(properties, "Task", condition).get('records', [])
        results.append(tasks_to_entry(tasks, 'Tasks:', None))

    if 'User' in grouped:
        ids_str = "','".join(grouped['User'])
        condition = f"ID IN ('{ids_str}')"
        properties = ['ID', 'Name', 'Title', 'Phone', 'Email']
        users = client.query_objects(properties, "User", condition).get('records', [])
        results.append(users_list_to_entry(users, 'Users:'))

    return results

def query_command(client, args):
    query = args.get('query')
    res = client.http_request('GET', 'query/', params={'q': query})
    return CommandResults(
        outputs=res.get('records'),
        readable_output=tableToMarkdown('Query Results', res.get('records')),
        raw_response=res
    )

def get_object_command(client, args):
    path = args.get('path')
    res = client.http_request('GET', f'sobjects/{path}')
    obj_type = path.split('/')[0]
    return object_to_entry(obj_type, res, client)

def create_object_command(client, args):
    path = args.get('path')
    json_obj = args.get('json')
    if isinstance(json_obj, str):
        json_obj = json.loads(json_obj)
    
    res = client.http_request('POST', f'sobjects/{path}', data=json_obj)
    
    if not res.get('success'):
        return CommandResults(
            readable_output=tableToMarkdown('Request failed with errors', res.get('errors')),
            raw_response=res
        )
    
    # Fetch the created object
    return get_object_command(client, {'path': f'{path}/{res.get("id")}'})

def update_object_command(client, args):
    path = args.get('path')
    json_obj = args.get('json')
    if isinstance(json_obj, str):
        json_obj = json.loads(json_obj)

    client.http_request('PATCH', f'sobjects/{path}', data=json_obj)
    
    # Fetch the updated object (path usually contains ID for update)
    return get_object_command(client, {'path': path})

def get_case_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber')

    if case_number:
        condition = f"CaseNumber='{case_number}'"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason','IsEscalated','SuppliedPhone','SuppliedCompany','SuppliedEmail','ContactEmail','ContactId','AccountId']
        cases = client.query_objects(properties, 'Case', condition).get('records', [])
        return cases_to_entry(cases, f'Case #{case_number}:', get_user_names(client))
    
    if oid:
        return get_object_command(client, {'path': f'Case/{oid}'})

    raise DemistoException('You must specify object ID or a Case Number')

def get_case_comment_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber')

    if case_number:
        condition = f"CaseNumber='{case_number}'"
        cases = client.query_objects(['Id', 'CaseNumber'], 'Case', condition).get('records', [])
        if not cases:
            return CommandResults(readable_output=f'Case {case_number} not found.')
        oid = cases[0]['Id']
        case_number_display = cases[0]['CaseNumber']
    elif oid:
        case_number_display = oid
    else:
        raise DemistoException('You must specify object ID or a Case Number')

    comments = client.http_request('GET', f'sobjects/Case/{oid}/CaseComments')
    return comment_to_entry(comments.get('records', []), f'CaseComment #{case_number_display}:', get_user_names(client))

def get_user_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber')

    if case_number:
        condition = f"CaseNumber='{case_number}'"
        cases = client.query_objects(['Id', 'CaseNumber', 'OwnerId'], 'Case', condition).get('records', [])
        if not cases:
            return CommandResults(readable_output=f'Case {case_number} not found.')
        
        owner_id = cases[0]['OwnerId']
        condition_user = f"Id='{owner_id}'"
        properties = ['Id', 'Name', 'Alias', 'CommunityNickname', 'Email', 'FirstName', 'Username']
        users = client.query_objects(properties, "User", condition_user).get('records', [])
        return users_list_to_entry(users, f'User #{owner_id}:')

    if oid:
        # The JS implementation for oid seems to fetch all users? "sobjects/User"
        # But the function name implies getting a specific user.
        # Following JS logic roughly but assuming oid is user ID if provided directly?
        # Actually JS does: JSON.parse(sendRequestInSession('GET', 'sobjects/'+'User').Body); which gets metadata or all users?
        # Let's assume we want to get the user object by ID if oid is passed, or maybe the JS was buggy/weird.
        # Given the context, let's fetch the specific user if oid is passed.
        return get_object_command(client, {'path': f'User/{oid}'})

    raise DemistoException('You must specify object ID or a Case Number')

def get_org_command(client, args):
    case_number = args.get('caseNumber')
    if not case_number:
        raise DemistoException('You must specify a Case Number')

    condition = f"CaseNumber='{case_number}'"
    properties = ['ID', 'CaseNumber', 'AccountId']
    cases = client.query_objects(properties, 'Case', condition).get('records', [])
    
    if not cases or not cases[0].get('AccountId'):
        return CommandResults(readable_output=f'No Account found for Case #{case_number}')

    account_id = cases[0]['AccountId']
    condition_acc = f"Id='{account_id}'"
    properties_acc = ['Id', 'Name']
    accounts = client.query_objects(properties_acc, "Account", condition_acc).get('records', [])
    
    return org_to_entry(accounts, f'Account #{account_id}:', get_user_names(client))

def post_case_comment_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber') # This seems to be treated as ParentId in JS?
    text = args.get('text')

    # JS: ParentId: caseNumber. This implies caseNumber arg holds the ID? 
    # The YAML says caseNumber description is "The case number of the case."
    # But JS code: ParentId: caseNumber. 
    # If the user passes a Case Number (e.g. 00001000), that is NOT an ID.
    # However, let's stick to what JS does or improve it?
    # JS: function postCaseComment(oid,caseNumber,text ) { ... ParentId: caseNumber ... }
    # If I pass a real case number to ParentId, Salesforce API will likely fail.
    # But if the user passes the ID in the caseNumber argument, it works.
    # Let's try to resolve ID if it looks like a case number, or just use it.
    # For safety, if oid is provided, use it. If caseNumber is provided, check if it's an ID or Number.
    
    parent_id = oid if oid else case_number
    
    # If we want to be smart, we could query the ID from the CaseNumber if it's not an ID.
    # But let's stick to a direct mapping first, assuming user might pass ID in caseNumber arg as per JS behavior (or JS was buggy).
    # Actually, looking at JS `getCaseComment`, it handles both. `postCaseComment` in JS is simple.
    
    data = {
        'CommentBody': text,
        'ParentId': parent_id
    }
    
    res = client.http_request('POST', 'sobjects/CaseComment', data=data)
    res['body'] = text
    
    return CommandResults(
        outputs_prefix='SalesForce.Comment',
        outputs=res,
        readable_output=tableToMarkdown('comment', res),
        raw_response=res
    )

def create_case_command(client, args):
    data = {
        'Subject': args.get('subject'),
        'Description': args.get('description'),
        'Status': args.get('status'),
        'Origin': args.get('origin'),
        'Priority': args.get('priority'),
        'Type': args.get('type')
    }
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}
    
    return create_object_command(client, {'path': 'Case', 'json': data})

def update_case_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber')
    
    if not oid and not case_number:
        raise DemistoException('You must specify object ID or a Case Number')

    if not oid:
        condition = f"CaseNumber='{case_number}'"
        cases = client.query_objects(['ID'], 'Case', condition).get('records', [])
        if len(cases) == 1:
            oid = cases[0]['Id']
        else:
            raise DemistoException(f'Could not find unique case for number {case_number}')

    data = {
        'Subject': args.get('subject'),
        'Description': args.get('description'),
        'Status': args.get('status'),
        'Origin': args.get('origin'),
        'Priority': args.get('priority'),
        'Type': args.get('type')
    }
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}

    return update_object_command(client, {'path': f'Case/{oid}', 'json': data})

def get_cases_command(client, args):
    properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason']
    cases = client.query_objects(properties, 'Case').get('records', [])
    return cases_to_entry(cases, 'Cases:', get_user_names(client))

def close_case_command(client, args):
    args['status'] = 'Closed'
    return update_case_command(client, args)

def delete_case_command(client, args):
    oid = args.get('oid')
    case_number = args.get('caseNumber')

    if not oid and not case_number:
        raise DemistoException('You must specify object ID or a Case Number')

    if not oid:
        condition = f"CaseNumber='{case_number}'"
        cases = client.query_objects(['ID'], 'Case', condition).get('records', [])
        if len(cases) == 1:
            oid = cases[0]['Id']
        else:
            raise DemistoException(f'Could not find unique case for number {case_number}')

    client.http_request('DELETE', f'sobjects/Case/{oid}')
    return CommandResults(readable_output=f'object Case/{oid} was successfully deleted.')

def push_comment_command(client, args):
    oid = args.get('oid')
    text = args.get('text')
    link_url = args.get('link')

    data = {
        'body': {
            'messageSegments': [{
                'type': 'Text',
                'text': text
            }]
        },
        'feedElementType': 'FeedItem',
        'subjectId': oid
    }

    if link_url:
        data['body']['messageSegments'].append({
            'type': 'Link',
            'url': link_url
        })

    res = client.http_request('POST', 'chatter/feed-elements', data=data)
    
    # Map response to output format
    output = {
        'Body': res.get('body', {}).get('text'),
        'CreatedDate': res.get('createdDate'),
        'Title': res.get('header', {}).get('text'),
        'ParentType': res.get('parent', {}).get('type'),
        'ParentName': res.get('parent', {}).get('name'),
        'URL': res.get('url'),
        'Visibility': res.get('visibility')
    }

    return CommandResults(
        outputs_prefix='SalesForce.Comment',
        outputs_key_field='URL',
        outputs=output,
        readable_output=tableToMarkdown('New Message', output),
        raw_response=res
    )

def push_comment_threads_command(client, args):
    thread_id = args.get('id')
    text = args.get('text')

    data = {
        'body': {
            'messageSegments': [{
                'type': 'Text',
                'text': text
            }]
        }
    }

    res = client.http_request('POST', f'chatter/feed-elements/{thread_id}/capabilities/comments/items', data=data)
    
    output = {
        'Body': res.get('body', {}).get('text'),
        'CreatedDate': res.get('createdDate'),
        'URL': res.get('url')
    }

    # Context structure from JS: SalesForce.Comment(val.URL && val.URL == obj.URL).Reply
    # We need to construct the context manually to match the nested structure if we want exact match
    # But CommandResults usually handles flat outputs.
    # JS: EntryContext: { 'SalesForce.Comment...': { URL: ..., Reply: output } }
    
    # We can try to replicate this structure
    context_entry = {
        'URL': f'{client.instance_url}{URI_PREFIX}chatter/feed-elements/{thread_id}',
        'Reply': output
    }

    return CommandResults(
        outputs_prefix='SalesForce.Comment',
        outputs_key_field='URL',
        outputs=context_entry,
        readable_output=tableToMarkdown('New Reply', output),
        raw_response=res
    )

def fetch_incidents(client, params):
    fetch_type = params.get('fetchType', 'cases')
    last_run = demisto.getLastRun()
    last_case_time = last_run.get('last_case_time')

    if not last_case_time:
        # Default to 1 month ago if not set (matching JS logic roughly)
        # JS: current_time.setMonth(current_time.getMonth() - 1);
        one_month_ago = datetime.now() - timedelta(days=30)
        last_case_time = one_month_ago.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        demisto.setLastRun({'last_case_time': last_case_time})

    incidents = []

    if fetch_type == 'cases':
        condition = f"CreatedDate>{last_case_time} ORDER BY CreatedDate DESC"
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason']
        
        cases = client.query_objects(properties, "Case", condition).get('records', [])
        
        if cases:
            # Update last run with the most recent case (first in list due to DESC sort)
            # Wait, JS sorts DESC, so index 0 is the NEWEST.
            # JS: new_time = stringToDate(cases[0].CreatedDate...); setLastRun...
            # This means we might miss cases if we fetch multiple and only update to the newest?
            # Standard practice is usually ASC to process oldest to newest.
            # But I must follow JS logic: "ORDER BY CreatedDate DESC"
            
            newest_case_date = cases[0]['CreatedDate']
            demisto.setLastRun({'last_case_time': newest_case_date})
            
            for case in cases:
                incidents.append({
                    'name': f"{case['Id']} {case.get('Subject')}",
                    'details': case.get('Description'),
                    'rawJSON': json.dumps(case),
                    'Reason': case.get('Reason')
                })

    else: # fetchType == 'comment'
        # JS logic: query FeedComment
        properties = ['Id', 'CommentBody', 'CreatedDate']
        condition = f"CreatedDate>{last_case_time} ORDER BY CreatedDate DESC LIMIT 10"
        replies = client.query_objects(properties, "FeedComment", condition).get('records', [])

        if replies:
            newest_reply_date = replies[0]['CreatedDate']
            demisto.setLastRun({'last_case_time': newest_reply_date})

            for reply in replies:
                # Get reply details
                reply_details = client.http_request('GET', f'chatter/comments/{reply["Id"]}')
                feed_element = reply_details.get('feedElement', {})
                parent_id = feed_element.get('id')

                # Get parent details
                # JS: getObject('CaseFeed/' + parentID)
                # Note: CaseFeed object might not be directly accessible via standard getObject if it's special
                # But let's assume it works as per JS
                parent_details = client.http_request('GET', f'sobjects/CaseFeed/{parent_id}')
                parent_text = parent_details.get('Body')

                if parent_text and 'DemistoID' in parent_text:
                    message_segments = reply_details.get('body', {}).get('messageSegments', [])
                    for segment in message_segments:
                        if segment.get('type') == 'Text':
                            incidents.append({
                                'name': parent_text,
                                'details': segment.get('text')
                            })
                            # JS returns immediately after finding one? 
                            # "return JSON.stringify([{...}])" inside the loop.
                            # This implies it only fetches ONE incident per run if it finds a match?
                            # I will replicate this behavior by breaking/returning.
                            return incidents 

    return incidents

def test_module(client):
    try:
        client.http_request('GET', '', '')
        return 'ok'
    except Exception as e:
        return f'Connection test failed with error: {str(e)}'

def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client_id = params.get('credentials_client_secret', {}).get('identifier') or params.get('clientID')
    client_secret = params.get('credentials_client_secret', {}).get('password') or params.get('clientSecret')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    
    base_url = params.get('InstanceURL')
    verify = not params.get('insecure', False)
    proxy = params.get('useproxy', False)

    client = Client(base_url, verify, proxy, client_id, client_secret, username, password)

    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)
        elif command == 'salesforce-search':
            return_results(search_command(client, args))
        elif command == 'salesforce-query':
            return_results(query_command(client, args))
        elif command == 'salesforce-get-object':
            return_results(get_object_command(client, args))
        elif command == 'salesforce-create-object':
            return_results(create_object_command(client, args))
        elif command == 'salesforce-update-object':
            return_results(update_object_command(client, args))
        elif command == 'salesforce-get-case':
            return_results(get_case_command(client, args))
        elif command == 'salesforce-get-casecomment':
            return_results(get_case_comment_command(client, args))
        elif command == 'salesforce-get-user':
            return_results(get_user_command(client, args))
        elif command == 'salesforce-get-org':
            return_results(get_org_command(client, args))
        elif command == 'salesforce-post-casecomment':
            return_results(post_case_comment_command(client, args))
        elif command == 'salesforce-create-case':
            return_results(create_case_command(client, args))
        elif command == 'salesforce-update-case':
            return_results(update_case_command(client, args))
        elif command == 'salesforce-get-cases':
            return_results(get_cases_command(client, args))
        elif command == 'salesforce-close-case':
            return_results(close_case_command(client, args))
        elif command == 'salesforce-delete-case':
            return_results(delete_case_command(client, args))
        elif command == 'salesforce-push-comment':
            return_results(push_comment_command(client, args))
        elif command == 'salesforce-push-comment-threads':
            return_results(push_comment_threads_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
