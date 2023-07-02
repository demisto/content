import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import requests
import json
import urllib3
urllib3.disable_warnings()

"""
GLOBAL VARIABLES
"""

SERVER = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
BASE_URL = SERVER + '/rest/api'
VERIFY_CERTIFICATE = not demisto.params().get('unsecure', False)

# Support Credentials
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

"""
Helper Functions
"""


def http_request(method, full_url, data=None, params=None, is_test=False):  # pragma: no cover
    try:
        res = requests.request(
            method,
            full_url,
            verify=VERIFY_CERTIFICATE,
            auth=(USERNAME, PASSWORD),
            data=data,
            headers=HEADERS,
            params=params
        )
    except requests.exceptions.RequestException:  # This is the correct syntax
        return_error('Failed to connect to - {} - Please check the URL'.format(full_url))

    # Handle error responses gracefully
    if res.status_code < 200 or res.status_code >= 400:
        if is_test:
            return res

        return_error('Failed to execute command.\nURL: {}, Status Code: {}\nResponse: {}'.format(full_url,
                                                                                                 res.status_code,
                                                                                                 res.text))

    if is_test:
        return res
    try:
        return res.json()

    except ValueError as err:
        return_error('Failed to parse response from service, received the following error:\n{}'.format(str(err)))


"""
Confluence Commands
"""


def update_content(page_id, content_title, space_key, content_body, content_type, content_version):
    content_data = {}
    # Populate the content_data dictionary
    content_data['type'] = content_type
    if space_key is not None:
        content_data['space'] = {"key": space_key}
    if content_title is not None:
        content_data['title'] = content_title

    content_data['body'] = {
        "storage": {
            "value": content_body,
            "representation": "storage"
        }
    }
    content_data['version'] = {
        "number": content_version
    }

    full_url = BASE_URL + '/content/' + page_id

    res = http_request('PUT', full_url, json.dumps(content_data))

    return res


def update_content_command():
    """
    Confluence Update Content method
    """

    page_id = demisto.args().get('pageid')
    content_title = demisto.args().get('title')
    space_key = demisto.args().get('space')
    content_body = demisto.args().get('body')
    content_type = demisto.args().get('type')
    content_version = int(demisto.args().get('currentversion')) + 1

    raw_content = update_content(page_id, content_title, space_key, content_body, content_type, content_version)
    content = {
        "ID": page_id,
        "Title": content_title,
        "Type": content_type,
        "Body": content_body
    }

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Updated Content', content, ['ID', 'Title', 'Type', 'Body'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_content,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Content(val.ID == obj.ID)': content
        }
    })


def create_content(content_type, content_title, space_key, content_body):
    content_data = {
        "type": content_type,
        "space": {
            "key": space_key
        },
        "title": content_title,
        "body": {
            "storage": {
                "value": content_body,
                "representation": "storage"
            }
        }
    }

    full_url = BASE_URL + '/content'

    res = http_request('POST', full_url, json.dumps(content_data))

    return res


def create_content_command():
    """
    Confluence Create Content method
    """
    content_type = demisto.args().get('type')
    content_title = demisto.args().get('title')
    space_key = demisto.args().get('space')
    content_body = demisto.args().get('body')

    raw_content = create_content(content_type, content_title, space_key, content_body)

    content = {
        "ID": raw_content['id'],
        "Title": content_title,
        "Type": content_type,
        "Body": content_body
    }

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('New Content', content, ['ID', 'Title', 'Type', 'Body'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_content,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Content(val.ID == obj.ID)': content
        }
    })


def create_space(space_description, space_key, space_name):
    space_data = {
        "type": "global",
        "description": {
            "plain": {
                "value": space_description,
                "representation": "plain"
            }
        },
        "name": space_name,
        "key": space_key
    }

    full_url = BASE_URL + '/space'

    res = http_request('POST', full_url, json.dumps(space_data))

    return res


def create_space_command():
    """
    Confluence Create Space method
    """
    space_description = demisto.args().get('description')
    space_key = demisto.args().get('key')
    space_name = demisto.args().get('name')

    raw_space = create_space(space_description, space_key, space_name)

    space = {
        "ID": raw_space['id'],
        "Key": raw_space['key'],
        "Name": raw_space['name']
    }

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Space created successfully', space, ['ID', 'Key', 'Name'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_space,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Space(val.ID == obj.ID)': space
        }
    })


def get_content(key, title):
    params = {
        "title": title,
        "spaceKey": key,
        "expand": "body.view,version"
    }

    full_url = BASE_URL + '/content'

    res = http_request('GET', full_url, None, params)

    return res


def get_content_command():
    """
    Confluence Get Content method
    """
    space_key = demisto.args().get('key')
    content_title = demisto.args().get('title')
    raw_content = get_content(space_key, content_title)

    content_list = []
    for obj in raw_content['results']:
        content = {
            "ID": obj['id'],
            "Title": obj['title'],
            "Type": obj['type']
        }
        if obj.get('version') is not None:
            content["Version"] = obj['version']['number']
        if obj.get('body') is not None:
            content["Body"] = obj['body']['view']['value']

        content_list.append(content)

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Content', content_list, ['ID', 'Title', 'Type', 'Version', 'Body'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_content,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Content(val.ID == obj.ID)': content_list
        }
    })


def search_content(cql, cql_context, expand, start, limit):
    params = {
        'limit': limit,
        'cql': cql
    }
    if cql_context is not None:
        params['cqlcontext'] = cql_context

    if expand is not None:
        params['expand'] = expand

    if start is not None:
        params['start'] = start

    full_url = BASE_URL + '/content/search'

    res = http_request('GET', full_url, None, params)

    return res


def search_content_command():
    """
    Confluence Search Content method
    Reference:  https://developer.atlassian.com/server/confluence/advanced-searching-using-cql/
    """

    cql = demisto.args().get('cql')
    cql_context = demisto.args().get('cqlcontext')
    expand = demisto.args().get('expand')
    start = demisto.args().get('start')
    limit = demisto.args().get('limit')

    raw_search = search_content(cql, cql_context, expand, start, limit)

    searches = []
    for result in raw_search['results']:
        search = {}

        search['ID'] = result['id']
        search['Title'] = result['title']
        search['Type'] = result['type']
        if result.get('version') is not None:
            search['Version'] = result['version']['number']

        searches.append(search)

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Content Search', searches, ['ID', 'Title', 'Type', 'Version'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_search,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Content(val.ID == obj.ID)': searches
        }
    })


def list_spaces(limit, status, space_type):
    full_url = BASE_URL + '/space'

    params = {
        'limit': limit
    }

    if status:
        params['status'] = status

    if space_type:
        params['type'] = space_type

    res = http_request('GET', full_url, params=params)

    return res


def list_spaces_command():
    """
    Confluence list Spaces method
    """
    limit = demisto.args().get('limit', 25)
    status = demisto.args().get('status')
    space_type = demisto.args().get('type')
    space_list = list_spaces(limit, status, space_type)

    spaces = []
    for raw_space in space_list['results']:
        space = {}

        space['ID'] = raw_space['id']
        space['Key'] = raw_space['key']
        space['Name'] = raw_space['name']

        spaces.append(space)

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Spaces', spaces, ['ID', 'Key', 'Name'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': space_list,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Space(val.ID == obj.ID)': spaces
        }
    })


def delete_content(content_id):

    full_url = BASE_URL + '/content/' + content_id
    http_request('DELETE', full_url, is_test=True)
    result = {
        "Results": "Successfully Deleted Content ID " + content_id,
        "ID": content_id
    }
    return result


def delete_content_command():
    """
    Confluence Delete Content Spaces method
    """

    content_id = demisto.args().get('id')

    deleted_content = delete_content(content_id)

    # create markdown table string from context
    # the outputs must be array in order the tableToMarkdown to work
    # headers must be array of strings (which column should appear in the table)
    md = tableToMarkdown('Content', deleted_content, ['ID', 'Results'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': deleted_content,
        'HumanReadable': md,
        'EntryContext': {
            'Confluence.Content(val.ID == obj.ID)': deleted_content
        }
    })


def test():  # pragma: no cover
    full_url = BASE_URL + '/user/current'
    res = http_request('GET', full_url, is_test=True)

    if not res:
        return_error('Test failed. \nCheck URL and Username/Password.\nURL: {}, Status Code: {}, Response: {}'.format(
            full_url, res.status_code, res.text.encode('utf8')))

    demisto.results('ok')


"""
CODE EXECUTION STARTS HERE

demisto.command() returns the name of the command which executed now
"""
LOG('Confluence integration is executing the command %s' % (demisto.command(), ))
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        """
        demisto.command() will return 'test-module' when the Test button in integration page clicked
        """
        test()

    elif demisto.command() == 'confluence-create-space':
        create_space_command()

    elif demisto.command() == 'confluence-create-content':
        create_content_command()

    elif demisto.command() == 'confluence-get-content':
        get_content_command()

    elif demisto.command() == 'confluence-list-spaces':
        list_spaces_command()

    elif demisto.command() == 'confluence-delete-content':
        delete_content_command()

    elif demisto.command() == 'confluence-update-content':
        update_content_command()

    elif demisto.command() == 'confluence-search-content':
        search_content_command()

except Exception as e:
    return_error(str(e))
