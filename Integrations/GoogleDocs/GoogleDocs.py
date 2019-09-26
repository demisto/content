from CommonServerPython import *

''' IMPORTS '''

import requests
import httplib2
import urllib.parse
from oauth2client import service_account
from googleapiclient import discovery

import typing
from collections import defaultdict
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

SCOPES = ['https://www.googleapis.com/auth/documents']

ACTION_TO_FUNCTION = {
    'createNamedRange': 'create_named_range',
    'createParagraphBullets': 'create_paragraph_bullets',
    'deleteContentRange': 'delete_content_range',
    'deleteNamedRange': 'delete_named_range',
    'deleteParagraphBullets': 'delete_paragraph_bullets',
    'deletePositionedObject': 'delete_position_object',
    'deleteTableColumn': 'delete_table_column',
    'deleteTableRow': 'delete_table_row',
    'insertInlineImage': 'insert_inline_image',
    'insertPageBreak': 'insert_page_break',
    'insertTable': 'insert_table',
    'insertTableColumn': 'insert_table_column',
    'insertTableRow': 'insert_Table_row',
    'insertText': 'insert_text',
    'replaceAllText': 'replace_all_text'
}
''' HELPER FUNCTIONS '''


def parse_actions(actions: str):
    """Destructs action1{param1,param2,...};action2{param1,param2,...}... to a dictionary where keys are action type and
      values are function params"""
    parsed_actions = dict()
    actions = actions.split(';')
    for action in actions:
        action_type, params = action.split('{')
        params = params[:-1]
        params = params.split(',')
        parsed_actions[action_type] = params
    return parsed_actions


def log_error(f):
    def wrapped(*args, **kwrags):
        try:
            res = f(*args, **kwrags)
            return res
        except Exception as e:
            return_error(str(e))

    return wrapped


@log_error
def get_http_client_with_proxy(disable_ssl):
    proxies = handle_proxy()
    if not proxies or not proxies['https']:
        raise Exception('https proxy value is empty. Check Demisto server configuration')
    https_proxy = proxies['https']
    if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
        https_proxy = 'https://' + https_proxy
    parsed_proxy = urllib.parse.urlparse(https_proxy)
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
        proxy_host=parsed_proxy.hostname,
        proxy_port=parsed_proxy.port,
        proxy_user=parsed_proxy.username,
        proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=disable_ssl)


@log_error
def get_credentials(credentials, scopes):
    credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(credentials, scopes=scopes)
    return credentials


def get_client(credentials, scopes, proxy, disable_ssl):
    credentials = get_credentials(credentials, scopes)

    if proxy or disable_ssl:
        http_client = credentials.authorize(get_http_client_with_proxy(disable_ssl))
        return discovery.build('docs', 'v1', http=http_client)
    return discovery.build('docs', 'v1', credentials=credentials)


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_range_object(start_index, end_index, segment_id=None):
    range_obj = {
        'range': {
            'startIndex': start_index,
            'endIndex': end_index,
        }
    }

    if segment_id:
        range_obj['range']['segmentId'] = segment_id

    return range_obj


def get_location_object(index, segment_id=None):
    location_obj = {
        "index": index,
    }
    if segment_id:
        location_obj["segmentId"] = segment_id
    return location_obj


def replace_all_text(action_name, source, target, match_case):
    return {
        action_name: {
            "replaceText": target,
            'containsText': {
                "text": source,
                "matchCase": match_case
            }
        }
    }


def insert_text(action_name, index, text, segment_id=None):
    return {
        action_name: {
            "location": get_location_object(index, segment_id),
            'text': text
        }
    }


def create_paragraph_bullets(action_name, start_index, end_index, bullet_type, segment_id=None):
    return {
        action_name: {
            **get_range_object(start_index, end_index, segment_id),
            'bulletPreset': bullet_type,
        }
    }


def delete_paragraph_bullets(action_name, start_index, end_index, segment_id=None):
    return {
        action_name: {
            **get_range_object(start_index, end_index, segment_id),
        }
    }


def create_named_range(action_name, start_index, end_index, name, segment_id=None):
    return {
        action_name: {
            "name": name,
            **get_range_object(start_index, end_index, segment_id),
        }
    }


def delete_named_range_by_id(action_name, named_range_id):
    return {
        action_name: {
            "namedRangeId": named_range_id
        }
    }


def delete_named_range_by_name(action_name, name):
    return {
        action_name: {
            "name": name
        }
    }


def delete_content_range(action_name, start_index, end_index, segment_id=None):
    return {action_name: get_range_object(segment_id, start_index, end_index)}


def inset_inline_image(action_name, index, uri, width, height, segment_id=None):
    return {
        action_name: {
            "uri": uri,
            "objectSize": {
                "height": {
                    "magnitude": height,
                    "unit": 'PT'
                },
                "width": {
                    "magnitude": width,
                    "unit": 'PT'
                }
            },
            "location": get_location_object(index, segment_id)
        }
    }


def insert_table(action_name, index, rows, columns, segment_id=None):
    return {
        action_name: {
            "rows": rows,
            "columns": columns,
            "location": get_location_object(index, segment_id)
        }
    }


def insert_table_row(action_name, index, row_index, column_index, insert_below, segment_id=None):
    return {
        action_name: {
            "tableCellLocation": {
                "tableStartLocation": get_location_object(index, segment_id),
                "rowIndex": row_index,
                "columnIndex": column_index
            },
            "insertBelow": insert_below
        }
    }


def insert_table_column(action_name, index, row_index, column_index, insert_below, segment_id=None):
    return {
        action_name: {
            "tableCellLocation": {
                "tableStartLocation": get_location_object(index, segment_id),
                "rowIndex": row_index,
                "columnIndex": column_index
            },
            "insertRight": insert_below
        }
    }


def delete_table_row(action_name, index, row_index, column_index, segment_id=None):
    return {
        action_name: {
            "tableCellLocation": {
                "tableStartLocation": get_location_object(index, segment_id),
                "rowIndex": row_index,
                "columnIndex": column_index
            },
        }
    }


def delete_table_column(action_name, index, row_index, column_index, segment_id=None):
    return {
        action_name: {
            "tableCellLocation": {
                "tableStartLocation": get_location_object(index, segment_id),
                "rowIndex": row_index,
                "columnIndex": column_index
            },
        }
    }


def insert_page_break(action_name, index, segment_id=None):
    return {
        action_name: {
            "location": get_location_object(index, segment_id)
        }
    }


def delete_positioned_object(action_name, object_id):
    return {
        action_name: {
            "objectId": object_id
        }
    }


def batch_update_document_command(service):
    args = demisto.args()
    document_id = args.get('document_id')
    actions = parse_actions(args.get('actions'))
    required_revision_id = args.get("required_revision_id", None)
    target_revision_id = args.get("target_revision_id", None)

    payload: dict = {
        "requests": []
    }

    write_control: typing.DefaultDict = defaultdict(dict)
    if required_revision_id and target_revision_id:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': 'Enter required_revision_id or target_revision_id but not both'
        })
        return
    elif required_revision_id:
        write_control['writeControl']["requiredRevisionId"] = required_revision_id
    elif target_revision_id:
        write_control['writeControl']["targetRevisionId"] = target_revision_id

    payload = {**payload, **write_control}

    for action_type, params in actions.items():
        request = globals()[ACTION_TO_FUNCTION[action_type]](action_type, *params)
        payload["requests"].append(request)

    service.documents().batchUpdate(documentId=document_id, body=payload).execute()
    document = get_document(service, document_id)
    return document


def create_document_command(service):
    args = demisto.args()
    title = args.get('title')

    payload = {
        "title": title,
    }

    document = service.documents().create(body=payload).execute()
    return document


def get_document_command(service):
    args = demisto.args()
    document_id = args.get('document_id')
    document = get_document(service, document_id)
    return document


def get_document(service, document_id):
    document = service.documents().get(documentId=document_id).execute()
    return document


def main():
    LOG('Command being called is %s' % (demisto.command()))
    proxy = demisto.params().get('proxy')
    disable_ssl = demisto.params().get('insecure', False)
    service_account_credentials = json.loads(demisto.params().get('service_account_credentials'))
    if demisto.command() == 'test-module':
        try:
            get_client(service_account_credentials, SCOPES, proxy, disable_ssl)
            demisto.results('ok')
        except Exception as e:
            return_error("Failed to execute test. Error: {}".format(str(e)), e)

    try:
        service = get_client(service_account_credentials, SCOPES, proxy, disable_ssl)
        if demisto.command() == 'update_document':
            res = batch_update_document_command(service)
        elif demisto.command() == 'create_document':
            res = create_document_command(service)
        elif demisto.command() == 'get_document':
            res = get_document_command(service)
        else:
            return_error("Command {} does not exist".format(demisto.command()))
            return

        ec = {
            'GoogleDocs(val.DocumentId && val.DocumentId == DocumentId.Query)': {
                'RevisionId': res['revisionId'],
                'DocumentId': res['documentId'],
                'Title': res['title']
            }
        }

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': ec,
            'HumanReadable': json.dumps(ec),
            'EntryContext': ec
        })

    # Log exceptions
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)), e)


''' COMMANDS MANAGER / SWITCH PANEL '''
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
