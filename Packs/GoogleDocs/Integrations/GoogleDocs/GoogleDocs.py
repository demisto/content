from CommonServerPython import *

''' IMPORTS '''

import urllib3
import httplib2
import urllib.parse
from oauth2client import service_account
from googleapiclient import discovery

from collections import defaultdict

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

SCOPES = ['https://www.googleapis.com/auth/documents']  # Permissions the application needs to use google docs

''' HELPER FUNCTIONS '''


def get_function_by_action_name(action):
    action_to_function = {
        'createNamedRange': create_named_range,
        'createParagraphBullets': create_paragraph_bullets,
        'deleteContentRange': delete_content_range,
        'deleteNamedRangeByName': delete_named_range_by_name,
        'deleteNamedRangeById': delete_named_range_by_id,
        'deleteParagraphBullets': delete_paragraph_bullets,
        'deletePositionedObject': delete_positioned_object,
        'deleteTableColumn': delete_table_column,
        'deleteTableRow': delete_table_row,
        'insertInlineImage': insert_inline_image,
        'insertPageBreak': insert_page_break,
        'insertTable': insert_table,
        'insertTableColumn': insert_table_column,
        'insertTableRow': insert_table_row,
        'insertText': insert_text,
        'replaceAllText': replace_all_text
    }
    return action_to_function[action]


def parse_actions(actions: str):
    """Destructs action1{param1,param2,...};action2{param1,param2,...}... to a dictionary where keys are action type and
      values are function params"""
    parsed_actions = {}
    actions = actions.split(';')
    for action in actions:
        action_type, params = action.split('{')
        params = params[:-1]
        params = params.split(',')
        parsed_actions[action_type] = params
    return parsed_actions


def get_http_client_with_proxy(disable_ssl):
    proxies = handle_proxy()
    if not proxies.get('https', True):
        raise Exception('https proxy value is empty. Check Demisto server configuration')
    https_proxy = proxies.get('https')
    if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
        https_proxy = f'https://{https_proxy}'
    parsed_proxy = urllib.parse.urlparse(https_proxy)
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
        proxy_host=parsed_proxy.hostname,
        proxy_port=parsed_proxy.port,
        proxy_user=parsed_proxy.username,
        proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=disable_ssl)


def get_credentials(credentials, scopes):
    credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(credentials, scopes=scopes)
    return credentials


def get_client(credentials, scopes, proxy, disable_ssl):
    credentials = get_credentials(credentials, scopes)

    if not proxy:
        return discovery.build('docs', 'v1', credentials=credentials)
    http_client = credentials.authorize(get_http_client_with_proxy(disable_ssl))
    return discovery.build('docs', 'v1', http=http_client)


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


def insert_inline_image(action_name, index, uri, width, height, segment_id=None):
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


def generate_results(document, human_readable_text):
    """ Generates the results dictionary for the command """

    res = {
        'RevisionId': document['revisionId'],
        'DocumentId': document['documentId'],
        'Title': document['title']
    }
    ec = {
        'GoogleDocs(val.DocumentId && val.DocumentId == obj.DocumentId)': res
    }
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': tableToMarkdown(human_readable_text, res),
        'EntryContext': ec
    }


def batch_update_document_command(service):
    args = demisto.args()
    document_id = args.get('document_id')
    actions = parse_actions(args.get('actions'))
    required_revision_id = args.get("required_revision_id", None)
    target_revision_id = args.get("target_revision_id", None)
    document = batch_update_document(service, document_id, actions, required_revision_id, target_revision_id)
    human_readable_text = "The document with the title {title} and actions {actions} was updated. the results are:".\
        format(title=document['title'], actions=args.get('actions'))
    return generate_results(document, human_readable_text)


def batch_update_document(service, document_id, actions, required_revision_id=None, target_revision_id=None):
    payload: dict = {
        "requests": []
    }

    write_control: defaultdict = defaultdict(dict)
    if required_revision_id and target_revision_id:
        raise Exception("Enter required_revision_id or target_revision_id but not both")
    elif required_revision_id:
        write_control['writeControl']["requiredRevisionId"] = required_revision_id
    elif target_revision_id:
        write_control['writeControl']["targetRevisionId"] = target_revision_id

    payload = {**payload, **write_control}

    # Return a function based on the action name and execute it
    for action_type, params in actions.items():
        request = get_function_by_action_name(action_type)(action_type, *params)
        payload["requests"].append(request)

    service.documents().batchUpdate(documentId=document_id, body=payload).execute()
    return get_document(service, document_id)


def create_document_command(service):
    args = demisto.args()
    title = args.get('title')
    document = create_document(service, title)
    human_readable_text = f"The document with the title {title} was created. The results are:"
    return generate_results(document, human_readable_text)


def create_document(service, title):
    payload = {
        "title": title,
    }

    return service.documents().create(body=payload).execute()


def get_document_command(service):
    args = demisto.args()
    document_id = args.get('document_id')
    document = get_document(service, document_id)
    human_readable_text = "The document with the title {title} was returned. The results are:".\
        format(title=document['title'])
    return generate_results(document, human_readable_text)


def get_document(service, document_id):
    return service.documents().get(documentId=document_id).execute()


def main():  # pragma: no cover
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    params = demisto.params()
    proxy = params.get('proxy', False)
    disable_ssl = params.get('insecure', False)
    service_account_credentials = params.get('credentials_service_account', {}).get(
        'password') or params.get('service_account_credentials')
    if not service_account_credentials:
        return_error('Service Account Private Key file must be provided.')
    try:
        service = get_client(json.loads(service_account_credentials), SCOPES, proxy, disable_ssl)
        if command == 'google-docs-update-document':
            return_results(batch_update_document_command(service))
        elif command == 'google-docs-create-document':
            return_results(create_document_command(service))
        elif command == 'google-docs-get-document':
            return_results(get_document_command(service))
        elif command == 'test-module':
            if not service:
                raise DemistoException('Failed to create client')
            return_results('ok')
        else:
            raise DemistoException(f"Command {command} does not exist.")

    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        return_error(f"Failed to execute {command} command. Error: {str(e)}", e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
