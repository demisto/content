import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import hmac
import uuid
import json
import base64
import hashlib
import requests

from datetime import timedelta
from urllib.error import HTTPError
from xml.etree import ElementTree


''' GLOBALS/PARAMS '''
BASE_URL = demisto.params().get('baseUrl')
ACCESS_KEY = demisto.params().get('accessKey')

SECRET_KEY = demisto.params().get('secretKey') or demisto.params().get('secretKey_creds')
if isinstance(SECRET_KEY, dict):
    SECRET_KEY = SECRET_KEY.get('password', '')
APP_ID = demisto.params().get('appId')
APP_KEY = demisto.params().get('appKey') or demisto.params().get('appKey_creds', {})
if isinstance(APP_KEY, dict):
    APP_KEY = APP_KEY.get('password', '')

USE_SSL = None  # assigned in determine_ssl_usage
PROXY = bool(demisto.params().get('proxy'))
# Flags to control which type of incidents are being fetched
FETCH_PARAMS = argToList(demisto.params().get('incidentsToFetch'))
FETCH_ALL = 'All' in FETCH_PARAMS
FETCH_URL = 'Url' in FETCH_PARAMS or FETCH_ALL
FETCH_ATTACHMENTS = 'Attachments' in FETCH_PARAMS or FETCH_ALL
FETCH_IMPERSONATIONS = 'Impersonation' in FETCH_PARAMS or FETCH_ALL
FETCH_HELD_MESSAGES = 'Held Messages' in FETCH_PARAMS or FETCH_ALL
# Used to refresh token / discover available auth types / login
EMAIL_ADDRESS = demisto.params().get('email') or demisto.params().get('credentials', {})
if isinstance(EMAIL_ADDRESS, dict):
    EMAIL_ADDRESS = EMAIL_ADDRESS.get('identifier', '')
PASSWORD = demisto.params().get('password') or demisto.params().get('credentials', {})
if isinstance(PASSWORD, dict):
    PASSWORD = PASSWORD.get('password', '')
FETCH_DELTA = int(demisto.params().get('fetchDelta', 24))
MAX_FETCH = arg_to_number(demisto.params().get('max_fetch', 100)) or 100
if MAX_FETCH > 200:
    raise DemistoException("The maximum fetch limit cannot exceed 200. Please enter a lower value.")


CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret', {}).get("password") if demisto.params().get('client_secret') else None
USE_OAUTH2 = bool(CLIENT_ID and CLIENT_SECRET)
TOKEN_OAUTH2 = ""
DEFAULT_POLICY_TYPE = 'blockedsenders'
LOG(f"command is {demisto.command()}")
PAGE_SIZE_MAX = 100
DEFAULT_PAGE_SIZE = 50
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S+00:00'

# default query xml template for test module
default_query_xml = "<?xml version=\"1.0\"?> \n\
    <xmlquery trace=\"iql,muse\">\n\
    <metadata query-type=\"emailarchive\" archive=\"true\" active=\"false\" page-size=\"25\" startrow=\"0\">\n\
        <smartfolders/>\n\
        <return-fields>\n\
            <return-field>attachmentcount</return-field>\n\
            <return-field>status</return-field>\n\
            <return-field>subject</return-field>\n\
            <return-field>size</return-field>\n\
            <return-field>receiveddate</return-field>\n\
            <return-field>displayfrom</return-field>\n\
            <return-field>id</return-field>\n\
            <return-field>displayto</return-field>\n\
            <return-field>smash</return-field>\n\
        </return-fields>\n\
    </metadata>\n\
    <muse>\n\
        <text></text>\n\
        <date select=\"last_year\"/>\n\
        <sent></sent>\n\
        <docs select=\"optional\"></docs>\n\
        <route/>\n\
    </muse>\n\
</xmlquery>"

''' API COMMUNICATION FUNCTIONS'''


def request_with_pagination(api_endpoint: str, data: list, response_param: str = None, limit: int = 100,
                            page: int = None,
                            page_size: int = None, use_headers: bool = False, is_file: bool = False,
                            dedup_held_messages: list = [], current_next_page: str = ''):
    """

    Creates paging response for relevant commands.

    """
    demisto.debug(f"Sending request from request_with_pagination with {limit=}, {data=}")
    headers = {}
    if page and page_size:
        limit = page * page_size
    pagination = {'pageSize': limit}
    payload = {
        'meta': {
            'pagination': pagination
        }
    }  # type: Dict[str, Any]
    if data and data != [{}]:
        payload['data'] = data
    if use_headers:
        headers = generate_user_auth_headers(api_endpoint)
    if not current_next_page:
        demisto.debug("No current_next_page")
        response = http_request('POST', api_endpoint, payload, headers=headers, is_file=is_file)
        next_page = str(response.get('meta', {}).get('pagination', {}).get('next', ''))
    else:
        demisto.debug(f"current_next_page exists with value {current_next_page}")
        next_page = current_next_page
    len_of_results = 0
    results = []
    while True:
        demisto.debug("Another loop")
        if not current_next_page:
            if response.get('fail'):
                raise Exception(json.dumps(response.get('fail')[0].get('errors')))
            if response_param:
                response_data = response.get('data')[0].get(response_param, [])
            else:
                response_data = response.get('data', [])
            for entry in response_data:
                # If returning this log will not exceed the specified limit
                entry_id = entry.get('id')
                if ((not limit or len_of_results < limit)
                    and (not entry_id or entry_id not in dedup_held_messages)): # dedup for fetch
                    len_of_results += 1
                    results.append(entry)
            # If limit is reached or there are no more pages
            if not next_page or (limit and len_of_results >= limit):
                break
        pagination = {'page_size': page_size,  # type: ignore
                      'pageToken': next_page}  # type: ignore
        payload['meta']['pagination'] = pagination
        response = http_request('POST', api_endpoint, payload, headers=headers)
        next_page = str(response.get('meta', {}).get('pagination', {}).get('next', ''))
        current_next_page = ''
    # returning next_page is only required for fetch mechanism
    if page and page_size:
        return results[(-1 * page_size):], page_size, next_page

    return results, len_of_results, next_page


def http_request(method, api_endpoint, payload=None, params={}, user_auth=True, is_file=False, headers={}, data=None):
    is_user_auth = True
    url = BASE_URL + api_endpoint
    # 3 types of auth, user, non user and OAuth2
    if USE_OAUTH2:
        if TOKEN_OAUTH2:
            headers['Authorization'] = f'Bearer {TOKEN_OAUTH2}'
            headers['Accept'] = 'application/json'
            headers['Content-Type'] = 'application/json'

    elif user_auth:
        headers = headers or generate_user_auth_headers(api_endpoint)

    else:
        # This type of auth is only supported for basic commands: login/discover/refresh-token
        is_user_auth = False
        auth = base64.b64encode((EMAIL_ADDRESS + ':' + PASSWORD).encode("utf-8")).decode()
        auth_type = 'Basic-Cloud'
        auth_header = auth_type + ' ' + auth
        headers = {
            'x-mc-app-id': APP_ID,
            'Content-Type': 'application/json',
            'Authorization': auth_header
        }

    LOG(f'running {method} request with url={url}\tparams={json.dumps(params)}\tdata={json.dumps(payload)}\tis user auth={is_user_auth}')
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            headers=headers,
            json=payload,
            data=data
        )
        res.raise_for_status()
        if is_file:
            return res
        return res.json()

    except HTTPError as e:
        LOG(e)
        if e.response.status_code == 418:  # type: ignore  # pylint: disable=no-member
            if not APP_ID or not EMAIL_ADDRESS or not PASSWORD:
                raise Exception(
                    'Credentials provided are expired, could not automatically refresh tokens.'
                    ' App ID + Email Address '
                    '+ Password are required.')
        else:
            raise

    except Exception as e:
        LOG(e)
        raise


def token_oauth2_request():
    api_endpoint = '/oauth/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    response = http_request('POST', api_endpoint, user_auth=False, headers=headers, data=data)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('message')))
    return response.get('access_token')


def search_message_request(args):
    """
    Builds payload for the request of search message command.
    Args:
        args: arguments given to command.

    Returns: the payload to be sent to the API.

    """
    search_reason = args.get('search_reason')
    from_date = arg_to_datetime(args.get('from_date')).isoformat() if args.get('from_date') else None  # type: ignore
    to_date = arg_to_datetime(args.get('to_date')).isoformat() if args.get('to_date') else None  # type: ignore
    message_id = args.get('message_id')
    advanced = {
        'senderIP': args.get('sender_ip'),
        'to': args.get('to'),
        'from': args.get('from'),
        'subject': args.get('subject'),
        'route': args.get('route')
    }
    advanced_is_none = all(value is None for value in advanced.values())
    payload = {'data': [
        {
            'start': from_date,
            'end': to_date,
            'searchReason': search_reason
        }
    ]}
    if advanced_is_none and message_id is None:
        raise Exception('Advanced Track And Trace Options or message ID must be given in order to execute the command.')
    elif advanced_is_none:
        payload.get('data')[0].update({'messageId': message_id})  # type: ignore
    elif message_id is None:
        payload.get('data')[0].update({'advancedTrackAndTraceOptions': advanced})  # type: ignore
    else:
        raise Exception('Only one of message id and advance options can contain value.')

    return http_request(method='POST',
                        api_endpoint='/api/message-finder/search',
                        payload=payload)


def get_message_info_request(id):
    """

    Builds payload for the request of get message info command.
    Args:
        args: arguments given to command.

    Returns: the payload to be sent to the API.


    """

    payload = {
        'data': [
            {
                'id': id
            }
        ]
    }
    return http_request(method='POST',
                        api_endpoint='/api/message-finder/get-message-info',
                        payload=payload)


def list_held_messages_request(args):
    """

        Builds payload for the request of list hold messages command.
        Args:
            args: arguments given to command.

        Returns: the payload to be sent to the API.


        """
    admin = argToBoolean(args.get('admin'))
    from_date = arg_to_datetime(args.get('from_date')).isoformat() if args.get('from_date') else None  # type: ignore
    to_date = arg_to_datetime(args.get('to_date')).isoformat() if args.get('to_date') else None  # type: ignore
    value = args.get('value', '')
    field_name = args.get('field_name', '')
    limit = arg_to_number(args.get('limit')) or 20
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    data = [
        {
            'admin': admin,
            'start': from_date,
            'end': to_date
        }
    ]
    if field_name or value:
        data[0].update({'searchBy': {
            'fieldName': field_name,
            'value': value
        }})
    return request_with_pagination(api_endpoint='/api/gateway/get-hold-message-list',
                                   data=data,
                                   limit=limit,
                                   page=page,
                                   page_size=page_size)


def reject_held_message_request(args):
    """

        Builds payload for the request of reject hold messages command.
        Args:
            args: arguments given to command.

        Returns: the payload to be sent to the API.


    """
    ids = argToList(args.get('ids'))
    message = args.get('message')
    reason_type = args.get('reason_type')
    notify = argToBoolean(args.get('notify'))
    payload = {'data': [
        {
            'message': message,
            'ids': ids,
            'reasonType': reason_type,
            'notify': notify
        }
    ]
    }
    return http_request('POST',
                        api_endpoint='/api/gateway/hold-reject',
                        payload=payload)


def release_held_message_request(id):
    """

      Builds payload for the request of release hold messages command.
      Args:
          args: arguments given to command.

      Returns: the payload to be sent to the API.

      """
    payload = {
        'data': [
            {
                'id': id
            }
        ]
    }
    return http_request('POST',
                        api_endpoint='/api/gateway/hold-release',
                        payload=payload)


def search_processing_message_request(args):
    """

      Builds payload for the request of search processing message command.
      Args:
          args: arguments given to command.

      Returns: the payload to be sent to the API.

      """
    sort_order = args.get('sort_order')
    from_date = arg_to_datetime(args.get('from_date')).isoformat() if args.get('from_date') else None  # type: ignore
    to_date = arg_to_datetime(args.get('to_date')).isoformat() if args.get('to_date') else None  # type: ignore
    attachments = argToBoolean(args.get('attachments')) if args.get('attachments') else None
    value = args.get('value')
    field_name = args.get('field_name')
    route = args.get('route')
    limit = arg_to_number(args.get('limit')) or 20
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    data = [
        {
            'sortOrder': sort_order,
        }
    ]
    if to_date:
        data[0].update({'end': to_date})
    if from_date:
        data[0].update({'start': from_date})
    if value or field_name:
        data[0].update({'searchBy': {
            'fieldName': field_name,
            'value': value
        }})
    if attachments or route:
        data[0].update({'filterBy': [
            {
                'attachments': attachments,
                'route': route
            }
        ]})
    return request_with_pagination(api_endpoint='/api/gateway/find-processing-messages',
                                   data=data,
                                   response_param='messages',
                                   limit=limit,
                                   page=page,
                                   page_size=page_size)


def list_email_queues_request(args):
    """

      Builds payload for the request of list email queues command.
      Args:
          args: arguments given to command.

      Returns: the payload to be sent to the API.

      """

    from_date = arg_to_datetime(args.get('from_date')).isoformat() if args.get('from_date') else None  # type: ignore
    to_date = arg_to_datetime(args.get('to_date')).isoformat() if args.get('to_date') else None  # type: ignore
    payload = {'data': [{
        'start': from_date,
        'end': to_date
    }]}

    return http_request('POST',
                        api_endpoint='/api/email/get-email-queues',
                        payload=payload)


''' HELPER FUNCTIONS '''


def determine_ssl_usage():
    global USE_SSL

    old_insecure = demisto.params().get('insecure', None)
    if old_insecure:
        USE_SSL = bool(old_insecure)
        return

    USE_SSL = not demisto.params().get('new_insecure')


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def auto_refresh_token():
    """
    Check if we have a valid token, if not automatically renew validation time for 3 days when necessary params are provided
    """
    if APP_ID and EMAIL_ADDRESS and PASSWORD:
        integration_context = demisto.getIntegrationContext()
        last_update_ts = integration_context.get('token_last_update')
        current_ts = epoch_seconds()
        if (last_update_ts and current_ts - last_update_ts > 60 * 60 * 24 * 3 - 1800) or last_update_ts is None:
            refresh_token_request()
            current_ts = epoch_seconds()
            demisto.setIntegrationContext({'token_last_update': current_ts})


def updating_token_oauth2():
    """
    Ensures the OAuth2 token is up to date, refreshing it if necessary.

    Returns:
        str: The updated OAuth2 token.
    """
    global TOKEN_OAUTH2
    global USE_SSL
    USE_SSL = False

    integration_context = demisto.getIntegrationContext()
    current_ts = epoch_seconds()
    last_update_ts = integration_context.get("last_update")
    if last_update_ts is None or (current_ts - last_update_ts > 15 * 60):
        TOKEN_OAUTH2 = token_oauth2_request()
        if TOKEN_OAUTH2:
            token_oauth2 = {"value": TOKEN_OAUTH2, "last_update": current_ts}
            demisto.setIntegrationContext(token_oauth2)
    else:
        TOKEN_OAUTH2 = integration_context.get("value")


def generate_user_auth_headers(api_endpoint):
    # type: (str) -> dict
    """
        Generate headers for a request
        Args:
            api_endpoint: The request's endpoint

        Returns:
            A dict of headers for the request
        """
    # Generate request header values
    request_id = str(uuid.uuid4())
    hdr_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

    # DataToSign is used in hmac_sha1
    dataToSign = ':'.join([hdr_date, request_id, api_endpoint, APP_KEY])

    # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
    hmac_sha1 = hmac.new(base64.b64decode(SECRET_KEY), dataToSign.encode(), digestmod=hashlib.sha1).digest()

    # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
    signature = base64.b64encode(hmac_sha1).rstrip()
    # Create request headers
    headers = {
        'Authorization': 'MC ' + ACCESS_KEY + ':' + signature.decode(),
        'x-mc-app-id': APP_ID,
        'x-mc-date': hdr_date,
        'x-mc-req-id': request_id,
        'Content-Type': 'application/json'
    }
    return headers


def parse_query_args(args):
    query_xml = default_query_xml
    if args.get('pageSize'):
        query_xml = query_xml.replace('page-size=\"25\"', 'page-size=\"' + args.get('pageSize') + '\"')
    if args.get('startRow'):
        query_xml = query_xml.replace('startrow=\"0\"', 'startrow=\"' + args.get('startRow') + '\"')
    if args.get('active') == 'true':
        query_xml = query_xml.replace('active=\"false\"', 'active=\"true\"')
    if args.get('body'):
        query_xml = query_xml.replace('<text></text>', '<text>(body: ' + args.get('body') + ')</text>')
    if args.get('subject'):
        query_xml = query_xml.replace('<text></text>', '<text>subject: ' + args.get('subject') + '</text>')
    if args.get('text'):
        query_xml = query_xml.replace('<text></text>', '<text>' + args.get('text') + '</text>')
    if args.get('date'):
        query_xml = query_xml.replace('<date select=\"last_year\"/>', '<date select=\"' + args.get('date') + '\"/>')

        if args.get('dateTo') or args.get('dateFrom'):
            raise Exception('Cannot use both date and dateFrom/dateTo arguments')

    date_to = ""
    date_from = ""

    if args.get('dateTo'):
        date_to = args.get('dateTo')
    if args.get('dateFrom'):
        date_from = args.get('dateFrom')
    if date_to and date_from:
        query_xml = query_xml.replace('<date select=\"last_year\"/>',
                                      '<date select=\"between\" from=\"' + date_from + '\" to=\"' + date_to + '\" />')
    elif date_from:
        query_xml = query_xml.replace('<date select=\"last_year\"/>',
                                      '<date select=\"between\" from=\"' + date_from + '\" />')
    elif date_to:
        query_xml = query_xml.replace('<date select=\"last_year\"/>',
                                      '<date select=\"between\" to=\"' + date_to + '\" />')

    sent_from = ""
    sent_to = ""
    if args.get('sentFrom'):
        sent_from = args.get('sentFrom')
    if args.get('sentTo'):
        sent_to = args.get('sentTo')
    if sent_from and sent_to:
        query_xml = query_xml.replace('<sent></sent>', f'<sent select=\"from\" >{sent_from}</sent>'
                                                       f'<sent select=\"to\" >{sent_to}</sent>')
    elif sent_from:
        query_xml = query_xml.replace('<sent></sent>', '<sent select=\"from\" >' + sent_from + '</sent>')
    elif sent_to:
        query_xml = query_xml.replace('<sent></sent>', '<sent select=\"to\" >' + sent_to + '</sent>')
    query_xml = query_xml.replace('<sent></sent>', '')  # no empty tag

    if args.get('attachmentText'):
        query_xml = query_xml.replace('</docs>', args.get('attachmentText') + '</docs>')
    if args.get('attachmentType'):
        query_xml = query_xml.replace('<docs select=\"optional\">',
                                      '<docs select=\"' + args.get('attachmentType') + '\">')

    return query_xml


def build_recipient_info(recipient_info: dict):
    """
    Builds markdown table for recipient info part of the response for get-message-info command

    """
    message_info = recipient_info.get('messageInfo', {})
    meta_info = recipient_info.get('recipientMetaInfo', {})
    message_info.update(meta_info)

    headers = {'fromEnv': 'From (Header)',
               'remoteIp': 'Remote Ip',
               'senderIP': 'IP Address',
               'remoteHost': 'Remote Host',
               'encryptionInfo': 'Recipient Encryption Info'}
    return tableToMarkdown('Recipient Info', t=message_info,
                           headerTransform=lambda header: headers.get(
                               header) if header in headers else header.capitalize(), removeNull=True,
                           headers=['fromHeader', 'subject', 'sent', 'remoteIp', 'remoteHost', 'encryptionInfo'])


def build_delivered_message(delivered_messgae: dict, to: List):
    """
    Builds markdown table for delivered message part of the response for get-message-info command
    Args:
        to: list of recipients that received the message.


    """
    markdown_per_recipient = '### Delivered Message Info\n'
    for to_mail in to:
        delivered = delivered_messgae.get(to_mail, {})
        message_info = delivered.get('messageInfo', {})
        to_cc_transformer = JsonTransformer(func=lambda data: ', '.join(data))
        table_json_transformer = {'to': to_cc_transformer,
                                  'cc': to_cc_transformer
                                  }
        markdown_per_recipient += tableToMarkdown(to_mail, t=message_info,
                                                  headerTransform=lambda header: header.capitalize(),
                                                  json_transform_mapping=table_json_transformer,
                                                  removeNull=True,
                                                  headers=['to', 'cc', 'subject', 'sent'])

    return markdown_per_recipient


def build_retention_info(retention_info: dict):
    """
    Builds markdown table for retention info part of the response for get-message-info command
    """
    arr_transformer = JsonTransformer(func=lambda arr: ', '.join(arr))
    table_json_transformer = {'litigationHoldInfo': arr_transformer,
                              'fbrStamps': arr_transformer,
                              'smartTags': arr_transformer,
                              'fbrExpireCheck': arr_transformer,
                              'audits': arr_transformer
                              }

    return tableToMarkdown('Retention Info', t=retention_info,
                           headerTransform=string_to_table_header,
                           json_transform_mapping=table_json_transformer,
                           removeNull=True)


def build_spam_info(spam_info: dict):
    """
    Builds markdown table for spam info part of the response for get-message-info command

    """
    spam_processing_detail = spam_info.get('spamProcessingDetail', {})
    spam_info.update(spam_processing_detail)
    spam_info.pop('spamProcessingDetail', None)

    headers = {'spamScore': 'Spam Score',
               'detectionLevel': 'Spam Detection Level',
               'permittedSender': 'PermittedSender'
               }
    return tableToMarkdown('Spam Info', t=spam_info,
                           headerTransform=lambda header: headers.get(
                               header) if header in headers else header.capitalize(),
                           removeNull=True,
                           )


def transformer_get_value(value):
    """
    Returns a transformer function to use in table_to_markdown function to get a value from a dict in a cell.
    Args:
        value: the value key to get his value from the dict.

    Returns: transformer function

    """

    def transformer(dict_value):
        return dict_value.get(value)

    return transformer


def build_get_message_info_outputs(outputs: dict):
    """

    Args:
        response: response from API

    Returns: outputs dictionary without dynamic keys.

    """

    delivered_message = outputs.get('deliveredMessage', {})
    result_emails = []
    for email in delivered_message:
        info_for_mail = delivered_message.get(email)
        info_for_mail.update({'mail_address': email})
        result_emails.append(info_for_mail)
    outputs.update({'deliveredMessage': result_emails})


def build_get_message_info_for_specific_id(id, show_recipient_info, show_delivered_message, show_retention_info,
                                           show_spam_info):
    """

    Args:
        id: message id to search.
        show_recipient_info: boolean deciding if to show recipient info in the readable output.
        show_delivered_message: boolean deciding if to show delivered info in the readable output.
        show_retention_info: boolean deciding if to show terention info in the readable output.
        show_spam_info: boolean deciding if to show spam info in the readable output.

    Returns:
        CommandResults object with data for the specific id.

    """
    total_markdown = ''
    outputs = {}

    response = get_message_info_request(id)

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    response_data = response.get('data')[0]
    recipient_info = response_data.get('recipientInfo', {})
    delivered_message = response_data.get('deliveredMessage', {})
    retention_info = response_data.get('retentionInfo', {})
    spam_info = response_data.get('spamInfo', {})
    to_list = recipient_info.get('messageInfo', {}).get('to', [])

    outputs.update({'status': response_data.get('status', '')})
    outputs.update({'id': response_data.get('id', '')})
    total_markdown += tableToMarkdown('Message Information', t=outputs)
    if show_recipient_info:
        total_markdown += build_recipient_info(recipient_info)
        outputs.update({'recipientInfo': recipient_info})
    if show_delivered_message:
        total_markdown += build_delivered_message(delivered_message, to_list)
        outputs.update({'deliveredMessage': delivered_message})
    if show_retention_info:
        total_markdown += build_retention_info(retention_info)
        outputs.update({'retentionInfo': retention_info})
    if show_spam_info:
        total_markdown += build_spam_info(spam_info)
        outputs.update({'spamInfo': spam_info})

    build_get_message_info_outputs(outputs)

    return CommandResults(
        outputs_prefix='Mimecast.MessageInfo',
        outputs_key_field='id',
        readable_output=total_markdown,
        outputs=outputs,
        raw_response=response
    )


'''COMMANDS '''


def test_module():
    if USE_OAUTH2:
        list_policies_command({'policyType': 'blockedsenders', 'limit': 1})
        return 'ok'

    if ACCESS_KEY:
        list_managed_url()
        return 'ok'

    raise Exception(
        "Cannot test a valid connection without the Client ID and Client Secret parameters for API 2.0\
        or without the Access Key parameter for API 1.0."
    )


def parse_queried_fields(query_xml: str) -> tuple[str, ...]:
    if not query_xml:
        return ()

    if not (fields := ElementTree.fromstring(query_xml).find('.//return-fields')):  # noqa:S314 - argument set by user
        demisto.debug("could not find a 'return-fields' section - will only return default fields")
        return ()
    return tuple(field.text for field in fields if field is not None and field.text)


DEFAULT_QUERY_KEYS = frozenset(('subject', 'displayfrom', 'displayto', 'receiveddate', 'size', 'attachmentcount', 'status', 'id'))


def query(args: dict):

    if args.get('queryXml'):
        query_xml = args.get('queryXml', '')
    else:
        query_xml = parse_query_args(args)

    additional_keys = sorted(set(parse_queried_fields(query_xml)).difference(DEFAULT_QUERY_KEYS))  # non-default keys in query)
    headers = ['Subject', 'Display From', 'Display To', 'Received Date', 'Size', 'Attachment Count', 'Status',
               'ID'] + additional_keys
    contents = []
    messages_context = []
    limit = arg_to_number(args.get('limit')) or 20
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))

    if args.get('dryRun') == 'true':
        return query_xml

    # API request demands admin boolean, since we don't have any other support but admin we simply pass true.
    data = [{
        'admin': True,
        'query': query_xml
    }]
    messages, _, _ = request_with_pagination(api_endpoint='/api/archive/search',
                                             data=data,
                                             response_param='items',
                                             limit=limit,
                                             page=page,
                                             page_size=page_size)

    for message in messages:
        additional_dict = {k: message[k] for k in additional_keys}

        contents.append({
            'Subject': message.get('subject'),
            'Display From': message.get('displayfrom'),
            'Display To': message.get('displayto'),
            'Received Date': message.get('receiveddate'),
            'Size': message.get('size'),
            'Attachment Count': message.get('attachmentcount'),
            'Status': message.get('status'),
            'ID': message.get('id')
        } | additional_dict)
        messages_context.append({
            'Subject': message.get('subject'),
            'Sender': message.get('displayfrom'),
            'Recipient': message.get('displayto'),
            'ReceivedDate': message.get('receiveddate'),
            'Size': message.get('size'),
            'AttachmentCount': message.get('attachmentcount'),
            'Status': message.get('status'),
            'ID': message.get('id')
        } | additional_dict)

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast archived emails', contents, headers),
        'EntryContext': {'Mimecast.Message(val.ID && val.ID == obj.ID)': messages_context}
    }


def url_decode():
    headers = []  # type: List[str]
    contents = {}
    context = {}
    protected_url = demisto.args().get('url')
    decoded_url = url_decode_request(protected_url)
    contents['Decoded URL'] = decoded_url
    context[outputPaths['url']] = {
        'Data': protected_url,
        'Mimecast': {
            'DecodedURL': decoded_url
        }
    }

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast Decoded URL:', contents, headers),
        'EntryContext': context
    }

    return results


def url_decode_request(url):
    # Setup required variables
    api_endpoint = '/api/ttp/url/decode-url'
    payload = {
        'data': [
            {
                'url': url
            }
        ]
    }
    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    if not response.get('data')[0].get('url'):
        raise Exception('No URL has been returned from the service')
    return response.get('data')[0].get('url')


def list_blocked_sender_policies_command(args):
    headers = ['Policy ID', 'Sender', 'Reciever', 'Bidirectional', 'Start', 'End']
    contents = []
    context = {}
    policy_id = args.get('policyID')
    title = 'Mimecast list blocked sender policies: \n These are the existing blocked sender Policies:'

    if policy_id:
        title = 'Mimecast Get Policy'

    policies_list = get_policy_request(policy_type='blockedsenders', policy_id=policy_id)
    policies_context = []
    for policy_list in policies_list:
        policy = policy_list.get('policy', {})
        sender = policy.get('from', {})
        reciever = policy.get('to', {})
        contents.append({
            'Policy ID': policy_list['id'],
            'Sender': {
                'Group': sender.get('groupId'),
                'Email Address': sender.get('emailAddress'),
                'Domain': sender.get('emailDomain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Email Address': reciever.get('emailAddress'),
                'Domain': reciever.get('emailDomain'),
                'Type': reciever.get('type')
            },
            'Bidirectional': policy.get('bidirectional'),
            'Start': policy.get('fromDate'),
            'End': policy.get('toDate')
        })
        policies_context.append({
            'ID': policy_list['id'],
            'Sender': {
                'Group': sender.get('groupId'),
                'Address': sender.get('emailAddress'),
                'Domain': sender.get('emailDomain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Address': reciever.get('emailAddress'),
                'Domain': reciever.get('emailDomain'),
                'Type': reciever.get('type')
            },
            'Bidirectional': policy.get('bidirectional'),
            'FromDate': policy.get('fromDate'),
            'ToDate': policy.get('toDate')
        })

    context['Mimecast.Policy(val.ID && val.ID == obj.ID)'] = policies_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, headers),
        'EntryContext': context
    }

    return results


def get_policy_command(args):
    headers = ['Policy ID', 'Sender', 'Reciever', 'Bidirectional', 'Start', 'End']
    contents = []
    policy_id = args.get('policyID')
    policy_type = args.get('policyType', 'blockedsenders')
    title = f'Mimecast Get {policy_type} Policy'

    policies_list = get_policy_request(policy_type, policy_id)
    policies_context = []
    for policy_list in policies_list:
        policy = policy_list.get('policy', {})
        sender = policy.get('from', {})
        reciever = policy.get('to', {})
        contents.append({
            'Policy ID': policy_list['id'],
            'Sender': {
                'Group': sender.get('groupId'),
                'Email Address': sender.get('emailAddress'),
                'Domain': sender.get('emailDomain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Email Address': reciever.get('emailAddress'),
                'Domain': reciever.get('emailDomain'),
                'Type': reciever.get('type')
            },
            'Bidirectional': policy.get('bidirectional'),
            'Start': policy.get('fromDate'),
            'End': policy.get('toDate')
        })
        policies_context.append({
            'ID': policy_list['id'],
            'Sender': {
                'Group': sender.get('groupId'),
                'Address': sender.get('emailAddress'),
                'Domain': sender.get('emailDomain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Address': reciever.get('emailAddress'),
                'Domain': reciever.get('emailDomain'),
                'Type': reciever.get('type')
            },
            'Bidirectional': policy.get('bidirectional'),
            'FromDate': policy.get('fromDate'),
            'ToDate': policy.get('toDate')
        })

    output_type = {
        "blockedsenders": "Blockedsenders",
        "antispoofing-bypass": "AntispoofingBypassPolicy",
        "address-alteration": "AddressAlterationPolicy",
    }

    return [
        CommandResults(
            outputs_prefix="Mimecast.Policy",
            outputs=policies_context,
            readable_output=tableToMarkdown(title, contents, headers),
            outputs_key_field="id",
        ),
        CommandResults(
            outputs_prefix=f"Mimecast.{output_type[policy_type]}",
            outputs=policies_context,
            readable_output=tableToMarkdown(title, contents, headers),
            outputs_key_field="id",
        ),
    ]


def get_policy_request(policy_type='blockedsenders', policy_id=None):
    if not policy_type:
        policy_type = 'blockedsenders'
    api_endpoints = {
        'blockedsenders': 'blockedsenders/get-policy',
        'antispoofing-bypass': 'antispoofing-bypass/get-policy',
        'address-alteration': 'address-alteration/get-address-alteration-set',
    }
    api_endpoint = f'/api/policy/{api_endpoints[policy_type]}'
    data = []

    id = 'id' if policy_type != 'address-alteration' else 'folderId'

    if policy_id:
        data.append({
            id: policy_id
        })
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')


def get_arguments_for_policy_command(args):
    # type: (dict) -> tuple[dict, str]
    """
      Args:
          args: Demisto arguments

      Returns:
          tuple. policy arguments, and option to choose from the policy configuration.
     """

    spf_domain = args.get('spf_domain')
    bidirectional = argToBoolean(args.get('bidirectional')) if args.get('bidirectional') else ""
    comment = args.get('comment', '')
    enabled = argToBoolean(args.get('enabled')) if args.get('enabled') else ""
    enforced = argToBoolean(args.get('enforced')) if args.get('enforced') else ""
    from_date = arg_to_datetime(args.get('from_date')).strftime(DATE_FORMAT) if args.get('from_date') else ""  # type: ignore
    from_eternal = argToBoolean(args.get('from_eternal')) if args.get('from_eternal') else ""
    to_date = arg_to_datetime(args.get('to_date')).strftime(DATE_FORMAT) if args.get('to_date') else ""  # type: ignore
    to_eternal = argToBoolean(args.get('to_eternal')) if args.get('to_eternal') else ""
    override = argToBoolean(args.get('override')) if args.get('override') else ""
    description = args.get('description', '') or args.get('policy_description', '')
    from_part = args.get('fromPart', '') or args.get('from_part', '')
    from_type = args.get('fromType', '') or args.get('from_type', '')
    from_value = args.get('fromValue', '') or args.get('from_value', '')
    to_type = args.get('toType', '') or args.get('to_type', '')
    conditions = args.get('conditions')
    to_value = args.get('toValue', '') or args.get('to_value', '')
    option = str(args.get('option', ''))
    policy_obj: dict[str, Any] = {
        'description': description,
        'fromType': from_type,
        'fromValue': from_value,
        'toType': to_type,
        'toValue': to_value,
        'bidirectional': bidirectional,
        'comment': comment,
        'enabled': enabled,
        'enforced': enforced,
        'override': override,
        "toDate": to_date,
        'fromPart': from_part,
        'fromDate': from_date,
        'fromEternal': from_eternal,
        'toEternal': to_eternal
    }

    if spf_domain:
        policy_obj['conditions'] = {'spfDomains': [spf_domain]}

    if conditions:
        policy_obj['conditions'] = {'sourceIPs': [conditions]}

    return policy_obj, option


def create_block_sender_policy_command(policy_args):
    headers = ['Policy ID', 'Description', 'Sender', 'Receiver', 'Bidirectional', 'Start', 'End']
    policy_obj, option = get_arguments_for_policy_command(policy_args)
    policy_list = create_or_update_policy_request(policy_obj, option)
    policy = policy_list.get('policy')
    policy_id = policy_list.get('id')
    title = 'Mimecast Create block sender Policy: \n Policy Was Created Successfully!'
    sender = policy.get('from')
    receiver = policy.get('to')
    description = policy.get('description')
    content = {
        'Policy ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Email Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Reciever': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'Start': policy.get('fromDate'),
        'End': policy.get('toDate')
    }  # type: Dict[Any, Any]
    policies_context = {
        'ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Reciever': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'FromDate': policy.get('fromDate'),
        'ToDate': policy.get('toDate')
    }  # type: Dict[Any, Any]

    return CommandResults(
        outputs_prefix='Mimecast.BlockedSendersPolicy',
        outputs=policies_context,
        readable_output=tableToMarkdown(title, content, headers),
        outputs_key_field='id'
    )


def create_policy_command():
    headers = ['Policy ID', 'Description', 'Sender', 'Receiver', 'Bidirectional', 'Start', 'End']
    context = {}
    policy_args = demisto.args()
    policy_obj, option = get_arguments_for_policy_command(policy_args)
    policy_list = create_or_update_policy_request(policy_obj, option)
    policy = policy_list.get('policy')
    policy_id = policy_list.get('id')
    title = 'Mimecast Create block sender Policy: \n Policy Was Created Successfully!'
    sender = policy.get('from')
    receiver = policy.get('to')
    description = policy.get('description')
    content = {
        'Policy ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Email Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Reciever': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'Start': policy.get('fromDate'),
        'End': policy.get('toDate')
    }  # type: Dict[Any, Any]
    policies_context = {
        'ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Reciever': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'FromDate': policy.get('fromDate'),
        'ToDate': policy.get('toDate')
    }  # type: Dict[Any, Any]

    context['Mimecast.Policy(val.ID && val.ID == obj.ID)'] = policies_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': policy_list,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, content, headers),
        'EntryContext': context
    }

    return results


def set_empty_value_args_policy_update(policy_obj, option, policy_id):
    """
    The function use the get policy request function to fill the empty arguments in the policy

    Args:
        policy_obj (Dict): Dict of policy details
        option: (str) Policy option
        policy_id: (str) Policy ID

    Returns:
          Tuple. Policy object, the option to configure on the policy, policy id.
     """
    empty_args_list = []
    # Add the empty arguments to empty args list
    for arg, value in policy_obj.items():
        if value == '':
            empty_args_list.append(arg)
    if option == '':
        empty_args_list.append("option")
    # Check if there are any empty arguments
    if len(empty_args_list) > 0:
        # Fill the empty arguments with the current data using get policy request function
        policy_details = get_policy_request(policy_id=policy_id)[0]
        for arg in empty_args_list:
            if arg == "option":
                option = policy_details["option"]
            else:
                policy_obj[arg] = policy_details["policy"].get(arg, "")

    return policy_obj, option, policy_id


def update_policy_command():
    """
          Update policy according to policy ID
     """
    headers = ['Policy ID', 'Description', 'Sender', 'Receiver', 'Bidirectional', 'Start', 'End']
    context = {}
    policy_args = demisto.args()
    policy_obj, option = get_arguments_for_policy_command(policy_args)
    policy_id = str(policy_args.get('policy_id', ''))
    if not policy_id:
        raise Exception("You need to enter policy ID")
    policy_obj, option, policy_id = set_empty_value_args_policy_update(policy_obj, option, policy_id)
    response = create_or_update_policy_request(policy_obj, option, policy_id=policy_id)
    policy = response.get('policy')
    title = 'Mimecast Update Policy: \n Policy Was Updated Successfully!'
    sender = policy.get('from')
    receiver = policy.get('to')
    description = policy.get('description')
    contents = {
        'Policy ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Email Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'Start': policy.get('fromDate'),
        'End': policy.get('toDate')
    }  # type: Dict[Any, Any]
    policies_context = {
        'ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'FromDate': policy.get('fromDate'),
        'ToDate': policy.get('toDate')
    }  # type: Dict[Any, Any]

    context['Mimecast.Policy(val.ID && val.ID == obj.ID)'] = policies_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, headers),
        'EntryContext': context
    }

    return results


def update_block_sender_policy_command(policy_args):
    """
          Update policy according to policy ID
     """
    headers = ['Policy ID', 'Description', 'Sender', 'Receiver', 'Bidirectional', 'Start', 'End']
    policy_obj, option = get_arguments_for_policy_command(policy_args)
    policy_id = str(policy_args.get('policy_id', ''))
    if not policy_id:
        raise Exception("You need to enter policy ID")
    policy_obj, option, policy_id = set_empty_value_args_policy_update(policy_obj, option, policy_id)
    response = create_or_update_policy_request(policy_obj, option, policy_id=policy_id)
    policy = response.get('policy')
    title = 'Mimecast Update Policy: \n Policy Was Updated Successfully!'
    sender = policy.get('from')
    receiver = policy.get('to')
    description = policy.get('description')
    contents = {
        'Policy ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Email Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Email Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'Start': policy.get('fromDate'),
        'End': policy.get('toDate')
    }  # type: Dict[Any, Any]
    policies_context = {
        'ID': policy_id,
        'Description': description,
        'Sender': {
            'Group': sender.get('groupId'),
            'Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Receiver': {
            'Group': receiver.get('groupId'),
            'Address': receiver.get('emailAddress'),
            'Domain': receiver.get('emailDomain'),
            'Type': receiver.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'FromDate': policy.get('fromDate'),
        'ToDate': policy.get('toDate')
    }  # type: Dict[Any, Any]

    return CommandResults(
        outputs_prefix='Mimecast.BlockedSendersPolicy',
        outputs=policies_context,
        readable_output=tableToMarkdown(title, contents, headers),
        outputs_key_field='id'
    )


def create_or_update_policy_request(policy, option, policy_id=None, policy_type='blockedsenders'):
    # Setup required variables

    # Using dictionary comprehension to filter out keys with None or empty string values
    policy = {k: v for k, v in policy.items() if v is not None and v != ""}

    api_endpoint = '/api/policy/blockedsenders/create-policy'
    payload = {
        'data': [{
            'policy': policy,
            'option': option
        }]
    }
    # Policy ID isnt None if it is an update policy request cause its required to
    # write a policy ID on update policy command
    if policy_id:
        payload['data'][0]['id'] = policy_id
    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def delete_policy(args):
    policy_id = args.get('policyID')
    policy_type = args.get('policyType')

    delete_policy_request(policy_type, policy_id)

    context = {
        'ID': policy_id,
        'Deleted': True
    }

    output_type = {
        'blockedsenders': 'Blockedsenders',
        'antispoofing-bypass': 'AntispoofingBypassPolicy',
        'address-alteration': 'AddressAlterationPolicy',
    }

    return [
        CommandResults(
            outputs_prefix="Mimecast.Policy",
            outputs=context,
            readable_output=f"Mimecast Policy {policy_id} deleted successfully!",
            outputs_key_field="ID",
        ),
        CommandResults(
            outputs_prefix=f"Mimecast.{output_type[policy_type]}",
            outputs=context,
            readable_output=f"Mimecast Policy {policy_id} deleted successfully!",
            outputs_key_field="ID",
        ),
    ]


def delete_policy_request(policy_type, policy_id=None):
    # Setup required variables
    api_endpoints = {
        'antispoofing-bypass': 'antispoofing-bypass/delete-policy',
        'address-alteration': 'address-alteration/delete-policy',
        'blockedsenders': 'blockedsenders/delete-policy'
    }
    api_endpoint = f'/api/policy/{api_endpoints[policy_type]}'
    id = 'id'

    data = [{
        id: policy_id
    }]

    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    if response.get('data')[0].get('id') != policy_id:
        raise Exception('Policy was not deleted.')
    return response.get('data')[0]


def manage_sender():
    headers = []  # type: List[str]
    context = {}
    sender = demisto.args().get('sender')
    recipient = demisto.args().get('recipient')
    action = demisto.args().get('action')
    title_action = 'permitted' if action == 'permit' else 'blocked'
    title = f'Mimecast messages from {sender} to {recipient} will now be {title_action}!'

    req_obj = {
        'sender': sender,
        'to': recipient,
        'action': action
    }

    managed_sender = manage_sender_request(req_obj)

    contents = {
        'Sender': managed_sender.get('sender'),
        'Recipient': managed_sender.get('to'),
        'Action': managed_sender.get('type'),
        'ID': managed_sender.get('id')
    }

    context['Mimecast.Managed(val.ID && val.ID == obj.ID)'] = {
        'Sender': managed_sender.get('sender'),
        'Recipient': managed_sender.get('to'),
        'Action': managed_sender.get('type'),
        'ID': managed_sender.get('id')
    }

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, headers),
        'EntryContext': context
    }

    return results


def manage_sender_request(req_obj):
    # Setup required variables
    api_endpoint = '/api/managedsender/permit-or-block-sender'
    data = []
    data.append(req_obj)
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def list_managed_url():
    headers = ['URL', 'Action', 'Match Type', 'User Awareness', 'URL Rewriting', 'Comment']
    contents = []
    context = {}
    managed_urls_context = []
    full_url_response = ''
    url = demisto.args().get('url')

    managed_urls = list_managed_url_request()
    for managed_url in managed_urls:
        query_string = ''
        scheme = ''
        if managed_url.get('queryString'):
            query_string = '?' + managed_url.get('queryString')
        if managed_url.get('scheme'):
            scheme = managed_url.get('scheme') + '://'
        full_url_response = scheme + managed_url.get('domain', '') + managed_url.get('path', '') + query_string
        if (url and url in full_url_response) or not url:
            contents.append({
                'URL': full_url_response,
                'Match Type': managed_url.get('matchType'),
                'Comment': managed_url.get('comment'),
                'Action': managed_url.get('action'),
                'URL Rewriting': managed_url.get('disableRewrite'),
                'User Awareness': managed_url.get('disableUserAwareness')
            })
            managed_urls_context.append({
                'Domain': managed_url.get('domain'),
                'disableLogClick': managed_url.get('disableLogClick'),
                'Action': managed_url.get('action'),
                'Path': managed_url.get('path'),
                'matchType': managed_url.get('matchType'),
                'ID': managed_url.get('id'),
                'disableRewrite': managed_url.get('disableRewrite')
            })

    context['Mimecast.URL(val.ID && val.ID == obj.ID)'] = managed_urls_context
    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast Managed URLs: ', contents, headers),
        'EntryContext': context
    }

    return results


def list_managed_url_request():
    # Setup required variables
    api_endpoint = '/api/ttp/url/get-all-managed-urls'
    data = []  # type: List[Any]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')


def create_managed_url():
    context = {}
    contents = {}  # type: Dict[Any, Any]
    managed_urls_context = []
    url = demisto.args().get('url')
    action = demisto.args().get('action')
    match_type = demisto.args().get('matchType')
    disable_rewrite = demisto.args().get('disableRewrite')
    disable_user_awareness = demisto.args().get('disableUserAwareness')
    disable_log_click = demisto.args().get('disableLogClick')
    comment = demisto.args().get('comment')

    url_req_obj = {
        'comment': comment,
        'disableRewrite': disable_rewrite,
        'url': url,
        'disableUserAwareness': disable_user_awareness,
        'disableLogClick': disable_log_click,
        'action': action,
        'matchType': match_type
    }

    managed_url = create_managed_url_request(url_req_obj)
    managed_urls_context.append({
        'Domain': managed_url.get('domain'),
        'disableLogClick': managed_url.get('disableLogClick'),
        'Action': managed_url.get('action'),
        'Path': managed_url.get('path'),
        'matchType': managed_url.get('matchType'),
        'ID': managed_url.get('id'),
        'disableRewrite': managed_url.get('disableRewrite')
    })

    context['Mimecast.URL(val.ID && val.ID == obj.ID)'] = managed_urls_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Managed URL {url} created successfully!',
        'EntryContext': context
    }

    return results


def create_managed_url_request(url_obj):
    # Setup required variables
    api_endpoint = '/api/ttp/url/create-managed-url'
    data = []
    data.append(url_obj)
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def list_messages():
    headers = ['Subject', 'Size', 'Recieved Date', 'From', 'Attachment Count', 'Message ID']
    context = {}
    contents = []
    messages_context = []
    search_params = {}

    limit = arg_to_number(demisto.args().get('limit')) or 20
    page = arg_to_number(demisto.args().get('page'))
    page_size = arg_to_number(demisto.args().get('page_size'))

    # can't send null values for keys, so if optional value not sent by user, do not add to request.
    mailbox = demisto.args().get('mailbox', '')
    if mailbox:
        search_params['mailbox'] = mailbox
    view = demisto.args().get('view', '')
    if view:
        search_params['view'] = view
    end_time = demisto.args().get('endTime', '')
    if end_time:
        search_params['end'] = end_time
    start_time = demisto.args().get('startTime', '')
    if start_time:
        search_params['start'] = start_time
    subject = demisto.args().get('subject')

    messages_list, _, _ = request_with_pagination(api_endpoint='/api/archive/get-message-list',
                                                  data=[search_params],
                                                  limit=limit,
                                                  page=page,
                                                  page_size=page_size)
    for message in messages_list:
        if subject == message.get('subject') or not subject:
            contents.append({
                'Message ID': message.get('id'),
                'Subject': message.get('subject'),
                'Size': message.get('size'),
                'Recieved Date': message.get('received'),
                'From': message.get('from').get('emailAddress'),
                'Attachment Count': message.get('attachmentCount')
            })
            messages_context.append({
                'Subject': message.get('subject'),
                'ID': message.get('id'),
                'Size': message.get('size'),
                'RecievedDate': message.get('received'),
                'From': message.get('from').get('emailAddress'),
                'AttachmentCount': message.get('attachmentCount')
            })

    context['Mimecast.Message(val.ID && val.ID == obj.ID)'] = messages_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast messages list', contents, headers),
        'EntryContext': context
    }

    return results


def get_url_logs():
    """
    Getting logs using pagination as specified here
    https://www.mimecast.com/tech-connect/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/

    Returns: TTP URl logs command results

    """
    headers = []  # type: List[Any]
    contents = []
    context = {}
    url_logs_context = []
    search_params = {}
    from_date = demisto.args().get('fromDate', '')
    to_date = demisto.args().get('toDate', '')
    scan_result = demisto.args().get('resultType', '')
    limit = arg_to_number(demisto.args().get('limit')) or 20
    page = arg_to_number(demisto.args().get('page'))
    page_size = arg_to_number(demisto.args().get('page_size'))

    if from_date:
        search_params['from'] = from_date
    if to_date:
        search_params['to'] = to_date
    if scan_result:
        search_params['scanResult'] = scan_result
    url_logs, _, _ = request_with_pagination(api_endpoint='/api/ttp/url/get-logs',
                                             data=[search_params],
                                             response_param='clickLogs',
                                             limit=limit,
                                             page=page,
                                             page_size=page_size)
    for url_log in url_logs:
        contents.append({
            'Action': url_log.get('action'),
            'Admin Override': url_log.get('adminOverride'),
            'Category': url_log.get('category'),
            'Date': url_log.get('date'),
            'Route': url_log.get('route'),
            'Scan Result': url_log.get('scanResult'),
            'URL': url_log.get('url'),
            'User Awareness Action': url_log.get('userAwarenessAction'),
            'User Email Address': url_log.get('userEmailAddress'),
            'User Override': url_log.get('userOverride')
        })
        url_logs_context.append({
            'Action': url_log.get('action'),
            'AdminOverride': url_log.get('adminOverride'),
            'Category': url_log.get('category'),
            'Date': url_log.get('date'),
            'Route': url_log.get('route'),
            'Result': url_log.get('scanResult'),
            'URL': url_log.get('url'),
            'Awareness': url_log.get('userAwarenessAction'),
            'Address': url_log.get('userEmailAddress'),
            'UserOverride': url_log.get('userOverride')
        })

    context['Mimecast.UrlLog'] = url_logs_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast URL logs: ', contents, headers),
        'EntryContext': context
    }

    return results


def get_attachment_logs():
    headers = []  # type: List[Any]
    contents = []
    context = {}
    attachment_logs_context = []
    search_params = {}
    from_date = demisto.args().get('fromDate', '')
    to_date = demisto.args().get('toDate', '')
    result = demisto.args().get('resultType', '')
    limit = arg_to_number(demisto.args().get('limit')) or arg_to_number(demisto.args().get('resultsNumber')) or 20
    page = arg_to_number(demisto.args().get('page'))
    page_size = arg_to_number(demisto.args().get('page_size'))

    if from_date:
        search_params['from'] = from_date
    if to_date:
        search_params['to'] = to_date
    if result:
        search_params['result'] = result

    attachment_logs, _, _ = request_with_pagination(api_endpoint='/api/ttp/attachment/get-logs',
                                                    data=[search_params],
                                                    response_param='attachmentLogs',
                                                    limit=limit,
                                                    page=page,
                                                    page_size=page_size)

    for attachment_log in attachment_logs:
        contents.append({
            'Result': attachment_log.get('result'),
            'Date': attachment_log.get('date'),
            'Sender Address': attachment_log.get('senderAddress'),
            'File Name': attachment_log.get('fileName'),
            'Action': attachment_log.get('actionTriggered'),
            'Route': attachment_log.get('route'),
            'Details': attachment_log.get('details'),
            'Recipient Address': attachment_log.get('recipientAddress'),
            'File Type': attachment_log.get('fileType')
        })
        attachment_logs_context.append({
            'Result': attachment_log.get('result'),
            'Date': attachment_log.get('date'),
            'Sender': attachment_log.get('senderAddress'),
            'FileName': attachment_log.get('fileName'),
            'Action': attachment_log.get('actionTriggered'),
            'Route': attachment_log.get('route'),
            'Details': attachment_log.get('details'),
            'Recipient': attachment_log.get('recipientAddress'),
            'FileType': attachment_log.get('fileType')
        })

    context['Mimecast.AttachmentLog'] = attachment_logs_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast attachment logs: ', contents, headers),
        'EntryContext': context
    }

    return results


def get_impersonation_logs():
    headers = []  # type: List[Any]
    contents = []
    context = {}
    impersonation_logs_context = []
    search_params = {}
    from_date = demisto.args().get('fromDate', '')
    to_date = demisto.args().get('toDate', '')
    tagged_malicious = demisto.args().get('taggedMalicious', '')
    search_field = demisto.args().get('searchField', '')
    query = demisto.args().get('query', '')
    identifiers = argToList(demisto.args().get('identifiers', ''))
    actions = argToList(demisto.args().get('actions', ''))
    limit = arg_to_number(demisto.args().get('limit')) or arg_to_number(demisto.args().get('resultsNumber')) or 20
    page = arg_to_number(demisto.args().get('page'))
    page_size = arg_to_number(demisto.args().get('pageSize'))

    if from_date:
        search_params['from'] = from_date
    if to_date:
        search_params['to'] = to_date
    if tagged_malicious:
        search_params['taggedMalicious'] = tagged_malicious
    if search_field:
        search_params['searchField'] = search_field
    if query:
        search_params['query'] = query
    if identifiers:
        search_params['identifiers'] = identifiers
    if actions:
        search_params['actions'] = actions

    impersonation_logs, result_count, _ = request_with_pagination(api_endpoint='/api/ttp/impersonation/get-logs',
                                                                  data=[search_params],
                                                                  response_param='impersonationLogs',
                                                                  limit=limit,
                                                                  page=page,
                                                                  page_size=page_size)

    for impersonation_log in impersonation_logs:
        contents.append({
            'Result Count': result_count,
            'Hits': impersonation_log.get('hits'),
            'Malicious': impersonation_log.get('taggedMalicious'),
            'Sender IP': impersonation_log.get('senderIpAddress'),
            'Sender Address': impersonation_log.get('senderAddress'),
            'Subject': impersonation_log.get('subject'),
            'Identifiers': impersonation_log.get('identifiers'),
            'Date': impersonation_log.get('eventTime'),
            'Action': impersonation_log.get('action'),
            'Policy': impersonation_log.get('definition'),
            'ID': impersonation_log.get('id'),
            'Recipient Address': impersonation_log.get('recipientAddress'),
            'External': impersonation_log.get('taggedExternal')
        })
        impersonation_logs_context.append({
            'ResultCount': result_count,
            'Hits': impersonation_log.get('hits'),
            'Malicious': impersonation_log.get('taggedMalicious'),
            'SenderIP': impersonation_log.get('senderIpAddress'),
            'SenderAddress': impersonation_log.get('senderAddress'),
            'Subject': impersonation_log.get('subject'),
            'Identifiers': impersonation_log.get('identifiers'),
            'Date': impersonation_log.get('eventTime'),
            'Action': impersonation_log.get('action'),
            'Policy': impersonation_log.get('definition'),
            'ID': impersonation_log.get('id'),
            'RecipientAddress': impersonation_log.get('recipientAddress'),
            'External': impersonation_log.get('taggedExternal')
        })

    context['Mimecast.Impersonation'] = impersonation_logs_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast impersonation logs: ', contents, headers),
        'EntryContext': context
    }

    return results


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')
    last_fetch_held_messages = last_run.get('time_held_messages')
    demisto.debug(f"Before fetch {last_run=}")

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(hours=FETCH_DELTA)
        last_fetch_held_messages = last_fetch
        last_fetch_date_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S") + '+0000'
        last_fetch_held_messages_date_time = last_fetch_date_time
    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')
        last_fetch_date_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S") + '+0000'
        if last_fetch_held_messages:
            last_fetch_held_messages = datetime.strptime(last_fetch_held_messages, '%Y-%m-%dT%H:%M:%SZ')
            last_fetch_held_messages_date_time = last_fetch_held_messages.strftime("%Y-%m-%dT%H:%M:%S") + '+0000'
        else:
            last_fetch_held_messages = last_fetch
            last_fetch_held_messages_date_time = last_fetch_date_time
    current_fetch = last_fetch
    current_fetch_held_message = last_fetch_held_messages
    demisto.debug(f"handle_first_time_fetch {current_fetch=}, {last_fetch=}, "
                  f"{last_fetch_date_time=}, {current_fetch_held_message=}, {last_fetch_held_messages=},"
                  f" {last_fetch_held_messages_date_time=}")

    incidents = []  # type: List[Any]
    if FETCH_URL:
        search_params = {
            'from': last_fetch_date_time,
            'scanResult': 'malicious'
        }
        url_logs, _, _ = request_with_pagination(api_endpoint='/api/ttp/url/get-logs',
                                                 data=[search_params],
                                                 response_param='clickLogs',
                                                 limit=MAX_FETCH)
        demisto.debug(f"Pulled {len(url_logs)} click logs.")
        for url_log in url_logs:
            incident = url_to_incident(url_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')
            # update last run
            if temp_date > last_fetch:
                demisto.debug(f"Increasing last_fetch since {temp_date=} but {last_fetch=}")
                last_fetch = temp_date + timedelta(seconds=1)
                demisto.debug(f"Increased last_fetch to {last_fetch}")

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)
            else:
                demisto.debug(f"Did not appended url_log with name {incident.get('name')} since {temp_date=}<= {current_fetch=}")

    if FETCH_ATTACHMENTS:
        search_params = {
            'from': last_fetch_date_time,
            'result': 'malicious'
        }
        demisto.debug(search_params, 'search_params')
        attachment_logs, _, _ = request_with_pagination(api_endpoint='/api/ttp/attachment/get-logs',
                                                        data=[search_params],
                                                        response_param='attachmentLogs',
                                                        limit=MAX_FETCH)
        demisto.debug(f"Pulled {len(attachment_logs)} attachment logs.")
        for attachment_log in attachment_logs:
            incident = attachment_to_incident(attachment_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')

            # update last run
            if temp_date > last_fetch:
                demisto.debug(f"Increasing last_fetch since {temp_date=} but {last_fetch=}")
                last_fetch = temp_date + timedelta(seconds=1)
                demisto.debug(f"Increased last_fetch to {last_fetch}")

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)
            else:
                demisto.debug(
                    f"Did not appended attachment_log with name {incident.get('name')} since {temp_date=}<= {current_fetch=}")

    if FETCH_IMPERSONATIONS:
        search_params = {
            'from': last_fetch_date_time,
            'taggedMalicious': True
        }
        impersonation_logs, _, _ = request_with_pagination(api_endpoint='/api/ttp/impersonation/get-logs',
                                                           data=[search_params],
                                                           response_param='impersonationLogs',
                                                           limit=MAX_FETCH)
        demisto.debug(f"number of impersonation_logs={len(impersonation_logs)}")
        for impersonation_log in impersonation_logs:
            incident = impersonation_to_incident(impersonation_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')

            # update last run
            if temp_date > last_fetch:
                demisto.debug(f"Increasing last_fetch since {temp_date=} but {last_fetch=}")
                last_fetch = temp_date + timedelta(seconds=1)
                demisto.debug(f"Increased last_fetch to {last_fetch}")

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)
            else:
                demisto.debug(
                    f"Did not appended impersonation_logs with name {incident.get('name')} since {temp_date=}<= {current_fetch=}")
    if FETCH_HELD_MESSAGES:
        next_page, next_dedup_held_messages, last_fetch_held_messages= fetch_held_messages(last_run,
                                                                  last_fetch_held_messages_date_time,
                                                                  current_fetch_held_message,
                                                                  incidents)

    time = last_fetch.isoformat().split('.')[0] + 'Z'
    time_held_messages = last_fetch_held_messages.isoformat().split('.')[0] + 'Z'
    new_last_run = {'time': time,
                    'dedup_held_messages': next_dedup_held_messages,
                    'time_held_messages': time_held_messages}
    if next_page:
        new_last_run["nextTrigger"] = "0"
        new_last_run['held_message_next_page'] = next_page
    demisto.setLastRun(new_last_run)
    demisto.debug(f"Changed last_run to {new_last_run=}")
    demisto.incidents(incidents)


def fetch_held_messages(last_run: dict,
                        last_fetch_held_messages_date_time: str,
                        current_fetch_held_message: datetime,
                        incidents: list):
    # Added dedup mechanism only to held_messages due to a bug
    next_dedup_held_messages = dedup_held_messages = last_run.get('dedup_held_messages', [])
    if not isinstance(dedup_held_messages, List):
        raise DemistoException(f"dedup_held_messages is of type {type(dedup_held_messages)}")
    current_next_page = last_run.get('held_message_next_page', '')
    demisto.debug(f"{current_next_page=}")
    demisto.debug(f"{dedup_held_messages=}")
    search_params = {
        'start': last_fetch_held_messages_date_time,
        'admin': True
    }
    held_messages, _, next_page = request_with_pagination(api_endpoint='/api/gateway/get-hold-message-list',
                                                            data=[search_params],
                                                            limit=MAX_FETCH,
                                                            dedup_held_messages=dedup_held_messages,
                                                            current_next_page=current_next_page)
    current_held_message_count = 0
    for held_message in held_messages:
        incident = held_to_incident(held_message)
        held_message_id = held_message.get('id')
        temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')
        # update last run
        if temp_date > last_fetch_held_messages:
            demisto.debug(f"Increasing last_fetch since {temp_date=} > {last_fetch_held_messages=}")
            last_fetch_held_messages = temp_date
            next_dedup_held_messages = [held_message.get('id')]
            demisto.debug(f"Increased last_fetch to {last_fetch_held_messages}")
        elif temp_date == last_fetch_held_messages:
            if isinstance(next_dedup_held_messages, List):
                next_dedup_held_messages.append(held_message_id)
                demisto.debug(f"Appended a held message {held_message_id} to dedup as temp_date=last_fetch_held_messages"
                                f"={last_fetch_held_messages}")
            else:
                demisto.debug(f"Next_dedup_held_messages is not of type List but of type "
                                f"{type(next_dedup_held_messages)}.")
        else:
            demisto.debug(f"In the else for held messages with id {held_message_id} as {temp_date=} < "
                            f"{last_fetch_held_messages=}")
        # avoid duplication due to weak time query
        if temp_date >= current_fetch_held_message:
            incidents.append(incident)
            current_held_message_count += 1
        else:
            demisto.debug(f"Did not append held_message with id {held_message_id} since {temp_date=} < "
                            f"{current_fetch_held_message=}.")
    demisto.debug(f"Pulled {len(held_messages)} held messages.")
    return next_page, next_dedup_held_messages, last_fetch_held_messages

def url_to_incident(url_log):
    incident = {}
    incident['name'] = 'Mimecast malicious URL: ' + url_log.get('url')
    incident['occurred'] = url_log.get('date').replace('+0000', 'Z')
    incident['rawJSON'] = json.dumps(url_log)
    return incident


def attachment_to_incident(attachment_log):
    incident = {}
    incident['name'] = 'Mimecast malicious attachment: ' + attachment_log.get('fileName')
    incident['occurred'] = attachment_log.get('date').replace('+0000', 'Z')
    incident['rawJSON'] = json.dumps(attachment_log)
    return incident


def impersonation_to_incident(impersonation_log):
    incident = {}
    incident['name'] = 'Mimecast malicious impersonation: ' + impersonation_log.get('subject')
    incident['occurred'] = impersonation_log.get('eventTime').replace('+0000', 'Z')
    incident['rawJSON'] = json.dumps(impersonation_log)
    incident['dbotMirrorId'] = impersonation_log.get('id')
    return incident


def held_to_incident(held_message):
    incident = {}
    incident['name'] = f'Mimecast held message: {held_message.get("subject")}'
    incident['occurred'] = held_message.get('dateReceived').replace('+0000', 'Z')
    incident['rawJSON'] = json.dumps(held_message)
    incident['dbotMirrorId'] = held_message.get('id')
    return incident


def discover():
    headers = []  # type: List[Any]
    context = {}
    context_obj = {}  # type: Dict[Any, Any]
    contents = []

    response = discover_request()

    contents.append({
        'Authentication Types': response.get('authenticate'),
        'Email Address': response.get('emailAddress'),
        'Email Token': response.get('emailToken')
    })

    context_obj = {
        'AuthenticationTypes': response.get('authenticate'),
        'EmailAddress': response.get('emailAddress'),
        'EmailToken': response.get('emailToken')
    }

    context['Mimecast.Authentication(val.EmailAddress && val.EmailAddress === obj.EmailAddress)'] = context_obj

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast Authentication Information', contents, headers),
        'EntryContext': context
    }

    return results


def discover_request():
    if not EMAIL_ADDRESS:
        raise Exception('In order to discover account\'s auth types, account\'s email is required.')
    email = EMAIL_ADDRESS
    # Setup required variables
    api_endpoint = '/api/login/discover-authentication'
    payload = {
        'data': [{
            'emailAddress': email
        }]
    }
    response = http_request('POST', api_endpoint, payload, {}, user_auth=False)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def refresh_token():
    contents = refresh_token_request()

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Token has been refreshed succesfully and is valid for the next 3 days'
    }

    return results


def refresh_token_request():
    if not EMAIL_ADDRESS:
        raise Exception('In order to refresh a token validty duration, account\'s email is required.')
    if not ACCESS_KEY:
        raise Exception('In order to refresh a token validty duration, account\'s access key is required.')
    email = EMAIL_ADDRESS
    access_key = ACCESS_KEY
    # Setup required variables
    api_endpoint = '/api/login/login'
    payload = {
        'data': [{
            'userName': email,
            'accessKey': access_key
        }]
    }
    response = http_request('POST', api_endpoint, payload, {}, user_auth=False)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def login():
    headers = ['Access Key', 'Secret Key']
    contents = []

    response = login_request()

    contents.append({
        'Access Key': response.get('accessKey'),
        'Secret Key': response.get('secretKey')
    })

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast authentication details \n Tokens are valid for 3 days', contents,
                                         headers)
    }

    return results


def login_request():
    if not EMAIL_ADDRESS:
        raise Exception('In order to refresh a token validty duration, account\'s email is required.')
    email = EMAIL_ADDRESS
    # Setup required variables
    api_endpoint = '/api/login/login'
    payload = {
        'data': [{
            'userName': email
        }]
    }
    response = http_request('POST', api_endpoint, payload, {}, user_auth=False)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def get_message():
    context = {}
    contents = {}  # type: Dict[Any, Any]
    metadata_context = {}  # type: Dict[Any, Any]
    results = []
    message_id = demisto.args().get('messageID')
    message_context = demisto.args().get('context')
    message_type = demisto.args().get('type')
    message_part = demisto.args().get('part')

    if message_part == 'all' or message_part == 'metadata':
        contents, metadata_context = get_message_metadata(message_id)

        context['Mimecast.Message(val.ID && val.ID === obj.ID)'] = metadata_context

        results.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contents,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Mimecast message details', contents, removeNull=True),
            'EntryContext': context
        })

    if message_part == 'all' or message_part == 'message':
        email_file = get_message_body_content_request(message_id, message_context, message_type)
        results.append(fileResult(message_id, email_file))

    return results


def get_message_body_content_request(message_id, message_context, message_type):
    # Setup required variables
    api_endpoint = '/api/archive/get-message-part'

    data = [{
        'id': message_id,
        'type': message_type,
        'context': message_context
    }]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload, is_file=True)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response.content


def get_message_metadata(message_id):
    contents = {}  # type: Dict[Any, Any]
    context = {}  # type: Dict[Any, Any]
    message = get_message_metadata_request(message_id)

    receivers = message.get('to', [])
    to_context = []
    to_contents = []
    for receiver in receivers:
        to_context.append({
            'EmailAddress': receiver.get('emailAddress')
        })
        to_contents.append(
            receiver.get('emailAddress')
        )

    copies = message.get('cc', [])
    cc_context = []
    cc_contents = []
    for copy in copies:
        cc_context.append({
            'EmailAddress': copy.get('emailAddress')
        })
        cc_contents.append(
            copy.get('emailAddress')
        )

    response_headers = message.get('headers', [])
    headers_contents = []
    headers_context = []
    for header in response_headers:
        values = header.get('values')
        values = list(values)
        headers_context.append({
            'Name': header.get('name'),
            'Values': values
        })
        headers_contents.append(
            'Name: {}, Values: {}'.format(str(header.get('name')), str(values))
        )

    attachments = message.get('attachments', [])
    attachments_context = []
    attachments_contents = []
    for attachment in attachments:
        attachments_context.append({
            'FileName': attachment.get('filename'),
            'SHA256': attachment.get('sha256'),
            'ID': attachment.get('id'),
            'Size': attachment.get('size'),
            'Extension': attachment.get('extension')
        })
        attachments_contents.append(
            'FileName: {}, SHA256: {}, ID: {}, Size: {}'.format(str(attachment.get('filename')),
                                                                str(attachment.get('sha256')),
                                                                str(attachment.get('id')),
                                                                str(attachment.get('size')))
        )

    contents = {
        'Subject': message.get('subject'),
        'Header Date': message.get('headerDate'),
        'Size': message.get('size'),
        'From': message.get('from', {}).get('emailAddress'),
        'To': to_contents,
        'Reply To': message.get('replyTo', {}).get('emailAddress'),
        'CC': cc_contents,
        'Envelope From': message.get('envelopeFrom', {}).get('emailAddress'),
        'Headers': headers_contents,
        'Attachments': attachments_contents,
        'Processed': message.get('processed'),
        'Has Html Body': message.get('hasHtmlBody'),
        'ID': message.get('id')
    }

    context = {
        'Subject': message.get('subject'),
        'HeaderDate': message.get('headerDate'),
        'Size': message.get('size'),
        'From': message.get('from', {}).get('emailAddress'),
        'To': to_context,
        'ReplyTo': message.get('replyTo', {}).get('emailAddress'),
        'CC': cc_context,
        'EnvelopeFrom': message.get('envelopeFrom', {}).get('emailAddress'),
        'Headers': headers_context,
        'Attachments': attachments_context,
        'Processed': message.get('processed'),
        'HasHtmlBody': message.get('hasHtmlBody'),
        'ID': message.get('id')
    }

    return contents, context


def get_message_metadata_request(message_id):
    # Setup required variables
    api_endpoint = '/api/archive/get-message-detail'
    data = [{
        'id': message_id
    }]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def download_attachment():
    attachment_id = demisto.args().get('attachmentID')
    attachment_name = demisto.args().get('attachmentName')
    attachment_file = download_attachment_request(attachment_id)
    return fileResult(attachment_name if attachment_name else attachment_id, attachment_file)


def download_attachment_request(attachment_id):
    # Setup required variables
    api_endpoint = '/api/archive/get-file'

    data = [{
        'id': attachment_id
    }]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, payload, is_file=True)
    try:
        json_response = response.json()
        if json_response.get('fail'):
            raise Exception(json_response.get('fail', [{}])[0].get('errors'))
    except ValueError:
        pass
    return response.content


def find_groups():
    api_response = create_find_groups_request()

    markdown_output = find_groups_api_response_to_markdown(api_response)
    entry_context = find_groups_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def create_find_groups_request():
    api_endpoint = '/api/directory/find-groups'
    query_string = demisto.args().get('query_string', '')
    query_source = demisto.args().get('query_source', '')
    limit = demisto.args().get('limit')

    meta = {}
    data = {}

    if limit:
        meta['pagination'] = {
            'pageSize': int(limit)
        }

    if query_string:
        data['query'] = query_string
    if query_source:
        data['source'] = query_source

    payload = {
        'meta': meta,
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def find_groups_api_response_to_markdown(api_response):
    num_groups_found = api_response.get('meta', {}).get('pagination', {}).get('pageSize', 0)
    query_string = demisto.args().get('query_string', '')
    query_source = demisto.args().get('query_source', '')

    if not num_groups_found:
        md = '### Found 0 groups'

        if query_string:
            md += '\n#### query: ' + query_string

        if query_source:
            md += '\n#### source: ' + query_source

        return md

    md = 'Found ' + str(num_groups_found) + ' groups:'
    md_metadata = ''

    if query_string:
        md_metadata += '#### query: ' + query_string

    if query_source:
        if md_metadata:
            md_metadata += '\n'
        md_metadata += '#### source: ' + query_source

    groups_list = []
    for group in api_response.get('data', [])[0]['folders']:
        group_entry = {
            'Name': group['description'],
            'Source': group['source'],
            'Group ID': group['id'],
            'Number of users': group['userCount'],
            'Parent ID': group['parentId'],
            'Number of child groups': group['folderCount']
        }

        groups_list.append(group_entry)

    md = tableToMarkdown(md, groups_list,
                         ['Name', 'Source', 'Group ID', 'Number of users', 'Parent ID', 'Number of child groups'],
                         metadata=md_metadata)

    return md


def find_groups_api_response_to_context(api_response):
    groups_list = []
    for group in api_response['data'][0]['folders']:
        group_entry = {
            'Name': group['description'],
            'Source': group['source'],
            'ID': group['id'],
            'NumberOfUsers': group['userCount'],
            'ParentID': group['parentId'],
            'NumberOfChildGroups': group['folderCount']
        }

        groups_list.append(group_entry)

    return {'Mimecast.Group(val.ID && val.ID == obj.ID)': groups_list}


def get_group_members():
    api_response = create_get_group_members_request()

    markdown_output = group_members_api_response_to_markdown(api_response)
    entry_context = group_members_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def retrieve_all_results(response, all_results, api_endpoint, meta, data, limit=100):
    """Retrieve all results according to limit or all_results arguments

    Args:
        response (dict): the response of the first request
        all_results (bool): whether to retrieve all results
        api_endpoint (str): the api endpoint
        meta (dict): metadata for request
        data (dict): data for request
        limit (int, optional): the limit of group members to retrieve. Defaults to 100.
    """
    next_page = response.get('meta', {}).get('pagination', {}).get('next')
    group_members = response.get('data', [{}])[0].get('groupMembers', [])
    while (int(limit) > len(group_members) and next_page) or (all_results and next_page):
        meta['pagination'] = {
            'pageToken': next_page
        }
        payload = {
            'meta': meta,
            'data': [data]
        }
        current_response = http_request('POST', api_endpoint, payload)
        next_page = current_response.get('meta', {}).get('pagination', {}).get('next')
        current_group_members = current_response.get('data', [{}])[0].get('groupMembers', [])
        group_members.extend(current_group_members)


def create_get_group_members_request(group_id=-1, limit=100):
    api_endpoint = '/api/directory/get-group-members'
    args = demisto.args()
    group_id = args.get('group_id', group_id)
    limit = args.get('limit', limit)
    all_results = argToBoolean(args.get("all_results", False))
    API_MAX_VALUE = 500

    meta = {}
    data = {}
    page_size = API_MAX_VALUE if all_results else arg_to_number(limit)
    meta['pagination'] = {'pageSize': page_size}
    data['id'] = group_id
    payload = {
        'meta': meta,
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    retrieve_all_results(response, all_results, api_endpoint, meta, data, limit)
    return response


def group_members_api_response_to_markdown(api_response):
    num_users_found = len(api_response.get('data', [{}])[0].get('groupMembers', []))
    group_id = demisto.args().get('group_id', '')

    if not num_users_found:
        md = 'Found 0 users for group ID: ' + group_id + ''
        return md

    md = 'Found ' + str(num_users_found) + ' users for group ID: ' + group_id

    users_list = []
    for user in api_response['data'][0]['groupMembers']:
        user_entry = {
            'Name': user.get('name'),
            'Email address': user.get('emailAddress'),
            'Domain': user.get('domain'),
            'Type': user.get('type'),
            'Internal user': user.get('internal'),
            'Notes': user.get('notes')
        }

        users_list.append(user_entry)

    md = tableToMarkdown(md, users_list,
                         ['Name', 'Email address', 'Domain', 'Type', 'Internal user', 'Notes'])

    return md


def add_users_under_group_in_context_dict(users_list, group_id):
    demisto_context = demisto.context()

    if demisto_context and 'Mimecast' in demisto_context and 'Group' in demisto_context['Mimecast']:
        groups_entry_in_context = demisto_context['Mimecast']['Group']
        groups_entry_in_context = [groups_entry_in_context] if isinstance(groups_entry_in_context,
                                                                          dict) else groups_entry_in_context
        for group in groups_entry_in_context:
            if group['ID'] == group_id:
                group['Users'] = users_list
                return groups_entry_in_context

    return [
        {
            'ID': group_id,
            'Users': users_list
        }
    ]


def group_members_api_response_to_context(api_response, group_id=-1):
    group_id = demisto.args().get('group_id', group_id)

    users_list = []
    for user in api_response['data'][0]['groupMembers']:
        user_entry = {
            'Name': user.get('name'),
            'EmailAddress': user.get('emailAddress'),
            'Domain': user.get('domain'),
            'Type': user.get('type'),
            'InternalUser': user.get('internal'),
            'IsRemoved': False,
            'Notes': user.get('notes')
        }

        users_list.append(user_entry)

    groups_after_update = add_users_under_group_in_context_dict(users_list, group_id)

    return {'Mimecast.Group(val.ID && val.ID == obj.ID)': groups_after_update}


def add_remove_member_to_group(action_type):
    """Adds or remove a member from a group

    Args:
        action_type: the action type

    Returns:
        Demisto Outputs
    """
    if action_type == 'add':
        api_endpoint = '/api/directory/add-group-member'
    else:
        api_endpoint = '/api/directory/remove-group-member'

    api_response = create_add_remove_group_member_request(api_endpoint)

    markdown_output = add_remove_api_response_to_markdown(api_response, action_type)
    entry_context = add_remove_api_response_to_context(api_response, action_type)
    return CommandResults(readable_output=markdown_output,
                          outputs=entry_context,
                          raw_response=api_response)


def create_add_remove_group_member_request(api_endpoint):
    """Adds or remove a member from a group

    Args:
        api_endpoint: the add or the remove endpoint

    Returns:
        response from API
    """
    group_id = demisto.args().get('group_id', '')
    email = demisto.args().get('email_address', '')
    domain = demisto.args().get('domain_address', '')
    notes = demisto.args().get('notes', '')

    data = {
        'id': group_id,
    }

    if email:
        data['emailAddress'] = email

    if domain:
        data['domain'] = domain

    if notes:
        data['notes'] = notes

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def add_remove_api_response_to_markdown(api_response, action_type):
    """Create a markdown response for the add or remove member operation

    Args:
        api_response: response from api
        action_type: the action type

    Returns:
        response from API
    """
    address_modified = api_response['data'][0].get('emailAddress')
    if not address_modified:
        address_modified = api_response['data'][0].get('domain', 'Address')
    group_id = api_response['data'][0].get('folderId', '')

    if action_type == 'add':
        return address_modified + ' had been added to group ID ' + group_id
    return address_modified + ' has been removed from group ID ' + group_id


def change_user_status_removed_in_context(user_info, group_id):
    demisto_context = demisto.context()

    if demisto_context and 'Mimecast' in demisto_context and 'Group' in demisto_context['Mimecast']:
        groups_entry_in_context = demisto_context['Mimecast']['Group']
        groups_entry_in_context = [groups_entry_in_context] if isinstance(groups_entry_in_context,
                                                                          dict) else groups_entry_in_context
        for group in groups_entry_in_context:
            if group['ID'] == group_id:
                for user in group['Users']:
                    if user['EmailAddress'] == user_info.get('EmailAddress', ''):
                        user['IsRemoved'] = True
                return groups_entry_in_context

    return [
        {
            'ID': group_id,
            'Users': [user_info]
        }
    ]


def add_remove_api_response_to_context(api_response, action_type):
    group_id = api_response['data'][0]['folderId']

    if action_type == 'add':
        # Run get group members again, to get all relevant data, the response from add user
        # does not match the get group members.
        api_response = create_get_group_members_request(group_id=group_id)
        return group_members_api_response_to_context(api_response, group_id=group_id)
    else:
        address_removed = api_response['data'][0].get('emailAddress', '')

        removed_user = {
            'EmailAddress': address_removed,
            'IsRemoved': True
        }

        groups_after_update = change_user_status_removed_in_context(removed_user, group_id)

        return {'Mimecast.Group(val.ID && val.ID == obj.ID)': groups_after_update}


def create_group():
    api_response = create_group_request()

    markdown_output = create_group_api_response_to_markdown(api_response)
    entry_context = create_group_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def create_group_request():
    api_endpoint = '/api/directory/create-group'
    group_name = demisto.args().get('group_name', '')
    parent_id = demisto.args().get('parent_id', '-1')

    data = {
        'description': group_name,
    }

    if parent_id != '-1':
        data['parentId'] = parent_id

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def create_group_api_response_to_markdown(api_response):
    group_name = api_response['data'][0]['description']
    group_source = api_response['data'][0]['source']
    group_id = api_response['data'][0]['id']

    md = group_name + ' has been created'

    group_info = {
        'Group Source': group_source,
        'Group ID': group_id
    }

    return tableToMarkdown(md, group_info, ['Group Source', 'Group ID'])


def create_group_api_response_to_context(api_response):
    group_created = {
        'Name': api_response['data'][0]['description'],
        'Source': api_response['data'][0]['source'],
        'ID': api_response['data'][0]['id'],
        'NumberOfUsers': 0,
        'ParentID': api_response['data'][0]['parentId'],
        'NumberOfChildGroups': 0
    }

    return {'Mimecast.Group(val.Name && val.Name == obj.Name)': group_created}


def update_group():
    api_response = create_update_group_request()

    markdown_output = update_group_api_response_to_markdown(api_response)
    entry_context = update_group_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def create_update_group_request():
    api_endpoint = '/api/directory/update-group'
    group_name = demisto.args().get('group_name', '')
    group_id = demisto.args().get('group_id', '')
    parent_id = demisto.args().get('parent_id', '')

    data = {
        'id': group_id
    }

    if group_name:
        data['description'] = group_name

    if parent_id:
        data['parentId'] = parent_id

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def update_group_api_response_to_markdown(api_response):
    group_name = api_response['data'][0]['description']

    return group_name + ' has been updated'


def update_group_api_response_to_context(api_response):
    group_updated = {
        'ID': api_response['data'][0]['id'],
        'Name': api_response['data'][0]['description'],
        'ParentID': api_response['data'][0]['parentId']
    }

    return {'Mimecast.Group(val.ID && val.ID == obj.ID)': group_updated}


def create_mimecast_incident():
    api_response = create_mimecast_incident_request()

    markdown_output = mimecast_incident_api_response_to_markdown(api_response, 'create')
    entry_context = mimecast_incident_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def create_mimecast_incident_request():
    api_endpoint = '/api/ttp/remediation/create'
    reason = demisto.args().get('reason', '')
    start_date = demisto.args().get('start_date', '')
    end_date = demisto.args().get('end_date', '')
    search_by = demisto.args().get('search_by', 'hash')
    hash_or_message_id = demisto.args().get('hash_message_id', '')

    if search_by == 'hash':
        get_hash_type(hash_or_message_id)
    else:
        if not hash_or_message_id.startswith('<'):
            hash_or_message_id = f'<{hash_or_message_id}'
        if not hash_or_message_id.endswith('>'):
            hash_or_message_id = f'{hash_or_message_id}>'

    data = {
        'reason': reason,
        'hashOrMessageId': hash_or_message_id,
        'searchBy': search_by
    }

    if start_date:
        data['start'] = start_date

    if end_date:
        data['end'] = end_date

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def get_mimecast_incident():
    api_response = get_mimecast_incident_request()

    markdown_output = mimecast_incident_api_response_to_markdown(api_response, 'get')
    entry_context = mimecast_incident_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def get_mimecast_incident_request():
    api_endpoint = '/api/ttp/remediation/get-incident'
    incident_id = demisto.args().get('incident_id', '')

    data = {
        'id': incident_id
    }

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def mimecast_incident_api_response_to_markdown(api_response, action_type):
    response_data = api_response.get('data', [{}])[0]
    incident_code = response_data.get('code', '')
    incident_type = response_data.get('type', '')
    incident_reason = response_data.get('reason', '')
    incident_identified_messages_amount = response_data.get('identified', 0)
    incident_successful_messages_amount = response_data.get('successful', 0)
    incident_failed_messages_amount = response_data.get('failed', 0)
    incident_restored_messages_amount = response_data.get('restored', 0)
    incident_id = response_data.get('id', '')

    if action_type == 'create':
        md = 'Incident ' + incident_id + ' has been created'
    else:
        md = 'Incident ' + incident_id + ' has been found'
    md_metadata = f"""
#### Code: {incident_code}
#### Type: {incident_type}
#### Reason: {incident_reason}
#### The number of messages identified based on the search criteria: {incident_identified_messages_amount}
#### The number successfully remediated messages: {incident_successful_messages_amount}
#### The number of messages that failed to remediate: {incident_failed_messages_amount}
#### The number of messages that were restored from the incident: {incident_restored_messages_amount}
"""

    message = response_data['searchCriteria']
    message_entry = {
        'From': message.get('from'),
        'To': message.get('to'),
        'Start date': message.get('start'),
        'End date': message.get('end'),
        'Message ID': message.get('messageId'),
        'File hash': message.get('fileHash')
    }

    md = tableToMarkdown(md,
                         message_entry,
                         ['From', 'To', 'Start', 'End date', 'Message ID', 'File hash'],
                         metadata=md_metadata,
                         removeNull=True)

    return md


def mimecast_incident_api_response_to_context(api_response):
    response_data = api_response['data'][0]
    message = response_data['searchCriteria']
    message_entry = {
        'From': message.get('from'),
        'To': message.get('to'),
        'StartDate': message.get('start'),
        'EndDate': message.get('end'),
        'MessageID': message.get('messageId'),
        'FileHash': message.get('fileHash')
    }

    incident_created = {
        'ID': response_data.get('id'),
        'Code': response_data.get('code'),
        'Type': response_data.get('type'),
        'Reason': response_data.get('reason'),
        'IdentifiedMessages': response_data.get('identified'),
        'SuccessfullyRemediatedMessages': response_data.get('successful'),
        'FailedRemediatedMessages': response_data.get('failed'),
        'MessagesRestored': response_data.get('restored'),
        'LastModified': response_data.get('modified'),
        'SearchCriteria': message_entry
    }

    return {'Mimecast.Incident(val.ID && val.ID == obj.ID)': incident_created}


def search_file_hash():
    api_response = create_search_file_hash_request()

    markdown_output = search_file_hash_api_response_to_markdown(api_response)
    entry_context = search_file_hash_api_response_to_context(api_response)

    return_outputs(markdown_output, entry_context, api_response)


def create_search_file_hash_request():
    api_endpoint = '/api/ttp/remediation/search-hash'
    hashes_to_search = argToList(demisto.args().get('hashes_to_search'))

    data = {
        'hashes': hashes_to_search
    }

    payload = {
        'data': [data]
    }

    response = http_request('POST', api_endpoint, payload)
    if isinstance(response, dict) and response.get('fail'):
        raise Exception(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response


def search_file_hash_api_response_to_markdown(api_response):
    md = 'Hashes detected:\n'
    detected_hashes_list = []
    for detected_hash in api_response['data'][0]['hashStatus']:
        detected_hash_entry = {
            'Hash': detected_hash['hash'],
            'Found within the account': detected_hash['detected']
        }

        detected_hashes_list.append(detected_hash_entry)

    md = tableToMarkdown(md, detected_hashes_list, ['Hash', 'Found within the account'])

    md += '### Hashes that failed verification:\n'

    failed_hash_list = [str(failed_hash) for failed_hash in api_response['data'][0]['failedHashes']]
    md += str(failed_hash_list)[1:-1] + '\n'

    return md


def search_file_hash_api_response_to_context(api_response):
    detected_hashes_list = []
    for detected_hash in api_response['data'][0]['hashStatus']:
        detected_hash_entry = {
            'HashValue': detected_hash['hash'],
            'Detected': detected_hash['detected']
        }

        detected_hashes_list.append(detected_hash_entry)

    if detected_hashes_list:
        return {'Mimecast.Hash(val.HashValue && val.HashValue == obj.HashValue)': detected_hashes_list}
    return None


def search_message_command(args):
    """
    Getting message info for specific messages id.
    Args:
        args: input arguments for the command.

    """
    response = search_message_request(args)
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    tracked_emails = response.get('data')[0].get('trackedEmails')

    to_transformer = JsonTransformer(func=lambda to_data: ', '.join([to.get('emailAddress', '') for to in to_data]))
    from_env_transformer = JsonTransformer(func=lambda env: env.get('emailAddress', ''))
    from_hdr_transformer = JsonTransformer(func=lambda hdr: hdr.get('displayableName', ''))
    table_json_transformer = {'to': to_transformer,
                              'fromEnv': from_env_transformer,
                              'fromHdr': from_hdr_transformer
                              }
    headers = {'fromEnv': 'From (Envelope)',
               'fromHdr': 'From (Header)',
               'received': 'Date/Time',
               'senderIP': 'IP Address',
               'spamScore': 'Spam Score',
               'detectionLevel': 'Spam Detection'}
    readable_output = tableToMarkdown('Tracked Emails', t=tracked_emails,
                                      headerTransform=lambda header: headers.get(
                                          header) if header in headers else header.capitalize(),
                                      removeNull=True, json_transform_mapping=table_json_transformer)

    return CommandResults(
        outputs_prefix='Mimecast.SearchMessage',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=tracked_emails,
        raw_response=response
    )


def held_message_summary_command():
    """
    Getting counts of currently held messages for each hold reason.
    Args:
        args: input arguments for the command.

    """
    response = http_request('POST', api_endpoint='/api/gateway/get-hold-summary-list', payload={'data': []})
    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    summary_list = response.get('data')

    headers = {'policyInfo': 'Held Reason',
               'numberOfItems': 'Number Of Items'
               }
    readable_output = tableToMarkdown('Message Summary', t=summary_list,
                                      headerTransform=lambda header: headers.get(header),
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='Mimecast.HeldMessageSummary',
        outputs_key_field='policyInfo',
        readable_output=readable_output,
        outputs=summary_list,
        raw_response=response
    )


def get_message_info_command(args):
    """
    Getting message info for specific messages ids.
    Args:
        args: input arguments for the command.

    """
    show_recipient_info = argToBoolean(args.get('show_recipient_info', True))
    show_delivered_message = argToBoolean(args.get('show_delivered_message', False))
    show_retention_info = argToBoolean(args.get('show_retention_info', True))
    show_spam_info = argToBoolean(args.get('show_spam_info', True))
    ids = argToList(args.get('ids', ''))
    results = []

    for id in ids:
        results.append(
            build_get_message_info_for_specific_id(id, show_recipient_info, show_delivered_message, show_retention_info,
                                                   show_spam_info))

    return results


def list_held_messages_command(args):
    """
        Getting hold messages list.
        Args:
            args: input arguments for the command.

    """
    response, _, _ = list_held_messages_request(args)
    from_transformer = JsonTransformer(func=transformer_get_value('emailAddress'))
    table_json_transformer = {'to': from_transformer,
                              'from': from_transformer,
                              'fromHeader': from_transformer
                              }
    headers = {'from': 'From (Envelope)',
               'fromHeader': 'From (Header)',
               'policyInfo': 'Held Reason',
               'dateReceived': 'Held Since',
               'hasAttachments': 'Has Attachments',
               'reasonCode': 'Reason Code',
               'reasonId': 'reason Id'
               }
    readable_output = tableToMarkdown('Held Messages', t=response,
                                      headerTransform=lambda header: headers.get(
                                          header) if header in headers else header.capitalize(),
                                      removeNull=True, json_transform_mapping=table_json_transformer,
                                      headers=['id', 'dateReceived', 'from', 'fromHeader', 'hasAttachments',
                                               'policyInfo', 'reason', 'reasonCode', 'reasonId',
                                               'route', 'size', 'subject', 'to'],
                                      metadata=f'Showing page number {args.get("page", "1")}')

    return CommandResults(
        outputs_prefix='Mimecast.HeldMessage',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=response,
        raw_response=response
    )


def reject_held_message_command(args):
    """

    Rejecting hold messages.
    Args:
        args: input arguments for the command.

    """
    response = reject_held_message_request(args)
    readable_output = ''

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    for message in response.get('data', []):
        if not message.get('reject', False):
            raise Exception(f'Held message with id {message.get("id")} rejection failed.')
        else:
            readable_output += f'Held message with id {message.get("id")} was rejected successfully.\n'

    return CommandResults(
        readable_output=readable_output,
        raw_response=response,
    )


def release_held_message_command(args):
    """

        Rejecting hold messages.
        Args:
            args: input arguments for the command.

        """
    id = args.get('id')
    response = release_held_message_request(id)

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))
    if not response.get('data', [])[0].get('release', False):
        raise Exception('Message release has failed.')
    else:
        readable_output = f'Held message with id {id} was released successfully'

    return CommandResults(
        readable_output=readable_output,
        raw_response=response,
    )


def search_processing_message_command(args):
    """

    Searching for message being processed.
    Args:
        args: input arguments for the command.

    """
    response, _, _ = search_processing_message_request(args)
    from_transformer = JsonTransformer(func=transformer_get_value('emailAddress'))

    table_json_transformer = {'to': from_transformer,
                              'fromHeader': from_transformer,
                              'fromEnv': from_transformer
                              }
    headers = {'fromEnv': 'From (Envelope)',
               'fromHeader': 'From (Header)',
               'routing': 'Route',
               'created': 'Date/Time',
               'remoteIp': 'IP Address',
               'nextAttempt': 'Next Attempt'
               }
    readable_output = tableToMarkdown('Processing Messages', t=response,
                                      headerTransform=lambda header: headers.get(
                                          header) if header in headers else header.capitalize(),
                                      removeNull=True, json_transform_mapping=table_json_transformer)

    return CommandResults(
        outputs_prefix='Mimecast.ProcessingMessage',
        readable_output=readable_output,
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )


def list_email_queues_command(args):
    """

    Listing email queue (Inbound and Outbound).
    Args:
        args: input arguments for the command.

    """
    response = list_email_queues_request(args)
    response_data = response.get('data')[0]
    inbound_data = response_data.get('inboundEmailQueue')
    outbound_data = response_data.get('outboundEmailQueue')

    headers = {
        'date': 'Email Queue Date',
        'count': 'Email Queue Count'
    }

    total_markdown = tableToMarkdown('Inbound Email Queue', t=inbound_data,
                                     headerTransform=lambda header: f'Inbound {headers.get(header)}'
                                     if header in headers else header.capitalize(),
                                     removeNull=True)
    total_markdown += tableToMarkdown('Outbound Email Queue', t=outbound_data,
                                      headerTransform=lambda header: f'Outbound {headers.get(header)}'
                                      if header in headers else header.capitalize(),
                                      removeNull=True)
    return CommandResults(
        outputs_prefix='Mimecast.EmailQueue',
        readable_output=total_markdown,
        outputs=response
    )


def get_archive_search_logs_command(args: dict) -> CommandResults:
    """
    Retrieves archive search logs based on the provided arguments.

    :param args: A dictionary containing the command arguments.

    :return: The CommandResults object containing the outputs and raw response.
    """
    api_endpoint = "/api/archive/get-archive-search-logs"
    query = args.get("query", "")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))

    data = assign_params(query=query)

    result_list = request_with_pagination(
        api_endpoint, [data], response_param="logs", limit=limit, page=page, page_size=page_size  # type: ignore
    )

    return CommandResults(
        outputs_prefix="Mimecast.ArchiveSearchLog",
        outputs=result_list[0]
    )


def get_search_logs_command(args: dict) -> CommandResults:
    query = args.get('query', '')
    start = arg_to_datetime(args.get('start')).strftime(DATE_FORMAT) if args.get('start') else None  # type: ignore
    end = arg_to_datetime(args.get('end')).strftime(DATE_FORMAT) if args.get('end') else None  # type: ignore

    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    data = assign_params(query=query, start=start, end=end)

    api_endpoint = "/api/archive/get-archive-search-logs"
    result_list, _, _ = request_with_pagination(
        api_endpoint, [data], response_param="logs", limit=limit, page=page, page_size=page_size)  # type: ignore

    return CommandResults(
        outputs_prefix='Mimecast.SearchLog',
        outputs=result_list[0]
    )


def get_view_logs_command(args: dict) -> CommandResults:
    query = args.get('query', '')
    start = arg_to_datetime(args.get('start')).strftime(DATE_FORMAT) if args.get('start') else None  # type: ignore
    end = arg_to_datetime(args.get('end')).strftime(DATE_FORMAT) if args.get('end') else None  # type: ignore

    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    data = assign_params(query=query, start=start, end=end)

    response = request_with_pagination(
        "/api/archive/get-view-logs", [data], limit=limit, page=page, page_size=page_size  # type: ignore
    )

    return CommandResults(
        outputs_prefix='Mimecast.ViewLog',
        outputs=response[0]
    )


def list_account_command(args: dict) -> CommandResults:
    account_name = args.get('account_name', '')
    account_code = args.get('account_code', '')
    admin_email = args.get('admin_email', '')
    region = args.get('region', '')
    user_count = arg_to_number(args.get('user_count', ''))

    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    data = assign_params(accountName=account_name, accountCode=account_code, adminEmail=admin_email, region=region,
                         userCount=user_count)

    response = request_with_pagination(
        "/api/account/get-account", [data], limit=limit, page=page, page_size=page_size  # type: ignore
    )

    return CommandResults(
        outputs_prefix='Mimecast.Account',
        outputs=response[0],
        outputs_key_field='accountCode'
    )


def list_policies_command(args: dict) -> CommandResults:
    policy_type = args.get('policyType', 'blockedsenders')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    api_endpoints = {
        'blockedsenders': 'blockedsenders/get-policy',
        'antispoofing-bypass': 'antispoofing-bypass/get-policy',
        'address-alteration': 'address-alteration/get-policy',
    }
    api_endpoint = f'/api/policy/{api_endpoints[policy_type]}'

    policies_list, _, _ = request_with_pagination(api_endpoint, data=[], limit=limit,
                                                  page=page, page_size=page_size)  # type: ignore

    contents = []
    for policy_list in policies_list:
        policy = policy_list.get('policy', {})
        sender = policy.get('from', {})
        reciever = policy.get('to', {})
        contents.append({
            'Policy ID': policy_list['id'],
            'Sender': {
                'Group': sender.get('groupId'),
                'Email Address': sender.get('emailAddress'),
                'Domain': sender.get('emailDomain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Email Address': reciever.get('emailAddress'),
                'Domain': reciever.get('emailDomain'),
                'Type': reciever.get('type')
            },
            'Bidirectional': policy.get('bidirectional'),
            'Start': policy.get('fromDate'),
            'End': policy.get('toDate')
        })
    headers = ['Policy ID', 'Sender', 'Reciever', 'Bidirectional', 'Start', 'End']

    title = f'Mimecast list {policy_type} policies: \n These are the existing {policy_type} Policies:'

    output_type = {
        'blockedsenders': 'BlockedSendersPolicy',
        'antispoofing-bypass': 'AntispoofingBypassPolicy',
        'address-alteration': 'AddressAlterationPolicy',
    }
    return CommandResults(
        outputs_prefix=f'Mimecast.{output_type[policy_type]}',
        outputs=policies_list,
        readable_output=tableToMarkdown(title, contents, headers),
        outputs_key_field='id'
    )


def create_antispoofing_bypass_policy_command(args: dict) -> CommandResults:
    policy_obj, option = get_arguments_for_policy_command(args)
    # Using dictionary comprehension to filter out keys with None or empty string values
    policy_obj = {k: v for k, v in policy_obj.items() if v is not None and v != ""}

    from_attribute_id = args.get('from_attribute_id')
    from_attribute_name = args.get('from_attribute_name')
    from_attribute_value = args.get('from_attribute_value')

    data: dict[str, Any] = {
        "option": option,
        "policy": policy_obj
    }

    from_attribute_data = {}
    if from_attribute_id:
        from_attribute_data['id'] = from_attribute_id
    if from_attribute_name:
        from_attribute_data['name'] = from_attribute_name
    if from_attribute_value:
        from_attribute_data['value'] = from_attribute_value

    if from_attribute_data:
        data['policy']['from'] = {"type": "address_attribute_value"}
        data['policy']['from']['attribute'] = from_attribute_data

    payload = {"data": [data]}
    api_endpoint = '/api/policy/antispoofing-bypass/create-policy'
    response = http_request('POST', api_endpoint, payload)

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    id = response['data'][0]['id']

    return CommandResults(
        outputs_prefix='Mimecast.AntispoofingBypassPolicy',
        outputs=response.get('data'),
        readable_output=f'Anti-Spoofing Bypass policy {id} was created successfully',
        outputs_key_field='id'
    )


def update_antispoofing_bypass_policy_command(args: dict) -> CommandResults:
    description = args.get('description')
    id = args.get('policy_id')
    enabled = argToBoolean(args.get('enabled'))
    from_date = arg_to_datetime(args.get('from_date')).strftime(DATE_FORMAT) if args.get('from_date') else None  # type: ignore
    from_eternal = argToBoolean(args.get('from_eternal'))
    from_part = args.get('from_part')
    to_date = arg_to_datetime(args.get('to_date')).strftime(DATE_FORMAT) if args.get('to_date') else None  # type: ignore
    to_eternal = argToBoolean(args.get('to_eternal'))
    bidirectional = argToBoolean(args.get('bidirectional')) if args.get('bidirectional') else None
    option = args.get('option')

    policy = assign_params(description=description, enabled=enabled, fromDate=from_date, fromEternal=from_eternal,
                           fromPart=from_part, toDate=to_date, toEternal=to_eternal, bidirectional=bidirectional)

    data: dict[str, Any] = {
        'id': id,
        'option': option,
        'policy': policy
    }

    payload = {"data": [data]}
    api_endpoint = '/api/policy/antispoofing-bypass/update-policy'
    response = http_request('POST', api_endpoint, payload)

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    return CommandResults(
        outputs_prefix='Mimecast.AntispoofingBypassPolicy',
        outputs=response.get('data'),
        readable_output=f'Policy ID- {id} has been updated successfully.',
        outputs_key_field='id'
    )


def create_address_alteration_policy_command(args: dict) -> CommandResults:
    policy_obj, _ = get_arguments_for_policy_command(args)
    # Using dictionary comprehension to filter out keys with None or empty string values
    policy_obj = {k: v for k, v in policy_obj.items() if v is not None and v != ""}
    folder_id = args.get("folder_id")

    data: dict[str, Any] = {"addressAlterationSetId": folder_id, "policy": policy_obj}

    payload = {"data": [data]}
    api_endpoint = "/api/policy/address-alteration/create-policy"
    response = http_request("POST", api_endpoint, payload)

    if response.get("fail"):
        raise Exception(json.dumps(response.get("fail")[0].get("errors")))

    return CommandResults(
        outputs_prefix="Mimecast.AddressAlterationPolicy",
        outputs=response.get("data"),
        readable_output="Address Alteration policy was created successfully",
        outputs_key_field="id",
    )


def update_address_alteration_policy_command(args: dict) -> CommandResults:
    policy_obj, _ = get_arguments_for_policy_command(args)
    # Using dictionary comprehension to filter out keys with None or empty string values
    policy_obj = {k: v for k, v in policy_obj.items() if v is not None and v != ""}
    id = args.get('policy_id')

    data: dict[str, Any] = {
        'id': id,
        'policy': policy_obj
    }

    payload = {'data': [data]}
    api_endpoint = '/api/policy/address-alteration/update-policy'
    response = http_request('POST', api_endpoint, payload)

    if response.get('fail'):
        raise Exception(json.dumps(response.get('fail')[0].get('errors')))

    return CommandResults(
        outputs_prefix='Mimecast.AddressAlterationPolicy',
        outputs=response.get('data'),
        readable_output=f'{id} has been updated successfully',
        outputs_key_field='id'
    )


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    # Check if token needs to be refresh, if it does and relevant params are set, refresh.
    command = demisto.command()
    args = demisto.args()

    try:
        if USE_OAUTH2 and any([APP_KEY, APP_ID, SECRET_KEY, ACCESS_KEY]):
            raise ValueError("When you use API 2.0 (Client ID and Client Secret) do not enter values in api 1.0 fields.")
        handle_proxy()
        determine_ssl_usage()
        if USE_OAUTH2:
            updating_token_oauth2()
        elif ACCESS_KEY:
            auto_refresh_token()
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif command == 'fetch-incidents':
            fetch_incidents()
        elif command == 'mimecast-query':
            demisto.results(query(args))
        elif command == 'mimecast-get-policy':
            return_results(get_policy_command(args))
        elif command == 'mimecast-list-blocked-sender-policies':
            return_results(list_blocked_sender_policies_command(args))
        elif command == 'mimecast-create-policy':
            demisto.results(create_policy_command())
        elif command == 'mimecast-create-block-sender-policy':
            return_results(create_block_sender_policy_command(args))
        elif command == 'mimecast-update-policy':
            demisto.results(update_policy_command())
        elif command == 'mimecast-update-block-sender-policy':
            return_results(update_block_sender_policy_command(args))
        elif command == 'mimecast-delete-policy':
            return_results(delete_policy(args))
        elif command == 'mimecast-manage-sender':
            demisto.results(manage_sender())
        elif command == 'mimecast-list-managed-url':
            demisto.results(list_managed_url())
        elif command == 'mimecast-create-managed-url':
            demisto.results(create_managed_url())
        elif command == 'mimecast-list-messages':
            demisto.results(list_messages())
        elif command == 'mimecast-get-attachment-logs':
            demisto.results(get_attachment_logs())
        elif command == 'mimecast-get-url-logs':
            demisto.results(get_url_logs())
        elif command == 'mimecast-get-impersonation-logs':
            demisto.results(get_impersonation_logs())
        elif command == 'mimecast-url-decode':
            demisto.results(url_decode())
        elif command == 'mimecast-discover':
            demisto.results(discover())
        elif command == 'mimecast-login':
            demisto.results(login())
        elif command == 'mimecast-refresh-token':
            demisto.results(refresh_token())
        elif command == 'mimecast-get-message':
            demisto.results(get_message())
        elif command == 'mimecast-download-attachments':
            demisto.results(download_attachment())
        elif command == 'mimecast-find-groups':
            find_groups()
        elif command == 'mimecast-get-group-members':
            get_group_members()
        elif command == 'mimecast-add-group-member':
            return_results(add_remove_member_to_group('add'))
        elif command == 'mimecast-remove-group-member':
            return_results(add_remove_member_to_group('remove'))
        elif command == 'mimecast-create-group':
            create_group()
        elif command == 'mimecast-update-group':
            update_group()
        elif command == 'mimecast-create-remediation-incident':
            create_mimecast_incident()
        elif command == 'mimecast-get-remediation-incident':
            get_mimecast_incident()
        elif command == 'mimecast-search-file-hash':
            search_file_hash()
        elif command == 'mimecast-search-message':
            return_results(search_message_command(args))
        elif command == 'mimecast-held-message-summary':
            return_results(held_message_summary_command())
        elif command == 'mimecast-get-message-info':
            return_results(get_message_info_command(args))
        elif command == 'mimecast-list-held-message':
            return_results(list_held_messages_command(args))
        elif command == 'mimecast-reject-held-message':
            return_results(reject_held_message_command(args))
        elif command == 'mimecast-release-held-message':
            return_results(release_held_message_command(args))
        elif command == 'mimecast-search-processing-message':
            return_results(search_processing_message_command(args))
        elif command == 'mimecast-list-email-queues':
            return_results(list_email_queues_command(args))
        elif command == 'mimecast-get-archive-search-logs':
            return_results(get_archive_search_logs_command(args))
        elif command == 'mimecast-get-search-logs':
            return_results(get_search_logs_command(args))
        elif command == 'mimecast-get-view-logs':
            return_results(get_view_logs_command(args))
        elif command == 'mimecast-list-account':
            return_results(list_account_command(args))
        elif command == 'mimecast-list-policies':
            return_results(list_policies_command(args))
        elif command == 'mimecast-create-antispoofing-bypass-policy':
            return_results(create_antispoofing_bypass_policy_command(args))
        elif command == 'mimecast-update-antispoofing-bypass-policy':
            return_results(update_antispoofing_bypass_policy_command(args))
        elif command == 'mimecast-create-address-alteration-policy':
            return_results(create_address_alteration_policy_command(args))
        elif command == 'mimecast-update-address-alteration-policy':
            return_results(update_address_alteration_policy_command(args))

    except Exception as e:
        return_error(e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
