import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import os
import hmac
import uuid
import json
import base64
import hashlib
import requests

from datetime import timedelta
from urllib2 import HTTPError

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

BASE_URL = demisto.params()['baseUrl']
ACCESS_KEY = demisto.params()['accessKey']
SECRET_KEY = demisto.params()['secretKey']
APP_ID = demisto.params()['appId']
APP_KEY = demisto.params()['appKey']
USE_SSL = True if demisto.params().get('insecure') else False
PROXY = True if demisto.params().get('proxy') else False
# Flags to control which type of incidents are being fetched
FETCH_URL = demisto.params().get('fetchURL')
FETCH_ATTACHMENTS = demisto.params().get('fetchAttachments')
FETCH_IMPERSONATIONS = demisto.params().get('fetchImpersonations')
# Used to refresh token / discover available auth types / login
EMAIL_ADDRESS = demisto.params().get('email')
PASSWORD = demisto.params().get('password')
FETCH_DELTA = int(demisto.params().get('fetchDelta', 24))

# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

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

''' HELPER FUNCTIONS '''


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


def http_request(method, api_endpoint, payload=None, params={}, user_auth=True, is_file=False):
    is_user_auth = True
    url = BASE_URL + api_endpoint
    # 2 types of auth, user and non user, mostly user is needed
    if user_auth:
        # Generate request header values
        request_id = str(uuid.uuid4())
        hdr_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

        # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        hmac_sha1 = hmac.new(SECRET_KEY.decode("base64"), ':'.join([hdr_date, request_id, api_endpoint, APP_KEY]),
                             digestmod=hashlib.sha1).digest()

        # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
        signature = base64.encodestring(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            'Authorization': 'MC ' + ACCESS_KEY + ':' + signature,
            'x-mc-app-id': APP_ID,
            'x-mc-date': hdr_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }

    else:
        # This type of auth is only supported for basic commands: login/discover/refresh-token
        is_user_auth = False
        auth = base64.b64encode(EMAIL_ADDRESS + ':' + PASSWORD)
        auth_type = 'Basic-Cloud'
        auth_header = auth_type + ' ' + auth
        headers = {
            'x-mc-app-id': APP_ID,
            'Content-Type': 'application/json',
            'Authorization': auth_header
        }

    LOG('running %s request with url=%s\tparams=%s\tdata=%s\tis user auth=%s' % (
        method, url, json.dumps(params), json.dumps(payload), is_user_auth))
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            headers=headers,
            data=payload
        )

        res.raise_for_status()
        if is_file:
            return res
        return res.json()

    except HTTPError as e:
        LOG(e)
        if e.response.status_code == 418:  # type: ignore  # pylint: disable=no-member
            if not APP_ID or not EMAIL_ADDRESS or not PASSWORD:
                return_error(
                    'Credentials provided are expired, could not automatically refresh tokens. App ID + Email Address '
                    '+ Password are required.')
        else:
            raise

    except Exception as e:
        LOG(e)
        raise


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
        query_xml = query_xml.replace('<text></text>', '<text>(subject: ' + args.get('subject') + ')</text>')
    if args.get('text'):
        query_xml = query_xml.replace('<text></text>', '<text>' + args.get('text') + '</text>')
    if args.get('date'):
        query_xml = query_xml.replace('<date select=\"last_year\"/>', '<date select=\"' + args.get('date') + '\"/>')

        if args.get('dateTo') or args.get('dateFrom'):
            return_error('Cannot use both date and dateFrom/dateTo arguments')

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

    if args.get('sentFrom'):
        query_xml = query_xml.replace('<sent></sent>', '<sent select=\"from\" >' + args.get('sentFrom') + '</sent>')
    if args.get('sentTo'):
        query_xml = query_xml.replace('<sent></sent>', '<sent select=\"to\" >' + args.get('sentTo') + '</sent>')
    query_xml = query_xml.replace('<sent></sent>', '')  # no empty tag
    if args.get('attachmentText'):
        query_xml = query_xml.replace('</docs>', args.get('attachmentText') + '</docs>')
    if args.get('attachmentType'):
        query_xml = query_xml.replace('<docs select=\"optional\">',
                                      '<docs select=\"' + args.get('attachmentType') + '\">')

    return query_xml


'''COMMANDS '''


def test_module():
    if not ACCESS_KEY:
        return_error('Cannot test valid connection without the Access Key parameter.')
    list_managed_url()


def query():
    headers = ['Subject', 'Display From', 'Display To', 'Received Date', 'Size', 'Attachment Count', 'Status', 'ID']
    contents = []
    context = {}
    messages_context = []
    query_xml = ''

    if demisto.args().get('queryXml'):
        query_xml = demisto.args().get('queryXml')
    else:
        query_xml = parse_query_args(demisto.args())
    if demisto.args().get('dryRun') == 'true':
        return query_xml

    messages = query_request(query_xml)
    for message in messages:
        contents.append({
            'Subject': message.get('subject'),
            'From': message.get('displayfrom'),
            'To': message.get('displayto'),
            'Received Date': message.get('receiveddate'),
            'Size': message.get('size'),
            'Attachment Count': message.get('attachmentcount'),
            'Status': message.get('status'),
            'ID': message.get('id')
        })
        messages_context.append({
            'Subject': message.get('subject'),
            'Sender': message.get('displayfrom'),
            'Recipient': message.get('displayto'),
            'ReceivedDate': message.get('receiveddate'),
            'Size': message.get('size'),
            'AttachmentCount': message.get('attachmentcount'),
            'Status': message.get('status'),
            'ID': message.get('id')
        })

    context['Mimecast.Message(val.ID && val.ID == obj.ID)'] = messages_context

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Mimecast archived emails', contents, headers),
        'EntryContext': context
    }

    return results


def query_request(query_xml):
    api_endpoint = '/api/archive/search'
    # API request demands admin boolean, since we don't have any other support but admin we simply pass true.
    data = [{
        'admin': True,
        'query': query_xml
    }]
    payload = {
        'data': data
    }
    response = http_request('POST', api_endpoint, json.dumps(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0].get('items')


def url_decode():
    headers = []  # type: List[str]
    contents = {}
    context = {}
    protected_url = demisto.args().get('url').encode('utf-8')
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
    response = http_request('POST', api_endpoint, str(payload))
    if not response.get('data')[0].get('url'):
        return_error('No URL has been returned from the service')
    return response.get('data')[0].get('url')


def get_policy():
    headers = ['Policy ID', 'Sender', 'Reciever', 'Bidirectional', 'Start', 'End']
    contents = []
    context = {}
    title = 'Mimecast list blocked sender policies: \n These are the existing Blocked Sender Policies:'
    policy_id = demisto.args().get('policyID')
    if policy_id:
        policy_id = policy_id.encode('utf-8')
        title = 'Mimecast Get Policy'

    policies_list = get_policy_request(policy_id)
    policies_context = []
    for policy_list in policies_list:
        policy = policy_list.get('policy')
        sender = policy.get('from')
        reciever = policy.get('to')
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
                'Domain': reciever.get('domain'),
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
                'Domain': sender.get('domain'),
                'Type': sender.get('type')
            },
            'Reciever': {
                'Group': reciever.get('groupId'),
                'Address': reciever.get('emailAddress'),
                'Domain': reciever.get('domain'),
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


def get_policy_request(policy_id=None):
    # Setup required variables
    api_endpoint = '/api/policy/blockedsenders/get-policy'
    data = []
    if policy_id:
        data.append({
            'id': policy_id
        })
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')


def create_policy():
    headers = ['Policy ID', 'Sender', 'Reciever', 'Bidirectional', 'Start', 'End']
    contents = {}  # type: Dict[Any, Any]
    context = {}
    policies_context = {}  # type: Dict[Any, Any]
    description = demisto.args().get('description').encode('utf-8')
    from_part = demisto.args().get('fromPart').encode('utf-8')
    from_type = demisto.args().get('fromType').encode('utf-8')
    from_value = demisto.args().get('fromValue').encode('utf-8')
    to_type = demisto.args().get('toType').encode('utf-8')
    to_value = demisto.args().get('toValue').encode('utf-8')
    option = demisto.args().get('option').encode('utf-8')

    policy_obj = {
        'description': description,
        'fromPart': from_part,
        'fromType': from_type,
        'fromValue': from_value,
        'toType': to_type,
        'toValue': to_value
    }

    policy_list = create_policy_request(policy_obj, option)
    policy = policy_list.get('policy')
    policy_id = policy_list.get('id')
    title = 'Mimecast Create Policy: \n Policy {} Was Created Successfully!'.format(policy_id)
    sender = policy.get('from')
    reciever = policy.get('to')
    contents = {
        'Policy ID': policy_id,
        'Sender': {
            'Group': sender.get('groupId'),
            'Email Address': sender.get('emailAddress'),
            'Domain': sender.get('emailDomain'),
            'Type': sender.get('type')
        },
        'Reciever': {
            'Group': reciever.get('groupId'),
            'Email Address': reciever.get('emailAddress'),
            'Domain': reciever.get('domain'),
            'Type': reciever.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'Start': policy.get('fromDate'),
        'End': policy.get('toDate')
    }
    policies_context = {
        'ID': policy_id,
        'Sender': {
            'Group': sender.get('groupId'),
            'Address': sender.get('emailAddress'),
            'Domain': sender.get('domain'),
            'Type': sender.get('type')
        },
        'Reciever': {
            'Group': reciever.get('groupId'),
            'Address': reciever.get('emailAddress'),
            'Domain': reciever.get('domain'),
            'Type': reciever.get('type')
        },
        'Bidirectional': policy.get('bidirectional'),
        'FromDate': policy.get('fromDate'),
        'ToDate': policy.get('toDate')
    }

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


def create_policy_request(policy, option):
    # Setup required variables
    api_endpoint = '/api/policy/blockedsenders/create-policy'
    payload = {
        'data': [{
            'policy': policy,
            'option': option
        }]
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def delete_policy():
    contents = []  # type: List[Any]
    context = {}
    policy_id = demisto.args().get('policyID').encode('utf-8')

    delete_policy_request(policy_id)

    context['Mimecast.Policy(val.ID && val.ID == obj.ID)'] = {
        'ID': policy_id,
        'Deleted': True
    }

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Mimecast Policy {} deleted successfully!'.format(policy_id),
        'EntryContext': context
    }

    return results


def delete_policy_request(policy_id=None):
    # Setup required variables
    api_endpoint = '/api/policy/blockedsenders/delete-policy'
    data = [{
        'id': policy_id
    }]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    if response.get('data')[0].get('id') != policy_id:
        return_error('Policy was not deleted.')
    return response.get('data')[0]


def manage_sender():
    headers = []  # type: List[str]
    context = {}
    sender = demisto.args().get('sender').encode('utf-8')
    recipient = demisto.args().get('recipient').encode('utf-8')
    action = demisto.args().get('action').encode('utf-8')
    title_action = 'permitted' if action == 'permit' else 'blocked'
    title = 'Mimecast messages from {} to {} will now be {}!'.format(sender, recipient, title_action)

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

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def list_managed_url():
    headers = ['URL', 'Action', 'Match Type', 'User Awareness', 'URL Rewriting', 'Comment']
    contents = []
    context = {}
    managed_urls_context = []
    full_url_response = ''
    url = demisto.args().get('url')
    if url:
        url = url.encode('utf-8')

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

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')


def create_managed_url():
    context = {}
    contents = {}  # type: Dict[Any, Any]
    managed_urls_context = []
    url = demisto.args().get('url').encode('utf-8')
    action = demisto.args().get('action').encode('utf-8')
    match_type = demisto.args().get('matchType').encode('utf-8')
    disable_rewrite = demisto.args().get('disableRewrite').encode('utf-8')
    disable_user_awareness = demisto.args().get('disableUserAwareness').encode('utf-8')
    disable_log_click = demisto.args().get('disableLogClick').encode('utf-8')
    comment = demisto.args().get('comment')
    if comment:
        comment = comment.encode('utf-8')

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
        'HumanReadable': 'Managed URL {} created successfully!'.format(url),
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

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def list_messages():
    headers = ['Subject', 'Size', 'Recieved Date', 'From', 'Attachment Count', 'Message ID']
    context = {}
    contents = []
    messages_context = []
    search_params = {}

    # can't send null values for keys, so if optional value not sent by user, do not add to request.
    mailbox = demisto.args().get('mailbox', '').encode('utf-8')
    if mailbox:
        search_params['mailbox'] = mailbox
    view = demisto.args().get('view', '').encode('utf-8')
    if view:
        search_params['view'] = view
    end_time = demisto.args().get('endTime', '').encode('utf-8')
    if end_time:
        search_params['end'] = end_time
    start_time = demisto.args().get('startTime', '').encode('utf-8')
    if start_time:
        search_params['start'] = start_time
    subject = demisto.args().get('subject')

    messages_list = list_messages_request(search_params)

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


def list_messages_request(search_params):
    # Setup required variables
    api_endpoint = '/api/archive/get-message-list'
    data = []
    data.append(search_params)
    payload = {
        'meta': {
            'pagination': {
            }
        },
        'data': data
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')


def get_url_logs():
    headers = []  # type: List[Any]
    contents = []
    context = {}
    url_logs_context = []
    search_params = {}
    result_number = demisto.args().get('resultsNumber', '').encode('utf-8')
    from_date = demisto.args().get('fromDate', '').encode('utf-8')
    to_date = demisto.args().get('toDate', '').encode('utf-8')
    scan_result = demisto.args().get('resultType', '').encode('utf-8')
    limit = int(demisto.args().get('limit', 100))

    if from_date:
        search_params['from'] = from_date
    if to_date:
        search_params['to'] = to_date
    if scan_result:
        search_params['scanResult'] = scan_result

    url_logs = get_url_logs_request(search_params, result_number)
    if limit:
        url_logs = url_logs[:limit]
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


def get_url_logs_request(search_params, result_number=None):
    # Setup required variables
    api_endpoint = '/api/ttp/url/get-logs'
    pagination = {}  # type: Dict[Any, Any]
    if result_number:
        pagination = {'page_size': result_number}
    payload = {
        'meta': {
            'pagination': pagination
        },
        'data': [search_params]
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0].get('clickLogs')


def get_attachment_logs():
    headers = []  # type: List[Any]
    contents = []
    context = {}
    attachment_logs_context = []
    search_params = {}
    result_number = demisto.args().get('resultsNumber', '').encode('utf-8')
    from_date = demisto.args().get('fromDate', '').encode('utf-8')
    to_date = demisto.args().get('toDate', '').encode('utf-8')
    result = demisto.args().get('resultType', '').encode('utf-8')
    limit = int(demisto.args().get('limit', 100))

    if from_date:
        search_params['from'] = from_date
    if to_date:
        search_params['to'] = to_date
    if result:
        search_params['result'] = result

    attachment_logs = get_attachment_logs_request(search_params, result_number)
    if limit:
        attachment_logs = attachment_logs[:limit]
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


def get_attachment_logs_request(search_params, result_number=None):
    # Setup required variables
    api_endpoint = '/api/ttp/attachment/get-logs'
    pagination = {}  # type: Dict[Any, Any]
    if result_number:
        pagination = {'page_size': result_number}
    payload = {
        'meta': {
            'pagination': pagination
        },
        'data': [search_params]
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0].get('attachmentLogs')


def get_impersonation_logs():
    headers = []  # type: List[Any]
    contents = []
    context = {}
    impersonation_logs_context = []
    search_params = {}
    result_number = demisto.args().get('resultsNumber', '').encode('utf-8')
    from_date = demisto.args().get('fromDate', '').encode('utf-8')
    to_date = demisto.args().get('toDate', '').encode('utf-8')
    tagged_malicious = demisto.args().get('taggedMalicious', '').encode('utf-8')
    search_field = demisto.args().get('searchField', '').encode('utf-8')
    query = demisto.args().get('query', '').encode('utf-8')
    identifiers = argToList(demisto.args().get('identifiers', '').encode('utf-8'))
    actions = argToList(demisto.args().get('actions', '').encode('utf-8'))
    limit = int(demisto.args().get('limit', 100))

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

    impersonation_logs, result_count = get_impersonation_logs_request(search_params, result_number)
    if limit:
        impersonation_logs = impersonation_logs[:limit]
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


def get_impersonation_logs_request(search_params, result_number=None):
    # Setup required variables
    api_endpoint = '/api/ttp/impersonation/get-logs'
    pagination = {}  # type: Dict[Any, Any]
    if result_number:
        pagination = {'page_size': result_number}
    payload = {
        'meta': {
            'pagination': pagination
        },
        'data': [search_params]
    }

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0].get('impersonationLogs'), response.get('data')[0].get('resultCount')


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(hours=FETCH_DELTA)
        last_fetch_date_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S") + '+0000'
    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')
        last_fetch_date_time = last_fetch.strftime("%Y-%m-%dT%H:%M:%S") + '+0000'
    current_fetch = last_fetch

    incidents = []
    if FETCH_URL:
        search_params = {
            'from': last_fetch_date_time,
            'scanResult': 'malicious'
        }
        url_logs = get_url_logs_request(search_params)
        for url_log in url_logs:
            incident = url_to_incident(url_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')
            # update last run
            if temp_date > last_fetch:
                last_fetch = temp_date + timedelta(seconds=1)

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)

    if FETCH_ATTACHMENTS:
        search_params = {
            'from': last_fetch_date_time,
            'result': 'malicious'
        }
        attachment_logs = get_attachment_logs_request(search_params)
        for attachment_log in attachment_logs:
            incident = attachment_to_incident(attachment_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')

            # update last run
            if temp_date > last_fetch:
                last_fetch = temp_date + timedelta(seconds=1)

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)

    if FETCH_IMPERSONATIONS:
        search_params = {
            'from': last_fetch_date_time,
            'taggedMalicious': True
        }
        impersonation_logs, _ = get_impersonation_logs_request(search_params)
        for impersonation_log in impersonation_logs:
            incident = impersonation_to_incident(impersonation_log)
            temp_date = datetime.strptime(incident['occurred'], '%Y-%m-%dT%H:%M:%SZ')

            # update last run
            if temp_date > last_fetch:
                last_fetch = temp_date + timedelta(seconds=1)

            # avoid duplication due to weak time query
            if temp_date > current_fetch:
                incidents.append(incident)

    demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})
    demisto.incidents(incidents)


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
        return_error('In order to discover account\'s auth types, account\'s email is required.')
    email = EMAIL_ADDRESS.encode('utf-8')
    # Setup required variables
    api_endpoint = '/api/login/discover-authentication'
    payload = {
        'data': [{
            'emailAddress': email
        }]
    }
    response = http_request('POST', api_endpoint, str(payload), {}, user_auth=False)
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
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
        return_error('In order to refresh a token validty duration, account\'s email is required.')
    if not ACCESS_KEY:
        return_error('In order to refresh a token validty duration, account\'s access key is required.')
    email = EMAIL_ADDRESS.encode('utf-8')
    access_key = ACCESS_KEY.encode('utf-8')
    # Setup required variables
    api_endpoint = '/api/login/login'
    payload = {
        'data': [{
            'userName': email,
            'accessKey': access_key
        }]
    }
    response = http_request('POST', api_endpoint, str(payload), {}, user_auth=False)
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
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
        return_error('In order to refresh a token validty duration, account\'s email is required.')
    email = EMAIL_ADDRESS.encode('utf-8')
    # Setup required variables
    api_endpoint = '/api/login/login'
    payload = {
        'data': [{
            'userName': email
        }]
    }
    response = http_request('POST', api_endpoint, str(payload), {}, user_auth=False)
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def get_message():
    context = {}
    contents = {}  # type: Dict[Any, Any]
    metadata_context = {}  # type: Dict[Any, Any]
    results = []
    message_id = demisto.args().get('messageID').encode('utf-8')
    message_context = demisto.args().get('context').encode('utf-8')
    message_type = demisto.args().get('type').encode('utf-8')
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

    response = http_request('POST', api_endpoint, str(payload), is_file=True)
    if isinstance(response, dict) and response.get('fail'):
        return_error(json.dumps(response.get('fail', [{}])[0].get('errors')))
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
        values = [value.encode('utf-8') for value in values]
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
            'Size': attachment.get('size')
        })
        attachments_contents.append(
            'FileName: {}, SHA256: {}, ID: {}, Size: {}'.format(str(attachment.get('filename')),
                                                                str(attachment.get('sha256')),
                                                                str(attachment.get('id')), str(attachment.get('size')))
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

    response = http_request('POST', api_endpoint, str(payload))
    if response.get('fail'):
        return_error(json.dumps(response.get('fail')[0].get('errors')))
    return response.get('data')[0]


def download_attachment():
    attachment_id = demisto.args().get('attachmentID').encode('utf-8')
    attachment_file = download_attachment_request(attachment_id)
    return fileResult(attachment_id, attachment_file)


def download_attachment_request(attachment_id):
    # Setup required variables
    api_endpoint = '/api/archive/get-file'

    data = [{
        'id': attachment_id
    }]
    payload = {
        'data': data
    }

    response = http_request('POST', api_endpoint, str(payload), is_file=True)
    if isinstance(response, dict) and response.get('fail'):
        return_error(json.dumps(response.get('fail', [{}])[0].get('errors')))
    return response.content


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('command is %s' % (demisto.command(),))

# Check if token needs to be refresh, if it does and relevant params are set, refresh.
if ACCESS_KEY:
    auto_refresh_token()

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'mimecast-query':
        demisto.results(query())
    elif demisto.command() == 'mimecast-list-blocked-sender-policies':
        demisto.results(get_policy())
    elif demisto.command() == 'mimecast-get-policy':
        demisto.results(get_policy())
    elif demisto.command() == 'mimecast-create-policy':
        demisto.results(create_policy())
    elif demisto.command() == 'mimecast-delete-policy':
        demisto.results(delete_policy())
    elif demisto.command() == 'mimecast-manage-sender':
        demisto.results(manage_sender())
    elif demisto.command() == 'mimecast-list-managed-url':
        demisto.results(list_managed_url())
    elif demisto.command() == 'mimecast-create-managed-url':
        demisto.results(create_managed_url())
    elif demisto.command() == 'mimecast-list-messages':
        demisto.results(list_messages())
    elif demisto.command() == 'mimecast-get-attachment-logs':
        demisto.results(get_attachment_logs())
    elif demisto.command() == 'mimecast-get-url-logs':
        demisto.results(get_url_logs())
    elif demisto.command() == 'mimecast-get-impersonation-logs':
        demisto.results(get_impersonation_logs())
    elif demisto.command() == 'mimecast-url-decode':
        demisto.results(url_decode())
    elif demisto.command() == 'mimecast-discover':
        demisto.results(discover())
    elif demisto.command() == 'mimecast-login':
        demisto.results(login())
    elif demisto.command() == 'mimecast-refresh-token':
        demisto.results(refresh_token())
    elif demisto.command() == 'mimecast-get-message':
        demisto.results(get_message())
    elif demisto.command() == 'mimecast-download-attachments':
        demisto.results(download_attachment())


except Exception as e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
