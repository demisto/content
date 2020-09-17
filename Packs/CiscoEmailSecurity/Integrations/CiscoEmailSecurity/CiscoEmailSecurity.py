import demistomock as demisto
from CommonServerPython import *

import urllib3
import traceback
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

MAX_MESSAGES_TO_GET = 20
SAFELIST_AND_BLOCKLIST_TO_FILTER_URL = {
    "safelist": "/sma/api/v2.0/quarantine/safelist",
    "blocklist": "/sma/api/v2.0/quarantine/blocklist"
}


class Client(BaseClient):

    def __init__(self, params):
        self.username = params.get('api_username')
        self.password = params.get('api_password')
        super().__init__(base_url=params.get('base_url'), verify=not params.get('insecure', False),
                         ok_codes=tuple(), proxy=params.get('proxy', False))

        self._jwt_token = self._generate_jwt_token()
        self._headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'jwtToken': self._jwt_token
        }

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)

    def _generate_base64_token(self) -> str:
        basic_authorization_to_encode = f'{self.username}:{self.password}'
        basic_authorization = base64.b64encode(basic_authorization_to_encode.encode('ascii')).decode('utf-8')
        return basic_authorization

    def _generate_jwt_token(self) -> str:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        data = {
            "data":
                {
                    "userName": base64.b64encode(self.username.encode('ascii')).decode('utf-8'),
                    "passphrase": base64.b64encode(self.password.encode('ascii')).decode('utf-8')
                }
        }
        output = self.http_request('POST', '/sma/api/v2.0/login', json_data=data, headers=headers)
        jwt_token = output.get('data').get('jwtToken')
        return jwt_token

    def list_report(self, url_suffix) -> Dict[str, Any]:
        return self.http_request(
            method='GET',
            url_suffix=url_suffix,
        )

    def list_messages(self, url_suffix) -> Dict[str, Any]:
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_get_message_details(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_get_dlp_details(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_get_amp_details(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_get_url_details(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_spam_quarantine(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_quarantine_get_details(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_delete_quarantine_messages(self, url_suffix, request_body):
        return self.http_request(
            method='DELETE',
            url_suffix=url_suffix,
            json_data=request_body
        )

    def list_release_quarantine_messages(self, url_suffix, request_body):
        return self.http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=request_body
        )

    def list_entries_get(self, url_suffix):
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_entries_add(self, url_suffix, request_body):
        return self.http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=request_body
        )

    def list_entries_delete(self, url_suffix, request_body):
        return self.http_request(
            method='DELETE',
            url_suffix=url_suffix,
            json_data=request_body
        )


def test_module(client: Client) -> str:
    suffix_url = "/sma/api/v2.0/message-tracking/messages?startDate=2018-01-01T00:00:00.000Z&" \
                 "endDate=2019-11-20T09:36:00.000Z&ciscoHost=All_Hosts&searchOption=messages&offset=0&limit=20"
    try:
        client.list_messages(suffix_url)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def date_to_cisco_date(date):
    return date.replace(' ', 'T') + '.000Z'


def set_limit(limit):
    return int(limit) if limit and int(limit) <= MAX_MESSAGES_TO_GET else MAX_MESSAGES_TO_GET


def build_url_params_for_list_report(args):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    device_type = args.get('device_type')
    url_params = f'?startDate={start_date}&endDate={end_date}&device_type={device_type}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'offset':
            limit = arguments.get('limit')
            url_params += f'&{key}={int(value)}&limit={int(limit)}'

        elif key == 'filter_key':
            filter_operator = arguments.get('filter_operator', 'is')
            filter_value = arguments.get('filter_value')
            url_params += f'&filterBy={value}&filter_operator={filter_operator}&filter_value={filter_value}'

        elif key == 'device_group':
            url_params += f'&{key}={value}'
        elif key == 'device_name':
            url_params += f'&{key}={value}'

    return url_params


def list_report_command(client: Client, args: Dict[str, Any]):
    url_suffix = '/sma/api/v2.0/reporting'
    url_params = build_url_params_for_list_report(args)
    url_suffix_to_filter_by = url_suffix + url_params
    report_response_data = client.list_report(url_suffix_to_filter_by)
    return CommandResults(
        readable_output='',
        outputs_prefix='CiscoEmailSecurity.report',
        outputs_key_field='',
        outputs=report_response_data
    )


def build_url_params_for_list_messages(args):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    limit = set_limit(args.get('limit'))
    offset = int(args.get('offset', '0'))

    url_params = f'?startDate={start_date}&endDate={end_date}&searchOption=messages&ciscoHost=All_Hosts' \
                 f'&offset={offset}&limit={limit}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'attachment_name_value':
            attachment_name_operator = arguments.get('attachment_name_operator', 'is')
            url_params += f'&attachmentNameOperator={attachment_name_operator}&attachmentNameValue={value}'

        elif key == 'recipient_filter_value':
            recipient_operator = arguments.get('recipient_filter_operator', 'is')
            url_params += f'&envelopeRecipientfilterOperator={recipient_operator}&envelopeRecipientfilterValue={value}'

        elif key == 'sender_filter_value':
            sender_filter_operator = arguments.get('sender_filter_operator', 'is')
            url_params += f'&envelopeSenderfilterOperator={sender_filter_operator}&envelopeSenderfilterValue={value}'

        elif key == 'subject_filter_value':
            subject_filter_operator = arguments.get('subject_filter_operator', 'is')
            url_params += f'&subjectfilterOperator={subject_filter_operator}&subjectfilterValue={value}'

        elif key == 'domain_name_value':
            domain_name_operator = arguments.get('domain_name_operator', 'is')
            url_params += f'&domainNameOperator={domain_name_operator}&domainNameValue={value}'

        elif key == 'spam_positive' and value == 'True':
            url_params += f'&spamPositive={argToBoolean(value)}'
        elif key == 'quarantined_as_spam' and value == 'True':
            url_params += f'&quarantinedAsSpam={argToBoolean(value)}'
        elif key == 'virus_positive' and value == 'True':
            url_params += f'&virusPositive={argToBoolean(value)}'
        elif key == 'contained_malicious_urls' and value == 'True':
            url_params += f'&containedMaliciousUrls={argToBoolean(value)}'
        elif key == 'contained_neutral_urls' and value == 'True':
            url_params += f'&containedNeutralUrls={argToBoolean(value)}'

        elif key == 'file_hash':
            url_params += f'&fileSha256={value}'
        elif key == 'message_id':
            url_params += f'&messageIdHeader={int(value)}'
        elif key == 'cisco_message_id':
            url_params += f'&ciscoMid={int(value)}'
        elif key == 'sender_ip':
            url_params += f'&senderIp={value}'
        elif key == 'message_direction':
            url_params += f'&messageDirection={value}'
        elif key == 'quarantine_status':
            url_params += f'&quarantineStatus={value}'
        elif key == 'url_reputation':
            url_params += f'&urlReputation={value}'
        elif key == 'macro_file_types_detected':
            url_params += f'&macroFileTypesDetected={value}'

    return url_params


def messages_to_human_readable(messages):
    messages_readable_outputs = []
    for message in messages:
        readable_output = assign_params(message_id=dict_safe_get(message, ['attributes', 'mid'], None),
                                        cisco_message_id=dict_safe_get(message, ['attributes', 'icid'], None),
                                        sender=dict_safe_get(message, ['attributes', 'sender'], None),
                                        sender_ip=dict_safe_get(message, ['attributes', 'senderIp'], None),
                                        subject=dict_safe_get(message, ['attributes', 'subject'], None),
                                        serial_number=dict_safe_get(message, ['attributes', 'serialNumber'], None),
                                        timestamp=dict_safe_get(message, ['attributes', 'timestamp'], None))
        messages_readable_outputs.append(readable_output)
    headers = ['message_id', 'cisco_message_id', 'sender', 'sender_ip', 'subject', 'serial_number', 'timestamp']
    human_readable = tableToMarkdown('CiscoEmailSecurity Messages', messages_readable_outputs, headers, removeNull=True)
    return human_readable


def list_search_messages_command(client, args):
    url_suffix = '/sma/api/v2.0/message-tracking/messages'
    url_params = build_url_params_for_list_messages(args)
    url_suffix_to_filter_by = url_suffix + url_params
    messages_response_data = client.list_messages(url_suffix_to_filter_by)
    messages_data = messages_response_data.get('data')
    for message in messages_data:
        message['attributes']['mid'] = message.get('attributes', {}).get('mid', [None])[0]
    human_readable = messages_to_human_readable(messages_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Messages',
        outputs_key_field='attributes.mid',
        outputs=messages_data
    )


def build_url_params_for_get_details(args, url_suffix):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    message_id = args.get('message_id')
    injection_connection_id = args.get('icid')
    appliance_serial_number = args.get('appliance_serial_number')
    url_params = f'?startDate={start_date}&endDate={end_date}&mid={message_id}&icid={injection_connection_id}' \
                 f'&serialNumber={appliance_serial_number}'

    url_suffix_to_filter_by = url_suffix + url_params
    return url_suffix_to_filter_by


def details_get_to_human_readable(message):
    readable_output = assign_params(message_id=message.get('mid'), direction=message.get('direction'),
                                    sender=message.get('sender'), recipient=message.get('recipient'),
                                    subject=message.get('subject'), timestamp=message.get('timestamp'))
    headers = ['message_id', 'direction', 'sender', 'recipient', 'subject', 'timestamp']
    human_readable = tableToMarkdown('CiscoEmailSecurity Messages', readable_output, headers, removeNull=True)
    return human_readable


def response_data_to_context_and_human_readable(response_data):
    context_data = response_data.get('data')
    context_message = context_data.get('messages')
    context_message['mid'] = context_message.get('mid', [None])[0]
    human_readable = details_get_to_human_readable(context_message)
    return context_message, human_readable


def list_get_message_details_command(client, args):
    url_suffix_to_filter_by = build_url_params_for_get_details(args, '/sma/api/v2.0/message-tracking/details')
    message_get_details_response_data = client.list_get_message_details(url_suffix_to_filter_by)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Message',
        outputs_key_field='messages.mid',
        outputs=message_data
    )


def list_get_dlp_details_command(client, args):
    url_suffix_to_filter_by = build_url_params_for_get_details(args, '/sma/api/v2.0/message-tracking/dlp-details')
    message_get_details_response_data = client.list_get_dlp_details(url_suffix_to_filter_by)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Dlp',
        outputs_key_field='messages.mid',
        outputs=message_data
    )


def list_get_amp_details_command(client, args):
    url_suffix_to_filter_by = build_url_params_for_get_details(args, '/sma/api/v2.0/message-tracking/amp-details')
    message_get_details_response_data = client.list_get_amp_details(url_suffix_to_filter_by)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Amp',
        outputs_key_field='messages.mid',
        outputs=message_data
    )


def list_get_url_details_command(client, args):
    url_suffix_to_filter_by = build_url_params_for_get_details(args, '/sma/api/v2.0/message-tracking/url-details')
    message_get_details_response_data = client.list_get_url_details(url_suffix_to_filter_by)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Url',
        outputs_key_field='messages.mid',
        outputs=message_data
    )


def build_url_params_for_spam_quarantine(args):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    limit = set_limit(args.get('limit'))
    offset = int(args.get('offset', '0'))
    url_params = f'?startDate={start_date}&endDate={end_date}&quarantineType=spam&offset={offset}&limit={limit}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'order_by_from_address':
            order_dir_from_address = arguments.get('order_dir_from_address', 'asc')
            url_params += f'&orderBy={value}&orderDir={order_dir_from_address}'
        elif key == 'order_by_to_address':
            order_dir_to_address = arguments.get('order_dir_to_address', 'asc')
            url_params += f'&orderBy={value}&orderDir={order_dir_to_address}'
        elif key == 'order_by_subject':
            order_dir_subject = arguments.get('order_dir_subject', 'asc')
            url_params += f'&orderBy={value}&orderDir={order_dir_subject}'

        elif key == 'recipient_value':
            recipient_operator = arguments.get('recipient_operator', 'is')
            url_params += f'&envelopeRecipientfilterOperator={recipient_operator}&envelopeRecipientfilterValue={value}'
        elif key == 'filter_value':
            filter_operator = arguments.get('filter_operator', 'is')
            url_params += f'&filterOperator={filter_operator}&filterValue={value}'

    return url_params


def spam_quarantine_to_human_readable(spam_quarantine):
    spam_quarantine_readable_outputs = []
    for message in spam_quarantine:
        readable_output = assign_params(recipient=dict_safe_get(message, ['attributes', 'envelopeRecipient'], None),
                                        to_address=dict_safe_get(message, ['attributes', 'toAddress'], None),
                                        subject=dict_safe_get(message, ['attributes', 'subject'], None),
                                        date=dict_safe_get(message, ['attributes', 'date'], None),
                                        from_address=dict_safe_get(message, ['attributes', 'fromAddress'], None))
        spam_quarantine_readable_outputs.append(readable_output)
    headers = ['recipient', 'to_address', 'from_address', 'subject', 'date']
    human_readable = tableToMarkdown('CiscoEmailSecurity SpamQuarantine', spam_quarantine_readable_outputs, headers,
                                     removeNull=True)
    return human_readable


def list_search_spam_quarantine_command(client, args):
    url_suffix = '/sma/api/v2.0/quarantine/messages'
    url_params = build_url_params_for_spam_quarantine(args)
    url_suffix_to_filter_by = url_suffix + url_params
    spam_quarantine_response_data = client.list_spam_quarantine(url_suffix_to_filter_by)
    spam_quarantine_data = spam_quarantine_response_data.get('data')
    human_readable = spam_quarantine_to_human_readable(spam_quarantine_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.SpamQuarantine',
        outputs_key_field='mid',
        outputs=spam_quarantine_data
    )


def quarantine_message_details_data_to_human_readable(message):
    readable_output = assign_params(recipient=message.get('envelopeRecipient'), date=message.get('date'),
                                    to_address=message.get('toAddress'), subject=message.get('subject'),
                                    from_address=message.get('fromAddress'))
    headers = ['recipient', 'to_address', 'from_address', 'subject', 'date']
    human_readable = tableToMarkdown('CiscoEmailSecurity QuarantineMessageDetails', readable_output, headers,
                                     removeNull=True)
    return human_readable


def list_get_quarantine_message_details_command(client, args):
    message_id = args.get('message_id')
    url_suffix_to_filter_by = f'/sma/api/v2.0/quarantine/messages?mid={message_id}&quarantineType=spam'
    quarantine_message_details_response = client.list_quarantine_get_details(url_suffix_to_filter_by)
    quarantine_message_details = quarantine_message_details_response.get('data')
    human_readable = quarantine_message_details_data_to_human_readable(quarantine_message_details.get('attributes'))
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.QuarantineMessageDetails',
        outputs_key_field='mid',
        outputs=quarantine_message_details
    )


def list_delete_quarantine_messages_command(client, args):
    messages_ids = args.get('messages_ids')
    url_suffix = '/sma/api/v2.0/quarantine/messages'
    request_body = {
        "quarantineType": "spam",
        "mids": messages_ids
    }
    delete_quarantine_messages_response = client.list_delete_quarantine_messages(url_suffix, request_body)
    return CommandResults(
        readable_output=delete_quarantine_messages_response,
        outputs_prefix='CiscoEmailSecurity.QuarantineDeleteMessages',
        outputs_key_field='mid'
    )


def list_release_quarantine_messages_command(client, args):
    messages_ids = args.get('messages_ids')
    url_suffix = '/sma/api/v2.0/quarantine/messages'
    request_body = {
        "action": "release",
        "quarantineType": "spam",
        "mids": messages_ids
    }
    release_quarantine_messages_response = client.list_release_quarantine_messages(url_suffix, request_body)
    return CommandResults(
        readable_output=release_quarantine_messages_response,
        outputs_prefix='CiscoEmailSecurity.QuarantineDeleteMessages',
        outputs_key_field='mid'
    )


def build_url_filter_for_get_list_entries(args):
    url_suffix = SAFELIST_AND_BLOCKLIST_TO_FILTER_URL[args.get('list_type')]
    limit = set_limit(args.get('limit'))
    offset = int(args.get('offset', '0'))
    view_by = args.get('view_by')
    url_params = f"?action=view&limit={limit}&offset={offset}&quarantineType=spam&orderDir=desc&viewBy={view_by}"
    order_by = args.get('order_by')
    if order_by:
        url_params += f"&orderBy={order_by}"
    url_suffix_to_filter_by = url_suffix + url_params
    return url_suffix_to_filter_by


def list_entries_get_command(client, args):
    url_suffix_to_filter_by = build_url_filter_for_get_list_entries(args)
    list_entries_response = client.list_entries_get(url_suffix_to_filter_by)
    list_entries = list_entries_response.get('data')
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix='CiscoEmailSecurity.ListEntriesGet',
        outputs_key_field='mid',
        outputs=list_entries
    )


def build_url_and_request_body_for_add_list_entries(args):
    url_suffix = SAFELIST_AND_BLOCKLIST_TO_FILTER_URL[args.get('list_type')]

    request_body = {
        "action": args.get('action'),
        "quarantineType": "spam",
        "viewBy": args.get('view_by')
    }

    if args.get('recipient_addresses'):
        request_body["recipientAddresses"] = args.get('recipient_addresses')
    if args.get('recipient_list'):
        request_body["recipientList"] = args.get('recipient_list')
    if args.get('sender_addresses'):
        request_body["senderAddresses"] = args.get('sender_addresses')
    if args.get('sender_list'):
        request_body["senderList"] = args.get('sender_list')
    return url_suffix, request_body


def list_entries_add_command(client, args):
    url_suffix, request_body = build_url_and_request_body_for_add_list_entries(args)
    list_entries_response = client.list_entries_add(url_suffix, request_body)
    list_entries = list_entries_response.get('data')
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix='CiscoEmailSecurity.listEntriesAdd',
        outputs_key_field='mid',
        outputs=list_entries
    )


def build_url_and_request_body_for_delete_list_entries(args):
    url_suffix = SAFELIST_AND_BLOCKLIST_TO_FILTER_URL[args.get('list_type')]

    request_body = {
        "quarantineType": "spam",
        "viewBy": args.get('view_by')
    }
    if args.get('recipient_list'):
        request_body["recipientList"] = args.get('recipient_list')
    if args.get('sender_list'):
        request_body["senderList"] = args.get('sender_list')
    return url_suffix, request_body


def list_entries_delete_command(client, args):
    url_suffix, request_body = build_url_and_request_body_for_delete_list_entries(args)
    list_entries_response = client.list_entries_delete(url_suffix, request_body)
    list_entries = list_entries_response.get('data')
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix='CiscoEmailSecurity.listEntriesDelete',
        outputs_key_field='mid',
        outputs=list_entries
    )


def main() -> None:

    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(params)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cisco-email-security-report-get':
            return_results(list_report_command(client, args))
        elif demisto.command() == 'cisco-email-security-messages-search':
            return_results(list_search_messages_command(client, args))
        elif demisto.command() == 'cisco-email-security-message-details-get':
            return_results(list_get_message_details_command(client, args))
        elif demisto.command() == 'cisco-email-security-spam-quarantine-search':
            return_results(list_search_spam_quarantine_command(client, args))
        elif demisto.command() == 'cisco-email-security-spam-quarantine-message-details-get':
            return_results(list_get_quarantine_message_details_command(client, args))
        elif demisto.command() == 'cisco-email-security-spam-quarantine-messages-delete':
            return_results(list_delete_quarantine_messages_command(client, args))
        elif demisto.command() == 'cisco-email-security-spam-quarantine-messages-release':
            return_results(list_release_quarantine_messages_command(client, args))
        elif demisto.command() == 'cisco-email-security-dlp-details-get':
            return_results(list_get_dlp_details_command(client, args))
        elif demisto.command() == 'cisco-email-security-amp-details-get':
            return_results(list_get_amp_details_command(client, args))
        elif demisto.command() == 'cisco-email-security-url-details-get':
            return_results(list_get_url_details_command(client, args))
        elif demisto.command() == 'cisco-email-security-list-entries-get':
            return_results(list_entries_get_command(client, args))
        elif demisto.command() == 'cisco-email-security-list-entry-add':
            return_results(list_entries_add_command(client, args))
        elif demisto.command() == 'cisco-email-security-list-entry-delete':
            return_results(list_entries_delete_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
