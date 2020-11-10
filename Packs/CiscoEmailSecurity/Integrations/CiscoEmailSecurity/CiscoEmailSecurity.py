import demistomock as demisto
from CommonServerPython import *

import urllib3
import traceback
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

MAX_MESSAGES_TO_GET = 20


class Client(BaseClient):

    def __init__(self, params):
        self.username = params.get('credentials').get('identifier')
        self.password = params.get('credentials').get('password')
        self.timeout = int(params.get('timeout'))
        super().__init__(base_url=params.get('base_url'), verify=not params.get('insecure', False),
                         ok_codes=tuple(), proxy=params.get('proxy', False))

        self._jwt_token = self._generate_jwt_token()
        self._headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'jwtToken': self._jwt_token
        }

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
        response_token = self._http_request('POST', '/sma/api/v2.0/login', json_data=data, headers=headers)
        jwt_token = response_token.get('data').get('jwtToken')
        return jwt_token

    def list_report(self, url_params) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/reporting' + url_params,
            timeout=self.timeout
        )

    def list_messages(self, url_params) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/message-tracking/messages' + url_params,
            timeout=self.timeout
        )

    def list_get_message_details(self, url_params):
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/message-tracking/details' + url_params,
            timeout=self.timeout
        )

    def list_get_dlp_details(self, url_params):
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/message-tracking/dlp-details' + url_params,
            timeout=self.timeout
        )

    def list_get_amp_details(self, url_params):
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/message-tracking/amp-details' + url_params,
            timeout=self.timeout
        )

    def list_get_url_details(self, url_params):
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/message-tracking/url-details' + url_params,
            timeout=self.timeout
        )

    def list_spam_quarantine(self, url_params):
        return self._http_request(
            method='GET',
            url_suffix='/sma/api/v2.0/quarantine/messages' + url_params,
            timeout=self.timeout
        )

    def list_quarantine_get_details(self, message_id):
        return self._http_request(
            method='GET',
            url_suffix=f'/sma/api/v2.0/quarantine/messages/details?mid={message_id}&quarantineType=spam',
            timeout=self.timeout
        )

    def list_delete_quarantine_messages(self, request_body):
        return self._http_request(
            method='DELETE',
            url_suffix='/sma/api/v2.0/quarantine/messages',
            json_data=request_body,
            timeout=self.timeout
        )

    def list_release_quarantine_messages(self, request_body):
        return self._http_request(
            method='POST',
            url_suffix='/sma/api/v2.0/quarantine/messages',
            json_data=request_body,
            timeout=self.timeout
        )

    def list_entries_get(self, url_params, list_type):
        return self._http_request(
            method='GET',
            url_suffix=f"/sma/api/v2.0/quarantine/{list_type}" + url_params,
            timeout=self.timeout
        )

    def list_entries_add(self, list_type, request_body):
        return self._http_request(
            method='POST',
            url_suffix=f"/sma/api/v2.0/quarantine/{list_type}",
            json_data=request_body,
            timeout=self.timeout
        )

    def list_entries_delete(self, list_type, request_body):
        return self._http_request(
            method='DELETE',
            url_suffix=f"/sma/api/v2.0/quarantine/{list_type}",
            json_data=request_body,
            timeout=self.timeout
        )


def parse_dates_to_ces_format(date_str):
    splitted_date = date_str.split('T')
    date_day = splitted_date[0]
    full_date_time = splitted_date[1]
    date_time_without_ms = full_date_time.split('.')[0]
    date_time_without_seconds = date_time_without_ms[:-3]
    date_time_with_zero_seconds = f'{date_time_without_seconds}:00.000Z'

    return f'{date_day}T{date_time_with_zero_seconds}'


def get_dates_for_test_module():
    now = datetime.now()
    start = now - timedelta(days=2)
    end = now - timedelta(days=1)

    start_date = start.isoformat()
    end_date = end.isoformat()

    start_date = parse_dates_to_ces_format(start_date)
    end_date = parse_dates_to_ces_format(end_date)
    return start_date, end_date


def test_module(client: Client) -> str:
    start_date, end_date = get_dates_for_test_module()
    suffix_url = f"?startDate={start_date}&" \
                 f"endDate={end_date}&ciscoHost=All_Hosts&searchOption=messages&offset=0&limit=20"
    try:
        client.list_messages(suffix_url)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key or Service URL are correctly set'
        else:
            raise e
    return 'ok'


def date_to_cisco_date(date):
    """
    This function gets a date and returns it according to the standard of Cisco Email security.
    Args:
        date: YYYY-MM-DD hh:mm:ss.
    Returns:
        The date according to the standard of Cisco Email security - YYYY-MM-DDThh:mm:ss.000Z.
    """
    return date.replace(' ', 'T') + '.000Z'


def set_limit(limit):
    return int(limit) if limit and int(limit) <= MAX_MESSAGES_TO_GET else MAX_MESSAGES_TO_GET


def message_ids_to_list_of_integers(args):
    messages_ids = args.get('messages_ids').split(',')
    messages_ids = [int(message_id) for message_id in messages_ids]
    return messages_ids


def build_url_params_for_list_report(args, report_counter):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    device_group_name = args.get('device_group_name')
    url_params = f'/{report_counter}?startDate={start_date}&endDate={end_date}&device_type=esa' \
                 f'&device_group_name={device_group_name}'
    return url_params


def set_var_to_output_prefix(counter):
    """
    This function gets a variable and returns it according to the standard of outputs prefix.
    Args:
        counter: report counter - mail_incoming_traffic_summary.
    Returns:
        The counter according to the standard of outputs prefix - MailIncomingTrafficSummary.
    """
    list_counter_words = counter.split('_')
    counter_words = ''
    for word in list_counter_words:
        counter_words += word + ' '
    counter_words_capital_letter = counter_words.title()
    counter_output_prefix = counter_words_capital_letter.replace(' ', '')
    return counter_output_prefix


def list_report_command(client: Client, args: Dict[str, Any]):
    counter = args.get('counter')
    url_params = build_url_params_for_list_report(args, counter)
    report_response_data = client.list_report(url_params)
    report_data = report_response_data.get('data', {}).get('resultSet')
    counter_output_prefix = set_var_to_output_prefix(counter)
    return CommandResults(
        readable_output=f'{report_response_data}',
        outputs_prefix=f'CiscoEmailSecurity.Report.{counter_output_prefix}',
        outputs_key_field=counter_output_prefix,
        outputs=report_data
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
        elif key == 'cisco_id':
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
                                        cisco_id=dict_safe_get(message, ['attributes', 'icid'], None),
                                        sender=dict_safe_get(message, ['attributes', 'sender'], None),
                                        sender_ip=dict_safe_get(message, ['attributes', 'senderIp'], None),
                                        subject=dict_safe_get(message, ['attributes', 'subject'], None),
                                        serial_number=dict_safe_get(message, ['attributes', 'serialNumber'], None),
                                        timestamp=dict_safe_get(message, ['attributes', 'timestamp'], None))
        messages_readable_outputs.append(readable_output)
    headers = ['timestamp', 'message_id', 'cisco_id', 'sender', 'sender_ip', 'subject', 'serial_number']
    human_readable = tableToMarkdown('CiscoEmailSecurity Messages', messages_readable_outputs, headers, removeNull=True)
    return human_readable


def list_search_messages_command(client, args):
    url_params = build_url_params_for_list_messages(args)
    messages_response_data = client.list_messages(url_params)
    messages_data = messages_response_data.get('data')
    for message in messages_data:
        message_details = message.get('attributes', {})
        message_id = message_details.get('mid', [None])[0]
        message['attributes']['mid'] = message_id
    human_readable = messages_to_human_readable(messages_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Message',
        outputs_key_field='attributes.mid',
        outputs=messages_data
    )


def build_url_params_for_get_details(args):
    start_date = date_to_cisco_date(args.get('start_date'))
    end_date = date_to_cisco_date(args.get('end_date'))
    message_id = args.get('message_id')
    cisco_id = args.get('cisco_id')
    appliance_serial_number = args.get('appliance_serial_number')
    url_params = f'?startDate={start_date}&endDate={end_date}&mid={message_id}&icid={cisco_id}' \
                 f'&serialNumber={appliance_serial_number}'
    return url_params


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
    url_params = build_url_params_for_get_details(args)
    message_get_details_response_data = client.list_get_message_details(url_params)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.Message',
        outputs_key_field='mid',
        outputs=message_data
    )


def list_get_dlp_details_command(client, args):
    url_params = build_url_params_for_get_details(args)
    message_get_details_response_data = client.list_get_dlp_details(url_params)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.DLP',
        outputs_key_field='mid',
        outputs=message_data
    )


def list_get_amp_details_command(client, args):
    url_params = build_url_params_for_get_details(args)
    message_get_details_response_data = client.list_get_amp_details(url_params)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.AMP',
        outputs_key_field='mid',
        outputs=message_data
    )


def list_get_url_details_command(client, args):
    url_params = build_url_params_for_get_details(args)
    message_get_details_response_data = client.list_get_url_details(url_params)
    message_data, human_readable = response_data_to_context_and_human_readable(message_get_details_response_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.URL',
        outputs_key_field='mid',
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
        if key == 'order_by':
            order_dir = arguments.get('order_dir', 'asc')
            url_params += f'&orderBy={value}&orderDir={order_dir}'

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
        readable_output = assign_params(message_id=message.get('mid'),
                                        recipient=dict_safe_get(message, ['attributes', 'envelopeRecipient'], None),
                                        to_address=dict_safe_get(message, ['attributes', 'toAddress'], None),
                                        subject=dict_safe_get(message, ['attributes', 'subject'], None),
                                        date=dict_safe_get(message, ['attributes', 'date'], None),
                                        from_address=dict_safe_get(message, ['attributes', 'fromAddress'], None))
        spam_quarantine_readable_outputs.append(readable_output)
    headers = ['message_id', 'recipient', 'to_address', 'from_address', 'subject', 'date']
    human_readable = tableToMarkdown('CiscoEmailSecurity The Quarantine Messages', spam_quarantine_readable_outputs,
                                     headers, removeNull=True)
    return human_readable


def list_search_spam_quarantine_command(client, args):
    url_params = build_url_params_for_spam_quarantine(args)
    spam_quarantine_response_data = client.list_spam_quarantine(url_params)
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
    quarantine_message_details_response = client.list_quarantine_get_details(message_id)
    quarantine_message_details = quarantine_message_details_response.get('data')
    human_readable = quarantine_message_details_data_to_human_readable(quarantine_message_details.get('attributes'))
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.QuarantineMessageDetail',
        outputs_key_field='mid',
        outputs=quarantine_message_details
    )


def list_delete_quarantine_messages_command(client, args):
    messages_ids = message_ids_to_list_of_integers(args)
    request_body = {
        "quarantineType": "spam",
        "mids": messages_ids
    }
    delete_quarantine_messages_response = client.list_delete_quarantine_messages(request_body)
    total_count = dict_safe_get(delete_quarantine_messages_response, ['data', 'totalCount'], None)
    return CommandResults(
        readable_output=f'{total_count} messages successfully deleted from quarantine list',
    )


def list_release_quarantine_messages_command(client, args):
    messages_ids = message_ids_to_list_of_integers(args)
    request_body = {
        "action": "release",
        "quarantineType": "spam",
        "mids": messages_ids
    }
    release_quarantine_messages_response = client.list_release_quarantine_messages(request_body)
    total_count = dict_safe_get(release_quarantine_messages_response, ['data', 'totalCount'], None)
    return CommandResults(
        readable_output=f'{total_count} messages successfully released from quarantine list',
    )


def build_url_filter_for_get_list_entries(args):
    limit = set_limit(args.get('limit'))
    offset = int(args.get('offset', '0'))
    view_by = args.get('view_by')
    order_by = args.get('order_by')
    url_params = f"?action=view&limit={limit}&offset={offset}&quarantineType=spam&orderDir=desc&viewBy={view_by}" \
                 f"&orderBy={order_by}"
    return url_params


def list_entries_get_command(client, args):
    list_type = args.get('list_type')
    url_params = build_url_filter_for_get_list_entries(args)
    list_entries_response = client.list_entries_get(url_params, list_type)
    list_entries = list_entries_response.get('data', [None])
    output_prefix = list_type.title()
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix=f'CiscoEmailSecurity.ListEntry.{output_prefix}',
        outputs_key_field=output_prefix,
        outputs=list_entries
    )


def build_request_body_for_add_list_entries(args):
    request_body = {
        "action": args.get('action'),
        "quarantineType": "spam",
        "viewBy": args.get('view_by')
    }

    if 'recipient_addresses' in args:
        request_body["recipientAddresses"] = args.get('recipient_addresses').split(',')
    if 'recipient_list' in args:
        request_body["recipientList"] = args.get('recipient_list').split(',')
    if 'sender_addresses' in args:
        request_body["senderAddresses"] = args.get('sender_addresses').split(',')
    if 'sender_list' in args:
        request_body["senderList"] = args.get('sender_list').split(',')
    return request_body


def set_outputs_key_for_list_recipient_and_sender(args):
    """
    This function checks which argument used and returns it for the outputs prefix.
    Args:
        args: The recipient list or the sender list.
    Returns:
        The recipient list or the sender list, depending on what was used.
    """
    return args.get('recipient_list') if args.get('recipient_list') else args.get('sender_list')


def list_entries_add_command(client, args):
    list_type = args.get('list_type')
    request_body = build_request_body_for_add_list_entries(args)
    list_entries_response = client.list_entries_add(list_type, request_body)
    list_entries = list_entries_response.get('data')
    output_prefix = list_type.title()
    outputs_key_field = set_outputs_key_for_list_recipient_and_sender(args)
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix=f'CiscoEmailSecurity.listEntry.{output_prefix}',
        outputs_key_field=outputs_key_field,
    )


def build_request_body_for_delete_list_entries(args):
    request_body = {
        "quarantineType": "spam",
        "viewBy": args.get('view_by')
    }
    if args.get('recipient_list'):
        request_body["recipientList"] = args.get('recipient_list').split(',')
    if args.get('sender_list'):
        request_body["senderList"] = args.get('sender_list').split(',')
    return request_body


def list_entries_delete_command(client, args):
    list_type = args.get('list_type')
    request_body = build_request_body_for_delete_list_entries(args)
    list_entries_response = client.list_entries_delete(list_type, request_body)
    list_entries = list_entries_response.get('data')
    output_prefix = list_type.title()
    outputs_key_field = set_outputs_key_for_list_recipient_and_sender(args)
    return CommandResults(
        readable_output=list_entries,
        outputs_prefix=f'CiscoEmailSecurity.listEntry.{output_prefix}',
        outputs_key_field=outputs_key_field,
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
