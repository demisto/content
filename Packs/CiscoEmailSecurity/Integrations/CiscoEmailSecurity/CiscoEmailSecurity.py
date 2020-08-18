import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, params):
        self.username = params.get('client_id')
        self.password = params.get('client_secret')
        super().__init__(base_url=params.get('base_url'), verify=not params.get('insecure', False),
                         ok_codes=tuple(), proxy=params.get('proxy', False))
        self._token_jwt = self._generate_jwt_token()
        self._token_base64 = self._generate_base64_token()
        self._headers = {'Authorization': 'Bearer ' + self._token_jwt}

        # Authorization base64 If jwtToken does not work
        # self._headers = {'Authorization': 'Basic ' + self._token_base64}

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)

    def _generate_jwt_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            'userName': self.username,
            'passphrase': self.password
        }
        token_res = self.http_request('POST', '/esa/api/v2.0/login', data=body, auth=(self.username, self.password))
        return token_res.get('data').get('jwtToken')

    def _generate_base64_token(self) -> str:
        basic_authorization_to_encode = f'{self.username}:{self.password}'
        basic_authorization = base64.b64encode(basic_authorization_to_encode.encode('ascii')).decode('utf-8')
        return basic_authorization


    def list_report(self, url_suffix) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
        )

    def list_messages(self, url_suffix) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_message_get_details(self, url_suffix):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_spam_quarantine(self, url_suffix):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_quarantine_get_details(self, url_suffix):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )


def test_module(client: Client, suffix_url: str) -> str:

    try:
        client.list_report(suffix_url)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def build_url_params_for_list_report(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    device_type = args.get('device_type')
    url_params = f'?startDate={start_date}&endDate={end_date}&device_type={device_type}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'offset':
            limit = arguments.get('limit')
            url_params += f'&{key}={int(value)}&limit={int(limit)}'

        if key == 'filter_key':
            filter_operator = arguments.get('filter_operator')
            filter_value = arguments.get('filter_value')
            url_params += f'&filterBy={value}&filter_operator={filter_operator}&filter_value{filter_value}'

        if key == 'device_group':
            url_params += f'&{key}={value}'
        if key == 'device_name':
            url_params += f'&{key}={value}'

    return url_params


def list_report_command(client: Client, args: Dict[str, Any]):
    url_suffix = '/api/v2.0/reporting'
    url_params = build_url_params_for_list_report(args)
    url_suffix_to_filter_by = url_suffix + url_params
    report_response_data = client.list_report(url_suffix_to_filter_by)
    return CommandResults(
        readable_output='human_readable',
        outputs_prefix='CiscoEmailSecurity.report',
        outputs_key_field='',
        outputs=report_response_data
    )


def build_url_params_for_list_messages(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    url_params = f'?startDate={start_date}&endDate={end_date}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'offset':
            limit = arguments.get('limit')
            url_params += f'&{key}={int(value)}&limit={int(limit)}'

        if key == 'attachment_name_value':
            attachment_name_operator = arguments.get('attachment_name_operator', 'is')
            url_params += f'&attachmentNameOperator={attachment_name_operator}&attachmentNameValue={value}'

        if key == 'recipient_filter_value':
            recipient_operator = arguments.get('recipient_filter_operator', 'is')
            url_params += f'&envelopeRecipientfilterOperator={recipient_operator}&envelopeRecipientfilterValue={value}'

        if key == 'sender_filter_value':
            sender_filter_operator = arguments.get('sender_filter_operator')
            url_params += f'&envelopeSenderfilterOperator={sender_filter_operator}&envelopeSenderfilterValue={value}'

        if key == 'subject_filter_value':
            subject_filter_operator = arguments.get('subject_filter_operator')
            url_params += f'&subjectfilterOperator={subject_filter_operator}&subjectfilterValue={value}'

        if key == 'domain_name_value':
            domain_name_operator = arguments.get('domain_name_operator')
            url_params += f'&domainNameOperator={domain_name_operator}&domainNameValue={value}'

        if key == 'spam_positive' and value == 'True':
            url_params += f'&spamPositive={argToBoolean(value)}'
        if key == 'quarantined_as_spam' and value == 'True':
            url_params += f'&quarantinedAsSpam={argToBoolean(value)}'
        if key == 'virus_positive' and value == 'True':
            url_params += f'&virusPositive={argToBoolean(value)}'
        if key == 'contained_malicious_urls' and value == 'True':
            url_params += f'&containedMaliciousUrls={argToBoolean(value)}'
        if key == 'contained_neutral_urls' and value == 'True':
            url_params += f'&containedNeutralUrls={argToBoolean(value)}'

        if key == 'file_hash':
            url_params += f'&fileSha256={value}'
        if key == 'message_id':
            url_params += f'&messageIdHeader={int(value)}'
        if key == 'cisco_message_id':
            url_params += f'&ciscoMid={int(value)}'
        if key == 'sender_ip':
            url_params += f'&senderIp={value}'
        if key == 'message_direction':
            url_params += f'&messageDirection={value}'
        if key == 'quarantine_status':
            url_params += f'&quarantineStatus={value}'
        if key == 'url_reputation':
            url_params += f'&urlReputation={value}'
        if key == 'macro_file_types_detected':
            url_params += f'&macroFileTypesDetected={value}'

    return url_params


def messages_to_human_readable(messages):
    messages_readable_outputs = []
    for message in messages:
        readable_output = assign_params(message_id=message.get('mid'), cisco_message_id=message.get('icid'),
                                        sender=message.get('sender'), sender_ip=message.get('senderIp'),
                                        subject=message.get('subject'),
                                        serial_number=message.get('serialNumber'), timestamp=message.get('timestamp'))
        messages_readable_outputs.append(readable_output)
    headers = ['message_id', 'cisco_message_id', 'sender', 'sender_ip', 'subject', 'serial_number', 'timestamp']
    human_readable = tableToMarkdown('CiscoEmailSecurity Messages', messages_readable_outputs, headers, removeNull=True)
    return human_readable


def list_search_messages_command(client, args):
    url_suffix = '/esa/api/v2.0/message-tracking/messages'
    url_params = build_url_params_for_list_messages(args)
    url_suffix_to_filter_by = url_suffix + url_params
    messages_response_data = client.list_messages(url_suffix_to_filter_by)
    messages_data = messages_response_data.get('data')
    messages_data['mid'] = messages_data.get('mid')[0]
    human_readable = messages_to_human_readable(messages_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.messages',
        outputs_key_field='mid',
        outputs=messages_data
    )


def build_url_params_for_get_details(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    message_id = args.get('message_id')
    icid = args.get('icid')
    url_params = f'?startDate={start_date}&endDate={end_date}&mid={message_id}&icid={icid}'

    if args.get('appliance_serial_number'):
        appliance_serial_number = args.get('appliance_serial_number')
        url_params += f'&serialNumber={appliance_serial_number}'

    return url_params


def message_to_human_readable(message):
    readable_output = assign_params(message_id=message.get('mid'), direction=message.get('direction'),
                                    sender=message.get('sender'), recipient=message.get('recipient')[0],
                                    subject=message.get('subject'), timestamp=message.get('timestamp'))
    headers = ['message_id', 'direction', 'sender', 'recipient', 'subject', 'timestamp']
    human_readable = tableToMarkdown('CiscoEmailSecurity Messages', readable_output, headers, removeNull=True)
    return human_readable


def list_get_message_details_command(client, args):
    url_suffix = '/api/v2.0/message-tracking/details'
    url_params = build_url_params_for_get_details(args)
    url_suffix_to_filter_by = url_suffix + url_params
    message_get_details_response_data = client.list_message_get_details(url_suffix_to_filter_by)
    message_data = message_get_details_response_data.get('data')
    message_data['mid'] = message_data.get('mid')[0]
    human_readable = message_to_human_readable(message_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='CiscoEmailSecurity.message',
        outputs_key_field='mid',
        outputs=message_data
    )


def build_url_params_for_spam_quarantine(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    url_params = f'?startDate={start_date}&endDate={end_date}&quarantineType=spam'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'from_address':
            from_address_order_dir = arguments.get('from_address_order_dir', 'asc')
            url_params += f'&orderBy={value}&orderDir={from_address_order_dir}'
        if key == 'to_address':
            to_address_order_dir = arguments.get('to_address_order_dir', 'asc')
            url_params += f'&orderBy={value}&orderBy={to_address_order_dir}'
        if key == 'subject':
            subject_order_dir = arguments.get('from_address_order_dir', 'asc')
            url_params += f'&orderBy={value}&orderBy={subject_order_dir}'

        if key == 'recipient_value':
            recipient_operator = arguments.get('recipient_operator', 'is')
            url_params += f'&envelopeRecipientfilterOperator={recipient_operator}&envelopeRecipientfilterValue={value}'
        if key == 'filter_value':
            filter_operator = arguments.get('filter_operator', 'is')
            url_params += f'&filterOperator={filter_operator}&filterValue={value}'

    return url_params


def list_search_spam_quarantine_command(client, args):
    url_suffix = '/api/v2.0/quarantine/messages'
    url_params = build_url_params_for_spam_quarantine(args)
    url_suffix_to_filter_by = url_suffix + url_params
    spam_quarantine_response_data = client.list_spam_quarantine(url_suffix_to_filter_by)
    spam_quarantine_data = spam_quarantine_response_data.get('data')
    return CommandResults(
        readable_output='human_readable',
        outputs_prefix='CiscoEmailSecurity.SpamQuarantine',
        outputs_key_field='mid',
        outputs=spam_quarantine_data
    )


def list_get_quarantine_message_details_command(client, args):
    mid = args.get('mid')
    url_suffix_to_filter_by = f'/api/v2.0/quarantine/messages?mid={mid}&quarantineType=spam'
    quarantine_message_details_response_data = client.list_quarantine_get_details(url_suffix_to_filter_by)
    quarantine_message_details_data = quarantine_message_details_response_data.get('data')
    return CommandResults(
        readable_output='human_readable',
        outputs_prefix='CiscoEmailSecurity.QuarantineMessageDetails',
        outputs_key_field='mid',
        outputs=quarantine_message_details_data
    )


def main() -> None:

    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(params)

        if demisto.command() == 'test-module':
            result = test_module(client,'/api/v2.0/reporting')
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

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
