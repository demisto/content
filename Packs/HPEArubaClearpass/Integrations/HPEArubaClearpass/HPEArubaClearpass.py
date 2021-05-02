import json
import sys
from datetime import datetime, timedelta

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR"
TOKEN_TYPE = "Bearer"


class Client(BaseClient):
    def __init__(self, proxy: bool, verify: bool, base_url: str, client_id: str, client_secret: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = ""
        self.headers = {}

    def generate_new_access_token(self):
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        return self._http_request(
            method='POST',
            url_suffix="oauth",
            json_data=body
        )

    def save_access_token_to_context(self, auth_response):
        access_token_expiration_in_seconds = auth_response.get("expires_in")
        if access_token_expiration_in_seconds and isinstance(auth_response.get("expires_in"), int):
            access_token_expiration_datetime = datetime.now() + timedelta(seconds=access_token_expiration_in_seconds)
            context = {"access_token": self.access_token,
                       "expires_in": access_token_expiration_datetime.strftime(DATE_FORMAT)}
            set_integration_context(context)
            demisto.debug(
                f"New access token that expires in : {access_token_expiration_datetime.strftime(DATE_FORMAT)} w"
                f"as set to integration_context.")
        else:
            return_error(f"HPEArubaClearpass error: Got an invalid access token "
                         f"expiration time from the API: {access_token_expiration_in_seconds} "
                         f"from type: {type(access_token_expiration_in_seconds)}")

    def login(self):
        integration_context = get_integration_context()
        if integration_context:
            access_token_expiration = integration_context.get('expires_in')
            access_token = integration_context.get('access_token')
            is_context_has_access_token = access_token and access_token_expiration
            access_token_expiration_datetime = datetime.strptime(access_token_expiration, DATE_FORMAT)
            if is_context_has_access_token and access_token_expiration_datetime > datetime.now():
                self.access_token = access_token
                self.set_request_headers()
                return
        else:
            # if the access is expired or not exist, generate a new one
            auth_response = self.generate_new_access_token()
            access_token = auth_response.get("access_token")
            if access_token:
                self.access_token = access_token
                self.save_access_token_to_context(auth_response)
                self.set_request_headers()
            else:
                return_error("HPE Aruba Clearpass error: The client credentials are invalid.")

    def set_request_headers(self):
        """
        Setting the headers for the future HTTP requests.
        The headers should be: {Authorization: Bearer <access_token>}
        """
        authorization_header_value = f"{TOKEN_TYPE} {self.access_token}"
        self.headers = {"Authorization": authorization_header_value}

    def prepare_request(self, method: str, params: dict, url_suffix: str, body={}, resp_type='json'):
        return self._http_request(
            method=method,
            params=params,
            url_suffix=url_suffix,
            headers=self.headers,
            json_data=body,
            resp_type=resp_type
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        params = {"filter": {}, "offset": 0, "limit": 25}
        client.prepare_request(method='GET', params=params, url_suffix='endpoint')
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def parse_items_response(response, parsing_function):
    items_list = response.get('_embedded', {}).get('items')
    human_readable = []
    if items_list:
        for item in items_list:
            human_readable.append(parsing_function(item))
    return human_readable, items_list


def get_endpoints_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mac_address = args.get('mac_address')
    status = args.get('status')
    offset = args.get('offset', 0)
    limit = args.get('limit', 25)
    endpoints_filter = {}
    endpoints_filter.update({"status": status}) if status else None
    endpoints_filter.update({"mac_address": mac_address}) if mac_address else None
    endpoints_filter = json.dumps(endpoints_filter)
    params = {"filter": endpoints_filter, "limit": limit, "offset": offset}
    res = client.prepare_request(method='GET', params=params, url_suffix='endpoint')

    readable_output, outputs = parse_items_response(res, endpoints_response_to_dict)
    human_readable = tableToMarkdown('HPE Aruba Clearpass endpoints', readable_output, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearpass.endpoints',
        outputs_key_field='id',
        outputs=outputs,
    )


def endpoints_response_to_dict(response):
    return {
        'ID': response.get('id'),
        'MAC Address': response.get('mac_address'),
        'Status': response.get('status', ""),
        'Attributes': response.get('attributes', ""),
        'Description': response.get('description', ""),
        'Device insight tags': response.get('device_insight_tags', "")
    }


def update_endpoint_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    endpoint_id = args.get('endpoint_id')
    mac_address = args.get('mac_address')
    status = args.get('status')
    description = args.get('description')
    device_insight_tags = argToList(args.get('device_insight_tags'))

    attributes = argToList(args.get('attributes'))
    attributes_values = {}
    for attribute in attributes:
        attributes_values.update(attribute)

    request_body = {}
    request_body.update({"status": status}) if status else None
    request_body.update({"mac_address": mac_address}) if mac_address else None
    request_body.update({"description": description}) if description else None
    request_body.update({"device_insight_tags": device_insight_tags}) if device_insight_tags else None
    request_body.update({"attributes": attributes_values}) if attributes else None

    res = client.prepare_request(method='PATCH', params={}, url_suffix=f'endpoint/{endpoint_id}', body=request_body)
    outputs = endpoints_response_to_dict(res)
    human_readable = tableToMarkdown('HPE Aruba Clearpass endpoints', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearpass.endpoints',
        outputs_key_field='id',
        outputs=outputs,
    )


def get_attributes_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    attribute_id = args.get('attribute_id')
    try:
        if attribute_id:
            attribute_id = int(attribute_id)
    except ValueError:
        return_error("Please note that attribute_id should be a valid id number (integer).")

    name = args.get('name')
    entity_name = args.get('entity_name')
    offset = args.get('offset', 0)
    limit = args.get('limit', 25)

    attribute_filter = {}
    attribute_filter.update({"id": attribute_id}) if attribute_id else None
    attribute_filter.update({"name": name}) if name else None
    attribute_filter.update({"entity_name": entity_name}) if entity_name else None
    attribute_filter = json.dumps(attribute_filter)
    params = {"filter": attribute_filter, "offset": offset, "limit": limit}

    res = client.prepare_request(method='GET', params=params, url_suffix='attribute')

    readable_output, outputs = parse_items_response(res, attributes_response_to_dict)
    human_readable = tableToMarkdown('HPE Aruba Clearpass attributes', readable_output, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearpass.attributes.list',
        outputs_key_field='id',
        outputs=outputs,
    )


def create_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    entity_name = args.get('entity_name')
    data_type = args.get('data_type')
    mandatory = args.get('mandatory', False)
    attribute_default_value = args.get('default_value', "")
    allow_multiple_data_type_string = args.get('allow_multiple', False)
    allowed_list_data_types_value = args.get('allowed_value', "")

    if allow_multiple_data_type_string and data_type != "String":
        return_error(f"Note: allow_multiple argument should be true only for data type String and not for {data_type}.")
    if allowed_list_data_types_value and data_type != 'List':
        return_error(f"Note: allowed_value argument should be set only for data type List and not for {data_type}.")

    new_attribute_body = {}
    new_attribute_body.update({"name": name})
    new_attribute_body.update({"entity_name": entity_name})
    new_attribute_body.update({"data_type": data_type})
    new_attribute_body.update({"mandatory": mandatory}) if mandatory else None
    new_attribute_body.update({"default_value": attribute_default_value}) if attribute_default_value else None
    new_attribute_body.update(
        {"allow_multiple": allow_multiple_data_type_string}) if allow_multiple_data_type_string else None
    new_attribute_body.update(
        {"allowed_value": allowed_list_data_types_value}) if allowed_list_data_types_value else None

    res = client.prepare_request(method='POST', params={}, url_suffix='attribute', body=new_attribute_body)

    outputs = attributes_response_to_dict(res)
    human_readable = tableToMarkdown('HPE Aruba Clearpass new attribute', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearpass.attributes.create',
        outputs_key_field='id',
        outputs=outputs,
    )


def update_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    attribute_id = args.get('attribute_id')

    name = args.get('name')
    entity_name = args.get('entity_name')
    data_type = args.get('data_type')
    mandatory = args.get('mandatory', False)
    attribute_default_value = args.get('default_value', "")
    allow_multiple_data_type_string = args.get('allow_multiple', False)
    allowed_list_data_types_value = args.get('allowed_value', "")

    if allow_multiple_data_type_string and data_type != "String":
        return_error("Note: allow_multiple argument should be true only for data type String.")
    if allowed_list_data_types_value and data_type != 'List':
        return_error("Note: allowed_value argument should be set only for data type List.")

    new_attribute_body = {}
    new_attribute_body.update({"name": name})
    new_attribute_body.update({"entity_name": entity_name})
    new_attribute_body.update({"data_type": data_type})
    new_attribute_body.update({"mandatory": mandatory}) if mandatory else None
    new_attribute_body.update({"default_value": attribute_default_value}) if attribute_default_value else None
    new_attribute_body.update(
        {"allow_multiple": allow_multiple_data_type_string}) if allow_multiple_data_type_string else None
    new_attribute_body.update(
        {"allowed_value": allowed_list_data_types_value}) if allowed_list_data_types_value else None

    res = client.prepare_request(method='PATCH', params={}, url_suffix=f'attribute/{attribute_id}',
                                 body=new_attribute_body)

    outputs = attributes_response_to_dict(res)
    human_readable = tableToMarkdown('HPE Aruba Clearpass update attribute', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearpass.attributes.update',
        outputs_key_field='id',
        outputs=outputs,
    )


def delete_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    attribute_id = args.get('attribute_id')
    client.prepare_request(method='DELETE', params={}, url_suffix=f'attribute/{attribute_id}', resp_type='content')
    human_readable = f"HPE Aruba Clearpass attribute with ID: {attribute_id} deleted successfully."
    return CommandResults(readable_output=human_readable)


def attributes_response_to_dict(response):
    return {
        'ID': response.get('id'),
        'Name': response.get('name'),
        'Entity name': response.get('entity_name'),
        'Data type': response.get('data_type'),
        'Mandatory': response.get('mandatory', False),
        'Default value': response.get('default_value'),
        'Allow multiple': response.get('allow_multiple', False),
        'Allowed value': response.get('allowed_value', False)
    }


def main() -> None:
    params = demisto.params()
    base_url = urljoin(params.get('url'), '/api')
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    client = Client(proxy=proxy,
                    verify=verify_certificate,
                    base_url=base_url,
                    client_id=client_id,
                    client_secret=client_secret)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client.login()
        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'aruba-clearpass-endpoints-list':
            return_results(get_endpoints_list_command(client, demisto.args()))

        elif demisto.command() == 'aruba-clearpass-endpoint-update':
            return_results(update_endpoint_command(client, demisto.args()))

        elif demisto.command() == 'aruba-clearpass-attributes-list':
            return_results(get_attributes_list_command(client, demisto.args()))

        elif demisto.command() == 'aruba-clearpass-attribute-create':
            return_results(create_attribute_command(client, demisto.args()))

        elif demisto.command() == 'aruba-clearpass-attribute-update':
            return_results(update_attribute_command(client, demisto.args()))

        elif demisto.command() == 'aruba-clearpass-attribute-delete':
            return_results(delete_attribute_command(client, demisto.args()))


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
