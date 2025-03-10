import json
from datetime import datetime, timedelta
from CommonServerPython import *

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR"


class Client(BaseClient):
    """
    Client to use in the HPE Aruba ClearPass integration. Overrides BaseClient.

        Args:
           proxy (bool): Whether the client should use proxies.
           verify (bool): Whether to check for SSL certificate validity.
           base_url (str) : Base URL for the service.
           client_id (str): HPE Aruba ClearPass client identifier.
           client_secret (str): HPE Aruba ClearPass client secret.
   """

    def __init__(self, proxy: bool, verify: bool, base_url: str, client_id: str, client_secret: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = ""
        self.headers: Dict[str, str] = {}
        self.login()

    def generate_new_access_token(self):
        """
        Makes an HTTP request in order to get back a new access token.
        """
        demisto.debug("access token does not exist, trying to generate a new one")
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

    def login(self):
        """
        Checks if a valid access token is set to integration context. Otherwise, generates one and save to it
        to integration context.
       """
        integration_context = get_integration_context()
        if integration_context and self.is_access_token_valid():
            self.set_valid_access_token()
        else:
            # if the access is expired or not exist, generate a new one
            auth_response_dict = self.generate_new_access_token()
            if auth_response_dict.get("access_token"):
                self.save_access_token_to_context(auth_response_dict)
            else:
                return_error("HPE Aruba ClearPass error: The client credentials are invalid.")

    def set_request_headers(self):
        """
        Setting the headers for the future HTTP requests.
        The headers should be: {Authorization: Bearer <access_token>}
        """
        authorization_header_value = f"Bearer {self.access_token}"
        self.headers = {"Authorization": authorization_header_value}

    def get_expiration_in_seconds(self, auth_response: Dict[str, str]):
        access_token_expiration_in_seconds = auth_response.get("expires_in")
        is_expiration_valid = access_token_expiration_in_seconds and isinstance(auth_response.get("expires_in"), int)
        error_msg = f"HPEArubaClearPass error: Got an invalid access token expiration time from the API: " \
                    f"{access_token_expiration_in_seconds} from type: {type(access_token_expiration_in_seconds)}"
        return access_token_expiration_in_seconds if is_expiration_valid else return_error(error_msg)

    def save_access_token_to_context(self, auth_response: dict):
        self.access_token = auth_response.get("access_token")  # type:ignore
        expiration_in_seconds = self.get_expiration_in_seconds(auth_response)
        expiration_timestamp = datetime.now() + timedelta(seconds=expiration_in_seconds)

        context = {"access_token": self.access_token, "expires_in": expiration_timestamp.strftime(DATE_FORMAT)}
        set_integration_context(context)
        self.set_request_headers()
        demisto.debug(f"New access token that expires in : {expiration_timestamp.strftime(DATE_FORMAT)}"
                      f" was set to integration_context.")

    def is_access_token_valid(self):
        integration_context = get_integration_context()
        access_token_expiration = integration_context.get('expires_in')
        access_token = integration_context.get('access_token')
        context_has_access_token_and_expiration = access_token and access_token_expiration
        access_token_expiration_datetime = datetime.strptime(access_token_expiration, DATE_FORMAT)
        return context_has_access_token_and_expiration and access_token_expiration_datetime > datetime.now()

    def set_valid_access_token(self):
        integration_context = get_integration_context()
        self.access_token = integration_context.get('access_token')
        self.set_request_headers()
        demisto.debug("access token is valid")

    def prepare_request(self, method: str, params: dict, url_suffix: str, body: dict = {}, resp_type: str = 'json'):
        return self._http_request(
            method=method,
            params=params,
            url_suffix=url_suffix,
            headers=self.headers,
            json_data=body,
            resp_type=resp_type
        )


def command_test_module(client: Client):
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


def parse_items_response(response: dict, active_sessions_parsing=None):  # type:ignore
    items_list = response.get('_embedded', {}).get('items')
    human_readable = []
    if items_list:
        for item in items_list:
            delete_redundant_data(item)
            if active_sessions_parsing:
                item = active_sessions_parsing(item)
            human_readable.append(item)
    return human_readable, items_list


def get_endpoints_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of endpoints. If mac_address was not given, all the endpoints will be returned.
    Note: In Aruba ClearPass all endpoints appear in Configuration > Identity > Endpoints.
    """
    mac_address = args.get('mac_address')
    status = args.get('status')
    offset = args.get('offset', 0)
    limit = args.get('limit', 25)
    endpoints_filter = endpoints_filter_to_json_object(status, mac_address)
    params = {"filter": endpoints_filter, "limit": limit, "offset": offset}

    res = client.prepare_request(method='GET', params=params, url_suffix='endpoint')
    readable_output, outputs = parse_items_response(res)
    human_readable = tableToMarkdown('HPE Aruba ClearPass endpoints', readable_output, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Endpoints',
        outputs_key_field='id',
        outputs=outputs,
    )


def endpoints_filter_to_json_object(status, mac_address):
    endpoints_filter = {}
    endpoints_filter.update({"status": status}) if status else None
    endpoints_filter.update({"mac_address": mac_address}) if mac_address else None
    return json.dumps(endpoints_filter)  # the API requires the value of 'filter' to be a json object.


def update_endpoint_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Updates an endpoint by its endpoint_id. Only endpoint_id is a mandatory field.
    """
    endpoint_id = args['endpoint_id']
    mac_address = args.get('mac_address')
    status = args.get('status')
    description = args.get('description')
    device_insight_tags = argToList(args.get('device_insight_tags'))
    attributes = argToList(args.get('attributes'))
    attributes_values = {}
    for attribute in attributes:  # converting the given list of attributes pairs to a a dict
        attributes_values.update(attribute)

    request_body = get_endpoint_request_body(status, mac_address, description, device_insight_tags, attributes_values,
                                             attributes)
    outputs = client.prepare_request(method='PATCH', params={}, url_suffix=f'endpoint/{endpoint_id}', body=request_body)
    delete_redundant_data(outputs)
    human_readable = tableToMarkdown('HPE Aruba ClearPass endpoints', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Endpoints',
        outputs_key_field='id',
        outputs=outputs,
    )


def delete_redundant_data(res: Dict[str, Any]):
    """
    Removes the '_links' entity from the response. This entity includes a url to Aruba server for the given object which
    equals the requested url suffix.
    """
    if res and '_links' in res:
        del res['_links']


def get_endpoint_request_body(status, mac_address, description, device_insight_tags, attributes_values, attributes):
    request_body = {}
    request_body.update({"status": status}) if status else None
    request_body.update({"mac_address": mac_address}) if mac_address else None
    request_body.update({"description": description}) if description else None
    request_body.update({"device_insight_tags": device_insight_tags}) if device_insight_tags else None
    request_body.update({"attributes": attributes_values}) if attributes else None
    return request_body


def get_attributes_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of attributes. If attribute_id was not given, all the attributes will be returned.
    Note: In Aruba ClearPass all attributes appear in Administration > Dictionaries > Dictionary Attributes.
    """
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
    attribute_filter = attributes_filter_to_json_object(attribute_id, name, entity_name)
    params = {"filter": attribute_filter, "offset": offset, "limit": limit}

    res = client.prepare_request(method='GET', params=params, url_suffix='attribute')
    readable_output, outputs = parse_items_response(res)
    human_readable = tableToMarkdown('HPE Aruba ClearPass attributes', readable_output, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Attributes',
        outputs_key_field='id',
        outputs=outputs,
    )


def attributes_filter_to_json_object(attribute_id, name, entity_name):
    attribute_filter = {}
    attribute_filter.update({"id": attribute_id}) if attribute_id else None
    attribute_filter.update({"name": name}) if name else None
    attribute_filter.update({"entity_name": entity_name}) if entity_name else None
    return json.dumps(attribute_filter)  # the API requires the value of 'filter' to be a json object.


def check_api_limitation_on_specific_data_types(args: Dict[str, Any]):
    """ Checks if the attribute data_type match the api limitations like:
    1. allow_multiple is available only when data_type is String.
    2. allowed_value is available only when data_type is List.
    API docs are here: {Aruba_url_server}/api-docs/Dictionaries-v1#!/Attribute
    """
    data_type = args.get('data_type')
    allow_multiple_data_type_string = argToBoolean(args.get('allow_multiple', False))
    allowed_list_data_types_value = args.get('allowed_value', "")

    if allow_multiple_data_type_string and data_type != "String":
        return_error(f"Note: allow_multiple argument should be true only for data type String and not for {data_type}.")
    if allowed_list_data_types_value and data_type != 'List':
        return_error(f"Note: allowed_value argument should be set only for data type List and not for {data_type}.")


def create_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an attribute by the given name, entity_name, data_type which are all mandatory fields.
    """
    check_api_limitation_on_specific_data_types(args)
    new_attribute_body = create_new_attribute_body(args)
    outputs = client.prepare_request(method='POST', params={}, url_suffix='attribute', body=new_attribute_body)
    delete_redundant_data(outputs)
    human_readable = tableToMarkdown('HPE Aruba ClearPass new attribute', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Attributes',
        outputs_key_field='id',
        outputs=outputs,
    )


def create_new_attribute_body(args: Dict[str, Any]):
    """
    Creates a new attribute body for creating and updating an attribute.
    """
    name = args.get('name')
    entity_name = args.get('entity_name')
    data_type = args.get('data_type')
    mandatory = argToBoolean(args.get('mandatory', False))
    attribute_default_value = args.get('default_value', "")
    allow_multiple_data_type_string = argToBoolean(args.get('allow_multiple', False))
    allowed_list_data_types_value = args.get('allowed_value', "")

    return get_attribute_request_body(name, entity_name, data_type, mandatory, attribute_default_value,
                                      allow_multiple_data_type_string, allowed_list_data_types_value)


def get_attribute_request_body(name, entity_name, data_type, mandatory, attribute_default_value,
                               allow_multiple_data_type_string, allowed_list_data_types_value):
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
    return new_attribute_body


def update_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Updates an attribute fields by the attribute_id which is a mandatory field.
    """
    attribute_id = args['attribute_id']
    new_attribute_body = create_new_attribute_body(args)
    outputs = client.prepare_request(method='PATCH', params={}, url_suffix=f'attribute/{attribute_id}',
                                     body=new_attribute_body)
    delete_redundant_data(outputs)
    human_readable = tableToMarkdown('HPE Aruba ClearPass update attribute', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Attributes',
        outputs_key_field='id',
        outputs=outputs,
    )


def delete_attribute_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes an attribute by the attribute_id which is a mandatory field.
    """
    attribute_id = args['attribute_id']
    client.prepare_request(method='DELETE', params={}, url_suffix=f'attribute/{attribute_id}', resp_type='content')

    human_readable = f"HPE Aruba ClearPass attribute with ID: {attribute_id} deleted successfully."
    return CommandResults(readable_output=human_readable)


def get_active_sessions_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of active sessions. If session_id was not given, all the active sessions will be returned.
    Note: In Aruba ClearPass all active sessions appear in: Home > Guest > Active Sessions.
    """
    session_id = args.get('session_id')
    device_ip = args.get('device_ip')
    device_mac_address = args.get('device_mac_address')
    visitor_phone = args.get('visitor_phone')
    limit = args.get('limit', 25)

    session_filter = sessions_filter_to_json_object(session_id, device_ip, device_mac_address, visitor_phone)
    params = {"filter": session_filter, "limit": limit}

    res = client.prepare_request(method='GET', params=params, url_suffix='session')
    readable_output, all_active_sessions_list = parse_items_response(res, parse_active_sessions_response)
    outputs = [parse_active_sessions_response(item) for item in all_active_sessions_list]
    human_readable = tableToMarkdown('HPE Aruba ClearPass Active Sessions', readable_output, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Sessions',
        outputs_key_field='id',
        outputs=outputs,
    )


def sessions_filter_to_json_object(session_id, device_ip, device_mac_address, visitor_phone):
    session_filter = {}
    session_filter.update({"id": session_id}) if session_id else None
    session_filter.update({"framedipaddress": device_ip}) if device_ip else None
    session_filter.update({"mac_address": device_mac_address}) if device_mac_address else None
    session_filter.update({"visitor_phone": visitor_phone}) if visitor_phone else None
    # the API requires the value of 'filter' to be a json object.
    return json.dumps(session_filter) if session_filter else session_filter


def parse_active_sessions_response(response: dict) -> dict:
    return {
        'ID': response.get('id'),
        'Device_IP': response.get('framedipaddress'),
        'Device_mac_address': response.get('mac_address'),
        'State': response.get('state'),
        'Visitor_phone': response.get('visitor_phone', False)
    }


def disconnect_active_session_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Disconnects an active session by the session_id which is a mandatory field.
    """
    session_id = args['session_id']
    encoded_session_id = urllib.parse.quote(session_id, safe='')
    url_suffix = f"/session/{encoded_session_id}/disconnect"
    body = {"id": session_id, "confirm_disconnect": True}

    res = client.prepare_request(method='POST', params={}, url_suffix=url_suffix, body=body)
    outputs = {"Error_code": res.get('error'), "Response_message": res.get('message')}
    human_readable = tableToMarkdown('HPE Aruba ClearPass Disconnect active session', outputs, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='HPEArubaClearPass.Sessions',
        outputs_key_field='id',
        outputs=outputs,
    )


def main() -> None:
    params = demisto.params()
    base_url = urljoin(params.get('url'), '/api')
    client_id = params.get('client_id_creds', {}).get('identifier') or params.get('client_id')
    client_secret = params.get('client_id_creds', {}).get('password') or params.get('client_secret')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(proxy=proxy,
                    verify=verify_certificate,
                    base_url=base_url,
                    client_id=client_id,
                    client_secret=client_secret)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        args = demisto.args()
        if demisto.command() == 'test-module':
            return_results(command_test_module(client))

        elif demisto.command() == 'aruba-clearpass-endpoints-list':
            return_results(get_endpoints_list_command(client, args))

        elif demisto.command() == 'aruba-clearpass-endpoint-update':
            return_results(update_endpoint_command(client, args))

        elif demisto.command() == 'aruba-clearpass-attributes-list':
            return_results(get_attributes_list_command(client, args))

        elif demisto.command() == 'aruba-clearpass-attribute-create':
            return_results(create_attribute_command(client, args))

        elif demisto.command() == 'aruba-clearpass-attribute-update':
            return_results(update_attribute_command(client, args))

        elif demisto.command() == 'aruba-clearpass-attribute-delete':
            return_results(delete_attribute_command(client, args))

        elif demisto.command() == 'aruba-clearpass-active-sessions-list':
            return_results(get_active_sessions_list_command(client, args))

        elif demisto.command() == 'aruba-clearpass-active-session-disconnect':
            return_results(disconnect_active_session_command(client, args))

        else:
            raise NotImplementedError(f'{demisto.command()} is not an existing HPE Aruba ClearPass command')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
