import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from copy import deepcopy
import requests
import traceback
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
API_VERSION = 'v7'
IMPORTANCE_DICTIONARY = {
    'Low': 1,
    'Medium': 2,
    'High': 3
}
ONGOING_DICTIONARY = {
    'Ongoing': 'true',
    'Not Ongoing': 'false',
}
IP_DICTIONARY = {
    'IPv4': 4,
    'IPv6': 6
}

ROUTERS_HR_HEADERS = [
    'description',
    'id',
    'is_proxy',
    'license_type',
    'name',
    'snmp_authprotocol',
    'snmp_priv_protocol',
    'snmp_security_level',
    'snmp_version',
]

MANAGED_OBJECTS_HR_HEADERS = [
    'tags',
    'name',
    'match_type',
    'match_enabled',
    'match',
    'id',
    'family',
    'autodetected'
]

''' CLIENT CLASS '''


class NetscoutClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    OPERATOR_NAME_DICTIONARY = {
        'importance': 'importance_operator',
        'start_time': 'start_time_operator',
        'stop_time': 'stop_time_operator',
    }

    RELATIONSHIP_TO_TYPE = {
        'routers': 'router'
    }

    def __init__(self, base_url, verify, headers, proxy, per_page=None, alert_class=None, alert_type=None,
                 classification=None, importance=None, importance_operator=None, ongoing=None):
        self.per_page = per_page
        self.alert_class = alert_class
        self.alert_type = alert_type
        self.classification = classification
        self.importance = importance
        self.importance_operator = importance_operator
        self.ongoing = ongoing

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    # def create_mitigation(self, **kwargs):

    def build_relationships(self, **kwargs) -> dict:
        """
        Builds the relationships object for creating a mitigation. An example of relationships object is:
        {
            "mitigation_template": {
                "data": {
                    "id": "4", "type": "mitigation_template"
                }
            },
            "alert": {
                "data": {
                    "id": "101", "type": "alert"
                    "id": "101", "type": "alert"
                }
            }
        }
        Args:
            kwargs (dict): Dict containing key values parameters to be used for relationships. for example:
            {'ip_version': 4}

        Returns:
            (dict) Netscout relationships object
        """
        relationships = {}
        for key, val in kwargs.items():
            if val:
                # In some cases the name of the relationships is not the same as the type (most cases it is)
                _type = self.RELATIONSHIP_TO_TYPE.get(key, key)
                relationships[key] = {
                    'data': {
                        'type': _type,
                        'id': val
                    }
                }
        return relationships

    def build_data_attribute_filter(self, **kwargs) -> str:
        """
        Builds data attribute filter in the NetscoutArbor form. For example: '/data/attributes/importance>1' where
        key=importance operator='>' and value=1.
        The function iterates over all arguments (besides operators listed in the OPERATOR_NAME_DICTIONARY) and chain
        together the 'key operator val' such that the argument name is 'key', its value is 'val' and operator is '=' if
        no relevant operator is present. In case of multiple parameters the attributes are separated with 'AND'.

        Args:
            kwargs (dict): Dict containing key values filter parameters. for example: {'importance': 1}

        Returns:
            (str) Netscout data attribute filter string. For example:
            /data/attributes/importance>1 AND /data/attributes/ongoing=true
        """

        param_list = []
        operator_names = self.OPERATOR_NAME_DICTIONARY.values()
        for key, val in kwargs.items():

            if key not in operator_names and val:
                operator = '='
                if operator_name := self.OPERATOR_NAME_DICTIONARY.get(key):
                    operator = kwargs.get(operator_name, '=')
                param_list.append(f'/data/attributes/{key + operator + val}')

        return ' AND '.join(param_list)

    def fetch_incidents(self):
        demisto.getLastRun()
        data_attribute_filter = self.build_data_attribute_filter(alert_class=self.alert_class,
                                                                 alert_type=self.alert_type,
                                                                 classification=self.classification,
                                                                 importance=self.importance,
                                                                 importance_operator=self.importance_operator,
                                                                 ongoing=self.ongoing)
        return self.list_alerts(data_attribute_filter=data_attribute_filter)

    def list_alerts(self, page: int = None, page_size: int = None, search_filter: str = None):

        return self._http_request(
            method='GET',
            url_suffix='alerts',
            params=assign_params(page=page, perPage=page_size, filter=search_filter)
        )

    def get_alert(self, alert_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'alerts/{alert_id}'
        )

    def get_annotations(self, alert_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'alerts/{alert_id}/annotations'
        )

    def list_mitigations(self, mitigation_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'mitigations/{mitigation_id}' if mitigation_id else 'mitigations'
        )

    def create_mitigation(self, data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'mitigations/',
            data=data
        )

    def mitigation_template_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'mitigation_templates/'
        )

    def router_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'routers/'
        )

    def managed_object_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'managed_objects/'
        )

    def tms_group_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'tms_groups/'
        )


''' HELPER FUNCTIONS '''


def validate_json_arg(json_str: str, arg_name: str) -> dict:
    """
    Parse the json data. If the format is invalid an appropriate will be raised
    Args:
        json_str (str): The data to parse
        arg_name (str): The argument name where the data eas given (for exception purposes)
    :return:
    """
    try:
        sub_object = json.loads(json_str)
        return sub_object
    except Exception:
        raise DemistoException(f'The value given in the {arg_name} argument is not a valid JSON format:\n{json_str}')


def build_human_readable(data: dict):
    """
    Removes the relationships data from the object and extracts the  dara to the root level of the object to
    be displayed nicely in human readable.
    Args:
        data (dict): The data to create human readable from.

    Return:
        The same object without the relationships data and with the attributes extracted to the root level.
    """
    hr = deepcopy(data)
    for key, val in hr.get('attributes').items():
        hr[key] = val
    del hr['attributes']
    del hr['relationships']
    if hr.get('subobject'):
        del hr['subobject']
    return hr


''' COMMAND FUNCTIONS '''


def test_module(client: NetscoutClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def list_alerts_commands(client: NetscoutClient, args: dict):
    page_size = arg_to_number(args.get('limit'))
    alert_id = args.get('alert_id')
    alert_class = args.get('alert_class')
    alert_type = args.get('alert_type')
    classification = args.get('classification')
    importance = args.get('importance')
    importance_operator = args.get('importance')
    ongoing = args.get('ongoing')
    start_time = args.get('start_time')
    start_time_operator = args.get('start_time_operator')
    stop_time = args.get('stop_time')
    stop_time_operator = args.get('stop_time_operator')
    managed_object_id = args.get('managed_object_id')
    if alert_id:
        raw_result = client.get_alert(alert_id)
    else:
        data_attribute_filter = client.build_data_attribute_filter(alert_id=alert_id, alert_class=alert_class,
                                                                   alert_type=alert_type,
                                                                   classification=classification, importance=importance,
                                                                   importance_operator=importance_operator,
                                                                   ongoing=ongoing, start_time=start_time,
                                                                   start_time_operator=start_time_operator,
                                                                   stop_time=stop_time,
                                                                   stop_time_operator=stop_time_operator)
        data_relationships_filter = f'AND /data/relationships/managed_object/data/id={managed_object_id}' if \
            managed_object_id else ''
        search_filter = data_attribute_filter + data_relationships_filter
        raw_result = client.list_alerts(page_size=page_size, search_filter=search_filter)

    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(mitigation) for mitigation in data]
    return CommandResults(outputs_prefix='NASightline.Alert',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Alerts', hr),
                          raw_response=raw_result)


def alert_annotations_list_command(client: NetscoutClient, args: dict):
    alert_id = args.get('alert_id')
    raw_result = client.get_annotations(alert_id)
    data = raw_result.get('data')
    hr = [build_human_readable(mitigation) for mitigation in data]
    context = {'AlertID': alert_id, 'Annotations': data}
    return CommandResults(outputs_prefix='NASightline.AlertAnnotation',
                          outputs_key_field='AlertID',
                          outputs=context,
                          readable_output=tableToMarkdown(f'Alert {alert_id} annotations', hr),
                          raw_response=raw_result)


def mitigations_list_command(client: NetscoutClient, args: dict):
    limit = args.get('limit')
    mitigation_id = args.get('mitigation_id')
    raw_result = client.list_mitigations(mitigation_id)
    data = raw_result.get('data')
    data = data[:limit] if isinstance(data, list) else [data]
    hr = [build_human_readable(mitigation) for mitigation in data]
    return CommandResults(outputs_prefix='NASightline.Mitigation',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Mitigation list', hr),
                          raw_response=raw_result)


def mitigations_create_command(client: NetscoutClient, args: dict):
    description = args.get('description')
    ip_version = IP_DICTIONARY.get(args.get('ip_version'), args.get('ip_version'))
    name = args.get('name')
    ongoing = argToBoolean(args.get('ongoing', 'false'))
    sub_type = args.get('subtype')
    sub_object = validate_json_arg(args.get('sub_object'), 'sub_object')
    alert_id = args.get('alert_id')
    managed_object_id = args.get('managed_object_id')
    mitigation_template_id = args.get('mitigation_template_id')
    router_ids = args.get('router_ids')
    tms_group_id = args.get('tms_group_id')

    relationships = client.build_relationships(alert=alert_id, managed_object=managed_object_id,
                                               mitigation_template=mitigation_template_id, routers=router_ids,
                                               tms_group=tms_group_id)
    attributes = assign_params(description=description, ip_version=ip_version, name=name, ongoing=ongoing,
                               subtype=sub_type, sub_object=sub_object)
    data = {'relationships': relationships, 'attributes': attributes}
    raw_result = client.create_mitigation(data=data)
    data = raw_result.get('data')
    hr = build_human_readable(data)
    return CommandResults(outputs_prefix='NASightline.Mitigation',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Mitigation was created', hr),
                          raw_response=raw_result)


def mitigation_template_list_command(client: NetscoutClient, args: dict):
    raw_result = client.mitigation_template_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(mitigation_template) for mitigation_template in data]
    return CommandResults(outputs_prefix='NASightline.MitigationTemplate',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Mitigation template list', hr, removeNull=True),
                          raw_response=raw_result)


def router_list_command(client: NetscoutClient, args: dict):
    raw_result = client.router_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(router) for router in data]
    return CommandResults(outputs_prefix='NASightline.Router',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Router list', hr, headers=ROUTERS_HR_HEADERS,
                                                          removeNull=True),
                          raw_response=raw_result)


def managed_object_list_command(client: NetscoutClient, args: dict):
    raw_result = client.managed_object_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(managed_object) for managed_object in data]
    return CommandResults(outputs_prefix='NASightline.ManagedObject',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Managed object list', hr,
                                                          headers=MANAGED_OBJECTS_HR_HEADERS, removeNull=True),
                          raw_response=raw_result)


def tms_group_list(client: NetscoutClient, args: dict):
    raw_result = client.tms_group_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(tms_group) for tms_group in data]
    return CommandResults(outputs_prefix='NASightline.TMSGroup',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'TMS group list', hr, removeNull=True),
                          raw_response=raw_result)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    api_token = params.get('api_token')
    base_url = urljoin(params['url'], f'api/sp/{API_VERSION}')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = max(arg_to_number(params.get('max_fetch', 50)), 100)
    alert_class = params.get('alert_class')
    alert_type = params.get('alert_type')
    classification = params.get('classification')
    importance = IMPORTANCE_DICTIONARY.get(params.get('importance'))
    importance_operator = params.get('importance_operator', '=')
    ongoing = ONGOING_DICTIONARY.get(params.get('ongoing'))

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        headers: Dict = {
            'X-Arbux-APIToken': api_token
        }

        client = NetscoutClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            per_page=max_fetch,
            alert_class=alert_class,
            alert_type=alert_type,
            classification=classification,
            importance=importance,
            importance_operator=importance_operator,
            ongoing=ongoing
        )
        args = demisto.args()
        if demisto.command() == 'test-module':
            result = test_module(client)
        elif demisto.command() == 'na-sightline-alert-list':
            result = list_alerts_commands(client, args)
        elif demisto.command() == 'na-sightline-alert-annotation-list':
            result = alert_annotations_list_command(client, args)
        elif demisto.command() == 'na-sightline-mitigation-list':
            result = mitigations_list_command(client, args)
        elif demisto.command() == 'na-sightline-mitigation-create':
            result = mitigations_create_command(client, args)
        elif demisto.command() == 'na-sightline-mitigation-template-list':
            result = mitigation_template_list_command(client, args)
        elif demisto.command() == 'na-sightline-router-list':
            result = router_list_command(client, args)
        elif demisto.command() == 'na-sightline-managed-object-list':
            result = managed_object_list_command(client, args)
        elif demisto.command() == 'na-sightline-tms-group-list':
            result = tms_group_list(client, args)

        return_results(result)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
