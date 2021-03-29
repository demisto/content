import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from copy import deepcopy
import requests
import traceback
from typing import Dict
from datetime import timezone

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
API_VERSION = 'v7'
IMPORTANCE_DICTIONARY = {
    'Low': '1',
    'Medium': '2',
    'High': '3'
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
    'id',
    'name',
    'description',
    'is_proxy',
    'license_type',
    'snmp_authprotocol',
    'snmp_priv_protocol',
    'snmp_security_level',
    'snmp_version',
]

MANAGED_OBJECTS_HR_HEADERS = [
    'id',
    'name',
    'tags',
    'match_type',
    'match_enabled',
    'match',
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
        # <parm name>: <argument operator name>
        'importance': 'importance_operator',
        'start_time': 'start_time_operator',
        'stop_time': 'stop_time_operator',
    }

    RELATIONSHIP_TO_TYPE = {
        'routers': 'router'
    }

    MAX_ALERTS_FOR_FIRST_FETCH = 10000

    def __init__(self, base_url, verify, headers, proxy, first_fetch, max_fetch=None, alert_class=None, alert_type=None,
                 classification=None, importance=None, importance_operator=None, ongoing=None):
        self.first_fetch = first_fetch
        self.max_fetch = max_fetch
        self.alert_class = alert_class
        self.alert_type = alert_type
        self.classification = classification
        self.importance = importance
        self.importance_operator = importance_operator
        self.ongoing = ongoing

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def _http_request(self, method, url_suffix=None, params=None, json_data=None):

        return super()._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data,
                                     error_handler=self.error_handler)

    @staticmethod
    def error_handler(res: requests.Response):
        """
        Error handler for API calls
        Args:
            res (requests.Response): Response to handle error for

        """
        try:
            demisto.info(json.dumps(demisto.args()))
            # Try to parse json error response
            error_entry = res.json()
            error: str = f'Error in API call [{res.status_code}] - {res.reason}'
            if res.status_code in (400, 422):
                error_list: list = []
                for err in error_entry.get('errors'):
                    # Building the list of errors
                    new_error_source = err.get('source', {}).get('pointer', '').split('/')[-1]
                    new_error_details = err.get('detail')
                    new_error = f'{new_error_source}: {new_error_details}' if new_error_source else new_error_details
                    error_list.append(new_error)

                # If we manged to build a list of errors use it otherwise use basic information
                if error_list:
                    error = f'{error}: \n' + '\n'.join(error_list)

            if res.status_code in (500, 401):
                message = error_entry.get('errors', [])[0].get('message')
                if message:
                    error = f'{error}\n{message}'

            raise DemistoException(error)

        except ValueError:
            raise DemistoException(f'Could not parse response from Netscout Arbor server:\n{res.content}')

    def calculate_amount_of_incidents(self, start_time: str) -> int:
        """
        Perform an API call with page size = 1 (perPage=1) to calculate the amount of incidents(#pages will be equal to
        #incidents).

        Arguments:
            start_time (str): Starting time to search by

        Returns:
            (int) The amount of pages (incidents) in total in the given query, 0 if none.
        """
        data_attribute_filter = self.build_data_attribute_filter(start_time=start_time,
                                                                 start_time_operator='>', alert_class=self.alert_class,
                                                                 alert_type=self.alert_type,
                                                                 classification=self.classification,
                                                                 importance=self.importance,
                                                                 importance_operator=self.importance_operator,
                                                                 ongoing=self.ongoing)
        page_size = 1
        results = self.list_alerts(page_size=page_size, search_filter=data_attribute_filter)
        last_page_link = results.get('links', {}).get('last')
        if last_page_link:
            last_page_number_matcher = re.match(r'.*&page=(\d+)', last_page_link)
            if not last_page_number_matcher:
                raise DemistoException(
                    f'Could not calculate page size, last page number was not found:\n{last_page_link}')
            last_page_number = last_page_number_matcher.group(1)
        else:
            last_page_number = 0

        return last_page_number

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
            (dict): Netscout relationships object
        """
        relationships = {}
        for key, val in kwargs.items():
            if val:
                # In some cases the name of the relationships is not the same as the type (most cases it is)
                _type = self.RELATIONSHIP_TO_TYPE.get(key, key)
                if key == 'routers':
                    relationships[key] = {
                        'data': [{
                            'type': _type,
                            'id': val[0]
                        }]
                    }
                else:
                    relationships[key] = {
                        'data': {
                            'type': _type,
                            'id': val
                        }
                    }
                # data = [{
                #     'type': _type,
                #     'id': element
                # } for element in val]
                #
                # relationships[key] = {'data': data[0]} if len(data) == 1 else {'data': data}
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
            (str): Netscout data attribute filter string. For example:
            /data/attributes/importance>1 AND /data/attributes/ongoing=true
        """
        param_list = []
        operator_names = self.OPERATOR_NAME_DICTIONARY.values()
        for key, val in kwargs.items():

            # We don't create a filter for operator names
            if key not in operator_names and val:
                operator = '='

                # If the current parameter supports a special operator (it appears in the OPERATOR_NAME_DICTIONARY),
                # we take the operator value using the operator name (that appears in the OPERATOR_NAME_DICTIONARY)
                if operator_name := self.OPERATOR_NAME_DICTIONARY.get(key):
                    operator = kwargs.get(operator_name) if kwargs.get(operator_name) else '='

                param_list.append(f'/data/attributes/{key + operator + val}')
        return ' AND '.join(param_list)

    def fetch_incidents(self) -> (list, str):
        """
        Perform fetch incidents process.
        1.  We first save the current time to know what was the time at the beginning of the incidents counting process.
        2.  We calculate the amount of incidents we need to fetch by performing a query for all incident newer
            than last run (or first fetch), we do this by setting the page size to 1, which makes the amount of returned
            pages to be equal to the amount of incidents.
        3.  Then, to get the relevant incidents, we query for all incidents *older* then the time we sampled in the
            step 1, with page size equal to the amount of incidents from step 2. This ensures that the first page in
            this search will have all of the incidents created after the given start time and only them.
        4.  Finally out of the relevant incidents we take the older ones (from the end of the list) and set the new
            start time to the creation time of the first incidnt in the list.

        Returns
            (list, str): List of incidents to save and string representing the creation time of the latest incident to
                be saved.
        """
        last_run = demisto.getLastRun()
        new_last_start_time = last_start_time = last_run.get('LastFetchTime', self.first_fetch)
        demisto.debug(f'Last fetch time to use is: {last_start_time}')

        # We calculate the page size to query, by performing an incidents query with page size = 1, the amount of
        # returned pages will equal to amount of incidents
        now = datetime.now(timezone.utc).isoformat()
        amount_of_incidents = self.calculate_amount_of_incidents(start_time=last_start_time)
        incidents: list = []

        if amount_of_incidents:
            data_attribute_filter = self.build_data_attribute_filter(start_time=now, start_time_operator='<',
                                                                     alert_class=self.alert_class,
                                                                     alert_type=self.alert_type,
                                                                     importance=self.importance,
                                                                     classification=self.classification,
                                                                     importance_operator=self.importance_operator,
                                                                     ongoing=self.ongoing)
            demisto.info(
                f'NetscoutArborSightline fetch params are: page_size={amount_of_incidents}, '
                f'search_filter={data_attribute_filter}')

            results = self.list_alerts(page_size=amount_of_incidents, search_filter=data_attribute_filter)
            all_alerts = results.get('data')
            short_alert_list = all_alerts[-self.max_fetch:]
            if short_alert_list:
                new_last_start_time = short_alert_list[0].get('attributes', {}).get('start_time')

                for alert in reversed(short_alert_list):
                    start_time = alert.get('attributes', {}).get('start_time')
                    alert_type = alert.get('attributes', {}).get('alert_type')
                    incidents.append({
                        'name': f"{alert_type}: {alert.get('id')}",
                        'type': 'Netscout Arbor Sightline Alert',
                        'occurred': start_time,
                        'rawJSON': json.dumps(alert)
                    })
        return incidents, new_last_start_time

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

    def list_mitigations(self, mitigation_id: str, page: int = None, page_size: int = None):
        return self._http_request(
            method='GET',
            url_suffix=f'mitigations/{mitigation_id}' if mitigation_id else 'mitigations',
            params=assign_params(page=page, perPage=page_size)

        )

    def create_mitigation(self, data: dict):
        return self._http_request(
            method='POST',
            url_suffix=f'mitigations/',
            json_data=data
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

    def managed_object_list(self, page: int = None, page_size: int = None):
        return self._http_request(
            method='GET',
            url_suffix=f'managed_objects/',
            params=assign_params(page=page, perPage=page_size)
        )

    def tms_group_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'tms_groups/'
        )


''' HELPER FUNCTIONS '''


def validate_json_arg(json_str: str, arg_name: str) -> dict:
    """
    Parse the json data. If the format is invalid an appropriate exception will be raised
    Args:
        json_str (str): The data to parse
        arg_name (str): The argument name where the data eas given (for exception purposes)
    Return:
        (dict): dict representing the given json
    """
    try:
        sub_object = json.loads(json_str)
        return sub_object
    except Exception:
        raise DemistoException(f'The value given in the {arg_name} argument is not a valid JSON format:\n{json_str}')


def build_human_readable(data: dict) -> dict:
    """
    Removes the relationships and subobject data from the object and extracts the data inside attributes to the root
    level of the object to be displayed nicely in human readable.
    Args:
        data (dict): The data to create human readable from.
    Return:
        (dict): The same object without the relationships data and with the attributes extracted to the root level.
    """
    hr = deepcopy(data)
    if attributes := hr.get('attributes'):
        for key, val in attributes.items():
            hr[key] = val
        del hr['attributes']
    if hr.get('relationships'):
        del hr['relationships']
    if hr.get('subobject'):
        del hr['subobject']
    if hr.get('links'):
        del hr['links']
    return hr


''' COMMAND FUNCTIONS '''


def test_module(client: NetscoutClient) -> str:
    client.fetch_incidents()
    return 'ok'


def fetch_incidents_command(client: NetscoutClient):
    incidents, last_start_time = client.fetch_incidents()
    demisto.incidents(incidents)
    demisto.setLastRun({'LastFetchTime': last_start_time})


def list_alerts_commands(client: NetscoutClient, args: dict):
    limit = arg_to_number(args.get('limit'))
    page = arg_to_number(args.get('page'))
    alert_id = args.get('alert_id')
    alert_class = args.get('alert_class')
    alert_type = args.get('alert_type')
    classification = args.get('classification')
    importance = IMPORTANCE_DICTIONARY.get(args.get('importance'))
    importance_operator = args.get('importance_operator')
    ongoing = args.get('ongoing') if args.get('ongoing') else None
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
        raw_result = client.list_alerts(page=page, page_size=limit, search_filter=search_filter)

    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(alert) for alert in data]
    return CommandResults(outputs_prefix='NASightline.Alert',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Alerts', hr),
                          raw_response=raw_result)


def alert_annotation_list_command(client: NetscoutClient, args: dict):
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


def mitigation_list_command(client: NetscoutClient, args: dict):
    page = arg_to_number(args.get('page'))
    limit = arg_to_number(args.get('limit'))
    mitigation_id = args.get('mitigation_id')
    raw_result = client.list_mitigations(mitigation_id, page=page, page_size=limit)
    data = raw_result.get('data')
    data = data[:limit] if isinstance(data, list) else [data]
    hr = [build_human_readable(mitigation) for mitigation in data]
    return CommandResults(outputs_prefix='NASightline.Mitigation',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Mitigation list', hr),
                          raw_response=raw_result)


def mitigation_create_command(client: NetscoutClient, args: dict):
    ip_version = IP_DICTIONARY.get(args.get('ip_version'))
    if not ip_version:
        raise DemistoException(f'ip_version value can be one of the following: '
                               f'{",".join(list(IP_DICTIONARY.keys()))}. {args.get("ip_version")} was given.')
    description = args.get('description')
    name = args.get('name')
    ongoing = args.get('ongoing', 'false')
    sub_type = args.get('sub_type')
    sub_object = validate_json_arg(args.get('sub_object'), {})
    alert_id = args.get('alert_id')
    managed_object_id = args.get('managed_object_id')
    mitigation_template_id = args.get('mitigation_template_id')
    router_ids = argToList(args.get('router_ids'))
    tms_group_id = args.get('tms_group_id')

    relationships = client.build_relationships(alert=alert_id, managed_object=managed_object_id,
                                               mitigation_template=mitigation_template_id, routers=router_ids,
                                               tms_group=tms_group_id)
    attributes = assign_params(description=description, ip_version=ip_version, name=name, ongoing=ongoing,
                               subtype=sub_type, subobject=sub_object)
    data = {'relationships': relationships, 'attributes': attributes}
    raw_result = client.create_mitigation(data={'data': data})
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
    page = arg_to_number(args.get('page'))
    limit = arg_to_number(args.get('limit'))
    raw_result = client.managed_object_list(page=page, page_size=limit)
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(managed_object) for managed_object in data]
    return CommandResults(outputs_prefix='NASightline.ManagedObject',
                          outputs_key_field='id',
                          outputs=data,
                          readable_output=tableToMarkdown(f'Managed object list', hr,
                                                          headers=MANAGED_OBJECTS_HR_HEADERS, removeNull=True),
                          raw_response=raw_result)


def tms_group_list(client: NetscoutClient):
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
    try:
        command = demisto.command()
        params = demisto.params()

        api_token = params.get('api_token', {}).get('password')
        base_url = urljoin(params['url'], f'api/sp/{API_VERSION}')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        first_fetch = arg_to_datetime(params.get('first_fetch', '3 days')).isoformat()
        max_fetch = min(arg_to_number(params.get('max_fetch', 50)), 100)
        alert_class = params.get('alert_class')
        alert_type = params.get('alert_type')
        classification = params.get('classification')
        importance = IMPORTANCE_DICTIONARY.get(params.get('importance'))
        importance_operator = params.get('importance_operator', '=')
        ongoing = ONGOING_DICTIONARY.get(params.get('ongoing'))

        demisto.debug(f'Command being called is {demisto.command()}')

        headers: Dict = {
            'X-Arbux-APIToken': api_token
        }

        client = NetscoutClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            first_fetch=first_fetch,
            max_fetch=max_fetch,
            alert_class=alert_class,
            alert_type=alert_type,
            classification=classification,
            importance=importance,
            importance_operator=importance_operator,
            ongoing=ongoing
        )
        args = demisto.args()

        result = ''
        if command == 'test-module':
            result = test_module(client)
        elif command == 'fetch-incidents':
            fetch_incidents_command(client)
        elif command == 'na-sightline-alert-list':
            result = list_alerts_commands(client, args)
        elif command == 'na-sightline-alert-annotation-list':
            result = alert_annotation_list_command(client, args)
        elif command == 'na-sightline-mitigation-list':
            result = mitigation_list_command(client, args)
        elif command == 'na-sightline-mitigation-create':
            result = mitigation_create_command(client, args)
        elif command == 'na-sightline-mitigation-template-list':
            result = mitigation_template_list_command(client, args)
        elif command == 'na-sightline-router-list':
            result = router_list_command(client, args)
        elif command == 'na-sightline-managed-object-list':
            result = managed_object_list_command(client, args)
        elif command == 'na-sightline-tms-group-list':
            result = tms_group_list(client)
        else:
            result = f'Command: {command} is not implemented'

        if result:
            return_results(result)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
