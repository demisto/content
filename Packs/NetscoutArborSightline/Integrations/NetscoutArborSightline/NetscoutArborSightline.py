from time import sleep

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from copy import deepcopy
import requests
from datetime import UTC
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
IMPORTANCE_DICTIONARY = {
    'Low': '0',
    'Medium': '1',
    'High': '2'
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

    def __init__(self, base_url, verify, proxy, first_fetch, headers=None, max_fetch=None, alert_class=None,
                 alert_type=None, classification=None, importance=None, ongoing=None):
        self.first_fetch = first_fetch
        self.max_fetch = max_fetch
        self.alert_class = alert_class
        self.alert_type = alert_type
        self.classification = classification
        self.importance = importance
        self.ongoing = ongoing
        self.importance_operator = '>'

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def http_request(self, method: str, url_suffix: Optional[str] = None, params: Optional[dict] = None,
                     json_data: Optional[dict] = None, return_empty_response: Optional[bool] = None,
                     status_list_to_retry: list = None):

        return super()._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data,
                                     error_handler=self.error_handler, return_empty_response=return_empty_response,
                                     status_list_to_retry=status_list_to_retry)

    @staticmethod
    def error_handler(res: requests.Response):
        """
        Error handler for API calls
        Args:
            res (requests.Response): Response to handle error for

        """
        try:
            # Try to parse json error response
            error_entry = res.json()
            error: str = f'Error in API call [{res.status_code}] - {res.reason}'
            if res.status_code in (400, 422, 404):
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

            elif res.status_code in (500, 401):
                message = error_entry.get('errors', [])[0].get('message')
                if message:
                    error = f'{error}\n{message}'
            demisto.error(res.text)
            raise DemistoException(error)

        except ValueError:
            raise DemistoException(
                f'Could not parse error returned from Netscout Arbor Sightline server:\n{str(res.content)}')

    def calculate_amount_of_incidents(self, start_time: str, params_dict: dict) -> int:
        """
        Perform an API call with page size = 1 (perPage=1) to calculate the amount of incidents (#pages will be equal to
        #incidents).

        Arguments:
            start_time (str): Starting time to search by
            params_dict (dict): The params configured by the user to perform the fetch with.

        Returns:
            (int) The amount of pages (incidents) in total in the given query, 0 if none.
        """
        time_attributes_dict = assign_params(start_time=start_time, start_time_operator='>')
        params_dict.update(time_attributes_dict)
        data_attribute_filter = self.build_data_attribute_filter(params_dict)
        page_size = 1
        results = self.list_alerts(page_size=page_size, search_filter=data_attribute_filter, status_list_to_retry=[500])
        last_page_link = results.get('links', {}).get('last')
        if last_page_link:
            last_page_number_matcher = re.match(r'.*&page=(\d+)', last_page_link)
            if not last_page_number_matcher:
                raise DemistoException(
                    f'Could not calculate page size, last page number was not found:\n{last_page_link}')
            last_page_number = last_page_number_matcher.group(1)
        else:
            last_page_number = 0

        return int(last_page_number)

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
        relationships: dict[str, Any] = {}
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
        return relationships

    def build_data_attribute_filter(self, attributes_dict: dict) -> str:
        """
        Builds data attribute filter in the NetscoutArbor form. For example: '/data/attributes/importance>1' where
        key=importance operator='>' and value=1.
        The function iterates over all arguments (besides operators listed in the OPERATOR_NAME_DICTIONARY) and chain
        together the 'key operator val' such that the argument name is 'key', its value is 'val' and operator is '=' if
        no relevant operator is present. In case of multiple parameters the attributes are separated with 'AND'.

        Args:
            attributes_dict (dict): Dict containing key values filter parameters. for example: {'importance': 1}

        Returns:
            (str): Netscout data attribute filter string. For example:
            /data/attributes/importance>1 AND /data/attributes/ongoing=true
        """
        param_list = []
        operator_names = self.OPERATOR_NAME_DICTIONARY.values()
        for key, val in attributes_dict.items():

            # We don't create a filter for operator names
            if key not in operator_names and val:
                operator = '='  # type: str

                # If the current parameter supports a special operator (it appears in the OPERATOR_NAME_DICTIONARY),
                # we take the operator value using the operator name (that appears in the OPERATOR_NAME_DICTIONARY)
                if operator_name := self.OPERATOR_NAME_DICTIONARY.get(key):
                    operator = attributes_dict.get(operator_name, '') if attributes_dict.get(
                        operator_name) else '='

                param_list.append(f'/data/attributes/{key + operator + val}')
        return ' AND '.join(param_list)

    def fetch_incidents(self, params_dict: dict) -> tuple[list, str]:
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
        Args:
            params_dict (dict): The params configured by the user to perform the fetch with.
        Returns:
            (list, str): List of incidents to save and string representing the creation time of the latest incident to
                be saved.
        """
        last_run = demisto.getLastRun()
        new_last_start_time = last_start_time = last_run.get('LastFetchTime', self.first_fetch)
        demisto.debug(f'Last fetch time to use is: {last_start_time}')

        # We calculate the page size to query, by performing an incidents query with page size = 1, the amount of
        # returned pages will equal to amount of incidents
        now = datetime.now(UTC).isoformat()
        amount_of_incidents = self.calculate_amount_of_incidents(start_time=last_start_time, params_dict=params_dict)
        incidents: list = []

        if amount_of_incidents:
            time_attributes_dict = assign_params(start_time=now, start_time_operator='<')
            params_dict.update(time_attributes_dict)
            data_attribute_filter = self.build_data_attribute_filter(params_dict)
            demisto.debug(
                f'NetscoutArborSightline fetch params are: page_size={amount_of_incidents}, '
                f'search_filter={data_attribute_filter}')

            # We use the status_list_to_retry since in some rare cases the API returns 500 error on consecutive API
            # calls.
            results = self.list_alerts(page_size=amount_of_incidents, search_filter=data_attribute_filter,
                                       status_list_to_retry=[500])
            all_alerts = results.get('data', [])
            short_alert_list = all_alerts[-1 * self.max_fetch:]
            if short_alert_list:
                new_last_start_time = short_alert_list[0].get('attributes', {}).get('start_time')

                for alert in reversed(short_alert_list):
                    start_time = alert.get('attributes', {}).get('start_time')
                    alert_type = alert.get('attributes', {}).get('alert_type')
                    incidents.append({
                        'name': f"{alert_type}: {alert.get('id')}",
                        'occurred': start_time,
                        'rawJSON': json.dumps(alert)
                    })
        return incidents, new_last_start_time

    def fetch_incidents_loop(self) -> tuple[list, str]:
        """
        Calls the fetch incidents function to pull incidents with for each alert_type/alert_class separately.

        Returns:
            (list, str): List of incidents to save and string representing the creation time of the latest incident to
            be saved.
        """
        incidents = []
        params_dict = assign_params(alert_class=self.alert_class, alert_type=self.alert_type,
                                    importance=self.importance, classification=self.classification,
                                    importance_operator=self.importance_operator, ongoing=self.ongoing)
        if self.alert_type:
            key = 'alert_type'
            class_type_list = self.alert_type

        elif self.alert_class:
            key = 'alert_class'
            class_type_list = self.alert_class
        else:
            key = ''
            class_type_list = []
            demisto.debug(f"No condition was matched {key=} {class_type_list=}")

        if self.alert_class or self.alert_type:
            new_last_start_time = ''
            for item in class_type_list:
                params_dict[key] = item

                last_incidents, new_last_start_time = self.fetch_incidents(params_dict)
                incidents += last_incidents
                sleep(5)
        else:
            incidents, new_last_start_time = self.fetch_incidents(params_dict)

        return incidents, new_last_start_time

    def list_alerts(self, page: Optional[int] = None, page_size: Optional[int] = None,
                    search_filter: Optional[str] = None, status_list_to_retry: list = None) -> dict:
        return self.http_request(
            method='GET',
            url_suffix='alerts',
            status_list_to_retry=status_list_to_retry,
            params=assign_params(page=page, perPage=page_size, filter=search_filter)
        )

    def get_alert(self, alert_id: str) -> dict:
        return self.http_request(
            method='GET',
            url_suffix=f'alerts/{alert_id}'
        )

    def get_annotations(self, alert_id: str) -> dict:
        return self.http_request(
            method='GET',
            url_suffix=f'alerts/{alert_id}/annotations'
        )

    def list_mitigations(self, mitigation_id: str, page: Optional[int] = None, page_size: Optional[int] = None) -> dict:
        return self.http_request(
            method='GET',
            url_suffix=f'mitigations/{mitigation_id}' if mitigation_id else 'mitigations',
            params=assign_params(page=page, perPage=page_size)

        )

    def create_mitigation(self, data: dict) -> dict:
        return self.http_request(
            method='POST',
            url_suffix='mitigations/',
            json_data=data
        )

    def delete_mitigation(self, mitigation_id: str):
        self.http_request(
            method='DELETE',
            url_suffix=f'mitigations/{mitigation_id}',
            return_empty_response=True
        )

    def mitigation_template_list(self) -> dict:
        return self.http_request(
            method='GET',
            url_suffix='mitigation_templates/'
        )

    def router_list(self) -> dict:
        return self.http_request(
            method='GET',
            url_suffix='routers/'
        )

    def managed_object_list(self, page: Optional[int] = None, page_size: Optional[int] = None) -> dict:
        return self.http_request(
            method='GET',
            url_suffix='managed_objects/',
            params=assign_params(page=page, perPage=page_size)
        )

    def tms_group_list(self) -> dict:
        return self.http_request(
            method='GET',
            url_suffix='tms_groups/'
        )


''' HELPER FUNCTIONS '''


def clean_links(target_obj: Union[dict, list]):
    """
    Recursively look for a all keys named 'links' and remove them from the object.
    Args:
        target_obj (dict/list): An object to remove the links key from.
    """

    if isinstance(target_obj, dict):
        remove_keys(target_obj, ['links'])
        for val in target_obj.values():
            clean_links(val)

    if isinstance(target_obj, list):
        for i in target_obj:
            clean_links(i)


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
    except Exception as err:
        raise DemistoException(
            f'The value given in the {arg_name} argument is not a valid JSON format:\n{json_str}\nERROR:\n{err}')


def remove_keys(obj: dict, keys_to_remove: list):
    """
    Removes the the given keys from a given dict.
    Args:
        obj (dict): The object to remove the key from.
        keys_to_remove (lst): List of keys to remove.
    """
    for key in keys_to_remove:
        if obj.get(key):
            del obj[key]


def flatten_key(obj: dict, key_to_flatten: str):
    """
    Extract the data inside a given key to the root level of the object.
    Args:
        obj (dict): The object to extract the data from.
        key_to_flatten (str): The key name to extract.
    """
    if sub_dictionary := obj.get(key_to_flatten):
        for sub_key, sub_val in sub_dictionary.items():
            obj[sub_key] = sub_val
        del obj[key_to_flatten]


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
    flatten_key(hr, 'attributes')
    remove_keys(hr, ['relationships', 'subobject'])
    return hr


def build_output(data: dict, extend_data: bool = False, key_to_flat: str = 'attributes',
                 keys_to_remove: list = None) -> dict:
    keys_to_remove = keys_to_remove if keys_to_remove else ['relationships']
    data_copy = deepcopy(data)
    clean_links(data_copy)
    if key_to_flat:
        flatten_key(data_copy, key_to_flat)
    if not extend_data:
        remove_keys(data_copy, keys_to_remove)
    return data_copy


def cast_importance_to_minimal(importance: str) -> Optional[str]:
    """
    If a minimal importance param was given, cast it to the corresponding minimal value to  be used with the '>'
    operator.
    That is:
        High -> '2' -> '1'
        Medium -> '1' -> '0'
        Low -> '0' -> None (so it will be ignored and will not be used as an  importance param)
    Args:
         importance (str): The  importance to cast.
    Returns:
         (str): The value to be used withh the '>` operator.
    """
    str_importance = IMPORTANCE_DICTIONARY.get(importance)
    if str_importance and str_importance != '0':
        return str(int(str_importance) - 1)
    else:
        return None


''' COMMAND FUNCTIONS '''


def test_module(client: NetscoutClient) -> str:
    client.fetch_incidents_loop()
    return 'ok'


def fetch_incidents_command(client: NetscoutClient):
    incidents, last_start_time = client.fetch_incidents_loop()
    demisto.incidents(incidents)
    demisto.setLastRun({'LastFetchTime': last_start_time})


def list_alerts_command(client: NetscoutClient, args: dict):
    limit = arg_to_number(args.get('limit'))
    page = arg_to_number(args.get('page'))
    alert_id = args.get('alert_id')
    alert_class = args.get('alert_class')
    alert_type = args.get('alert_type')
    classification = args.get('classification')
    importance = IMPORTANCE_DICTIONARY.get(args.get('importance', ''))
    importance_operator = args.get('importance_operator')
    ongoing = args.get('ongoing') if args.get('ongoing') else None
    start_time = args.get('start_time')
    start_time_operator = args.get('start_time_operator')
    stop_time = args.get('stop_time')
    stop_time_operator = args.get('stop_time_operator')
    managed_object_id = args.get('managed_object_id')
    extend_data = argToBoolean(args.get('extend_data', False))
    if alert_id:
        raw_result = client.get_alert(alert_id)
    else:
        attributes_dict = assign_params(alert_id=alert_id, alert_class=alert_class, alert_type=alert_type,
                                        classification=classification, importance=importance,
                                        importance_operator=importance_operator, ongoing=ongoing, start_time=start_time,
                                        start_time_operator=start_time_operator, stop_time=stop_time,
                                        stop_time_operator=stop_time_operator)
        data_attribute_filter = client.build_data_attribute_filter(attributes_dict)
        data_relationships_filter = f'AND /data/relationships/managed_object/data/id={managed_object_id}' if \
            managed_object_id else ''
        search_filter = data_attribute_filter + data_relationships_filter
        raw_result = client.list_alerts(page=page, page_size=limit, search_filter=search_filter)

    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(data=alert) for alert in data]
    outputs = [build_output(data=alert, extend_data=extend_data) for alert in data]

    return CommandResults(outputs_prefix='NASightline.Alert',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=tableToMarkdown('Alerts', hr),
                          raw_response=raw_result)


def alert_annotation_list_command(client: NetscoutClient, args: dict):
    alert_id = args.get('alert_id', '')
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.get_annotations(alert_id)
    data = raw_result.get('data', [])
    hr = [build_human_readable(data=annotation) for annotation in data]
    annotations = [build_output(data=annotation, extend_data=extend_data) for annotation in data]
    context = {'AlertID': alert_id, 'Annotations': annotations}
    return CommandResults(outputs_prefix='NASightline.AlertAnnotation',
                          outputs_key_field='AlertID',
                          outputs=context,
                          readable_output=tableToMarkdown(f'Alert {alert_id} annotations', hr),
                          raw_response=raw_result)


def mitigation_list_command(client: NetscoutClient, args: dict):
    page = arg_to_number(args.get('page'))
    limit = arg_to_number(args.get('limit'))
    mitigation_id = args.get('mitigation_id', '')
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.list_mitigations(mitigation_id, page=page, page_size=limit)
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(data=mitigation) for mitigation in data]
    mitigations = [build_output(data=mitigation, keys_to_remove=['relationships', 'subobject'], extend_data=extend_data)
                   for mitigation in data]
    return CommandResults(outputs_prefix='NASightline.Mitigation',
                          outputs_key_field='id',
                          outputs=mitigations,
                          readable_output=tableToMarkdown('Mitigation list', hr),
                          raw_response=raw_result)


def mitigation_create_command(client: NetscoutClient, args: dict):
    ip_version = IP_DICTIONARY.get(args['ip_version'])
    if not ip_version:
        raise DemistoException('ip_version value can be one of the following: '
                               f'{",".join(list(IP_DICTIONARY.keys()))}. {args.get("ip_version")} was given.')
    description = args.get('description')
    name = args.get('name')
    ongoing = args.get('ongoing', 'false')
    sub_type = args.get('sub_type')
    sub_object = validate_json_arg(args['sub_object'], 'sub_object')
    alert_id = args.get('alert_id')
    managed_object_id = args.get('managed_object_id')
    mitigation_template_id = args.get('mitigation_template_id')
    router_ids = argToList(args.get('router_ids'))
    tms_group_id = args.get('tms_group_id')
    extend_data = argToBoolean(args.get('extend_data', False))

    relationships = client.build_relationships(alert=alert_id, managed_object=managed_object_id,
                                               mitigation_template=mitigation_template_id, routers=router_ids,
                                               tms_group=tms_group_id)
    attributes = assign_params(description=description, ip_version=ip_version, name=name, ongoing=ongoing,
                               subtype=sub_type, subobject=sub_object)
    object_data = {'relationships': relationships, 'attributes': attributes}
    raw_result = client.create_mitigation(data={'data': object_data})
    data = raw_result.get('data', {})
    hr = build_human_readable(data=data)
    mitigation = build_output(data=data, extend_data=extend_data)
    return CommandResults(outputs_prefix='NASightline.Mitigation',
                          outputs_key_field='id',
                          outputs=mitigation,
                          readable_output=tableToMarkdown('Mitigation was created', hr),
                          raw_response=raw_result)


def mitigation_delete_command(client: NetscoutClient, args: dict[str, str]):
    mitigation_id = args.get('mitigation_id', '')
    client.delete_mitigation(mitigation_id)
    hr = f'### Mitigation {mitigation_id} was deleted'
    return CommandResults(readable_output=hr)


def mitigation_template_list_command(client: NetscoutClient, args: dict):
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.mitigation_template_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(data=mitigation_template) for mitigation_template in data]
    mitigation_templates = [
        build_output(data=mitigation_template, extend_data=extend_data, keys_to_remove=['relationships', 'subobject'])
        for mitigation_template in data]

    return CommandResults(outputs_prefix='NASightline.MitigationTemplate',
                          outputs_key_field='id',
                          outputs=mitigation_templates,
                          readable_output=tableToMarkdown('Mitigation template list', hr, removeNull=True),
                          raw_response=raw_result)


def router_list_command(client: NetscoutClient, args: dict):
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.router_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(router) for router in data]
    routers = [build_output(data=router, extend_data=extend_data) for router in data]
    return CommandResults(outputs_prefix='NASightline.Router',
                          outputs_key_field='id',
                          outputs=routers,
                          readable_output=tableToMarkdown('Router list', hr, headers=ROUTERS_HR_HEADERS,
                                                          removeNull=True),
                          raw_response=raw_result)


def managed_object_list_command(client: NetscoutClient, args: dict):
    page = arg_to_number(args.get('page'))
    limit = arg_to_number(args.get('limit'))
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.managed_object_list(page=page, page_size=limit)
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    objects = [build_output(data=managed_object, extend_data=extend_data) for managed_object in data]
    hr = [build_human_readable(data=managed_object) for managed_object in data]
    return CommandResults(outputs_prefix='NASightline.ManagedObject',
                          outputs_key_field='id',
                          outputs=objects,
                          readable_output=tableToMarkdown('Managed object list', hr,
                                                          headers=MANAGED_OBJECTS_HR_HEADERS, removeNull=True),
                          raw_response=raw_result)


def tms_group_list_command(client: NetscoutClient, args: dict):
    extend_data = argToBoolean(args.get('extend_data', False))
    raw_result = client.tms_group_list()
    data = raw_result.get('data')
    data = data if isinstance(data, list) else [data]
    hr = [build_human_readable(data=tms_group) for tms_group in data]
    groups = [build_output(data=group, extend_data=extend_data) for group in data]
    return CommandResults(outputs_prefix='NASightline.TMSGroup',
                          outputs_key_field='id',
                          outputs=groups,
                          readable_output=tableToMarkdown('TMS group list', hr, removeNull=True),
                          raw_response=raw_result)


''' MAIN FUNCTION '''


def main() -> None:
    try:
        command = demisto.command()
        params = demisto.params()

        if not params.get('User') or not (api_token := params.get('User', {}).get('password')):
            raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
        base_url = urljoin(params['url'], 'api/sp')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        first_fetch = None
        if first_fetch_dt := arg_to_datetime(params.get('first_fetch', '3 days')):
            first_fetch = first_fetch_dt.isoformat()
        max_fetch = min(arg_to_number(params.get('max_fetch')) or 50, 100)
        alert_class = argToList(params.get('alert_class'))
        alert_type = argToList(params.get('alert_type'))
        if alert_class and alert_type:
            raise DemistoException(
                'Cannot filter alerts with both \'Alert Class\' and \'Alert Type\' configured. Either choose '
                'the entire class you want to fetch or the specific types from within that class.')
        classification = params.get('classification')
        importance = cast_importance_to_minimal(params.get('importance'))
        ongoing = ONGOING_DICTIONARY.get(params.get('ongoing'))

        demisto.debug(f'Command being called is {demisto.command()}')

        headers: dict = {
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
            ongoing=ongoing
        )
        args: dict = demisto.args()

        result = ''
        if command == 'test-module':
            result = test_module(client)
        elif command == 'fetch-incidents':
            fetch_incidents_command(client)
        elif command == 'na-sightline-alert-list':
            result = list_alerts_command(client, args)
        elif command == 'na-sightline-alert-annotation-list':
            result = alert_annotation_list_command(client, args)
        elif command == 'na-sightline-mitigation-list':
            result = mitigation_list_command(client, args)
        elif command == 'na-sightline-mitigation-create':
            result = mitigation_create_command(client, args)
        elif command == 'na-sightline-mitigation-delete':
            result = mitigation_delete_command(client, args)
        elif command == 'na-sightline-mitigation-template-list':
            result = mitigation_template_list_command(client, args)
        elif command == 'na-sightline-router-list':
            result = router_list_command(client, args)
        elif command == 'na-sightline-managed-object-list':
            result = managed_object_list_command(client, args)
        elif command == 'na-sightline-tms-group-list':
            result = tms_group_list_command(client, args)
        else:
            raise NotImplementedError(f'Command: {command} is not implemented')

        if result:
            return_results(result)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
