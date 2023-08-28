import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re
import traceback
from typing import Any, Dict, List, Mapping, Tuple
import urllib3

"""EclecticIQ Integration for Cortex XSOAR."""

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    def sighting(self, value: str, description: str,
                 title: str, tags: str, type_eiq: str, confidence_level: str) -> Dict[str, Any]:
        """Create the sighting using the '/entities' API endpoint
        :param value: sighting value
        :type value: str
        :param description: sighting description
        :type description: str
        :param title: title for the sighting
        :type title: str
        :param tags: sighting tags
        :type tags: str
        :param type_eiq: sighting value type
        :type type_eiq: str
        :param confidence_level: maliciousness of the value
        :type confidence_level : ``str``
        :return: sighting payload
        :rtype: ``Dict[str, Any]``
        """
        sighting_schema: Mapping[str, Any] = {
            "data": {
                "data": {
                    "value": "value1",
                    "confidence": "medium",
                    "description": "test_desc",
                    "type": "eclecticiq-sighting",
                    "timestamp": "2022-03-10T05:37:42Z",
                    "title": "title1",
                    "security_control": {
                            "type": "information-source",
                            "identity": {
                                "name": "EclecticIQ Platform App for cortex XSOAR",
                                "type": "identity"
                            },
                        "time": {
                                "type": "time",
                                "start_time": "2022-03-10T05:37:42Z",
                                "start_time_precision": "second"}
                    }
                },
                "meta": {"tags": ["XSOAR Alert"], "ingest_time": "2022-03-10T05:37:42Z"}
            }
        }
        sighting_schema["data"]["data"]["value"] = value
        sighting_schema["data"]["data"]["confidence"] = confidence_level
        sighting_schema["data"]["data"]["description"] = description
        sighting_schema["data"]["data"]["title"] = title
        sighting_schema["data"]["data"]["security_control"]["type"] = type_eiq
        sighting_schema["data"]["meta"]["tags"] = tags.split(",")
        sighting_schema["data"]["data"]["timestamp"] = datetime.strftime(
            datetime.utcnow(), DATE_FORMAT)
        return self._http_request(
            method='POST',
            url_suffix='/entities',
            data=json.dumps(sighting_schema)
        )

    def lookup_obs(self, type_eiq: str, value: str) -> Dict[str, Any]:
        """Get observables using the '/observables' API endpoint.
        :param type_eiq: observable type
        :type type_eiq: str
        :param value: observable value
        :type value: str
        :return: observables
        :rtype: Dict[str, Any]
        """
        return self._http_request(
            method='GET',
            url_suffix='observables',
            params={"filter[type]": type_eiq, "filter[value]": value}
        )

    def fetch_entity(self, id: str) -> Dict[str, Any]:
        """Get entity details by id.
        :param id: entity id
        :type: str
        :return: id releted entity
        :rtype: Dict[str, Any]
        """
        return self._http_request(
            method='GET',
            url_suffix='/entities/{}'.format(id),
            params={}
        )

    def get_observable_by_id(self, id: str) -> Dict[str, Any]:
        """Get observables by id.
        :param id: observable id
        :type id: str
        :return: id related observable
        :rtype: Dict[str, Any]
        """
        return self._http_request(
            method='GET',
            url_suffix=f'observables/{id}',
            params={}
        )

    def observable(self, type_eiq: str, value: str, maliciousness: str) -> Dict[str, Any]:
        """Create the observable using the '/observables' API endpoint
        :param type_eiq: observable type
        :type type_eiq: str
        :param value: observable value
        :type value: str
        :param maliciousness: maliciousness of the value
        :type maliciousness: str
        :return: observable payload
        :rtype: ``Dict[str, Any]``
        """
        body_params: Mapping[str, Any] = {
            "data": {
                "meta": {
                    "maliciousness": "Unknown"
                },
                "type": "Unknown",
                "value": "value1"
            }
        }
        body_params["data"]["type"] = type_eiq
        body_params["data"]["value"] = value
        body_params["data"]["meta"]["maliciousness"] = maliciousness
        return self._http_request(
            method='POST',
            url_suffix='/observables',
            data=json.dumps(body_params)
        )

    def get_user_granted_permissions(self) -> Any:
        """Get user granted permissions.
        :param: self
        :type: str
        :return: user granted permissions
        :rtype: Any
        """
        response = self._http_request(
            method='GET',
            url_suffix='users/self',
            params={}
        )
        data = response.get("data")
        if data:
            return data.get("permissions")
        return {}

    def get_platform_permissions(self) -> Any:
        """Get platform permissions for user.
        :param: self
        :type: str
        :return: permissions data
        :rtype: Any
        """
        response = self._http_request(
            method='GET',
            url_suffix='permissions',
            params={}
        )
        data = response.get("data", {})
        return data or {}


def get_platform_permission_ids(permissions_data: Any) -> List[Any]:
    """Get permission ids required for user to authenticate.
    :param feeds: permissions_data
    :type response: list
        [{"id": 1, "name": "read history-events"},{"id": 2,"name": "read discovery-rules"}...]
    :return: List of permission ids
        [33, 59, 66,78]
    :rtype: list
    """
    wanted_permissions = [
        "read entitites",
        "modify entities",
        "read extracts",
        "read outgoing-feeds",
    ]
    ids_required_for_user = []
    for value in permissions_data:
        if value.get("name") in wanted_permissions:
            ids_required_for_user.append(value.get("id"))

    return ids_required_for_user


def authenticate_user(ids_of_user: list, ids_required_for_user: list) -> Tuple[bool, List[int]]:
    """Get user authentication and missing permission ids .
    :param ids_of_user: permission ids user have
    :type ids_of_user: list
    :param ids_required_for_user: permission ids required for user to authenticate
    :type ids_required_for_user: list
    :return: is user authenticated , missing permissions ids
    :rtype: boolean,list
    """
    user_authenticated = False
    value = list(set(ids_required_for_user).difference(ids_of_user))

    if not value:
        user_authenticated = True
    return user_authenticated, value


def get_permission_name_from_id(permission_data: Dict, permission_ids: list) -> Any:
    """Get permission name from permission ids.
    :param permission_data: permission data
    :type permission_data: Dict
    :param permission_ids: permission id for authenticate
    :type permission_ids: list
    :return: permissions name
    :rtype: Any
    """
    permissions_name = []
    for data in permission_data:
        for permission_id in permission_ids:
            if data.get("id") == permission_id:
                permissions_name.append(data.get("name"))
    return permissions_name


def data_ingestion(client: Client) -> Any:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type client: ``Client``
    :param Client: EclecticIQ client to use
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``Any``
    """
    try:
        permissions_of_user = client.get_user_granted_permissions()
    except Exception:
        return "Please provide correct URL & API Key."

    permission_ids = []
    missing_permissions = ""
    if isinstance(permissions_of_user, list):
        for permission in permissions_of_user:
            permission_ids.append(int(permission.split("/")[-1]))
    try:
        permissions_data = client.get_platform_permissions()
    except Exception:
        return "API Key does not have access to view permissions."
    if permissions_data:
        ids_required_for_user = get_platform_permission_ids(
            permissions_data
        )
        user_authenticated, permission_ids = authenticate_user(
            permission_ids, ids_required_for_user
        )
        if not user_authenticated:
            # check for missing permissions
            permissions_data = client.get_platform_permissions()
            missing_permissions = get_permission_name_from_id(
                permissions_data, permission_ids
            )
    else:
        missing_permissions = "Read Permissions"

    if missing_permissions:
        return "API Key is missing permissions {}".format(missing_permissions)

    return 'ok'


def maliciousness_to_dbotscore(maliciousness) -> int:
    """Translates EclecticIQ obversable maliciousness confidence level to DBotScore based on given threshold
    Parameters
    ----------
    maliciousness : str
        EclecticIQ obversable maliciousness confidence level.
    threshold : str
        Minimum maliciousness confidence level to consider the IOC malicious.
    Returns
    -------
    number
        Translated DBot Score
    """
    maliciousness_Dictionary = {
        'unknown': 0,
        'safe': 1,
        'low': 2,
        'medium': 2,
        'high': 3
    }
    return maliciousness_Dictionary[maliciousness]


def prepare_observable_data(data: Any) -> Dict:
    """Prepare Observable data to show on UI.
    :param data: Observable data
    :type data: Dict
    :return: Only selected fields Dict
    :rtype: Dict
    """
    new_data = {}
    new_data["type"] = data.get("type")
    new_data["value"] = data.get("value")
    new_data["classification"] = data.get("meta", {}).get("maliciousness")
    return new_data


def get_entity_data(client, data_item: Any) -> List[Any]:
    """Get entity data to show on UI.
    :param data_item: Data from lookup obsrvables Dict
    :type data_item: Any
    :return: prepared data to show on UI
    :rtype: List
    """
    entity_data_Dict_list = []
    for item in data_item.get("entities"):
        entity_data_Dict = {}
        entity_data = client.fetch_entity(
            str(item.split("/")[-1])
        )
        entity_data = entity_data.get("data")
        observables = entity_data.get(
            "observables") if entity_data.get("observables") else []
        obs_data_list = []
        for observable in observables:
            obs_data = client.get_observable_by_id(
                str(observable.split("/")[-1])
            )
            obs_data = obs_data.get("data")
            append_data = prepare_observable_data(obs_data)

            obs_data_list.append(append_data)

        entity_data_Dict.update(
            prepare_entity_data(entity_data, obs_data_list))
        entity_data_Dict_list.append(entity_data_Dict)
    return entity_data_Dict_list


def prepare_entity_data(data: Any, obs_data: Any) -> Dict[Any, Any]:
    """Prepare entity data to show on UI.
    :param data: Entity data
    :type data: Any
    :param obs_data: Observable data
    :type data: Any
    :return: Only selected fields Dict
    :rtype: Dict
    """
    new_data = {}
    if data.get("data"):
        new_data["title"] = (
            data.get("data", {}).get("title") if data.get(
                "data", {}).get("title") else ""
        )

        new_data["description"] = (
            data.get("data", {}).get("description")
            if data.get("data", {}).get("description")
            else ""
        )
        new_data["confidence"] = (
            data.get("data", {}).get("confidence")
            if data.get("data", {}).get("confidence")
            else ""
        )
        new_data["tags"] = (
            data.get("data", {}).get("tags") if data.get(
                "data", {}).get("tags") else ""
        )
    if data.get("meta"):
        new_data["threat_start_time"] = (
            data.get("meta", {}).get("estimated_threat_start_time")
            if data.get("meta", {}).get("estimated_threat_start_time")
            else ""
        )
        if data.get("data", {}).get("producer"):
            new_data["source_name"] = (
                data.get("data", {}).get("producer", {}).get("identity")
                if data.get("data", {}).get("producer", {}).get("identity")
                else ""
            )
        else:
            new_data["source_name"] = ""
        new_data["observables"] = obs_data

    return new_data


def validate_type(s_type: str, value: Any) -> Any:  # pylint: disable=R0911
    """Get the type of the observable.
    :param s_type :observable pattern type
    :type s_type: str
    :param value: observable value
    :type value: Any
    :return: type of the observable
    :rtype: Any
    """
    if s_type == "ipv4":  # pylint: disable=R1705
        return bool(re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value))
    elif s_type == "ipv6":
        return bool(
            re.match(
                r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\
                    ([0-9a-fA-F]{1,4}:){1,7}:|\
                    ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|\
                    ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|\
                    ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|\
                    ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|\
                    ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|\
                    [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|\
                    :((:[0-9a-fA-F]{1,4}){1,7}|:)|\
                    fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|\
                    ::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|\
                    1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|\
                    1{0,1}[0-9]){0,1}[0-9])|\
                    ([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|\
                    1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|\
                    (2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$",
                value,   # pylint: disable=C0301
            )
        )
    elif s_type == "email":
        return bool(re.match(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+", value))
    elif s_type == "uri":
        return bool(re.match(r"[^\:]+\:\/\/[\S]+", value))
    elif s_type == "domain":
        return bool(
            re.match(
                r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$",
                value,
            )
        )
    elif s_type == "hash-md5":
        return bool(re.match(r"^[a-f0-9A-F]{32}$", value))
    elif s_type == "hash-sha256":
        return bool(re.match(r"^[a-f0-9A-F]{64}$", value))
    elif s_type == "hash-sha1":
        return bool(re.match(r"\b[0-9a-f]{5,40}\b", value))
    elif s_type == "hash-sha512":
        return bool(re.match(r"^\w{128}$", value))
    else:
        return False


def EclecticIQ_lookup_observables(client: Client, args: Any) -> CommandResults:
    """lookup_observables command: Returns the observable
    :type client: ``Client``
    :param Client: EclecticIQ client to use
    :type args: ``Any``
    :param args: args {type, value}
    :return: observable data
    :rtype: ``CommandResults``
    """
    type_eiq = args.get("type")
    value_eiq = args.get("value")
    if not validate_type(type_eiq, value_eiq):
        raise ValueError("Type does not match specified value")
    response = client.lookup_obs(type_eiq, value_eiq)
    if response.get("data"):
        data_item = response["data"]
    else:
        return CommandResults(readable_output="No observable data found.")
    standard_observable_outputs = []
    final_data = []
    for observable in data_item:
        maliciousness = observable.get("meta", {}).get("maliciousness")
        score = maliciousness_to_dbotscore(maliciousness)
        standard_observable_output = {
            'data': observable
        }
        if score == 3:
            standard_observable_output['Malicious'] = {
                'Vendor': 'EclecticIQ',
                'Description': 'EclecticIQ maliciousness confidence level: ' + maliciousness
            }
            standard_observable_outputs.append(standard_observable_output)
        dbot_output = {
            'Type': observable.get("type"),
            'indicator': observable.get("type"),
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'score': score
        }
        context = {
            'DBotScore': dbot_output
        }  # type: Dict
        if observable.get("entities"):
            entity_data = get_entity_data(client, observable)
            final_data = entity_data
    human_readable_title = 'EclecticIQ observable reputation - {}'.format(
        value_eiq)
    human_readable = tableToMarkdown(human_readable_title, final_data)
    context['Entity'] = createContext(
        data=final_data, removeNull=True)
    context[outputPaths['ip']] = standard_observable_outputs
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='EclecticIQ',
        outputs_key_field='value',
        outputs=context
    )


def EclecticIQ_create_sighting(client: Client, args: Any) -> CommandResults:
    """create_sighting command: Returns the sighting data
    :type client: ``Client``
    :param Client: EclecticIQ client to use
    :type args: ``Any``
    :param args: args {value, description, title, tags, type, confidence_level}
    :return: sighting data
    :rtype: ``CommandResults``
    """
    value = args.get("value")
    description = args.get("description")
    title = args.get("title")
    tags = args.get("tags")
    type_eiq = args.get("type")
    confidence_level = args.get("confidence_level")
    if not validate_type(type_eiq, value):
        raise ValueError("Type does not match specified value")
    response = client.sighting(
        value, description, title, tags, type_eiq, confidence_level)
    context = {}
    output = {'value': value,
              'description': description,
              'title': title,
              'tags': tags,
              'Type': type_eiq,
              'confidence_level': confidence_level}
    human_readable_title = '!sighting created for- {}'.format(
        args.get("value"))
    human_readable = tableToMarkdown(human_readable_title, t=output)
    context['Data'] = createContext(
        data=response, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Sighting',
        outputs_key_field='value',
        outputs=context
    )


def EclecticIQ_create_observable(client: Client, args: Any) -> CommandResults:
    """create_observable command: Returns the observable data
    :type client: ``Client``
    :param Client: EclecticIQ client to use
    :type args: ``Any``
    :param args: args {type, value}
    :return: observable data
    :rtype: ``CommandResults``
    """
    type_eiq = args.get("type")
    value = args.get("value")
    maliciousness = args.get("maliciousness")
    if not validate_type(type_eiq, value):
        raise ValueError("Type does not match specified value")
    response = client.observable(type_eiq, value, maliciousness)
    context = {}
    output = {'type': type_eiq,
              'value': value,
              'maliciousness': maliciousness
              }
    human_readable_title = "Observables created successfully..!!"
    human_readable = tableToMarkdown(human_readable_title, t=output)
    context['Data'] = createContext(
        data=response, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Observables',
        outputs_key_field='value',
        outputs=context
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    api_key = params.get('apikey', {}).get('password')
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(data_ingestion(client))

        elif demisto.command() == 'EclecticIQ_lookup_observables':
            return_results(EclecticIQ_lookup_observables(client, demisto.args()))

        elif demisto.command() == 'EclecticIQ_create_sighting':
            return_results(EclecticIQ_create_sighting(client, demisto.args()))

        elif demisto.command() == 'EclecticIQ_create_observable':
            return_results(EclecticIQ_create_observable(client, demisto.args()))

        else:
            raise NotImplementedError(f'{demisto.command()} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
