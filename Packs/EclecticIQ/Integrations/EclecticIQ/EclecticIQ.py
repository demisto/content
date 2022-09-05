import json
import re
import traceback
# import datetime
from typing import Any, Dict, List, Mapping, Tuple
import demistomock as demisto
import urllib3
from CommonServerPython import *

"""EcleticIQ Integration for Cortex XSOAR (aka Demisto)."""


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def sighting(self, value: str, description: str,
                 title: str, tags: str, type_eiq: str, confidence_level: str) -> Dict[str, Any]:
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
        return self._http_request(
            method='GET',
            url_suffix='observables',
            params={"filter[type]": type_eiq, "filter[value]": value}
        )

    def fetch_entity(self, id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/entities/{}'.format(id),
            params={}
        )

    def get_observable_by_id(self, id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'observables/{id}',
            params={}
        )

    def observable(self, type_eiq: str, value: str, maliciousness: str) -> Dict[str, Any]:
        Body_paramas: Mapping[str, Any] = {
            "data": {
                "meta": {
                    "maliciousness": "Unknown"
                },
                "type": "Unknown",
                "value": "value1"
            }
        }
        Body_paramas["data"]["type"] = type_eiq
        Body_paramas["data"]["value"] = value
        Body_paramas["data"]["meta"]["maliciousness"] = maliciousness
        return self._http_request(
            method='POST',
            url_suffix='/observables',
            data=json.dumps(Body_paramas)
        )

    def get_user_granted_permissions(self):
        response = self._http_request(
            method='GET',
            url_suffix='users/self',
            params={}
        )
        data = response.get("data")
        if data:
            return data.get("permissions")
        return {}

    def get_platform_permissions(self):
        response = self._http_request(
            method='GET',
            url_suffix='permissions',
            params={}
        )
        data = response.get("data")
        if data:
            return data
        return {}


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
        if value["name"] in wanted_permissions:
            ids_required_for_user.append(value["id"])

    return ids_required_for_user


def authenticate_user(ids_of_user: list, ids_required_for_user: list) -> Tuple[bool, List[int]]:
    """Get user authentication and missing permission ids .
    :param ids_of_user: permission ids user have
    :type ids_of_user: list
    :param ids_required_for_user: permission ids required for user to authenticate
    :type ids_required_for_user: list
    :return: is user authenticated , missing permissions ids
    :rtype: boolean,set
    """
    user_authenticated = False
    value = list(set(ids_required_for_user).difference(ids_of_user))

    if not value:
        user_authenticated = True
    return user_authenticated, value


def get_permission_name_from_id(permission_data: dict, permission_ids: list):
    """Get permission name from permission ids.
    :return: permissions name
    :rtype: list of str
    """
    permissions_name = []
    for data in permission_data:
        for permission_id in permission_ids:
            if data["id"] == permission_id:
                permissions_name.append(data["name"])
    return permissions_name


def test_module(client: Client) -> Any:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        permissions_of_user = client.get_user_granted_permissions()
    except Exception:
        permissions_of_user = []
        return "Please provide valid API Key."

    permission_ids = []
    missing_permissions = ""
    for permission in permissions_of_user:
        permission_ids.append(int(permission.split("/")[-1]))
    try:
        permissions_data = client.get_platform_permissions()
    except Exception:
        permissions_data = []
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


def maliciousness_to_dbotscore(maliciousness) -> Any:
    """

    Translates EclecticIQ obversable maliciousness confidence level to DBotScore based on given threshold

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

    maliciousness_dictionary = {
        'unknown': 0,
        'safe': 1,
        'low': 2,
        'medium': 2,
        'high': 3
    }

    return maliciousness_dictionary[maliciousness]


def prepare_observable_data(data: Any) -> dict:
    """Prepare Observable data to show on UI.
    :param data: Observable data
    :type data: dict
    :return: Only selected fields dict
    :rtype: dict
    """
    new_data = {}
    new_data["type"] = data.get("type")
    new_data["value"] = data.get("value")
    new_data["classification"] = data.get("meta").get("maliciousness")
    return new_data


def get_entity_data(client, data_item: Any) -> List[Any]:
    """Get entity data to show on UI.
    :param data_item: Data from lookup obsrvables Dict
    :type data_item: dict
    :param eiq_api: EIQ API object
    :type eiq_api: object
    :return: prepared data to show on UI
    :rtype: List
    """
    entity_data_dict_list = []
    for item in data_item.get("entities"):
        entity_data_dict = {}
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

        entity_data_dict.update(
            prepare_entity_data(entity_data, obs_data_list))
        entity_data_dict_list.append(entity_data_dict)
    return entity_data_dict_list


def prepare_entity_data(data: Any, obs_data: Any) -> dict[Any, Any]:
    """Prepare entity data to show on UI.
    :param data: Entity data
    :type data: dict
    :param data: Observable data
    :type data: list
    :return: Only selected fields dict
    :rtype: dict
    """
    new_data = {}
    if data.get("data"):
        new_data["title"] = (
            data.get("data").get("title") if data.get(
                "data").get("title") else ""
        )

        new_data["description"] = (
            data.get("data").get("description")
            if data.get("data").get("description")
            else ""
        )
        new_data["confidence"] = (
            data.get("data").get("confidence")
            if data.get("data").get("confidence")
            else ""
        )
        new_data["tags"] = (
            data.get("data").get("tags") if data.get(
                "data").get("tags") else ""
        )
    if data.get("meta"):
        new_data["threat_start_time"] = (
            data.get("meta").get("estimated_threat_start_time")
            if data.get("meta").get("estimated_threat_start_time")
            else ""
        )
        if data.get("data").get("producer"):
            new_data["source_name"] = (
                data.get("data").get("producer").get("identity")
                if data.get("data").get("producer").get("identity")
                else ""
            )
        else:
            new_data["source_name"] = ""
        new_data["observables"] = obs_data

    return new_data


def validate_type(s_type: str, value: Any) -> Any:  # pylint: disable=R0911
    """Get the type of the observable.
    :param value: observable value
    :type value: str
    :return: type of the observable
    :rtype: str
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


def lookup_observables(client: Client, args: Any) -> CommandResults:
    type_eiq = args.get("type")
    value_eiq = args.get("value")
    if not validate_type(type_eiq, value_eiq):
        raise ValueError("Type does not match specified value")
    data = client.lookup_obs(type_eiq, value_eiq)
    data = data["data"] if data.get("data") else []
    standard_observable_outputs = []
    final_data = []
    for observable in data:
        maliciousness = observable["meta"]["maliciousness"]
        score = maliciousness_to_dbotscore(maliciousness)
        standard_observable_output = {
            'data': observable
        }
        if score == 3:
            standard_observable_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
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
        }  # type: dict
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


def create_sighting(client: Client, args: Any) -> CommandResults:
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
    context['Sighting.Data'] = createContext(
        data=response, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Sighting.Data',
        outputs_key_field='value',
        outputs=output
    )


def create_observable(client: Client, args: Any) -> CommandResults:
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
    context['Observable.Data'] = createContext(
        data=response, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Observables.Data',
        outputs_key_field='value',
        outputs=output
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = demisto.params().get('url')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

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
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'lookup_observables':
            return_results(lookup_observables(client, demisto.args()))

        elif demisto.command() == 'create_sighting':
            return_results(create_sighting(client, demisto.args()))

        elif demisto.command() == 'create_observable':
            return_results(create_observable(client, demisto.args()))

        else:
            demisto.error(f'{demisto.command} command is not implemented.')
            raise NotImplementedError(f'{demisto.command} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

