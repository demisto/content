#
#
#                 _____            _         _____      _
#                / ____|          (_)       |  __ \    (_)
#               | (___   ___ _ __  _  ___   | |__) | __ _ _ __ ___   ___
#                \___ \ / _ \ '_ \| |/ _ \  |  ___/ '__| | '_ ` _ \ / _ \
#                ____) |  __/ |_) | | (_) | | |   | |  | | | | | | |  __/
#               |_____/ \___| .__/|_|\___/  |_|   |_|  |_|_| |_| |_|\___|
#                           | |
#                           |_|
#
#
#    _____                 _     _          _____       _                       _   _
#   |  __ \               (_)   | |        |_   _|     | |                     | | (_)
#   | |  | | ___ _ __ ___  _ ___| |_ ___     | |  _ __ | |_ ___  __ _ _ __ __ _| |_ _  ___  _ __
#   | |  | |/ _ \ '_ ` _ \| / __| __/ _ \    | | | '_ \| __/ _ \/ _` | '__/ _` | __| |/ _ \| '_ \
#   | |__| |  __/ | | | | | \__ \ || (_) |  _| |_| | | | ||  __/ (_| | | | (_| | |_| | (_) | | | |
#   |_____/ \___|_| |_| |_|_|___/\__\___/  |_____|_| |_|\__\___|\__, |_|  \__,_|\__|_|\___/|_| |_|
#                                                                __/ |
#                                                               |___/
#
#
# info : https://www.sepio.systems/
# support : support@sepio.systems

# IMPORTS
import json
import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MAX_RESULTS = 1000000
MAX_RESULTS_EVENTS = 50

SEPIO = 'Sepio Systems'

# Convert Sepio Prime events severity to Demisto severity
SEPIO_PRIME_SEVERITY_TO_DEMOISTO_SEVERITY_CONVERT = {
    'Debug': 1,
    'Notice': 1,
    'Informational': 1,
    'Alert': 2,
    'Warning': 2,
    'Error': 3,
    'Emergency': 4,
    'Critical': 4
}

# Agents set mode values
AGENTS_ARMED_MODE_CONVERT = {
    'Free': 'free',
    'Armed': 'ARM'
}

# Peripherals set mode values
AGENT_PERIPHERALS_APPROVE_MODE_CONVERT = {
    'Approve': 'APPROVE',
    'Disapprove': 'DISAPPROVE'
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, *args, **kwargs):
        self._prime_auth = kwargs.pop('auth')
        super().__init__(*args, **kwargs)

    def prime_get_agents(self, host_identifier, ip_address, uuid, has_unapproved_peripherals, has_vulnerable_peripherals,
                         has_known_attack_tools, limit):
        """Gets Agents from Sepio Prime using the '/agents' API endpoint

        :type host_identifier: ``str``
        :param host_identifier: filter only agents that their host identifier contains this

        :type ip_address: ``str``
        :param ip_address: filter only agents that their ip address contains this

        :type uuid: ``str``
        :param uuid: filter only agents that their uuid contains this

        :type has_unapproved_peripherals: ``str`` or ``bool``
        :param has_unapproved_peripherals: filter only agents their has_unapproved_peripherals is equal to this

        :type has_vulnerable_peripherals: ``str`` or ``bool``
        :param has_vulnerable_peripherals: filter only agents their has_vulnerable_peripherals is equal to this

        :type has_known_attack_tools: ``str`` or ``bool``
        :param has_known_attack_tools: filter only agents their has_known_attack_tools is equal to this

        :type limit: ``int``
        :param limit: maximum number of items to be returned

        :return: List containing all the matching agents from Sepio Prime API
        :rtype: ``List[Dict[str, Any]]``
        """

        get_agents_params = {
            'hostIdentifier': host_identifier,
            'ipAddress': ip_address,
            'uuid': uuid,
            'hasUnapprovedPeripherals': has_unapproved_peripherals,
            'hasVulnerablePeripherals': has_vulnerable_peripherals,
            'hasKnownAttackTools': has_known_attack_tools
        }

        res = self.__prime_get_from_api_retries('/agents', get_agents_params, 'lastConfiguration_desc', limit)
        return res

    def prime_get_global_peripherals(self, host_identifier, ip_address, host_uuid, vendor_name, product_name, serial_number,
                                     is_unapproved_peripheral, is_vulnerable_peripheral, is_known_attack_tool, limit):
        """Gets Peripherals from Sepio Prime using the '/peripherals' API endpoint

        :type host_identifier: ``str``
        :param host_identifier: filter only peripherals that their agent host identifier contains this

        :type ip_address: ``str``
        :param ip_address: filter only peripherals that their agent ip address contains this

        :type host_uuid: ``str``
        :param host_uuid: filter only peripherals that their agent uuid contains this

        :type vendor_name: ``str``
        :param vendor_name: filter only peripherals that their gui vid contains this

        :type product_name: ``str``
        :param product_name: filter only peripherals that their gui pid contains this

        :type serial_number: ``str``
        :param serial_number: filter only peripherals that their serial number contains this

        :type is_unapproved_peripheral: ``str`` or ``bool``
        :param is_unapproved_peripheral: filter only peripherals their is_unapproved_peripheral is equal to this

        :type is_vulnerable_peripheral: ``str`` or ``bool``
        :param is_vulnerable_peripheral: filter only peripherals their is_vulnerable_peripheral is equal to this

        :type is_known_attack_tool: ``str`` or ``bool``
        :param is_known_attack_tool: filter only peripherals is_known_attack_tool is equal to this

        :type limit: ``int``
        :param limit: maximum number of items to be returned

        :return: List containing all the matching peripherals from Sepio Prime API
        :rtype: ``List[Dict[str, Any]]``
        """

        get_global_peripherals_params = {
            'hostIdentifier': host_identifier,
            'ipAddress': ip_address,
            'hostUuid': host_uuid,
            'productInfo': product_name,
            'vendor': vendor_name,
            'serialNumber': serial_number,
            'isUnapprovedPeripheral': is_unapproved_peripheral,
            'isVulnerablePeripheral': is_vulnerable_peripheral,
            'isKnownAttackTool': is_known_attack_tool
        }

        res = self.__prime_get_from_api_retries('/peripherals', get_global_peripherals_params, 'hostUuid_asc', limit)
        return res

    def prime_get_switches(self):
        """Gets Switches from Sepio Prime using the '/switches/switches' API endpoint

        :return: List containing all switches from Sepio Prime API
        :rtype: ``List[Dict[str, Any]]``
        """

        res = self.__prime_get_from_api_retries('/switches/switches', None, None, MAX_RESULTS, results_key=None)
        return res

    def prime_get_switch_ports(self, switch_ip_address, switch_name, port_id, port_name, link_partner_data_contains,
                               is_alarmed, limit):
        """Gets Switch Ports from Sepio Prime using the '/switches/ports' API endpoint

        :type switch_ip_address: ``str``
        :param switch_ip_address: filter only ports that their switch_ip address contains this

        :type switch_name: ``str``
        :param switch_name: filter only ports that their switch_name contains this

        :type port_id: ``str``
        :param port_id: filter only ports that their port_id contains this

        :type port_name: ``str``
        :param port_name: filter only peripherals that their port_name contains this

        :type link_partner_data_contains: ``str``
        :param link_partner_data_contains: filter only peripherals that link_partner_data_contains contains this

        :type is_alarmed: ``str`` or ``bool``
        :param is_alarmed: filter only ports that their is_alarmed is equal to this

        :type limit: ``int``
        :param limit: maximum number of items to be returned

        :return: List containing all the matching ports from Sepio Prime API
        :rtype: ``List[Dict[str, Any]]``
        """

        get_switch_ports_params = {
            'switchIp': switch_ip_address,
            'switchName': switch_name,
            'portID': port_id,
            'assignedName': port_name,
            'linkPartnerData': link_partner_data_contains,
            'alarmed': is_alarmed
        }

        res = self.__prime_get_from_api_retries('/switches/ports', get_switch_ports_params, 'switchIp_asc', limit)
        return res

    def prime_get_events(self, from_datetime, min_severity, categories, max_results,
                         to_datetime=None, source=None, peripheral_type=None, from_eventid=None):
        """Gets Events from Sepio Prime using the '/events/getevents' API endpoint

        :type from_datetime: ``str``
        :param from_datetime: filter only events that their creation date is after this

        :type min_severity: ``str``
        :param min_severity: filter only events that their severity is equal to this or higher

        :type categories: ``str`` or ``list``
        :param categories: filter only events that their category is contained in this

        :type max_results: ``int``
        :param max_results: maximum number of results

        :type to_datetime: ``str``
        :param to_datetime: filter only events that their creation date is before this

        :type source: ``str``
        :param source: filter only events their source contains this

        :type peripheral_type: ``str`` or ``list``
        :param peripheral_type: maximum number of items to be returned

        :return: List containing all the matching events from Sepio Prime API
        :rtype: ``List[Dict[str, Any]]``
        """

        search_category = categories[0] if categories and len(categories) == 1 else None
        get_events_params = {
            'category': search_category,
            'minimumSeverity': min_severity,
            'source': source,
            'peripheralIcon': peripheral_type
        }
        if from_eventid is None:
            get_events_params["FromDate"] = from_datetime
            get_events_params["ToDate"] = to_datetime
        else:
            get_events_params["FromEventId"] = from_eventid

        res = self.__prime_get_from_api_retries('/events/getevents', get_events_params, 'date_asc', max_results)
        return res

    def prime_set_agent_mode(self, uuid, host_identifier, ip_address, mode):
        """Set Agent Mode in Sepio Prime using the '/agents/configuration' API endpoint

        At least one of uuid, host_identifier or ip_address should not be empty,
        if only one agent that match all the search params (uuid, host_identifier, ip_address)
        is found, its mode will be updated

        :type uuid: ``str``
        :param uuid: Agent unique identifier

        :type host_identifier: ``str``
        :param host_identifier: Agent host identifier

        :type ip_address: ``str``
        :param ip_address: Agent ip address identifier

        :type mode: ``str``
        :param mode: mode to be applied

        :return: List containing all updated agents details
        :rtype: ``List[Dict[str, Any]]``
        """

        set_agent_mode_data = [
            {
                'uuid': uuid,
                'hostIdentifier': host_identifier,
                'ipAddress': ip_address,
                'agentConfigViewResource':
                {
                    'isSystemArmed': mode
                }
            }
        ]

        res = self.__prime_post_to_api_retries('/agents/configuration', set_agent_mode_data)
        return res

    def prime_set_agent_peripherals_mode(self, uuid, host_identifier, ip_address, vid, pid, mode):
        """Set Agent peripherals Mode in Sepio Prime using the '/peripherals/command' API endpoint

        At least one of uuid, host_identifier or ip_address should not be empty,
        if only one agent that match all the search params (uuid, host_identifier, ip_address)
        is found, all the peripherals that match the vid and pid will be updated to new mode

        :type uuid: ``str``
        :param uuid: Agent unique identifier

        :type host_identifier: ``str``
        :param host_identifier: Agent host identifier

        :type ip_address: ``str``
        :param ip_address: Agent ip address identifier

        :type vid: ``str``
        :param vid: Agent ip address identifier

        :type pid: ``str``
        :param pid: Agent ip address identifier

        :type mode: ``str``
        :param mode: mode to be applied

        :return: List containing all updated agents uuid
        :rtype: ``List[str]``
        """

        set_agent_peripherals_data = {
            'opCode': mode,
            'peripheralsIds': [
                {
                    'uuid': uuid,
                    'hostIdentifier': host_identifier,
                    'ipAddress': ip_address,
                    'vid': vid,
                    'pid': pid
                }
            ]
        }

        res = self.__prime_post_to_api_retries('/peripherals/command', set_agent_peripherals_data)
        return res

    def prime_test_connection(self):
        """Test connection to Sepio Prime server using the url, username and password
        that was inserted by the user

        :return: success boolean result and error message if its not successfully
        :rtype: ``Tuple[bool, str]``

        """

        try:
            res = self.__prime_request_token()
            is_successfull = bool(res and res.get('token'))
            message = res.get('text') if not is_successfull else None
            return is_successfull, message
        except Exception as e:
            error_message = str(e)
            demisto.error(error_message)
            if isinstance(e, DemistoException):
                args_len = len(e.args)
                if args_len > 0:
                    error_message = e.args[0]
            return False, error_message

    def __prime_request_token(self):
        data = {'username': self._prime_auth[0], 'password': self._prime_auth[1]}
        res = self._http_request('POST', '/auth/signin', json_data=data, ok_codes=(200, 400), resp_type='response')
        return {
            'is_successfull': res.ok,
            'token': res.json()['token'] if res.ok else None,
            'text': res.text
        }

    def __prime_get_from_api(self, url_suffix, search_params, sort_by, max_size, resp_type='response'):
        params = {}

        if max_size:
            params.update({
                'pageSize': str(max_size),
                'pageNumber': '1'
            })

        if sort_by:
            params['sortBy'] = sort_by

        if search_params:
            for key, value in search_params.items():
                if value is not None:
                    params[key] = value

        headers = self.__prime_api_auth_headers_format(self.__prime_get_token_from_cache())
        res = self._http_request('GET', url_suffix, headers=headers, params=params, resp_type=resp_type)

        return res

    def __prime_get_from_api_retries(self, url_suffix, search_params, sort_by, max_size, retries=2, results_key='data'):
        i = 1
        while i <= retries:
            i += 1
            try:
                res = self.__prime_get_from_api(url_suffix, search_params, sort_by, max_size)

                if res.status_code == 401:  # api token in not valid
                    self.__prime_get_token_from_cache(renew=True)
                    continue

                self.__prime_handle_http_response(res, url_suffix)

                data = res.json()
                return data[results_key] if results_key else data
            except Exception as e:
                demisto.error(str(e))
                raise

    def __prime_post_to_api(self, url_suffix, json_data, resp_type='response'):
        headers = self.__prime_api_auth_headers_format(self.__prime_get_token_from_cache())
        res = self._http_request('POST', url_suffix, headers=headers, json_data=json_data, resp_type=resp_type)

        return res

    def __prime_post_to_api_retries(self, url_suffix, json_data, retries=2):
        i = 1
        while i <= retries:
            i += 1
            try:
                res = self.__prime_post_to_api(url_suffix, json_data)

                if res.status_code == 401:  # api token in not valid
                    self.__prime_get_token_from_cache(renew=True)
                    continue

                self.__prime_handle_http_response(res, url_suffix)

                res_obj = res.json() if res.ok else None
                return {'ok': res.ok, 'text': res.text, 'object': res_obj}
            except Exception as e:
                demisto.error(str(e))
                raise

    def __prime_set_token_to_cache(self, token):
        demisto.setIntegrationContext({'api_token': token})

    def __prime_get_token_from_cache(self, renew=False):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('api_token')
        #  renew token
        if not access_token or renew:
            token_new = None
            try:
                res = self.__prime_request_token()
                token_new = res.get('token')
            except Exception as e:
                demisto.error(str(e))

            #  if an error to connect with prime and get token
            if not token_new:
                self.__prime_set_cache_keys_to_none('api_token')
                raise Exception(f'Cannot get token from Sepio Prime server at ({self._base_url})')

            self.__prime_set_token_to_cache(token_new)
            return token_new
        return access_token

    def __prime_set_cache_keys_to_none(self, *keys):
        integration_context = demisto.getIntegrationContext()
        for key in keys:
            if key in integration_context:
                integration_context[key] = None
        if integration_context:
            demisto.setIntegrationContext(integration_context)

    @staticmethod
    def __prime_api_auth_headers_format(token):
        return {'Authorization': f'Bearer {token}'}

    @staticmethod
    def __prime_handle_http_response(http_res, url_suffix):
        if http_res.status_code == 400:
            raise Exception(http_res.text)

        if http_res.status_code == 403:  # forbbiden for users with this type of user
            raise Exception('This command can be used only by Sepio Prime '
                            'users with higher user profile')

        if not http_res.ok:
            raise Exception(
                f'Failed to request {url_suffix}, reason: ({http_res.status_code}) {http_res.reason}: {http_res.text}')


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Sepio Prime Events severity to Cortex XSOAR severity

    Converts the SepioPrimeAPI alert severity level ('Debug', 'Notice',
    'Informational', 'Alert', 'Warning', 'Error', 'Emergency', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Sepio Prime event (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    return SEPIO_PRIME_SEVERITY_TO_DEMOISTO_SEVERITY_CONVERT[severity]


def arg_to_int(arg, arg_name, required):
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg, arg_name, required):
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "1 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def validate_fetch_data_max_result(user_results, max_results, arg_name):
    """ Validate and handle cases where the limit of result requested from Sepio Prime API
    is exceeding or not positive value

    :type user_results: ``int``
    :param user_results: maximum results value

    :type max_results: ``int``
    :param max_results: maximum allowed value for results count

    :type arg_name: ``str``
    :param arg_name: argument name for error message

    :return:
        returns an ``int`` of the original max_results value if its ok
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if not user_results or not isinstance(user_results, int) or user_results <= 0 or user_results > max_results:
        raise ValueError(f'{arg_name} must be an integer, in the range between 1 to {max_results}')
    return user_results


def string_contains(original, should_contains_str):
    """Custom string contains method that handales cases where original is None

    :type original: ``str``
    :param original: the string that should contain

    :type should_contains_str: ``str``
    :param should_contains_str: the string that should be contained

    :return:
        returns an ``bool`` that indicates that original contains should_contains_str
        otherwise throws an if original is not None and should_contains_str is None
    :rtype: ``Optional[bool]``
    """

    if should_contains_str and not original:
        return False
    return should_contains_str in original


def string_startswith(original, starts_with_str):
    """Custom string startswith method that handales cases where original is None

    :type original: ``str``
    :param original: the string that should starts with

    :type starts_with_str: ``str``
    :param starts_with_str: the string that should be the begining of original

    :return:
        returns an ``bool`` that indicates that original contains should_contains_str
        otherwise throws an if original is not None and starts_with_str is None
    :rtype: ``Optional[bool]``
    """

    if starts_with_str and not original:
        return False
    return original.startswith(starts_with_str)


def list_of_object_to_list_subset(original, *args):
    """Creates new list of object with only few fields from the original

    :type original: ``List[Dict[str, any]]``
    :param original: original list of objects

    :type args: ``List[str]``
    :param args: list of fields that should be in each new object

    :return:
        returns an ``List[Dict[str, any]]`` that contains only the fields from args
    :rtype: ``List[Dict[str, any]]``
    """

    return [{k: v for k, v in d.items() if k in args} for d in original]


def list_of_objects_to_readable_output(name, items, headers):
    """Creates readable output from list of items

    :type name: ``str``
    :param name: readable output table name

    :type items: ``List[Dict[str, any]]``
    :param items: original list of objects

    :type headers: ``List[Dict[str, any]]``
    :param headers: original list of objects

    :return:
        returns an ``str`` with markdown format
    :rtype: ``str``
    """

    return tableToMarkdown(name, list_of_object_to_list_subset(items, *headers), headers)


def empty_get_result_to_readable_result(readable_output_markdown):
    """Creates readable output for empty reults

    :type readable_output_markdown: ``str``
    :param readable_output_markdown: the readable output markdown

    :return:
        returns an ``[Dict[str, any]`` with result object
    :rtype: ``[Dict[str, any]``
    """

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': [],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output_markdown
    }


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SepioPrimeAPI client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    is_successfull, message = client.prime_test_connection()
    if is_successfull:
        return 'ok'
    return message


def sepio_query_agents_command(client, args):
    """
    Returns CommandResults with all the agents that are in the query args

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        All the agents that are in the query args

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
    """

    host_identifier = args.get('host_identifier')
    ip_address = args.get('ip_address')
    uuid = args.get('uuid')
    has_unapproved_peripherals = args.get('has_unapproved_peripherals')
    has_vulnerable_peripherals = args.get('has_vulnerable_peripherals')
    has_known_attack_tools = args.get('has_known_attack_tools')
    limit = validate_fetch_data_max_result(arg_to_int(args.get('limit', 20), 'limit', False), MAX_RESULTS, 'limit')

    agents = client.prime_get_agents(host_identifier, ip_address, uuid, has_unapproved_peripherals,
                                     has_vulnerable_peripherals, has_known_attack_tools, limit)

    outputs = [{
        'HostIdentifier': agent['hostIdentifier'],
        'IpAddress': agent['localIpAddress'],
        'UUID': agent['uuid'],
        'OsVersion': agent['osVersion'],
        'HardwareModel': agent['pcModel'],
        'NicInfo': agent['nicsText'].split('**') if agent['nicsText'] is not None else None,
        'LastUpdate': agent['lastUpdated'],
        'Status': agent['displayStatusCombined'],
        'HasUnapprovedPeripherals': agent['hasUnapprovedPeripherals'],
        'HasVulnerablePeripherals': agent['hasVulnerablePeripherals'],
        'HasKnownAttackTools': agent['hasKnownAttackTools'],
        'LastConfiguration': agent['lastConfiguered'],
        'Version': agent['serviceVersion'],
        'License': agent['licenseStatus']
    } for agent in agents]

    outputs_headers = ['UUID', 'IpAddress', 'HostIdentifier',
                       'HasUnapprovedPeripherals', 'HasVulnerablePeripherals', 'HasKnownAttackTools']
    readable_output = list_of_objects_to_readable_output('Agents', outputs, outputs_headers)
    return CommandResults(
        outputs_prefix='Sepio.Agent',
        outputs_key_field='UUID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=agents
    ) if outputs else empty_get_result_to_readable_result(readable_output)


def sepio_query_global_peripherals_command(client, args):
    """
    Returns CommandResults with all the agent peripherals that are in the query args

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        All the agents that are in the query args

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
    """

    host_identifier = args.get('host_identifier')
    ip_address = args.get('ip_address')
    host_uuid = args.get('host_uuid')
    vendor_name = args.get('vendor_name')
    product_name = args.get('product_name')
    serial_number = args.get('serial_number')
    is_unapproved_peripheral = args.get('is_unapproved_peripheral')
    is_vulnerable_peripheral = args.get('is_vulnerable_peripheral')
    is_known_attack_tool = args.get('is_known_attack_tool')
    limit = validate_fetch_data_max_result(arg_to_int(args.get('limit', 20), 'limit', False), MAX_RESULTS, 'limit')

    peripherals = client.prime_get_global_peripherals(host_identifier, ip_address, host_uuid,
                                                      vendor_name, product_name, serial_number,
                                                      is_unapproved_peripheral, is_vulnerable_peripheral, is_known_attack_tool,
                                                      limit)

    outputs = [{
        'HostIdentifier': peripheral['hostIdentifier'],
        'HostUUID': peripheral['uuid'],
        'DeviceID': peripheral['deviceID'],
        'DeviceIcon': peripheral['devIcon'],
        'DeviceType': peripheral['devIconDescription'],
        'VID': peripheral['vid'],
        'VendorName': peripheral['guiVid'],
        'PID': peripheral['pid'],
        'ProductName': peripheral['guiPid'],
        'SerialNumber': peripheral['guiSerial'],
        'Status': peripheral['status'],
        'IsUnapprovedPeripheral': not peripheral['approved'],
        'IsVulnerablePeripheral': peripheral['isVulnerablePeripheral'],
        'IsKnownAttackTool': peripheral['isKnownAttackTool']
    } for peripheral in peripherals]

    outputs_headers = ['HostUUID', 'DeviceID', 'Status', 'IsUnapprovedPeripheral', 'IsVulnerablePeripheral', 'IsKnownAttackTool']
    readable_output = list_of_objects_to_readable_output('Peripherals', outputs, outputs_headers)
    return CommandResults(
        outputs_prefix='Sepio.Peripheral((val.HostUUID == obj.HostUUID) && (val.DeviceID == obj.DeviceID))',
        outputs_key_field='',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=peripherals
    ) if outputs else empty_get_result_to_readable_result(readable_output)


def sepio_query_switches_command(client, args):
    """
    Returns CommandResults with all the switches that are in the query args,
    this command is getting all the data from Sepio Prime server and filter and order it locally

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        All the agents that are in the query args

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
    """

    ip_address = args.get('ip_address')
    switch_name = args.get('switch_name')
    model = args.get('model')
    ios_version = args.get('ios_version')
    is_alarmed = args.get('is_alarmed')
    is_alarmed_bool_or_none = argToBoolean(is_alarmed) if is_alarmed is not None else None
    limit = validate_fetch_data_max_result(arg_to_int(args.get('limit', 20), 'limit', False), MAX_RESULTS, 'limit')

    switches = client.prime_get_switches()

    outputs = []
    for switch in switches:

        switch_connection_data = switch['connectionData']
        switch_ip_address = switch_connection_data['ipAddress']
        switch_assigned_name = switch['assignedName']
        switch_model = switch['model']
        switch_ios = switch['ios']
        switch_status = switch['statusDescription']
        switch_is_alarmed = switch_status == 'Alarmed'

        if ((ip_address and not string_contains(switch_ip_address, ip_address))
                or (switch_name and not string_contains(switch_assigned_name, switch_name))
                or (model and not string_startswith(switch_model, model))
                or (ios_version and not string_contains(switch_ios, ios_version))
                or (is_alarmed_bool_or_none is not None and is_alarmed_bool_or_none != switch_is_alarmed)):
            continue

        outputs.append({
            'SwitchID': switch['switchID'],
            'IpAddress': switch_ip_address,
            'Name': switch_assigned_name,
            'Model': switch_model,
            'IosVersion': switch_ios,
            'LastUpdate': switch_connection_data['lastUpdated'],
            'NumberOfPorts': switch['numOfPorts'],
            'Status': switch_status,
            'IsAlarmed': switch_is_alarmed
        })

        if len(outputs) == limit:
            break

    outputs_headers = ['SwitchID', 'Status', 'IsAlarmed']
    readable_output = list_of_objects_to_readable_output('Switches', outputs, outputs_headers)
    return CommandResults(
        outputs_prefix='Sepio.Switch',
        outputs_key_field='SwitchID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=switches
    ) if outputs else empty_get_result_to_readable_result(readable_output)


def sepio_query_switch_ports_command(client, args):
    """
    Returns CommandResults with all the ports that are in the query args

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        All the agents that are in the query args

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
    """

    switch_ip_address = args.get('switch_ip_address')
    switch_name = args.get('switch_name')
    port_id = args.get('port_id')
    port_name = args.get('port_name')
    link_partner_data_contains = args.get('link_partner_data_contains')
    is_alarmed = args.get('is_alarmed')
    limit = validate_fetch_data_max_result(arg_to_int(args.get('limit', 20), 'limit', False), MAX_RESULTS, 'limit')

    ports = client.prime_get_switch_ports(switch_ip_address, switch_name, port_id,
                                          port_name, link_partner_data_contains, is_alarmed,
                                          limit)

    outputs = [{
        'SwitchID': port['switchID'],
        'SwitchIpAddress': port['switchIp'],
        'SwitchName': port['switchName'],
        'PortID': port['portID'],
        'Name': port['assignedName'],
        'LastUpdate': port['switchLastPolled'],
        'NumberOfMacAddresses': port['portMacsDataCount'],
        'LinkPartners': [mac_data['mac'] for mac_data in port['linkPartnerInfo']['portMacsData']],
        'Status': port['portStatusString'],
        'IsAlarmed': port['alarmed'],
        'AlarmInfo': port['identifiedString']
    } for port in ports]

    outputs_headers = ['SwitchID', 'PortID', 'Status', 'IsAlarmed', 'AlarmInfo']
    readable_output = list_of_objects_to_readable_output('Ports', outputs, outputs_headers)
    return CommandResults(
        outputs_prefix='Sepio.Port((val.SwitchID == obj.SwitchID) && (val.PortID == obj.PortID))',
        outputs_key_field='',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=ports
    ) if outputs else empty_get_result_to_readable_result(readable_output)


def sepio_query_system_events_command(client, args):
    """
    Returns CommandResults with all the events that are in the query args

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        All the agents that are in the query args

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
    """

    start_datetime = args.get('start_datetime')
    end_datetime = args.get('end_datetime')
    min_severity = args.get('min_severity')
    category = argToList(args.get('category'))
    source = args.get('source')
    peripheral_type = args.get('peripheral_type')
    limit = validate_fetch_data_max_result(arg_to_int(args.get('limit', 20), 'limit', False), MAX_RESULTS, 'limit')

    events = client.prime_get_events(start_datetime, min_severity, category, limit, end_datetime, source, peripheral_type)

    outputs = [{
        'EventID': event['eventID'],
        'CreationDatetime': event['creationTime'],
        'Severity': event['severityString'],
        'Description': event['description'],
        'Category': event['category'],
        'Source': event['eventEntityID'],
        'PeripheralType': event['peripheralIcon'],
        'Details': event['details']
    } for event in events]

    outputs_headers = ['EventID', 'CreationDatetime', 'Category', 'Source', 'Description']
    readable_output = list_of_objects_to_readable_output('Events', outputs, outputs_headers)
    return CommandResults(
        outputs_prefix='Sepio.Event',
        outputs_key_field='EventID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=events
    ) if outputs else empty_get_result_to_readable_result(readable_output)


def sepio_set_agent_mode_command(client, args):
    """
    Updates agent mode

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        (str) update response
    """

    uuid = args.get('uuid')
    host_identifier = args.get('host_identifier')
    ip_address = args.get('ip_address')
    mode = args.get('mode')

    prime_agent_mode = AGENTS_ARMED_MODE_CONVERT.get(mode)
    if not prime_agent_mode:
        raise ValueError('mode must be one value from ' + ' or '.join(AGENTS_ARMED_MODE_CONVERT.keys()))

    res = client.prime_set_agent_mode(uuid, host_identifier, ip_address, prime_agent_mode)

    return f'Agent [\'{res["object"][0]["uuid"]}\'] mode has been changed successfully to \'{mode}\''


def sepio_set_agent_peripherals_mode_command(client, args):
    """
    Updates agent peripherals mode

    Args:
        client (Client): SepioPrimeAPI client.
        args (dict): all command arguments.

    Returns:
        (str) update response
    """

    uuid = args.get('uuid')
    ip_address = args.get('ip_address')
    host_identifier = args.get('host_identifier')
    vid = args.get('vid')
    pid = args.get('pid')
    mode = args.get('mode')

    prime_agent_peripherals_mode = AGENT_PERIPHERALS_APPROVE_MODE_CONVERT.get(mode)
    if not prime_agent_peripherals_mode:
        raise ValueError('mode must be one value from ' + ' or '.join(AGENT_PERIPHERALS_APPROVE_MODE_CONVERT.keys()))

    res = client.prime_set_agent_peripherals_mode(uuid, host_identifier, ip_address, vid, pid, prime_agent_peripherals_mode)

    return f'Peripherals of [\'{res["object"][0]}\'] with vid \'{vid}\' and pid \'{pid}\' mode changed successfully to \'{mode}\''


def fetch_incidents(client, last_run, first_fetch_time, min_serverity, categories, max_results):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): SepioPrimeAPI client
        last_run (dict): The greatest incident created_time we fetched from last fetch
        first_fetch_time (str): If last_run is None then fetch all incidents since first_fetch_time
        min_serverity (str): Alert minimum severity from which to retrieve. Values are: Warning, Error, Critical
        categories (list): Alert category to retrieve. Values are:USB, Network
        max_results (int): Maximum number of alerts to fetch at a time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """

    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')
    last_fetch_eventid = last_run.get('last_fetch_eventid')

    # Handle first time fetch
    last_fetch_dt = None
    if last_fetch is None:
        last_fetch_dt = dateparser.parse(first_fetch_time)
    else:
        last_fetch_dt = dateparser.parse(last_fetch)

    last_fetch_timestamp = date_to_timestamp(last_fetch_dt)

    #  the number of new incidents for each time is limited
    max_results = validate_fetch_data_max_result(max_results, MAX_RESULTS_EVENTS, 'limit')

    incidents = []
    items = client.prime_get_events(timestamp_to_datestring(last_fetch_timestamp), min_serverity,
                                    categories, max_results, None, None, None, last_fetch_eventid)
    for item in items:
        item['eventSource'] = SEPIO  # constant for mapping
        incident_created_time = dateparser.parse(item['creationTime'])
        incident_created_timestamp = date_to_timestamp(incident_created_time)
        incident = {
            'name': f'[{item["eventSource"]}] ' + item["description"] + ' ' + item["details"],
            'occurred': timestamp_to_datestring(incident_created_timestamp, DATE_FORMAT),
            'rawJSON': json.dumps(item),
            'severity': convert_to_demisto_severity(item.get('severityString', 'Debug'))
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_timestamp > last_fetch_timestamp:
            last_fetch_timestamp = incident_created_timestamp
    if len(items):
        last_fetch_eventid = items[0]["eventID"] + 1
    next_run = {'last_fetch': timestamp_to_datestring(
        last_fetch_timestamp, DATE_FORMAT), 'last_fetch_eventid': last_fetch_eventid}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')

    # get the service API url
    base_url = urljoin(params['url'], '/prime/webui')

    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get('fetch_time', '1 days').strip()

    proxy = params.get('proxy', False)

    # Maximum number of alerts to receive teach run of fetch_incidents
    fetch_incidents_max_alerts = arg_to_int(
        arg=params.get('max_alerts'),
        arg_name='max_alerts',
        required=False
    )

    # Categories for events to be receive in fetch_incidents, the values are USB, Network
    fetch_incidents_categories = argToList(params.get('category'))

    fetch_incidents_min_severity = params.get('min_severity')

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            ok_codes=(200, 201, 204, 400, 401, 403))

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'sepio-query-agents':
            return_results(sepio_query_agents_command(client, demisto.args()))

        elif demisto.command() == 'sepio-query-peripherals':
            return_results(sepio_query_global_peripherals_command(client, demisto.args()))

        elif demisto.command() == 'sepio-query-switches':
            return_results(sepio_query_switches_command(client, demisto.args()))

        elif demisto.command() == 'sepio-query-switch-ports':
            return_results(sepio_query_switch_ports_command(client, demisto.args()))

        elif demisto.command() == 'sepio-query-system-events':
            return_results(sepio_query_system_events_command(client, demisto.args()))

        elif demisto.command() == 'sepio-set-agent-mode':
            return_results(sepio_set_agent_mode_command(client, demisto.args()))

        elif demisto.command() == 'sepio-set-peripherals-mode':
            return_results(sepio_set_agent_peripherals_mode_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                min_serverity=fetch_incidents_min_severity,
                categories=fetch_incidents_categories,
                max_results=fetch_incidents_max_alerts)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
