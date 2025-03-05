import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Any

# Disable insecure warnings
# requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
READABLE_DATE_FORMAT = "%B %d, %Y at %I:%M:%S %p"
API_VERSION = 2
LOGGING_INTEGRATION_NAME = "[VMware Workspace ONE UEM (AirWatch MDM)]"
HTTP_ERROR = {
    401: "An error occurred while validating the credentials, please check the username or password.",
    403: "Invalid API key or the user doesn't have sufficient permissions to perform this operation.",
    404: "The resource cannot be found.",
    407: "Proxy Error - cannot connect to proxy. Either try clearing the 'Use system proxy' check-box or"
    "check the host, authentication details and connection details for the proxy.",
    500: "The server encountered an internal error for VMWare Workspace ONE UEM " "and was unable to complete your request.",
}
ARG_TO_PARAM_OWNERSHIP = {"corporate owned": "C", "employee owned": "E", "shared": "S", "undefined": "undefined"}
REVERSED_ARG_TO_PARAM_OWNERSHIP = {"C": "Corporate owned", "E": "Employee owned", "S": "Shared", "Undefined": "Undefined"}
MESSAGES = {
    "NO_RECORDS_FOUND": "No {} record(s) found for the given argument(s).",
    "INVALID_PAGE_SIZE": "Argument page_size should be greater than 1.",
    "INVALID_PAGE": "Argument page should be greater than 0.",
    "INVALID_OWNERSHIP": "Argument ownership should be one of the following: "
    "Corporate owned, Employee owned, Shared, or Undefined.",
    "INVALID_SORT_ORDER": "Argument sort_order should be one of the following: ASC, or DESC.",
    "REQUIRED_ARGUMENT": "{} is a required argument.",
    "INVALID_COMPLIANCE_STATUS": "Argument compliance_status should be one of the following: true, or false.",
}
CONSTANT_STRING = {
    "DEVICE_FRIENDLY": "Device Friendly Name",
    "SERIAL_NUM": "Serial Number",
    "MAC_ADDR": "MAC Address",
    "COMPLIANCE_STATUS": "Compliance Status",
    "USER_EMAIL": "User Email Address",
    "LAST_SEEN": "Last Seen (In UTC)",
}
""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, username, password, base_url, headers, verify=True, proxy=False):
        """
        Store username and password for authentication.

        :type username: ``string``
        :param username: username of salesforce account

        :type password: ``string``
        :param password: password of salesforce account

        :type base_url: ``string``
        :param base_url: service API url.

        :type headers: ``dict``
        :param headers: The request headers, for example: {'Accept`: `application/json`}.

        :type verify: ``bool``
        :param verify: SSL verification is handled out of the box.

        :type proxy: ``bool``
        :param proxy: system proxy is handled out of the box.
        """

        super().__init__(base_url=base_url, auth=(username, password), headers=headers, verify=verify, proxy=proxy)

    def http_request(self, *args, **kwargs) -> requests.Response:
        """
        Overrides the _http_request method of base class and authenticate using bearer token generated from
        session id which is cached in IntegrationContext
        """

        kwargs["ok_codes"] = (200, 201, 204)
        kwargs["error_handler"] = self.exception_handler
        kwargs["resp_type"] = "response"
        return super()._http_request(*args, **kwargs)

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code of response.
        """

        err_msg = ""
        if response.status_code in HTTP_ERROR:
            if response.status_code in [401, 403]:
                demisto.error(f"{LOGGING_INTEGRATION_NAME} {response.json()}")
            err_msg = HTTP_ERROR[response.status_code]
        elif response.status_code > 500:
            err_msg = HTTP_ERROR[500]
        elif response.status_code not in HTTP_ERROR:
            err_msg = "Error in API call [{}] - {}".format(response.status_code, response.reason)
            headers = response.headers
            if "application/json" in headers.get("Content-Type", ""):
                error_entry = response.json()
                if error_entry.get("message"):
                    err_msg = "{}".format(error_entry.get("message"))

        raise DemistoException(err_msg)


""" HELPER FUNCTIONS """


def remove_empty_elements_for_context(src):
    """
     Recursively remove empty lists, empty dicts, empty string or None elements from a dictionary.

    :type src: ``dict``
    :param src: Input dictionary.

    :return: Dictionary with all empty lists,empty string and empty dictionaries removed.
    :rtype: ``dict``
    """

    def empty(x):
        return x is None or x == "" or x == {} or x == []

    if not isinstance(src, dict | list):
        return src
    elif isinstance(src, list):
        return [v for v in (remove_empty_elements_for_context(v) for v in src) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_for_context(v)) for k, v in src.items()) if not empty(v)}


def validate_uuid_argument(args: dict) -> str:
    """
    To validate argument uuid.

    :type args: ``dict``
    :param args: dictionary returned by demisto.args

    :return: validated arguments.
    :rtype: ``str``
    """
    if not args.get("uuid"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("uuid"))

    return args.get("uuid")  # type: ignore


def camel_to_pascal(src: dict) -> dict:
    """
    Convert the keys of a nested dictionary and list from camel case to pascal case.

    :type src: ``dict``
    :param src: the dictionary whose keys require change in case
    :return: a dictionary with the keys changed from camel case to pascal case
    """
    if not isinstance(src, dict | list):
        return src
    return_src = {}

    def capitalize_first_letter(string: str) -> str:
        """
        Capitalize only the first letter of a string
        :param string: string whose first letter needs to be capitalized
        :return: string with first letter capitalized
        """
        return string[0].upper() + string[1:]

    if isinstance(src, list):
        return_src = [camel_to_pascal(obj) for obj in src]
        return return_src

    for key, value in src.items():
        if isinstance(value, dict | list):
            return_src[capitalize_first_letter(key)] = camel_to_pascal(value)  # type: ignore
        else:
            return_src[capitalize_first_letter(key)] = value
    return return_src


def prepare_context_hr_os_updates_list_command(result: dict, uuid: str) -> tuple[Union[dict, list[dict]], str]:
    """
    To prepare context and human readable output for vmwuem_device_os_updates_list_command.

    :type result: ``dict``
    :param result: dictionary returned by api response of vmwuem_device_os_updates_list_command.

    :type uuid: ``str``
    :param uuid: argument of vmwuem_device_os_updates_list_command.

    :return: Context and human readable output.
    :rtype: ``Tuple[Dict, str]``
    """
    result = remove_empty_elements_for_context(result)  # type: ignore
    result["OSUpdateList"] = camel_to_pascal(result["OSUpdateList"])
    result["Uuid"] = uuid.lower()
    context_data = result
    hr = []
    for osupdate in result["OSUpdateList"]:
        release_date = osupdate.get("ReleaseDate", "")
        expiration_date = osupdate.get("ExpiationDate", "")
        if release_date:
            release_date = dateparser.parse(release_date).strftime(READABLE_DATE_FORMAT)  # type: ignore
        if expiration_date:
            expiration_date = dateparser.parse(expiration_date).strftime(READABLE_DATE_FORMAT)  # type: ignore
        data = {
            "Device UUID": result["Uuid"],
            "Update Name": osupdate.get("DeviceUpdateName", ""),
            "Update Version": osupdate.get("DeviceUpdateVersion", ""),
            "Critical Update": "Yes" if osupdate.get("IsCritical", False) else "No",
            "Restart Required": "Yes" if osupdate.get("RestartRequired", False) else "No",
            "Release Date": release_date,
            "Expiration Date": expiration_date,
        }
        hr.append(data)

    headers = [
        "Device UUID",
        "Update Name",
        "Update Version",
        "Critical Update",
        "Restart Required",
        "Release Date",
        "Expiration Date",
    ]
    hr_output = tableToMarkdown("OSUpdate(s)", hr, headers=headers, removeNull=True)

    return context_data, hr_output


def strip_args(args: dict):
    """
    Strips argument dictionary values of spaces

    :type args: dict
    :param args: argument dictionary
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()


def is_present_in_list(value_to_check: Any, list_to_check_in: list[Any], message: str) -> bool | None:
    """
    Checks for presence of value in list, raises ValueError, if the value is not present

    :type value_to_check: ``Any``
    :param value_to_check: value to check presence of
    :type list_to_check_in: ``List[Any]``
    :param list_to_check_in: list to check the presence of value
    :type message: ``str``
    :param message: message with which the ValueError will be raised with

    :rtype: ``bool``
    :returns: True, if the value is present
    """
    if value_to_check not in list_to_check_in:
        raise ValueError(message)
    return True


def prepare_context_and_hr_for_devices_search(response: dict) -> tuple[Union[dict, list[dict]], str]:
    """
    Prepare entry context and human readable for devices search command

    :type response: ``dict``
    :param response: dictionary json response from search api

    :rtype: ``Tuple[list, str]``
    :return: tuple of dict entry context and str human readable
    """
    context = response.get("Devices", [])
    hr_devices_list = []
    for device in context:
        last_seen = device.get("LastSeen", "")
        if last_seen:
            last_seen = dateparser.parse(last_seen).strftime(READABLE_DATE_FORMAT)  # type: ignore

        compromised = device.get("CompromisedStatus", "")
        compromised = "Unknown" if isinstance(compromised, str) else "Compromised" if compromised else "Not Compromised"

        ownership = device.get("Ownership", "")
        ownership = REVERSED_ARG_TO_PARAM_OWNERSHIP[ownership] if ownership in REVERSED_ARG_TO_PARAM_OWNERSHIP else ""

        hr_devices_list.append(
            {
                CONSTANT_STRING["DEVICE_FRIENDLY"]: device.get(CONSTANT_STRING["DEVICE_FRIENDLY"].replace(" ", ""), ""),
                "UUID": device.get("Uuid", ""),
                "Platform": device.get("Platform", ""),
                "Model": device.get("Model", ""),
                "Ownership": ownership,
                CONSTANT_STRING["SERIAL_NUM"]: device.get(CONSTANT_STRING["SERIAL_NUM"].replace(" ", ""), ""),
                CONSTANT_STRING["MAC_ADDR"]: device.get("MacAddress", ""),
                CONSTANT_STRING["COMPLIANCE_STATUS"]: device.get("ComplianceStatus", ""),
                "Compromised Status": compromised,
                CONSTANT_STRING["USER_EMAIL"]: device.get("UserEmailAddress", ""),
                CONSTANT_STRING["LAST_SEEN"]: last_seen,
            }
        )
    hr = tableToMarkdown(
        "Device(s)",
        hr_devices_list,
        [
            CONSTANT_STRING["DEVICE_FRIENDLY"],
            "UUID",
            "Platform",
            "Model",
            "Ownership",
            CONSTANT_STRING["SERIAL_NUM"],
            CONSTANT_STRING["MAC_ADDR"],
            CONSTANT_STRING["COMPLIANCE_STATUS"],
            "Compromised Status",
            CONSTANT_STRING["USER_EMAIL"],
            CONSTANT_STRING["LAST_SEEN"],
        ],
        removeNull=True,
    )

    return remove_empty_elements_for_context(context), hr


def validate_and_parameterize_devices_search_arguments(args: dict) -> dict:
    """
    Convert arguments to parameter for command vmwuem-devices-search command, raise ValueError with
    appropriate message

    :type args: ``dict``
    :param args: dictionary returned by demisto.args()

    :rtype: ``dict``
    :return: dictionary parameters for http request
    """
    params = {
        "user": args.get("user"),
        "model": args.get("model"),
        "platform": args.get("platform"),
        "lgid": args.get("lgid"),
        "orderby": args.get("order_by"),
    }
    params = remove_empty_elements(params)
    if args.get("ownership"):
        ownership = args.get("ownership", "").lower()  # type: ignore
        is_present_in_list(ownership, list(ARG_TO_PARAM_OWNERSHIP.keys()), MESSAGES["INVALID_OWNERSHIP"])
        params["ownership"] = ARG_TO_PARAM_OWNERSHIP[ownership]

    # Validate date-time params
    if args.get("last_seen"):
        params["lastseen"] = arg_to_datetime(args.get("last_seen"), "last_seen").strftime(DATE_FORMAT)  # type: ignore

    # Validate paging and sorting params
    if args.get("page_size"):
        page_size = arg_to_number(args.get("page_size", "10"), "page_size")
        if page_size < 1:  # type: ignore
            raise ValueError(MESSAGES["INVALID_PAGE_SIZE"])
        params["pagesize"] = page_size

    if args.get("page"):
        page = arg_to_number(args.get("page"), "page")
        if page < 0:  # type: ignore
            raise ValueError(MESSAGES["INVALID_PAGE"])
        params["page"] = page

    if args.get("sort_order"):
        sort_order = args.get("sort_order").upper()  # type: ignore
        is_present_in_list(sort_order, ["ASC", "DESC"], MESSAGES["INVALID_SORT_ORDER"])
        params["sortorder"] = sort_order

    return params


def prepare_context_and_hr_for_devices_get(response: dict) -> tuple[dict, str]:
    """
    Prepare entry context and human readable for device get command

    :type response: ``dict``
    :param response: dictionary json response from get api

    :rtype: ``Tuple[dict, str]``
    :return: tuple of dict entry context and str human readable
    """
    enrollment_info = response.get("enrollmentInfo", {})

    compliance = enrollment_info.get("compliant", "")
    compliance = "Unknown" if isinstance(compliance, str) else "Compliant" if compliance else "Non-Compliant"

    last_seen = enrollment_info.get("lastSeenTimestamp", "")
    if last_seen:
        last_seen = dateparser.parse(last_seen).strftime(READABLE_DATE_FORMAT)  # type: ignore

    hr_dict = {
        CONSTANT_STRING["DEVICE_FRIENDLY"]: response.get("friendlyName", ""),
        "UUID": response.get("uuid", ""),
        "Platform": response.get("platformInfo", {}).get("platformName", ""),
        "Model": response.get("platformInfo", {}).get("modelName"),
        "Ownership": enrollment_info.get("ownership", ""),
        CONSTANT_STRING["SERIAL_NUM"]: response.get("serialNumber", ""),
        CONSTANT_STRING["MAC_ADDR"]: response.get("macAddress", ""),
        CONSTANT_STRING["COMPLIANCE_STATUS"]: compliance,
        CONSTANT_STRING["USER_EMAIL"]: enrollment_info.get("userEmailAddress", ""),
        CONSTANT_STRING["LAST_SEEN"]: last_seen,
    }
    hr = tableToMarkdown(
        "Device",
        hr_dict,
        [
            CONSTANT_STRING["DEVICE_FRIENDLY"],
            "UUID",
            "Platform",
            "Model",
            "Ownership",
            CONSTANT_STRING["SERIAL_NUM"],
            CONSTANT_STRING["MAC_ADDR"],
            CONSTANT_STRING["COMPLIANCE_STATUS"],
            CONSTANT_STRING["USER_EMAIL"],
            CONSTANT_STRING["LAST_SEEN"],
        ],
        removeNull=True,
    )
    return remove_empty_elements_for_context(camel_to_pascal(response)), hr


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.http_request(method="GET", url_suffix="devices/search")
    return "ok"


def vmwuem_devices_search_command(client: Client, args: dict) -> CommandResults:
    """
    Searches devices using the search API according to the arguments

    :type client: ``Client``
    :param client: client to use
    :type args: ``dict``
    :param args: arguments from demisto.args

    :return: Command results containing the outputs and context.
    :rtype: ``CommandResults``
    """
    # Prepare parameters for request
    args = remove_empty_elements(args)
    params = validate_and_parameterize_devices_search_arguments(args)

    # Make the call.
    response = client.http_request(method="GET", url_suffix="devices/search", params=params)

    if not response.text:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("device"))

    # Prepare context and human readable
    json_response = response.json()
    outputs, readable_output = prepare_context_and_hr_for_devices_search(json_response)
    return CommandResults(
        outputs_prefix="VMwareWorkspaceONEUEM.Device",
        outputs_key_field="Uuid",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=json_response,
    )


def vmwuem_device_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a device using get device endpoint according to given uuid.

    :type client: ``Client``
    :param client: client to use
    :type args: ``dict``
    :param args: dictionary returned by demisto.args

    :return: configured command result object containing the outputs and hr.
    :rtype: ``CommandResults``
    """
    # Validate uuid argument.
    uuid = validate_uuid_argument(args)

    response = client.http_request(method="GET", url_suffix=f"devices/{uuid}")

    # Prepare context and human readable
    json_response = response.json()
    outputs, readable_output = prepare_context_and_hr_for_devices_get(json_response)
    return CommandResults(
        outputs_prefix="VMwareWorkspaceONEUEM.Device",
        outputs_key_field="Uuid",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=json_response,
    )


def vmwuem_device_os_updates_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of all available OS and software updates for the specified device.

    :type client: ``Client``
    :param client: client to use

    :type args: ``dict``
    :param args: dictionary returned by demisto.args

    :return: configured command result object containing the outputs and hr.
    :rtype: ``CommandResults``
    """
    # validating arguments
    uuid = validate_uuid_argument(args)

    response = client.http_request(method="GET", url_suffix=f"devices/{uuid}/osupdate")
    result = response.json()

    if not result.get("OSUpdateList", []):
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("osupdate(s)"))

    # prepare context and human readable
    context_data, hr_output = prepare_context_hr_os_updates_list_command(result, uuid)

    return CommandResults(
        outputs_prefix="VMwareWorkspaceONEUEM.OSUpdate",
        outputs_key_field="Uuid",
        outputs=context_data,
        readable_output=hr_output,
        raw_response=result,
    )


""" MAIN FUNCTION """


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    dict_param = demisto.params()
    dict_args = demisto.args()
    strip_args(dict_args)

    command = demisto.command()

    # get the username and password for authentication
    username = dict_param.get("credentials")["identifier"].strip()
    password = dict_param.get("credentials")["password"]

    api_key = dict_param.get("aw_tenant_code_creds", {}).get("password") or dict_param.get("aw_tenant_code")

    # get the service API url
    base_url = urljoin(dict_param["url"], "/API/mdm/")

    verify_certificate = False
    proxy = dict_param.get("proxy", False)

    demisto.debug(f"{LOGGING_INTEGRATION_NAME} Command being called is {command}")
    try:
        headers: dict = {"aw-tenant-code": f"{api_key}", "Accept": f"application/json;version={API_VERSION}"}

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy, username=username, password=password
        )

        commands = {
            "vmwuem-devices-search": vmwuem_devices_search_command,
            "vmwuem-device-get": vmwuem_device_get_command,
            "vmwuem-device-os-updates-list": vmwuem_device_os_updates_list_command,
        }
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, dict_args))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
