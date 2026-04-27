import traceback
from typing import Any

import copy
import dateparser
import demistomock as demisto
from enum import Enum
import requests
import urllib3
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """
POST_HEADERS = {"Content-Type": "application/xml", "Accept": "application/xml"}

GET_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
MAX_PAGE_SIZE = 200

INTEGRATION_NAME = "JAMF v2"
AUTHENTICATION_PARAMS_ERROR = "Please provide either client_id and client_secret or username and password."


class ComputersInventorySection(str, Enum):
    """
    Represents the valid subsections of a computer inventory record in the Pro API.
    """

    GENERAL = "GENERAL"
    HARDWARE = "HARDWARE"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    USER_AND_LOCATION = "USER_AND_LOCATION"
    PURCHASING = "PURCHASING"
    DISK_ENCRYPTION = "DISK_ENCRYPTION"
    SECURITY = "SECURITY"
    SOFTWARE_UPDATES = "SOFTWARE_UPDATES"
    APPLICATIONS = "APPLICATIONS"
    STORAGE = "STORAGE"
    CONFIGURATION_PROFILES = "CONFIGURATION_PROFILES"
    PRINTERS = "PRINTERS"
    SERVICES = "SERVICES"
    LOCAL_USER_ACCOUNTS = "LOCAL_USER_ACCOUNTS"
    CERTIFICATES = "CERTIFICATES"
    ATTACHMENTS = "ATTACHMENTS"
    PACKAGE_RECEIPTS = "PACKAGE_RECEIPTS"
    LICENSED_SOFTWARE = "LICENSED_SOFTWARE"
    IBEACONS = "IBEACONS"
    EXTENSION_ATTRIBUTES = "EXTENSION_ATTRIBUTES"
    CONTENT_CACHING = "CONTENT_CACHING"
    GROUP_MEMBERSHIPS = "GROUP_MEMBERSHIPS"

    @classmethod
    def list_values(cls) -> list[str]:
        """
        Retrieves all valid enum values as a list of strings.

        Returns:
            list[str]: A list containing the string values of all inventory sections.
        """
        return [section.value for section in cls]

    @classmethod
    def subset_to_sections(cls, subset: str) -> list[str]:
        """
        Maps a Classic API 'subset' parameter to one or more Pro API inventory sections.

        This helper facilitates backward compatibility by translating legacy subset names
        into the granular sections required by the Jamf Pro API computer inventory endpoint.

        Args:
            subset (str): The Classic API subset name (e.g., 'software', 'location').

        Returns:
            list[str]: A list of corresponding ComputersInventorySection values.

        Raises:
            DemistoException: If the subset is unsupported in the Pro API
                (e.g., 'peripherals', 'iphones').
        """

        UNSUPPORTED = {"peripherals", "iphones"}
        SUBSET_MAP = {
            "general": [
                ComputersInventorySection.GENERAL.value,
                ComputersInventorySection.HARDWARE.value,
            ],
            "location": [ComputersInventorySection.USER_AND_LOCATION.value],
            "purchasing": [ComputersInventorySection.PURCHASING.value],
            "hardware": [
                # some elements were moved into other sections,
                #   this collection of sections should cover the old Hardware subset.
                ComputersInventorySection.HARDWARE.value,
                ComputersInventorySection.OPERATING_SYSTEM.value,
                ComputersInventorySection.SECURITY.value,
                ComputersInventorySection.DISK_ENCRYPTION.value,
                ComputersInventorySection.STORAGE.value,
            ],
            "certificates": [ComputersInventorySection.CERTIFICATES.value],
            "security": [ComputersInventorySection.SECURITY.value],
            "software": [
                # does not have a one-to-one mapping,
                #   this collection of sections should cover the old Software subset.
                ComputersInventorySection.LICENSED_SOFTWARE.value,
                ComputersInventorySection.SOFTWARE_UPDATES.value,
                ComputersInventorySection.PACKAGE_RECEIPTS.value,
                ComputersInventorySection.SERVICES.value,
                ComputersInventorySection.APPLICATIONS.value,
            ],
            "extensionattributes": [ComputersInventorySection.EXTENSION_ATTRIBUTES.value],
            "groupsaccounts": [
                # some elements were moved into other sections,
                #   this collection of sections should cover the old GroupsAccounts subset.
                ComputersInventorySection.GROUP_MEMBERSHIPS.value,
                ComputersInventorySection.LOCAL_USER_ACCOUNTS.value,
            ],
            "configurationprofiles": [ComputersInventorySection.CONFIGURATION_PROFILES.value],
        }

        subset_lower = subset.lower()

        if subset_lower in UNSUPPORTED:
            raise DemistoException(f"Subset {subset} is not supported in the Pro API. Please use the Classic API.")

        sections = SUBSET_MAP.get(subset_lower)
        if not sections:
            raise DemistoException(f"Subset {subset} is not supported.")

        return sections

    @classmethod
    def section_to_response_key(cls, section: "ComputersInventorySection") -> str:
        """
        Transforms a ComputersInventorySection to its corresponding key in the API response.

        This helper converts the SCREAMING_SNAKE_CASE enum values into the lowerCamelCase
        format required by the Jamf Pro API JSON response body.

        Args:
            section (ComputersInventorySection): The enum member representing the
                inventory subsection.

        Returns:
            str: The lowerCamelCase string representation (e.g., 'operatingSystem').

        Raises:
            AttributeError: If the provided section is not a valid
                ComputersInventorySection member.
        """
        return camelize_string(section.value, delim="_", upper_camel=False)


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        verify: bool,
        username: str = "",
        password: str = "",
        proxy: bool = False,
        token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        auth: str | None | tuple[str, str] = None,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth = auth

        # Basic authentication is deprecated in classical API versions 10.35 and above,
        # therefore, serving only as a fallback if token generation fails.
        try:
            self.token = self._get_token()
            self._headers = {"Authorization": f"Bearer {self.token}"}
            add_sensitive_log_strs(self.token)

        except DemistoException as e:
            demisto.info(str(e))
            demisto.info("Couldn't create token will proceed using basic auth")
            # if token is not available, use basic auth directly if username and password are provided
            self.auth = (self.username, self.password) if self.username and self.password else None

    def _get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid.
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        token = integration_context.get("token", "")
        valid_until = integration_context.get("expires")

        now_timestamp = arg_to_datetime("now").timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until and now_timestamp < valid_until:
            return token

        # else generate a token and update the integration context accordingly
        token = self._generate_token()

        return token

    def _generate_token(self) -> str:
        """
        Generates new token and updates the integration context.
        """
        if self.username and self.password:  # basic auth is used to create a token
            token, expiration_time = self.generate_basic_auth_token()

        elif self.client_id and self.client_secret:  # client id and client secret are used to create a token
            token, expiration_time = self.generate_client_credentials_token()
        else:
            raise ValueError(
                "Invalid authentication configuration."
                "Please provide either username and password or client id and client secret."
            )

        integration_context = get_integration_context()
        integration_context.update({"token": token})
        # subtract 60 seconds from the expiration time to make sure the token is still valid
        integration_context.update({"expires": expiration_time - 60})
        set_integration_context(integration_context)

        return token

    def generate_basic_auth_token(self) -> tuple[str, int]:
        """
        Generates a token using basic authentication.
        """
        resp = self._http_request(
            method="POST", url_suffix="api/v1/auth/token", resp_type="json", auth=(self.username, self.password)
        )
        token = resp.get("token")
        expiration_time = int(dateparser.parse(resp.get("expires")).timestamp())  # type: ignore
        return token, expiration_time

    def generate_client_credentials_token(self) -> tuple[str, int]:
        """
        Generates a token using client credentials.
        """
        resp = self._http_request(
            method="POST",
            url_suffix="/api/v1/oauth/token",
            data={"client_id": self.client_id, "grant_type": "client_credentials", "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            resp_type="json",
        )
        token = resp.get("access_token")
        now_timestamp = arg_to_datetime("now").timestamp()  # type:ignore
        expiration_time = now_timestamp + resp.get("expires_in")
        return token, expiration_time

    def _classic_api_post(self, url_suffix, data, error_handler):
        # If using a token, it will be available in the headers. If token creation failed, the basic auth is found in self.auth.
        post_headers = (self._headers or {}) | POST_HEADERS  # merge the token and the POST headers
        classic_url_suffix = urljoin("/JSSResource", url_suffix)  # classic API endpoints starts with JSSResource
        return self._http_request(
            method="POST",
            data=data,
            url_suffix=classic_url_suffix,
            headers=post_headers,
            resp_type="response",
            error_handler=error_handler,
            auth=self.auth,
        )

    def _classic_api_get(self, url_suffix, error_handler=None):
        get_headers = (self._headers or {}) | GET_HEADERS  # merge the token and the GET headers
        classic_url_suffix = urljoin("/JSSResource", url_suffix)  # classic API endpoints starts with JSSResource
        return self._http_request(
            method="GET", url_suffix=classic_url_suffix, headers=get_headers, error_handler=error_handler, auth=self.auth
        )

    def _pro_api_get(self, url_suffix: str, params: dict[str, Any] | None = None, error_handler: Any = None) -> dict[str, Any]:
        """Helper method for making GET requests to the Jamf Pro API (v3).

        Args:
            url_suffix (str): The URL suffix to append to the base Pro API URL.
            params (dict[str, Any] | None): Query parameters for the request.
            error_handler (Any): Optional error handler for the request.

        Returns:
            dict[str, Any]: The JSON response from the API.
        """
        get_headers = (self._headers or {}) | GET_HEADERS  # merge the token and the GET headers
        pro_url_suffix = urljoin("/api/v3", url_suffix)
        return self._http_request(
            method="GET",
            url_suffix=pro_url_suffix,
            headers=get_headers,
            params=params,
            error_handler=error_handler,
        )

    def get_computers_inventory_request(
        self,
        sections: list[str] | None = None,
        limit: int = 50,
        page: int = 0,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve the computers inventory results from Pro API.

        Args:
            sections (list[str] | None): List of sections to retrieve.
            limit (int): Maximum number of results per page.
            page (int): Page number.
            filter_query (str | None): Filter query for the Pro API.

        Returns:
            dict[str, Any]: Computers response from API.
        """
        params: dict[str, Any] = {"page": page, "page-size": limit}
        if sections:
            params["section"] = sections
        if filter_query:
            params["filter"] = filter_query

        demisto.debug(f"Sending a Pro API /computers-inventory request with params: {params}")

        return self._pro_api_get(url_suffix="/computers-inventory", params=params, error_handler=self._generic_error_handler)

    def get_computer_inventory_detail_request(self, computer_id: str) -> dict[str, Any]:
        """Retrieve all inventory sections for a specific computer record from Pro API.

        Args:
            computer_id (str): The computer id.

        Returns:
            dict[str, Any]: A dictionary containing all available inventory sections for the specified computer.
        """
        demisto.debug(f"Sending a Pro API /computers-inventory-details/{computer_id} request.")

        return self._pro_api_get(
            url_suffix=f"/computers-inventory-detail/{computer_id}",
            error_handler=self._generic_error_handler,
        )

    def get_computer_subset_deprecated_request(self, identifier: str, identifier_value: str, subset: str):
        """Retrieve the computer subset results.
        Args:
            identifier: The identifier to search computer.
            identifier_value: The value of the identifier.
            subset: Subset to search for.
        Returns:
            Computer subset response from API.
        """

        url_suffix = f"/computers/{identifier}/{identifier_value}/subset/{subset}"
        res = self._classic_api_get(url_suffix=url_suffix, error_handler=self._generic_error_handler)

        return res

    @staticmethod
    def _generic_error_handler(res):
        err_msg = BeautifulSoup(res.text)
        err_msg_body = err_msg.body.text if err_msg.body else err_msg.title

        if res.status_code == 400:
            raise DemistoException(f"Bad request. Origin response from server: {err_msg_body}")

        if res.status_code == 401:
            raise DemistoException(f"Unauthorized. Origin response from server: {err_msg_body}")

        if res.status_code == 403:
            raise DemistoException(f"Invalid permissions. Origin response from server: {err_msg_body}")

        if res.status_code == 404:
            raise DemistoException(
                f"The server has not found anything matching the request URI. Origin response from server: {err_msg_body}"
            )
        if res.status_code == 500:
            raise DemistoException(f"Internal server error. Origin response from server: {err_msg_body}")

        if res.status_code == 502:
            raise DemistoException(f"Bad gateway. Origin response from server: {err_msg.title}")

    def computer_lock_request(self, computer_id: str, passcode: str, lock_message: str = None):
        """
        API link: https://www.jamf.com/developers/apis/classic/reference/#/computercommands/createComputerCommandByCommand
        """
        uri = "/computercommands/command/DeviceLock"
        request_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            + "<computer_command>"
            + "<general>"
            + f"<passcode>{passcode}</passcode>"
            + f"<lock_message>{lock_message}</lock_message>"
            + "</general>"
            + "<computers>"
            + "<computer>"
            + f"<id>{computer_id}</id>"
            + "</computer>"
            + "</computers>"
            + "</computer_command>"
        )

        res = self._classic_api_post(data=request_body, url_suffix=uri, error_handler=self._computer_lock_erase_error_handler)

        json_res = json.loads(xml2json(res.content))
        return json_res

    @staticmethod
    def _computer_lock_erase_error_handler(res):
        err_msg = BeautifulSoup(res.text)
        err_msg = str(err_msg.body.text) if err_msg.body else str(err_msg.title)
        if res.status_code == 400 and "Unable to match computer" in res.text:
            raise DemistoException(f"ID doesn't exist. Origin error from server: {err_msg}")
        if res.status_code == 400 and "is not managed" in res.text:
            raise DemistoException(f"Device is unmanaged. Origin error from server: {err_msg}")

    def computer_erase_request(self, computer_id: str, passcode: str):
        """
        API link: https://www.jamf.com/developers/apis/classic/reference/#/computercommands/createComputerCommandByCommand
        """
        uri = "/computercommands/command/EraseDevice"
        request_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            + "<computer_command>"
            + "<general>"
            + "<command> EraseDevice </command>"
            + f"<passcode>{passcode}</passcode>"
            + "</general>"
            + "<computers>"
            + "<computer>"
            + f"<id>{computer_id}</id>"
            + "</computer>"
            + "</computers>"
            + "</computer_command>"
        )

        res = self._classic_api_post(data=request_body, url_suffix=uri, error_handler=self._computer_lock_erase_error_handler)

        raw_action = json.loads(xml2json(res.content))
        return raw_action

    def get_users_request(self, user_id: str = None, name: str = None, email: str = None):
        """Get users.
        Args:
            user_id: The user id.
            name: The name of the user.
            email: The email of the user.
        Returns:
            Get users response from API.
        """

        uri = "/users"
        if user_id:
            res = self._classic_api_get(url_suffix=f"{uri}/id/{user_id}", error_handler=self._generic_error_handler)
        elif name:
            res = self._classic_api_get(url_suffix=f"{uri}/name/{name}", error_handler=self._generic_error_handler)
        elif email:
            res = self._classic_api_get(url_suffix=f"{uri}/email/{email}", error_handler=self._generic_error_handler)
        else:
            res = self._classic_api_get(url_suffix=f"{uri}", error_handler=self._generic_error_handler)

        return res

    def get_mobile_devices_request(self, mobile_id: str = None, match: str = None):
        """Get mobile devices.
        Args:
            mobile_id: The user id.
            match: Match mobile devices by specific characteristics.
        Returns:
            Get mobile devices response from API.
        """

        uri = "/mobiledevices"
        if mobile_id:
            res = self._classic_api_get(url_suffix=f"{uri}/id/{mobile_id}", error_handler=self._generic_error_handler)
        elif match:
            res = self._classic_api_get(url_suffix=f"{uri}/match/{match}", error_handler=self._generic_error_handler)
        else:
            res = self._classic_api_get(url_suffix=f"{uri}", error_handler=self._generic_error_handler)

        return res

    def get_mobile_devices_subset_request(self, identifier: str, identifier_value: str, subset: str):
        """Retrieve the mobile device subset results.
        Args:
            identifier: The identifier to search mobile device.
            identifier_value: The value of the identifier.
            subset: Subset to search for.
        Returns:
            Mobile device subset response from API.
        """

        url_suffix = f"/mobiledevices/{identifier}/{identifier_value}/subset/{subset}"
        res = self._classic_api_get(url_suffix=url_suffix, error_handler=self._generic_error_handler)
        return res

    def get_computers_by_app_request(self, app: str, version: str = None):
        """Get computers by application.
        Args:
            app: The name of the application.
            version: The version of the application.
        Returns:
            Get computer by application response from API.
        """

        url_suffix = f"/computerapplications/application/{app}"
        if version:
            res = self._classic_api_get(url_suffix=f"{url_suffix}/version/{version}")
        else:
            res = self._classic_api_get(url_suffix=url_suffix)

        return res

    @staticmethod
    def _mobile_lost_erase_error_handler(res):
        err_msg = BeautifulSoup(res.text)
        err_msg = str(err_msg.body.text) if err_msg.body else str(err_msg.title)
        if res.status_code == 400 and "Unable to match mobile device" in res.text:
            raise DemistoException(f"Unable to match mobile device. Origin error from server: {err_msg}")
        if res.status_code == 400 and "not support" in res.text:
            raise DemistoException(f"The device does not support lost mode. Origin error from server: {err_msg}")

    def mobile_device_lost_request(self, mobile_id: str, lost_message: str = None):
        """
        API link: https://www.jamf.com/developers/apis/classic/reference/#/mobiledevicecommands/createMobileDeviceCommand
        """

        uri = "/mobiledevicecommands/command/DeviceLock"
        request_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            + "<mobile_device_command>"
            + "<general>"
            + "<command>EnableLostMode</command>"
            + f"<lost_mode_message>{lost_message}</lost_mode_message>"
            + "</general>"
            + "<mobile_devices>"
            + "<mobile_device>"
            + f"<id>{mobile_id}</id>"
            + "</mobile_device>"
            + "</mobile_devices>"
            + "</mobile_device_command>"
        )

        res = self._classic_api_post(data=request_body, url_suffix=uri, error_handler=self._mobile_lost_erase_error_handler)

        json_response = json.loads(xml2json(res.content))
        return json_response

    def mobile_device_erase_request(
        self, mobile_id: str = None, preserve_data_plan: bool = False, clear_activation_code: bool = False
    ):
        """
        API link: https://www.jamf.com/developers/apis/classic/reference/#/mobiledevicecommands/createMobileDeviceCommand
        """

        uri = "/mobiledevicecommands/command/EraseDevice"
        request_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            + "<mobile_device_command>"
            + "<general>"
            + "<command>EraseDevice</command>"
            + f"<preserve_data_plan>{preserve_data_plan}</preserve_data_plan>"
            + f"<clear_activation_code>{clear_activation_code}</clear_activation_code>"
            + "</general>"
            + "<mobile_devices>"
            + "<mobile_device>"
            + f"<id>{mobile_id}</id>"
            + "</mobile_device>"
            + "</mobile_devices>"
            + "</mobile_device_command>"
        )

        res = self._classic_api_post(data=request_body, url_suffix=uri, error_handler=self._mobile_lost_erase_error_handler)

        json_response = json.loads(xml2json(res.content))
        return json_response

    def get_mobiledeviceconfigurationprofiles_by_id(self, jamf_id):
        """
        API link: https://developer.jamf.com/jamf-pro/reference/findmobiledeviceconfigurationprofilesbyid
        """
        uri = f"/mobiledeviceconfigurationprofiles/id/{jamf_id}"
        res = self._classic_api_get(url_suffix=uri, error_handler=self._generic_error_handler)
        return res

    def get_osxconfigurationprofiles_by_id(self, jamf_id):
        """
        API link: https://developer.jamf.com/jamf-pro/reference/findosxconfigurationprofilesbyid
        """
        uri = f"/osxconfigurationprofiles/id/{jamf_id}"
        res = self._classic_api_get(url_suffix=uri, error_handler=self._generic_error_handler)
        return res


""" HELPER FUNCTIONS """


def pagination(response, limit, page):
    """
    Args:
        response: The response from the API.
        limit: Maximum number of objects to retrieve.
        page: Page number
    Returns:
        Return a list of objects from the response according to the page and limit per page.
    """
    limit = min(limit, MAX_PAGE_SIZE)
    start = page * limit
    end = (page + 1) * limit
    return response[start:end]


def get_computers_readable_output(computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extracts relevant fields from the computers inventory response for Human Readable output.

    Args:
        computers (list[dict[str, Any]]): List of computer objects from the Pro API.

    Returns:
        list[dict[str, Any]]: Mapped fields for the Human Readable table.
    """
    readable_output = []
    for computer in computers:
        general = computer.get("general", {})
        readable_output.append(
            {
                "Computer ID": computer.get("id"),
                "Computer Name": general.get("name"),
            }
        )

    return readable_output


def get_computers_basic_subset_readable_output(computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extracts relevant fields from the computers inventory response for the basic subset Human Readable output.

    Args:
        computers (list[dict[str, Any]]): List of computer objects from the Pro API.

    Returns:
        list[dict[str, Any]]: Mapped fields for the Human Readable table.
    """
    readable_output = []
    for computer in computers:
        general = computer.get("general", {})
        hardware = computer.get("hardware", {})
        user_location = computer.get("userAndLocation", {})

        readable_output.append(
            {
                "ID": computer.get("id"),
                "Mac Address": hardware.get("macAddress"),
                "Name": general.get("name"),
                "Serial Number": hardware.get("serialNumber"),
                "UDID": computer.get("udid"),
                "Username": user_location.get("username"),
            }
        )

    return readable_output


def get_computer_by_id_readable_output(response: dict[str, Any]) -> dict[str, Any]:
    """Extracts relevant fields from the computer inventory detail response for Human Readable output.

    Args:
        response (dict[str, Any]): Computer detail object from the Pro API.

    Returns:
        dict[str, Any]: Mapped fields for the Human Readable table.
    """
    general = response.get("general", {})
    hardware = response.get("hardware", {})

    readable_output = {
        "ID": general.get("id"),
        "Last IP Address": general.get("lastIpAddress"),
        "Jamf Version": general.get("jamfBinaryVersion"),
        "MAC Address": hardware.get("macAddress"),
        "Name": general.get("name"),
        "Platform": general.get("platform"),
        "Serial Number": hardware.get("serialNumber"),
        "UDID": general.get("udid"),
    }

    return readable_output


def get_computer_by_match_readable_output(computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extracts relevant fields from the computers inventory response for the match command Human Readable output.

    Args:
        computers (list[dict[str, Any]]): List of computer objects from the Pro API.

    Returns:
        list[dict[str, Any]]: Mapped fields for the Human Readable table.
    """
    readable_output = []
    for computer in computers:
        general = computer.get("general", {})
        hardware = computer.get("hardware", {})
        user_location = computer.get("userAndLocation", {})

        readable_output.append(
            {
                "ID": computer.get("id"),
                "Name": general.get("name"),
                "MAC Address": hardware.get("macAddress"),
                "Serial Number": hardware.get("serialNumber"),
                "UDID": computer.get("udid"),
                "Username": user_location.get("username"),
            }
        )

    return readable_output


def get_computer_subset_deprecated_readable_output(response, subset):
    """
    Extracts fields for human-readable output from Classic API responses.

    Args:
        response (dict[str, Any]): The raw computer data from the Classic API.
        subset (str): The subset name (e.g., 'Peripherals', 'iphones').

    Returns:
        Union[dict, list]: The data to be displayed in the readable output.
    """
    readable_output = {}
    computers_response = response.get("computer")
    # NOTE: trimmed down unused deprecated logic
    if subset == "Peripherals":
        readable_output = computers_response.get("peripherals")

    elif subset == "iphones":
        readable_output = computers_response.get("iphones")

    return readable_output


def get_computer_subset_readable_output(response, subset):
    """
    Extracts fields from the Pro API response for human-readable output.

    Args:
        response (dict[str, Any]): The raw computer data from the Pro API.
        subset (str): The subset name.

    Returns:
        dict[str, Any]: A dictionary of fields formatted for display in a table.
    """
    readable_output = {}

    general = response.get("general", {})
    hardware = response.get("hardware", {})
    user_and_location = response.get("userAndLocation", {})
    purchasing = response.get("purchasing", {})
    security = response.get("security", {})

    if subset == "General":
        remote_management = general.get("remoteManagement", {})
        readable_output = {
            "ID": response.get("id"),
            "Name": general.get("name"),
            "Last IP Address": general.get("lastIpAddress"),
            "Managed": remote_management.get("managed"),
            "Platform": general.get("platform"),
            "UDID": response.get("udid"),
        }

    elif subset == "Location":
        readable_output = {
            "Email Address": user_and_location.get("email"),
            "Phone": user_and_location.get("phone"),
            "Real Name": user_and_location.get("realname"),
            "Room": user_and_location.get("room"),
            "Username": user_and_location.get("username"),
        }

    elif subset == "Purchasing":
        readable_output = {
            "Is Leased": purchasing.get("leased"),
            "Is Purchased": purchasing.get("purchased"),
        }

    elif subset == "Hardware":
        readable_output = {
            "Printers": response.get("printers", []),
            "Storage": response.get("storage", []),
            "Applications": response.get("applications", []),
            "Services": response.get("services", []),
            "Hardware Make": hardware.get("make"),
            "Hardware Model": hardware.get("model"),
            "Model Identifier": hardware.get("modelIdentifier"),
            "Serial Number": hardware.get("serialNumber"),
            "Processor Speed Mhz": hardware.get("processorSpeedMhz"),
            "Processor Count": hardware.get("processorCount"),
            "Core Count": hardware.get("coreCount"),
            "Processor Type": hardware.get("processorType"),
            "Processor Architecture": hardware.get("processorArchitecture"),
        }

    elif subset == "Certificates":
        readable_output = {
            "ID": response.get("id"),
            "UDID": response.get("udid"),
            "Certificates": response.get("certificates", []),
        }

    elif subset == "Security":
        readable_output = {
            "ID": response.get("id"),
            "UDID": response.get("udid"),
            "Auto Login Disabled": security.get("autoLoginDisabled"),
            "Remote Desktop Enabled": security.get("remoteDesktopEnabled"),
            "Activation Lock Enabled": security.get("activationLockEnabled"),
            "Secure Boot Level": security.get("secureBootLevel"),
            "External Boot Level": security.get("externalBootLevel"),
            "Bootstrap Token Allowed": security.get("bootstrapTokenAllowed"),
            "Bootstrap Token Escrowed Status": security.get("bootstrapTokenEscrowedStatus"),
            "Recovery Lock Enabled": security.get("recoveryLockEnabled"),
            "Firewall Enabled": security.get("firewallEnabled"),
        }

    elif subset == "Software":
        readable_output = {
            "Applications": len(response.get("applications", [])),
            "Services": len(response.get("services", [])),
        }

    elif subset == "ExtensionAttributes":
        readable_output = {
            "ID": response.get("id"),
            "UDID": response.get("udid"),
            "Extension Attributes": response.get("extensionAttributes", []),
        }

    elif subset == "GroupsAccounts":
        readable_output = {
            "ID": response.get("id"),
            "UDID": response.get("udid"),
            "Group Memberships": response.get("groupMemberships", []),
        }

    elif subset == "ConfigurationProfiles":
        readable_output = {
            "ID": response.get("id"),
            "UDID": response.get("udid"),
            "Configuration Profiles": response.get("configurationProfiles", []),
        }

    return readable_output


def get_computer_subset_context_mapping(response, subset):
    """
    Maps Pro API computer inventory response to the integration's context structure.

    Handles flattening of nested fields and date formatting for various subsets.

    Args:
        response (dict[str, Any]): The raw computer data from the Pro API.
        subset (str): The subset name to map.

    Returns:
        dict[str, Any]: The mapped context dictionary.
    """
    context = copy.deepcopy(response)

    general = response.get("general", {})
    hardware = response.get("hardware", {})
    user_and_location = response.get("userAndLocation", {})
    purchasing = response.get("purchasing", {})
    operating_system = response.get("operatingSystem", {})
    security = response.get("security", {})
    disk_encryption = response.get("diskEncryption", {})

    if subset == "General":
        remote_management = general.get("remoteManagement", {})
        mdm_capable = general.get("mdmCapable", {})

        context["general"].update(
            {
                "id": response.get("id"),
                "network_adapter_type": hardware.get("networkAdapterType"),
                "mac_address": hardware.get("macAddress"),
                "alt_network_adapter_type": hardware.get("altNetworkAdapterType"),
                "alt_mac_address": hardware.get("altMacAddress"),
                "ip_address": general.get("lastIpAddress"),
                "last_reported_ip": general.get("lastReportedIpV4"),
                "serial_number": hardware.get("serialNumber"),
                "udid": response.get("udid"),
                "jamf_version": general.get("jamfBinaryVersion"),
                "barcode_1": general.get("barcode1"),
                "barcode_2": general.get("barcode2"),
                "asset_tag": general.get("assetTag"),
                "remote_management": {
                    "managed": remote_management.get("managed"),
                    "management_username": remote_management.get("managementUsername"),
                },
                "mdm_capable": mdm_capable.get("capable"),
                "mdm_capable_users": mdm_capable.get("capableUsers"),
                "management_status": {"user_approved_mdm": general.get("userApprovedMdm")},
                "distribution_point": general.get("distributionPoint"),
                "itunes_store_account_is_active": general.get("itunesStoreAccountActive"),
            }
        )

    elif subset == "Location":
        context["location"] = {
            "username": user_and_location.get("username"),
            "realname": user_and_location.get("realname"),
            "real_name": user_and_location.get("realname"),
            "email_address": user_and_location.get("email"),
            "position": user_and_location.get("position"),
            "phone": user_and_location.get("phone"),
            "phone_number": user_and_location.get("phone"),
            "room": user_and_location.get("room"),
        }

    elif subset == "Purchasing":
        context["purchasing"].update(
            {
                "is_purchased": purchasing.get("purchased"),
                "is_leased": purchasing.get("leased"),
                "po_number": purchasing.get("poNumber"),
                "vendor": purchasing.get("vendor"),
                "applecare_id": purchasing.get("appleCareId"),
                "purchase_price": purchasing.get("purchasePrice"),
                "purchasing_account": purchasing.get("purchasingAccount"),
                "life_expectancy": purchasing.get("lifeExpectancy"),
                "purchasing_contact": purchasing.get("purchasingContact"),
            }
        )

    elif subset == "Hardware":
        context["hardware"].update(
            {
                "make": hardware.get("make"),
                "model": hardware.get("model"),
                "model_identifier": hardware.get("modelIdentifier"),
                "os_name": operating_system.get("name"),
                "os_version": operating_system.get("version"),
                "os_build": operating_system.get("build"),
                "active_directory_status": operating_system.get("activeDirectoryStatus"),
            }
        )

        context["hardware"].update(
            {
                "processor_type": hardware.get("processorType"),
                "processor_architecture": hardware.get("processorArchitecture"),
                "processor_speed": hardware.get("processorSpeedMhz"),
                "processor_speed_mhz": hardware.get("processorSpeedMhz"),
                "number_processors": hardware.get("processorCount"),
                "number_cores": hardware.get("coreCount"),
                "total_ram": hardware.get("totalRamMegabytes"),
                "total_ram_mb": hardware.get("totalRamMegabytes"),
                "boot_rom": hardware.get("bootRom"),
                "bus_speed": hardware.get("busSpeedMhz"),
                "bus_speed_mhz": hardware.get("busSpeedMhz"),
                "battery_capacity": hardware.get("batteryCapacityPercent"),
                "cache_size": hardware.get("cacheSizeKilobytes"),
                "cache_size_kb": hardware.get("cacheSizeKilobytes"),
                "available_ram_slots": hardware.get("openRamSlots"),
                "optical_drive": hardware.get("opticalDrive"),
                "nic_speed": hardware.get("nicSpeed"),
                "smc_version": hardware.get("smcVersion"),
                "ble_capable": hardware.get("bleCapable"),
                "supports_ios_app_installs": hardware.get("supportsIosAppInstalls"),
            }
        )

        context["hardware"].update(
            {
                "sip_status": security.get("sipStatus"),
                "gatekeeper_status": security.get("gatekeeperStatus"),
                "xprotect_version": security.get("xprotectVersion"),
                "disk_encryption_configuration": disk_encryption.get("diskEncryptionConfigurationName"),
                "storage": response.get("storage", {}),  # NOTE: no mapping is performed for storage.*
            }
        )

    elif subset == "Certificates":
        for cert in context.get("certificates", []):
            cert["common_name"] = cert.get("commonName")

    elif subset == "Security":
        context["security"].update(
            {
                "activation_lock": security.get("activationLockEnabled"),
                "secure_boot_level": security.get("secureBootLevel"),
                "external_boot_level": security.get("externalBootLevel"),
            }
        )

    elif subset == "Software":
        package_receipts = response.get("packageReceipts", {})
        # NOTE: no mapping is performed except for the child items.
        context["software"] = {
            "licensed_software": response.get("licensedSoftware", []),
            "installed_by_installer_swu": package_receipts.get("installedByInstallerSwu", []),
            "available_updates": response.get("softwareUpdates", []),
            "running_services": response.get("services", []),
            "applications": response.get("applications", []),
        }

    elif subset == "ExtensionAttributes":
        extension_attributes = copy.deepcopy(context.get("extensionAttributes", []))
        for attr in extension_attributes:
            attr["id"] = attr.get("definitionId")
            attr["value"] = attr.get("values", [])
            attr["multi_value"] = attr.get("multiValue")

        context["extension_attributes"] = extension_attributes

    elif subset == "GroupsAccounts":
        # NOTE: no mapping is performed except for the child items.
        context["groups_accounts"] = {
            "computer_group_memberships": response.get("groupMemberships", []),
            "local_accounts": response.get("localUserAccounts", []),
            "user_inventories": response.get("localUserAccounts", []),
        }

    elif subset == "ConfigurationProfiles":
        # NOTE: no mapping is performed except for the subset-section name.
        context["configuration_profiles"] = response.get("configurationProfiles", [])

    return context


def computer_commands_readable_output(response):
    computer_response = response.get("computer_command").get("command")
    readable_output = {
        "Name": computer_response.get("name"),
        "Computer ID": computer_response.get("computer_id"),
        "Command UUID": computer_response.get("command_uuid"),
    }
    return readable_output


def get_users_readable_output(users_response, user_id=None, name=None, email=None):
    if user_id or name:
        readable_output = {
            "ID": users_response.get("id"),
            "Name": users_response.get("name"),
            "Email": users_response.get("email"),
            "Phone": users_response.get("phone_number"),
        }
    elif email:
        readable_output = []  # type: ignore
        for user in users_response:
            readable_output.append(  # type: ignore
                {
                    "ID": user.get("id"),
                    "Name": user.get("name"),
                    "Email": user.get("email"),
                    "Phone": user.get("phone_number"),
                }
            )
    else:
        readable_output = []  # type: ignore
        for user in users_response:
            readable_output.append(  # type: ignore
                {
                    "ID": user.get("id"),
                    "Name": user.get("name"),
                }
            )
    return readable_output


def get_mobile_devices_readable_output(mobile_response, mobile_id=None):
    readable_output = []
    if mobile_id:
        readable_output.append(
            {
                "ID": mobile_response.get("id"),
                "Name": mobile_response.get("name"),
                "WIFI MAC address": mobile_response.get("wifi_mac_address"),
                "Bluetooth MAC address": mobile_response.get("bluetooth_mac_address"),
                "IP address": mobile_response.get("ip_address"),
                "Serial Number": mobile_response.get("serial_number"),
                "UDID": mobile_response.get("udid"),
                "Model": mobile_response.get("model"),
                "Model Number": mobile_response.get("model_number"),
                "Managed": mobile_response.get("managed"),
                "Supervised": mobile_response.get("supervised"),
            }
        )
    else:
        for mobile_device in mobile_response:
            readable_output.append(
                {
                    "ID": mobile_device.get("id"),
                    "Name": mobile_device.get("name"),
                    "UDID": mobile_device.get("udid"),
                    "Serial Number": mobile_device.get("serial_number"),
                }
            )
    return readable_output


def get_mobile_device_subset_readable_output(response, subset):
    readable_output = {}
    mobile_response = response.get("mobile_device")
    if subset == "General":
        general_mobile_response = mobile_response.get("general")

        readable_output = {
            "ID": general_mobile_response.get("id"),
            "Name": general_mobile_response.get("name"),
            "WIFI MAC address": general_mobile_response.get("wifi_mac_address"),
            "Bluetooth MAC address": general_mobile_response.get("bluetooth_mac_address"),
            "IP address": general_mobile_response.get("ip_address"),
            "Serial Number": general_mobile_response.get("serial_number"),
            "UDID": general_mobile_response.get("udid"),
            "Model": general_mobile_response.get("model"),
            "Model Number": general_mobile_response.get("model_number"),
            "Managed": general_mobile_response.get("managed"),
            "Supervised": general_mobile_response.get("supervised"),
        }
    elif subset == "Location":
        location_mobile_response = mobile_response.get("location")

        readable_output = {
            "Username": location_mobile_response.get("username"),
            "Real Name": location_mobile_response.get("realname"),
            "Email Address": location_mobile_response.get("email_address"),
            "Position": location_mobile_response.get("position"),
            "Department": location_mobile_response.get("department"),
            "Building": location_mobile_response.get("building"),
            "Room": location_mobile_response.get("room"),
            "Phone": location_mobile_response.get("phone"),
        }
    elif subset == "Purchasing":
        purchasing_mobile_response = mobile_response.get("purchasing")

        readable_output = {
            "Is Purchased": purchasing_mobile_response.get("is_purchased"),
            "Is Leased": purchasing_mobile_response.get("is_leased"),
            "Vendor": purchasing_mobile_response.get("vendor"),
            "Purchase Price": purchasing_mobile_response.get("purchase_price"),
            "Warranty Expires": purchasing_mobile_response.get("warranty_expires"),
            "Lease Expires": purchasing_mobile_response.get("lease_expires"),
            "Purchasing Contact": purchasing_mobile_response.get("purchasing_contact"),
        }
    elif subset == "Certificates":
        certificates_mobile_response = mobile_response.get("certificates")

        certificate_details = []
        for certificate in certificates_mobile_response:
            certificate_details.append(
                {
                    "Common Name": certificate.get("common_name"),
                    "Identity": certificate.get("identity"),
                    "Expires UTC": certificate.get("expires_utc"),
                    "Expires Epoch": certificate.get("expires_epoch"),
                }
            )
        readable_output = certificate_details  # type: ignore
    elif subset == "Applications":
        applications_mobile_response = mobile_response.get("applications")

        readable_output = {"Number of applications": len(applications_mobile_response)}
    elif subset == "ExtensionAttributes":
        extension_attributes_mobile_response = mobile_response.get("extension_attributes")
        extension_attributes = []
        for extension_attribute in extension_attributes_mobile_response:
            extension_attributes.append(
                {
                    "ID": extension_attribute.get("id"),
                    "Name": extension_attribute.get("name"),
                    "Type": extension_attribute.get("type"),
                    "Value": extension_attribute.get("multi_value"),
                }
            )
        readable_output = extension_attributes  # type: ignore

    elif subset == "ConfigurationProfiles":
        configuration_profiles_mobile_response = mobile_response.get("configuration_profiles")
        configuration_profiles = []
        for profile in configuration_profiles_mobile_response:
            configuration_profiles.append(
                {
                    "Display Name": profile.get("display_name"),
                    "version": profile.get("version"),
                    "identifier": profile.get("identifier"),
                    "uuid": profile.get("uuid"),
                }
            )
        readable_output = configuration_profiles  # type: ignore

    elif subset == "Security":
        security_mobile_response = mobile_response.get("security")

        readable_output = {
            "Data Protection": security_mobile_response.get("data_protection"),
            "Block Level Encryption Capable": security_mobile_response.get("block_level_encryption_capable"),
            "File Level Encryption Capable": security_mobile_response.get("file_level_encryption_capable"),
            "Passcode Present": security_mobile_response.get("passcode_present"),
            "Passcode Compliant": security_mobile_response.get("passcode_compliant"),
            "Passcode Lock Grace Period Enforced": security_mobile_response.get("passcode_lock_grace_period_enforced"),
            "Hardware Encryption": security_mobile_response.get("hardware_encryption"),
            "Activation Lock Enabled": security_mobile_response.get("activation_lock_enabled"),
            "Jailbreak Detected": security_mobile_response.get("jailbreak_detected"),
            "Lost Mode Enabled": security_mobile_response.get("lost_mode_enabled"),
            "Lost Mode Enforced": security_mobile_response.get("lost_mode_enforced"),
            "Lost Mode Enable Issued UTC": security_mobile_response.get("lost_mode_enable_issued_utc"),
            "Lost Mode Message": security_mobile_response.get("lost_mode_message"),
            "Lost Mode Phone": security_mobile_response.get("lost_mode_phone"),
            "Lost Mode Footnote": security_mobile_response.get("lost_mode_footnote"),
            "Phone": security_mobile_response.get("activation_lock_enabled"),
        }
    elif subset == "Network":
        network_mobile_response = mobile_response.get("network")

        readable_output = {
            "Home Carrier Network": network_mobile_response.get("home_carrier_network"),
            "Cellular Technology": network_mobile_response.get("cellular_technology"),
            "Voice_roaming_enabled": network_mobile_response.get("voice_roaming_enabled"),
            "Imei": network_mobile_response.get("imei"),
            "Iccid": network_mobile_response.get("iccid"),
            "Meid": network_mobile_response.get("meid"),
            "Current Carrier Network": network_mobile_response.get("current_carrier_network"),
            "Carrier Settings Version": network_mobile_response.get("carrier_settings_version"),
            "Current Mobile Country Code": network_mobile_response.get("current_mobile_country_code"),
            "Current Mobile Network Code": network_mobile_response.get("current_mobile_network_code"),
            "Home Mobile Country Code": network_mobile_response.get("home_mobile_country_code"),
            "Home Mobile Network Code": network_mobile_response.get("home_mobile_network_code"),
            "Data Roaming Enabled": network_mobile_response.get("data_roaming_enabled"),
            "Phone Number": network_mobile_response.get("phone_number"),
        }
    elif subset == "ProvisioningProfiles":
        readable_output = mobile_response.get("provisioning_profiles")

    elif subset == "MobileDeviceGroups":
        mobile_device_groups_mobile_response = mobile_response.get("mobile_device_groups")

        readable_output = {"Number of groups": len(mobile_device_groups_mobile_response)}
    return readable_output


def get_computers_by_app_readable_output(response):
    readable_output = []
    versions_list = response.get("versions")
    for version in versions_list:
        total_computers = len(version.get("computers"))
        readable_output.append({"version": version.get("number"), "Total number of computers": total_computers})

    return readable_output


def mobile_device_commands_readable_output(response):
    mobile_device_response = response.get("mobile_device_command").get("mobile_devices").get("mobile_device")
    readable_output = {
        "ID": mobile_device_response.get("id"),
        "Management ID": mobile_device_response.get("management_id"),
    }
    return mobile_device_response, readable_output


def generate_endpoint_by_context_standard(endpoints):
    standard_endpoints = []
    for single_endpoint in endpoints:
        endpoint = Common.Endpoint(
            id=single_endpoint.get("id"),
            hostname=single_endpoint.get("name"),
            ip_address=single_endpoint.get("ip"),
            os=single_endpoint.get("platform"),
            mac_address=single_endpoint.get("mac_address"),
            vendor=INTEGRATION_NAME,
        )

        standard_endpoints.append(endpoint)
    return standard_endpoints


def command_results_endpoint_command(standard_endpoints, outputs):
    command_results = []
    if standard_endpoints:
        for endpoint in standard_endpoints:
            endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)

            hr = tableToMarkdown("Jamf Endpoint", endpoint_context)

            command_results.append(CommandResults(readable_output=hr, raw_response=outputs, indicator=endpoint))

    else:
        command_results.append(
            CommandResults(
                readable_output="No endpoints were found",
                raw_response=outputs,
            )
        )
    return command_results


def get_paging_hr_and_outputs(total_results, page_size, current_page):
    paging_outputs = {"total_results": total_results, "page_size": page_size, "current_page": current_page}
    paging_hr = {"Total Results": total_results, "Page Size": page_size, "Current Page": current_page}
    return paging_outputs, paging_hr


def get_sections_from_query(query: str) -> list[str]:
    """Extracts the required inventory sections from an RSQL filter query.

    Args:
        query (str): The RSQL filter query.

    Returns:
        list[str]: A list of unique section names required by the query.
    """
    # Mapping with lowercase keys for case-insensitive matching
    prefix_map = {section.value.lower().replace("_", ""): section for section in ComputersInventorySection}

    key_pattern = r"([a-z0-9._-]+)(?:==|!=|=in=|=out=|<|>|<=|>=)"  # any keyword that is followed by an RSQL operator
    found_keys = re.findall(key_pattern, query.lower())

    sections = set()
    for key in found_keys:
        if "." in key:
            prefix = key.split(".", 1)[0]
            if prefix in prefix_map:
                sections.add(prefix_map[prefix])

    return list(sections)


def get_full_identifier_from_mapping(identifier: str) -> str:
    identifier_mapping = {
        "id": "id",
        "name": "general.name",
        "udid": "udid",
        "serialnumber": "hardware.serialNumber",
        "macaddress": "hardware.macAddress",
    }

    if identifier not in identifier_mapping:
        demisto.debug("Identifier is a PREDEFINED value, and needs mapping for the Pro API.")
        raise DemistoException(f"The identifier '{identifier}' is not supported.")

    return identifier_mapping[identifier]


def computers_endpoint_request(client: Client, filter_query: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Helper for the endpoint command. Requests computer inventory data and maps it to a simplified structure.

    Args:
        client (Client): Jamf Client instance.
        filter_query (str): RSQL filter query string.

    Returns:
        tuple[list[dict[str, Any]], list[dict[str, Any]]]: A tuple containing:
            - A list of mapped computer dictionaries (id, name, ip, platform, mac_address, udid).
            - The raw computer inventory results from the API.
    """
    sections = ComputersInventorySection.subset_to_sections("general")

    raw_response = client.get_computers_inventory_request(filter_query=filter_query, sections=sections)

    # only a single match is expected, but handle as if there are multiple matches
    mapped_response_list = []

    raw_computers = raw_response.get("results", [])

    for computer_response in raw_computers:
        general = computer_response.get("general", {})
        hardware = computer_response.get("hardware", {})

        mapped_response = {
            "id": computer_response.get("id"),
            "name": general.get("name"),
            "ip": general.get("lastIpAddress"),
            "platform": general.get("platform"),
            "mac_address": hardware.get("macAddress"),
            "udid": computer_response.get("udid"),
        }

        mapped_response_list.append(mapped_response)

    return mapped_response_list, raw_computers


""" COMMAND FUNCTIONS """


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

    message: str = ""
    try:
        if client.get_computers_inventory_request(limit=1):
            message = "ok"
    except requests.ReadTimeout as e:  # type: ignore
        message = f"Read Timeout Error: Make sure your username is correctly set. Original error: {e!s}"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            message = "Authorization Error: Make sure server url and credentials are correctly set."
        else:
            raise e
    return message


def get_computers_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Returns a list of all computers with their associated IDs.

    Args:
        client (Client): Jamf client.
        args (dict[str, Any]): Command arguments.

    Returns:
        list[CommandResults]: Command results.
    """
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))

    sections = [ComputersInventorySection.GENERAL.value]
    response = client.get_computers_inventory_request(sections=sections, limit=limit, page=page)  # type: ignore
    computers = response.get("results", [])
    total_results = response.get("totalCount", 0)

    readable_output = get_computers_readable_output(computers)

    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    context_outputs = copy.deepcopy(computers)
    for computer_context in context_outputs:
        general = computer_context.get("general", {})
        computer_context["name"] = general.get("name")

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get computers results", readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer",
            outputs_key_field="id",
            outputs=context_outputs,
            raw_response=response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get computers", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def get_computers_basic_subset_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Returns the “basic” subset for all of the computers.

    Args:
        client (Client): Jamf client.
        args (dict[str, Any]): Command arguments.

    Returns:
        list[CommandResults]: Command results.
    """
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))

    sections = [
        ComputersInventorySection.GENERAL.value,
        ComputersInventorySection.HARDWARE.value,
        ComputersInventorySection.USER_AND_LOCATION.value,
    ]
    response = client.get_computers_inventory_request(sections=sections, limit=limit, page=page)  # type: ignore
    computers = response.get("results", [])
    total_results = response.get("totalCount", 0)

    readable_output = get_computers_basic_subset_readable_output(computers)

    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    context_outputs = copy.deepcopy(computers)
    for computer_context in context_outputs:
        general = computer_context.get("general", {})
        remoteManagement = general.get("remoteManagement", {})
        userAndLocation = computer_context.get("userAndLocation", {})
        hardware = computer_context.get("hardware", {})

        computer_context.update(
            {
                "name": general.get("name"),
                "managed": remoteManagement.get("managed"),
                "username": userAndLocation.get("username"),
                "model": hardware.get("model"),
                "mac_address": hardware.get("macAddress"),
                "serial_number": hardware.get("serialNumber"),
            }
        )

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get computers basic subset results", readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer",
            outputs_key_field="id",
            outputs=context_outputs,
            raw_response=response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get computers basic subset", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def get_computer_by_match_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Matches computers by specific characteristics using a filter query.

    Args:
        client (Client): Jamf client.
        args (dict[str, Any]): Command arguments.

    Returns:
        list[CommandResults]: Command results.
    """
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))
    filter_query = args.get("filter")

    sections = get_sections_from_query(filter_query)  # type: ignore

    demisto.debug(f"Provided filter query: {filter_query}")
    demisto.debug(f"Extracted sections: {sections}")

    # extend the sections list, these sections are necessary for the human readable output
    required_sections = {
        ComputersInventorySection.GENERAL.value,
        ComputersInventorySection.HARDWARE.value,
        ComputersInventorySection.USER_AND_LOCATION.value,
    }
    sections = list(set(sections) | required_sections)

    demisto.debug(f"Extended sections: {sections}")

    response = client.get_computers_inventory_request(sections=sections, limit=limit, page=page, filter_query=filter_query)  # type: ignore
    computers = response.get("results", [])
    total_results = response.get("totalCount", 0)

    readable_output = get_computer_by_match_readable_output(computers)

    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    context_outputs = copy.deepcopy(computers)
    for computer_context in context_outputs:
        general = computer_context.get("general", {})
        hardware = general.get("hardware", {})
        userAndLocation = computer_context.get("userAndLocation", {})

        computer_context.update(
            {
                "name": general.get("name"),
                "serial_number": hardware.get("serialNumber"),
                "mac_address": hardware.get("macAddress"),
                "alt_mac_address": hardware.get("altMacAddress"),
                "asset_tag": general.get("assetTag"),
                "barcode_1": general.get("barcode1"),
                "barcode_2": general.get("barcode2"),
                "username": userAndLocation.get("username"),
                "realname": userAndLocation.get("realname"),
                "email": userAndLocation.get("email"),
                "email_address": userAndLocation.get("email"),
                "room": userAndLocation.get("room"),
                "position": userAndLocation.get("position"),
            }
        )

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get computer by match results", readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer",
            outputs_key_field="id",
            outputs=context_outputs,
            raw_response=response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get computer by match", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.Computer.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def get_computer_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Returns the "general" subset of a specific computer.

    Args:
        client (Client): Jamf client.
        args (dict[str, Any]): Command arguments.

    Returns:
        CommandResults: Command results.
    """
    computer_id = args.get("id")

    response = client.get_computer_inventory_detail_request(computer_id)  # type: ignore

    readable_output = get_computer_by_id_readable_output(response)

    computers_hr = f"Jamf get computers result for computer ID: {computer_id}"

    general = response.get("general", {})
    hardware = response.get("hardware", {})
    remoteManagement = general.get("remoteManagement", {})
    mdmCapable = general.get("mdmCapable", {})
    site = general.get("site", {})

    context_outputs = copy.deepcopy(response)
    context_outputs.update(
        {
            "name": general.get("name"),
            "network_adapter_type": hardware.get("networkAdapterType"),
            "mac_address": hardware.get("macAddress"),
            "alt_network_adapter_type": hardware.get("altNetworkAdapterType"),
            "alt_mac_address": hardware.get("altMacAddress"),
            "ip_address": general.get("lastIpAddress"),
            "last_reported_ip": general.get("lastReportedIpV4"),
            "serial_number": hardware.get("serialNumber"),
            "jamf_version": general.get("jamfBinaryVersion"),
            "platform": general.get("platform"),
            "barcode_1": general.get("barcode1"),
            "barcode_2": general.get("barcode2"),
            "asset_tag": general.get("assetTag"),
            "remote_management": {
                "managed": remoteManagement.get("managed"),
                "management_username": remoteManagement.get("managementUsername"),
            },
            "supervised": general.get("supervised"),
            "mdm_capable": mdmCapable.get("capable"),
            "mdm_capable_users": mdmCapable.get("capableUsers"),
            "distribution_point": general.get("distributionPoint"),
            "site": {
                "id": site.get("id"),
                "name": site.get("name"),
            },
            "itunes_store_account_is_active": general.get("itunesStoreAccountActive"),
        }
    )

    return CommandResults(
        readable_output=tableToMarkdown(computers_hr, readable_output, removeNull=True),
        outputs_prefix="JAMF.Computer",
        outputs_key_field="id",
        outputs=context_outputs,
        raw_response=response,
    )


def get_computer_subset_deprecated_command(client: Client, args: dict[str, Any], subset_name: str) -> CommandResults:
    """
    Executes deprecated computer subset commands using the Classic API.

    Args:
        client (Client): Jamf Client instance.
        args (dict[str, Any]): Command arguments containing 'identifier' and 'identifier_value'.
        subset_name (str): The name of the subset to retrieve (e.g., 'Peripherals', 'iphones').

    Returns:
        CommandResults: The results of the command execution.
    """
    identifier = args["identifier"]
    identifier_value = args["identifier_value"]

    computer_subset_response = client.get_computer_subset_deprecated_request(identifier, identifier_value, subset_name)
    computer_id = get_computer_id_deprecated(client, computer_subset_response, subset_name, identifier, identifier_value)
    readable_output = get_computer_subset_deprecated_readable_output(computer_subset_response, subset_name)
    computer_subset_response["computer"]["id"] = computer_id
    return CommandResults(
        readable_output=tableToMarkdown(f"Jamf computer {subset_name} subset result", readable_output, removeNull=True),
        outputs_prefix="JAMF.ComputerSubset.computer",
        outputs_key_field="id",
        outputs=computer_subset_response["computer"],
        raw_response=computer_subset_response,
    )


def get_computer_subset_command(client: Client, args: dict[str, Any], subset_name: str) -> CommandResults:
    """
    Retrieves a specific computer subset using the Pro API.

    Maps legacy subset names to Pro API sections and fetches the inventory data.

    Args:
        client (Client): Jamf Client instance.
        args (dict[str, Any]): Command arguments containing 'identifier' and 'identifier_value'.
        subset_name (str): The name of the subset to retrieve.

    Returns:
        CommandResults: The results of the command execution.

    Raises:
        DemistoException: If no computer or multiple computers are found for the given identifier.
    """
    identifier = args["identifier"]
    identifier_value = args["identifier_value"]

    sections = ComputersInventorySection.subset_to_sections(subset_name)

    if not (identifier and identifier_value):
        raise DemistoException("Both 'identifier' and 'identifier_value' are required arguments.")

    filter_query = f'{get_full_identifier_from_mapping(identifier)}=="{identifier_value}"'

    response = client.get_computers_inventory_request(filter_query=filter_query, sections=sections)

    if response.get("totalCount") != 1:
        raise DemistoException(f"Expected 1 computer, got {response.get('totalCount')}.")

    if not response.get("results"):
        demisto.debug(f"Full response from API:\n{response}\n")
        raise DemistoException("No 'results' found in response.")

    computer_response = response.get("results")[0]  # type: ignore

    context_output = get_computer_subset_context_mapping(computer_response, subset_name)

    readable_title = f"Jamf computer {subset_name} subset result"

    readable_output = get_computer_subset_readable_output(computer_response, subset_name)

    return CommandResults(
        readable_output=tableToMarkdown(readable_title, readable_output, removeNull=True),
        outputs_prefix="JAMF.ComputerSubset.computer",
        outputs_key_field="id",
        outputs=context_output,
        raw_response=response,
    )


def get_computer_section_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a specific section of a computer inventory record.

    Implements the `jamf-get-computer-subset` command, which is a generalization of the older
    `jamf-get-computer-*-subset` commands.

    Args:
        client (Client): Jamf client.
        args (dict[str, Any]): Command arguments.

    Returns:
        CommandResults: Command results containing the requested computer section data.
    """

    identifier = args["identifier"]
    identifier_value = args["identifier_value"]
    section_arg = args.get("section")

    section_as_enum = ComputersInventorySection(section_arg) if section_arg else ComputersInventorySection.GENERAL

    if not (identifier and identifier_value):
        raise DemistoException("Both 'identifier' and 'identifier_value' are required arguments.")

    filter_query = f'{get_full_identifier_from_mapping(identifier)}=="{identifier_value}"'

    response = client.get_computers_inventory_request(filter_query=filter_query, sections=[section_as_enum.value])

    if response.get("totalCount") != 1:
        raise DemistoException(f"Expected 1 computer, got {response.get('totalCount')}")

    if not response.get("results"):
        demisto.debug(f"Full response from API:\n{response}\n")
        raise DemistoException("No 'results' found in response.")

    computer_response = response.get("results")[0]  # type: ignore

    readable_title = f"Jamf computer {section_as_enum.value} section result"

    readable_output = {
        "ID": computer_response.get("id"),
        "UDID": computer_response.get("udid"),
    }

    return CommandResults(
        readable_output=tableToMarkdown(readable_title, readable_output, removeNull=True),
        outputs_prefix="JAMF.Computer",
        outputs_key_field="id",
        outputs=computer_response,
        raw_response=response,
    )


def get_computer_id_deprecated(client: Client, response, subset_name, identifier, identifier_value):
    """
    Retrieves the computer ID for Classic API requests.

    If the requested subset is not 'General', an additional request is made to fetch the ID.

    Args:
        client (Client): Jamf Client instance.
        response (dict): The current API response.
        subset_name (str): The name of the subset being processed.
        identifier (str): The identifier type (e.g., 'id', 'name').
        identifier_value (str): The value of the identifier.

    Returns:
        str: The computer ID.
    """
    # Need to send another request with General subset to get the computer ID.
    if subset_name != "General":
        computer_id = (
            client.get_computer_subset_deprecated_request(identifier, identifier_value, "General")
            .get("computer")
            .get("general")
            .get("id")
        )
    else:
        computer_id = response.get("computer").get("general").get("id")
    return computer_id


def computer_lock_command(client: Client, args: dict[str, Any]) -> CommandResults:
    computer_id = args["id"]
    passcode = args["passcode"]
    lock_msg = args.get("lock_message")

    computer_response = client.computer_lock_request(computer_id, passcode, lock_msg)
    computer_lock_hr = computer_commands_readable_output(computer_response)
    outputs = computer_response.get("computer_command").get("command")
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Computer {computer_id} locked successfully", computer_lock_hr, removeNull=True, headerTransform=pascalToSpace
        ),
        outputs_prefix="JAMF.ComputerCommand",
        outputs_key_field="id",
        outputs=outputs,
        raw_response=computer_response,
    )


def computer_erase_command(client: Client, args: dict[str, Any]) -> CommandResults:
    computer_id = args["id"]
    passcode = args["passcode"]

    computer_response = client.computer_erase_request(computer_id, passcode)
    computer_erase_outputs = computer_commands_readable_output(computer_response)
    outputs = computer_response.get("computer_command").get("command")

    return CommandResults(
        readable_output=tableToMarkdown(
            f"Computer {computer_id} erased successfully", computer_erase_outputs, removeNull=True, headerTransform=pascalToSpace
        ),
        outputs_prefix="JAMF.ComputerCommand",
        outputs_key_field="id",
        outputs=outputs,
        raw_response=computer_response,
    )


def get_users_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))
    user_response = client.get_users_request()
    total_results = len(user_response.get("users"))
    user_response = pagination(user_response.get("users"), limit, page)

    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    readable_output = get_users_readable_output(user_response)

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get users results", readable_output, removeNull=True),
            outputs_prefix="JAMF.User",
            outputs_key_field="id",
            outputs=user_response,
            raw_response=user_response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get users", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.User.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def get_users_by_identifier_command(client: Client, args: dict[str, Any]) -> CommandResults:
    user_id = args.get("id")
    name = args.get("name")
    email = args.get("email")

    user_response = client.get_users_request(user_id, name, email)

    if email:
        user_response = user_response["users"]
    else:
        user_response = user_response["user"]

    users_hr = "Jamf get user result"

    readable_output = get_users_readable_output(user_response, user_id, name, email)

    return CommandResults(
        readable_output=tableToMarkdown(users_hr, readable_output, removeNull=True),
        outputs_prefix="JAMF.User",
        outputs_key_field="id",
        outputs=user_response,
        raw_response=user_response,
    )


def get_mobile_devices_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    match = args.get("match", False)
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))

    mobile_response = client.get_mobile_devices_request(match=match)

    total_results = len(mobile_response.get("mobile_devices"))
    mobile_response = pagination(mobile_response.get("mobile_devices"), limit, page)

    readable_output = get_mobile_devices_readable_output(mobile_response)
    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get mobile devices result", readable_output, removeNull=True),
            outputs_prefix="JAMF.MobileDevice",
            outputs_key_field="id",
            outputs=mobile_response,
            raw_response=mobile_response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get mobile devices", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.MobileDevice.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def get_mobile_device_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    mobile_id = args.get("id")

    mobile_response = client.get_mobile_devices_request(mobile_id)
    mobile_response = mobile_response.get("mobile_device").get("general")

    readable_output = get_mobile_devices_readable_output(mobile_response, mobile_id)

    return CommandResults(
        readable_output=tableToMarkdown(
            f"Jamf get mobile devices result on mobile ID:{mobile_id}", readable_output, removeNull=True
        ),
        outputs_prefix="JAMF.MobileDevice",
        outputs_key_field="id",
        outputs=mobile_response,
        raw_response=mobile_response,
    )


def get_mobile_device_subset_command(client: Client, args: dict[str, Any], subset: str) -> CommandResults:
    identifier = args["identifier"]
    identifier_value = args["identifier_value"]

    mobile_subset_response = client.get_mobile_devices_subset_request(identifier, identifier_value, subset)
    mobile_id = get_mobile_device_id(client, mobile_subset_response, subset, identifier, identifier_value)
    readable_output = get_mobile_device_subset_readable_output(mobile_subset_response, subset)
    mobile_subset_response["mobile_device"]["id"] = mobile_id
    return CommandResults(
        readable_output=tableToMarkdown(f"Jamf mobile device {subset} subset result", readable_output, removeNull=True),
        outputs_prefix="JAMF.MobileDeviceSubset.mobiledevice",
        outputs_key_field="id",
        outputs=mobile_subset_response["mobile_device"],
        raw_response=mobile_subset_response,
    )


def get_mobile_device_id(client: Client, response, subset, identifier, identifier_value):
    # Need to send another request with General subset to get the mobile device ID.
    if subset != "General":
        mobile_id = (
            client.get_mobile_devices_subset_request(identifier, identifier_value, "General")
            .get("mobile_device")
            .get("general")
            .get("id")
        )
    else:
        mobile_id = response.get("mobile_device").get("general").get("id")
    return mobile_id


def get_computers_by_app_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    app = args["application"]
    version = args.get("version")
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page", 0))
    computer_response = client.get_computers_by_app_request(app, version)

    total_results = len(computer_response.get("computer_applications").get("unique_computers"))
    computers_list = pagination(computer_response.get("computer_applications").get("unique_computers"), limit, page)

    readable_output = get_computers_by_app_readable_output(computer_response.get("computer_applications"))[:limit]
    outputs = {"Application": app, "Computer": computers_list}

    paging_outputs, paging_readable_output = get_paging_hr_and_outputs(total_results, limit, page)

    return [
        CommandResults(
            readable_output=tableToMarkdown("Jamf get computers by application result", readable_output, removeNull=True),
            outputs_prefix="JAMF.ComputersByApp",
            outputs_key_field="Application",
            outputs=outputs,
            raw_response=computer_response,
        ),
        CommandResults(
            readable_output=tableToMarkdown("Paging for get mobile devices", paging_readable_output, removeNull=True),
            outputs_prefix="JAMF.ComputersByApp.Paging",
            outputs_key_field="id",
            outputs=paging_outputs,
        ),
    ]


def mobile_device_lost_command(client: Client, args: dict[str, Any]) -> CommandResults:
    mobile_id = args["id"]
    lost_mode_msg = args.get("lost_mode_message")

    mobile_response = client.mobile_device_lost_request(mobile_id, lost_mode_msg)
    mobile_outputs, readable_output = mobile_device_commands_readable_output(mobile_response)
    mobile_outputs["name"] = "EnableLostMode"

    return CommandResults(
        readable_output=tableToMarkdown(f"Computer {mobile_id} locked successfully", readable_output, removeNull=True),
        outputs_prefix="JAMF.MobileDeviceCommands",
        outputs_key_field="id",
        outputs=mobile_outputs,
        raw_response=mobile_response,
    )


def mobile_device_erase_command(client: Client, args: dict[str, Any]) -> CommandResults:
    mobile_id = args["id"]
    preserve_data_plan = args.get("preserve_data_plan", False)
    clear_activation_code = args.get("clear_activation_code", False)

    mobile_response = client.mobile_device_erase_request(mobile_id, preserve_data_plan, clear_activation_code)
    mobile_outputs, readable_output = mobile_device_commands_readable_output(mobile_response)
    mobile_outputs["name"] = "EraseDevice"
    return CommandResults(
        readable_output=tableToMarkdown(f"Mobile device {mobile_id} erased successfully", readable_output, removeNull=True),
        outputs_prefix="JAMF.MobileDeviceCommands",
        outputs_key_field="id",
        outputs=mobile_outputs,
        raw_response=mobile_response,
    )


def endpoint_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """
    Implements the 'endpoint' command to search for computers.

    Searches by ID, IP, or hostname and returns standard Common.Endpoint indicators.
    Results are deduplicated by UDID.

    Args:
        client (Client): Jamf Client instance.
        args (dict[str, Any]): Command arguments (id, ip, hostname).

    Returns:
        list[CommandResults]: A list of CommandResults objects.
    """
    arg_values = {
        "id": argToList(args.get("id")),
        "ip": argToList(args.get("ip")),
        "hostname": argToList(args.get("hostname")),
    }

    if not any(arg_values.values()):
        raise Exception(f"{INTEGRATION_NAME} - In order to run this command, please provide valid id, ip or hostname")

    field_map = {
        "id": "id",
        "ip": "general.lastIpAddress",
        "hostname": "general.name",
    }

    filters = [f'{field_map[key]}=="{val}"' for key, values in arg_values.items() for val in values]

    outputs = []
    raw_outputs = []

    for filter_query in filters:
        mapped, raw = computers_endpoint_request(client, filter_query)
        outputs.extend(mapped)
        raw_outputs.extend(raw)

    # Remove duplicates by taking entries with unique `uuid`:
    if outputs:
        outputs = list({v["udid"]: v for v in outputs}.values())
    if raw_outputs:
        raw_outputs = list({v["udid"]: v for v in raw_outputs}.values())

    standard_endpoints = generate_endpoint_by_context_standard(outputs)
    command_results = command_results_endpoint_command(standard_endpoints, raw_outputs)

    return command_results


def check_authentication_parameters(
    client_id: str | None, client_secret: str | None, username: str | None, password: str | None
) -> DemistoException | None:
    """
    Validate that the authentication parameters are correctly provided
    """
    if (not all([client_id and client_secret]) and not all([username and password])) or (
        any([client_id, client_secret]) and any([username, password])
    ):
        raise DemistoException(AUTHENTICATION_PARAMS_ERROR)
    return None


def get_profile_configuration_osx(client: Client, args: dict[str, Any]) -> CommandResults:
    profile_id = args.get("id")
    profile_response = client.get_osxconfigurationprofiles_by_id(profile_id)
    readable_output = profile_response.get("os_x_configuration_profile")
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Jamf get profile configuration result for profile ID:{profile_id}", readable_output, removeNull=True
        ),
        outputs_prefix="JAMF.OSX.ProfileConfiguration",
        outputs=readable_output,
        raw_response=profile_response,
    )


def get_profile_configuration_mobile(client: Client, args: dict[str, Any]) -> CommandResults:
    profile_id = args.get("id")
    profile_response = client.get_mobiledeviceconfigurationprofiles_by_id(profile_id)
    readable_output = profile_response.get("configuration_profile")
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Jamf get profile configuration result for profile ID:{profile_id}", readable_output, removeNull=True
        ),
        outputs_prefix="JAMF.Mobile.ProfileConfiguration",
        outputs=readable_output,
        raw_response=profile_response,
    )


""" MAIN FUNCTION """


def main() -> None:
    try:
        params = demisto.params()
        base_url = params.get("url", "").rstrip("/")
        username = params.get("credentials", {}).get("identifier")
        password = params.get("credentials", {}).get("password")
        client_id = params.get("client_credentials", {}).get("identifier")
        client_secret = params.get("client_credentials", {}).get("password")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)
        check_authentication_parameters(client_id, client_secret, username, password)

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            username=username,
            password=password,
            client_id=client_id,
            client_secret=client_secret,
        )

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "jamf-get-computers":
            return_results(get_computers_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-computers-basic-subset":
            return_results(get_computers_basic_subset_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-computer-by-id":
            return_results(get_computer_by_id_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-computer-by-match":
            return_results(get_computer_by_match_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-computer-general-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "General"))

        elif demisto.command() == "jamf-get-computer-location-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Location"))

        elif demisto.command() == "jamf-get-computer-purchasing-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Purchasing"))

        elif demisto.command() == "jamf-get-computer-peripherals-subset":
            return_results(get_computer_subset_deprecated_command(client, demisto.args(), "Peripherals"))

        elif demisto.command() == "jamf-get-computer-hardware-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Hardware"))

        elif demisto.command() == "jamf-get-computer-certificates-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Certificates"))

        elif demisto.command() == "jamf-get-computer-security-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Security"))

        elif demisto.command() == "jamf-get-computer-software-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "Software"))

        elif demisto.command() == "jamf-get-computer-extension-attributes-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "ExtensionAttributes"))

        elif demisto.command() == "jamf-get-computer-groups-accounts-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "GroupsAccounts"))

        elif demisto.command() == "jamf-get-computer-iphones-subset":
            return_results(get_computer_subset_deprecated_command(client, demisto.args(), "iphones"))

        elif demisto.command() == "jamf-get-computer-configuration-profiles-subset":
            return_results(get_computer_subset_command(client, demisto.args(), "ConfigurationProfiles"))

        elif demisto.command() == "jamf-computer-lock":
            return_results(computer_lock_command(client, demisto.args()))

        elif demisto.command() == "jamf-computer-erase":
            return_results(computer_erase_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-users":
            return_results(get_users_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-user-by-id":
            return_results(get_users_by_identifier_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-user-by-name":
            return_results(get_users_by_identifier_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-user-by-email":
            return_results(get_users_by_identifier_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-mobile-devices":
            return_results(get_mobile_devices_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-mobile-device-by-id":
            return_results(get_mobile_device_by_id_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-mobile-device-by-match":
            return_results(get_mobile_devices_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-mobile-device-general-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "General"))

        elif demisto.command() == "jamf-get-mobile-device-location-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Location"))

        elif demisto.command() == "jamf-get-mobile-device-purchasing-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Purchasing"))

        elif demisto.command() == "jamf-get-mobile-device-applications-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Applications"))

        elif demisto.command() == "jamf-get-mobile-device-security-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Security"))

        elif demisto.command() == "jamf-get-mobile-device-network-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Network"))

        elif demisto.command() == "jamf-get-mobile-device-certificates-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "Certificates"))

        elif demisto.command() == "jamf-get-mobile-device-extension-attributes-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "ExtensionAttributes"))

        elif demisto.command() == "jamf-get-mobile-device-provisioning-profiles-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "ProvisioningProfiles"))

        elif demisto.command() == "jamf-get-mobile-device-groups-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "MobileDeviceGroups"))

        elif demisto.command() == "jamf-get-mobile-device-configuration-profiles-subset":
            return_results(get_mobile_device_subset_command(client, demisto.args(), "ConfigurationProfiles"))

        elif demisto.command() == "jamf-get-computers-by-application":
            return_results(get_computers_by_app_command(client, demisto.args()))

        elif demisto.command() == "jamf-mobile-device-lost-mode":
            return_results(mobile_device_lost_command(client, demisto.args()))

        elif demisto.command() == "jamf-mobile-device-erase":
            return_results(mobile_device_erase_command(client, demisto.args()))

        elif demisto.command() == "endpoint":
            return_results(endpoint_command(client, demisto.args()))

        elif demisto.command() == "jamf-get-mobile-configuration-profiles-by-id":
            return_results(get_profile_configuration_mobile(client, demisto.args()))

        elif demisto.command() == "jamf-get-computer-configuration-profiles-by-id":
            return_results(get_profile_configuration_osx(client, demisto.args()))

        elif demisto.command() == "jamf-get-computer-subset":
            return_results(get_computer_section_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
