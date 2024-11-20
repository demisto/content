import shutil
from collections.abc import Callable
from pathlib import Path

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
TOKEN_TTL = 7200  # in seconds (120 minutes token's expiration time)
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_FORMAT_FOR_TOKEN = "%m/%d/%Y, %H:%M:%S"
VENDOR = "NetQuest"
PRODUCT = "OMX"

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, credentials: dict, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy,  headers={"Accept": "application/json"})
        self.credentials = {"UserName": credentials["identifier"], "Password": credentials["password"]}
        self.login()

    def login(self):
        """
        In this method, the validity of the Access Token is checked, since the Access Token has a 120 minutes validity period.
        Refreshes the token as needed.
        """
        now = datetime.utcnow()

        if (cache := get_integration_context()) and cache.get("Token"):
            expiration_time = datetime.strptime(
                cache["expiration_time"], DATE_FORMAT_FOR_TOKEN
            )

            # check if token is still valid, continue using it. otherwise regenerate a new one
            if (seconds_left := (expiration_time - now).total_seconds()) > 0:
                demisto.debug(f"No need to regenerate the token, it is still valid for {seconds_left} more seconds")
                return

        demisto.debug("IntegrationContext token cache is empty or token has expired, regenerating a new token")
        raw_response = self._refresh_access_token()
        self._set_headers(raw_response)

        set_integration_context(
            {
                "Token": self.headers["X-Auth-Token"],
                "expiration_time": (
                    now + timedelta(seconds=(TOKEN_TTL - 60))  # decreasing 60s from token expiry for safety
                ).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        )

    def _refresh_access_token(self) -> dict:
        """
        Since the validity of the Access Token is 120 minutes, this method refreshes it and returns the new token json.

        """

        try:
            response_json = self._http_request(
                method="POST", url_suffix="/api/SessionService/Sessions", data=self.credentials
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when creating a new token. Please verify your credentials."
            ) from e
        return response_json

    def _set_headers(self, raw_response: dict):
        """
        This method is called during the client's building or when a new token is generated since the old one has expired.
        """
        # TODO - Ensure the access
        self._headers["X-Auth-Token"] = raw_response["Headers"]["X-Auth-Token"]

    def address_list_upload_request(self, file_name: str) -> requests.Response:
        try:
            with open(file_name) as file:
                result = self._http_request(
                    method="POST",
                    url_suffix="/api/v1/UpdateService/ImportList/Config",
                    data={"UpdateFile": file},
                )
        finally:
            Path(file_name).unlink()

        return result

    def address_list_optimize_request(self) -> requests.Response:
        try:
            response = self._http_request(
                method="GET", url_suffix="/api/Systems/Filters/Address/Status/Optimization"
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when optimizing the IP's list."
            ) from e
        return response

    def address_list_create_request(self, name: str) -> requests.Response:
        try:
            response = self._http_request(
                method="POST", url_suffix="/api/Systems/Filters/ListImport/Config/Install", data={"Name": name}
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when creating the IP's list."
            ) from e
        return response

    def address_list_rename_request(self, new_name: str, existing_name: str) -> requests.Response:
        try:
            response = self._http_request(
                method="PUT", url_suffix=f"/api/Systems/Filters/ListImport/ListName/{existing_name}/Config/Install",
                data={"Name": new_name}
            )
        except Exception as e:
            raise DemistoException(
                f"An error was occurred when renaming the {existing_name} IP's list to {new_name}."
            ) from e
        return response

    def address_list_delete_request(self, list_name_to_delete: str) -> requests.Response:
        try:
            response = self._http_request(
                method="DELETE",
                url_suffix=f"/api/Systems/Filters/Address/ListName/{list_name_to_delete}/Config/List",
            )
        except Exception as e:
            raise DemistoException(
                f"An error was occurred when deleting the {list_name_to_delete} IP's list."
            ) from e
        return response


''' COMMAND FUNCTIONS '''


def address_list_upload_command(client: Client, args: dict):
    """
    This function uploads a .txt file with address list to the appliance.
    The appliance temporarily stores the file until it is saved to the Library and replaces any previously loaded list file.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    entry_id = args["entry_id"]  # a required argument
    file_info = demisto.getFilePath(entry_id)
    file_path = file_info['path']
    file_name = file_info['name']

    try:
        shutil.copy(file_path, file_name)
    except Exception as exc:
        demisto.error(f'Failed to prepare file for upload. Error: {exc}')
        raise DemistoException('Failed to prepare file for upload.') from exc

    result = client.address_list_upload_request(file_name)

    if result.status_code == '200':
        return CommandResults(readable_output="Address list was successfully uploaded")
    raise DemistoException(
        f"An error was occurred when uploading the given file. Please check the file, {file_name=} and {file_path=}."
    )


def address_list_optimize_command(client: Client):
    """
    If the traffic elements are IP addresses,
    the integration should optimize the list by compressing IP addresses into CIDR groups.

    Returns:
        A CommandResults containing full API response .
    """

    result = client.address_list_optimize_request()
    return CommandResults(outputs_prefix="NetQuest.AddressList",
                          outputs=result.json())


def address_list_create_command(client: Client, args: dict):
    """
    This function replaces the old list entity and overrides it.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    name = args["name"]  # a required argument - The name of the address list to create
    result = client.address_list_create_request(name)

    if result.status_code == '200':
        return CommandResults(readable_output=f"Successfully created a new instance of {name}")
    raise DemistoException(
        f"An error was occurred when creating an IP's list with {name=}. Maybe a list with the name {name} already exists."
    )


def address_list_rename_command(client: Client, args: dict):
    """
    This function only meant to change the name of the list.
    Nothing else. If we try to give as a new_name, an existing list name, it will fail, and we’ll get an error.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    new_name = args["new_name"]  # a required argument - The new name for an existing address list
    existing_name = args["existing_name"]  # a required argument - Name of the existing address list that we want to modify
    result = client.address_list_rename_request(new_name, existing_name)

    if result.status_code == '200':
        return CommandResults(readable_output=f"Successfully renamed {existing_name} to {new_name}")
    raise DemistoException(
        f"An error was occurred when renaming {existing_name} IP's list to {new_name}."
        f" Maybe the {existing_name} list's name does not exist."
    )


def address_list_delete_command(client: Client, args: dict):
    """
    This function deletes the list by the given list's name.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    list_name_to_delete = args["name"]  # a required argument - The name of the address list to delete
    result = client.address_list_delete_request(list_name_to_delete)

    if result.status_code == '200':
        return CommandResults(readable_output=f"Successfully deleted {list_name_to_delete} list")
    raise DemistoException(
        f"An error was occurred when deleting the {list_name_to_delete} IP's list."
        f" Maybe the {list_name_to_delete} list's name does not exist."
    )


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

    message: str = ''
    try:
        # create a list and then delete it for sanity check
        address_list_create_command(client=client, args={"name": "test_module"})
        address_list_delete_command(client=client, args={"name": "test_module"})
        message = 'ok'
    except DemistoException as e:
        raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    demisto.debug(f"Command being called is {command}")

    try:

        client = Client(
            base_url=params["url"],
            credentials=params["credentials"],
            verify=verify_certificate,
            proxy=proxy,
        )

        commands: Dict[str, Callable] = {
            'netquest-address-list-upload': address_list_upload_command,
            'netquest-address-list-optimize': address_list_optimize_command,
            'netquest-address-list-create': address_list_create_command,
            'netquest-address-list-rename': address_list_rename_command,
            'netquest-address-list-delete': address_list_delete_command,

        }

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command in commands:
            return_results(commands[command](client, **args))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
