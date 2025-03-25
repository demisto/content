import tempfile
from collections.abc import Callable
from enum import Enum
from pathlib import Path

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
TOKEN_TTL_S = 120 * 60  # tokens are valid for 120 minutes
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_FORMAT_FOR_TOKEN = "%m/%d/%Y, %H:%M:%S"
VENDOR = "NetQuest"
PRODUCT = "OMX"

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, credentials: dict, verify: bool, proxy: bool):
        self._headers = {"Accept": "application/json", "X-Auth-Token": ""}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self._headers)
        self.credentials = {"UserName": credentials["identifier"], "Password": credentials["password"]}
        self.login()

    def login(self):
        """
        If there's an existing token in context, its validity is checked.
        Otherwise, logs in and stores token in the `Client` instance
        Refreshes the token as needed.
        """
        now = datetime.utcnow()

        if (cache := get_integration_context()) and cache.get("Token"):
            expiration_time = datetime.strptime(
                cache["expiration_time"], DATE_FORMAT_FOR_TOKEN
            )

            # if the token is still valid, continue using it. otherwise, generate a new one.
            if (seconds_left := (expiration_time - now).total_seconds()) > 60:  # decreasing 60s from token expiry for safety
                demisto.debug(f"No need to regenerate the token, it is still valid for {seconds_left} more seconds")
                self._headers["X-Auth-Token"] = cache["Token"]  # in this case, the Token key exists
                return

        demisto.debug("IntegrationContext token cache is empty or token has expired, regenerating a new token")

        self._refresh_access_token(now)

    def _refresh_access_token(self, now: datetime):
        """
        Since the validity of the Access Token is 120 minutes, this method refreshes the token
        and keep the token and the expiration time in the integration context.
        """

        try:
            response = self._http_request(
                method="POST", url_suffix="/api/SessionService/Sessions", json_data=self.credentials, resp_type='response'
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when creating a new token. Please verify your credentials."
            ) from e

        new_token = response.headers["X-Auth-Token"]
        self._headers["X-Auth-Token"] = new_token
        set_integration_context(
            {
                "Token": new_token,
                "expiration_time": (
                    now + timedelta(seconds=TOKEN_TTL_S)
                ).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        )

    def address_list_upload_request(self, file_name: str, file_path: str):
        """
        Sends a POST request to upload an address list file to the appliance.

        The file is managed as a temporary file to ensure proper cleanup.

        Args:
            file_name (str): The name of the original file to be uploaded.
            file_path (str): The path to the original file to be uploaded.

        Raises:
            DemistoException: If the HTTP request fails or other errors occur.
        """
        try:
            # Create a temporary file
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file_name = temp_file.name

                # Copy the contents of the original file to the temporary file
                Path(temp_file_name).write_bytes(Path(file_path).read_bytes())

                # Use the temporary file for the upload request
                self._http_request(
                    method="POST",
                    url_suffix="/api/v1/UpdateService/ImportList/Config",
                    files={"UpdateFile": open(temp_file_name, 'rb')},
                    ok_codes=(200,)
                )
        except Exception as e:
            raise DemistoException(f"An error occurred while uploading the file {file_name}."
                                   ) from e
        finally:
            # Ensure the temporary file is deleted
            Path(temp_file_name).unlink(missing_ok=True)

    def address_list_optimize_request(self) -> dict:
        try:
            response_json = self._http_request(
                method="GET", url_suffix="/api/Systems/Filters/Address/Status/Optimization"
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when optimizing the list of IPs."
            ) from e

        return response_json

    def address_list_create_request(self, name: str):
        try:
            self._http_request(
                method="POST", url_suffix="/api/Systems/Filters/ListImport/Config/Install",
                json_data={"Name": name},
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when creating the list of IPs."
            ) from e

    def address_list_rename_request(self, new_name: str, existing_name: str):
        try:
            self._http_request(
                method="PUT", url_suffix=f"/api/Systems/Filters/ListImport/ListName/{existing_name}/Config/Install",
                json_data={"Name": new_name},
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                f"An error occurred when renaming the {existing_name} IP list to {new_name}."
            ) from e

    def address_list_delete_request(self, list_name_to_delete: str):
        try:
            self._http_request(
                method="DELETE",
                url_suffix=f"/api/Systems/Filters/Address/ListName/{list_name_to_delete}/Config/List",
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                f"An error was occurred when deleting the {list_name_to_delete} IP list."
            ) from e

    def metering_stats_request(self, slot_number: str, port_number: str) -> dict[str, Any]:
        try:
            metering_stats_event = self._http_request(
                method="GET",
                url_suffix=f"/api/Systems/Slot/{slot_number}/Ipfix/Status/Metering",
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when requesting for an event of Metering Stats type."
            ) from e

        metering_stats_event["STAT_TYPE"] = 'MeteringStats'

        return metering_stats_event

    def export_stats_request(self, slot_number: str, port_number: str) -> dict[str, Any]:
        try:
            export_stats_event = self._http_request(
                method="GET",
                url_suffix=f"/api/Systems/Slot/{slot_number}/Ipfix/Status/Export",
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when requesting for an event of Export Stats type."
            ) from e

        export_stats_event["STAT_TYPE"] = 'ExportStats'

        return export_stats_event

    def export_peaks_FPS_request(self, slot_number: str, port_number: str) -> dict[str, Any]:
        try:
            export_peaks_FPS_event = self._http_request(
                method="GET",
                url_suffix=f"/api/Systems/Slot/{slot_number}/Ipfix/Status/ExportHwm",
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when requesting for an event of Export Peaks FPS type."
            ) from e

        export_peaks_FPS_event["STAT_TYPE"] = 'ExportPeaksFPS'

        return export_peaks_FPS_event

    def optimization_stats_request(self, slot_number: str, port_number: str) -> dict[str, Any]:
        try:
            optimization_stats_event = self._http_request(
                method="GET",
                url_suffix=f"/api/Systems/Slot/{slot_number}/Port/{port_number}/EthernetInterfaces/Status/EthRxTx",
                ok_codes=(200,)
            )
        except Exception as e:
            raise DemistoException(
                "An error was occurred when requesting for an event of Optimization Stats type."
            ) from e

        optimization_stats_event["STAT_TYPE"] = 'OptimizationStats'

        return optimization_stats_event


''' COMMAND FUNCTIONS '''


class StatType(Enum):
    METERING_STATS = "Metering Stats"
    EXPORT_STATS = "Export Stats"
    EXPORT_PEAKS_FPS = "Export Peaks FPS"
    OPTIMIZATION_STATS = "Optimization Stats"


def address_list_upload_command(client: Client, args: dict) -> CommandResults:
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
        client.address_list_upload_request(file_name, file_path)
    except Exception as e:
        raise DemistoException(
            f"An error occurred when uploading {file_name}."
        ) from e

    return CommandResults(readable_output="Address list was successfully uploaded")


def address_list_optimize_command(client: Client, args: dict = None) -> CommandResults:
    """
    If the traffic elements are IP addresses,
    the integration should optimize the list by compressing IP addresses into CIDR groups.

    Returns:
        A CommandResults containing full API response.
    """

    response_json = client.address_list_optimize_request()

    return CommandResults(outputs_prefix="NetQuest.AddressList",
                          outputs=response_json)


def address_list_create_command(client: Client, args: dict) -> CommandResults:
    """
    This function replaces the old list entity and overrides it.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    name = args["name"]  # a required argument - The name of the address list to create
    try:
        client.address_list_create_request(name)
    except Exception as e:
        raise DemistoException(
            f"An error was occurred when creating an IP list with {name=}."
            f" This may indicate a list with this name already exists."
        ) from e

    return CommandResults(readable_output=f"Successfully created a new instance of {name}")


def address_list_rename_command(client: Client, args: dict) -> CommandResults:
    """
    This function only meant to change the name of the list.
    Nothing else. If we try to give as a new_name, an existing list name, it will fail, and we’ll get an error.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    new_name = args["new_name"]  # a required argument - The new name for an existing address list
    existing_name = args["existing_name"]  # a required argument - Name of the existing address list that we want to modify

    try:
        client.address_list_rename_request(new_name, existing_name)
    except Exception as e:
        raise DemistoException(
            f"An error was occurred when renaming {existing_name} IPs list to {new_name}."
            f" Make sure {existing_name} exists and that {new_name} doesn't."
        ) from e

    return CommandResults(readable_output=f"Successfully renamed {existing_name} to {new_name}")


def address_list_delete_command(client: Client, args: dict) -> CommandResults:
    """
    This function deletes the list by the given list's name.

    Returns:
        A CommandResults containing a success indication or a DemistoException.
    """
    list_name_to_delete = args["name"]  # a required argument - The name of the address list to delete

    try:
        client.address_list_delete_request(list_name_to_delete)
    except Exception as e:
        raise DemistoException(
            f"An error was occurred when deleting the {list_name_to_delete} IPs list."
            f" Make sure {list_name_to_delete} exists."
        ) from e

    return CommandResults(readable_output=f"Successfully deleted {list_name_to_delete} list")


def add_time_to_events(events: list[dict]) -> None:
    """
    Adds the _time key to the events.
    Args:
        events: list[dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    create_time = datetime.utcnow().strftime(DATE_FORMAT)
    for event in events:
        event["_time"] = create_time  # type: ignore[union-attr]


def fetch_events(client: Client, slot_number: str, port_number: str, statistic_types_to_fetch: list[str]) -> list[dict]:
    """
    Args:
        client (Client): NetQuest client to use.
        slot_number (str): A Target Netquest device slot number.
        port_number (str): A port number to use.
        statistic_types_to_fetch (list): List of event types to fetch.
    Returns:
        events (list[dict]): A list of events (number of events equal to the number of statistic types given)
        that will be created in XSIAM.
    """
    demisto.debug(f'Starting Fetch: {slot_number=}, {port_number=}')

    events: list[dict] = []
    statistic_types_mapping: Dict[str, Callable] = {
        'Metering Stats': client.metering_stats_request,
        'Export Stats': client.export_stats_request,
        'Export Peaks FPS': client.export_peaks_FPS_request,
        'Optimization Stats': client.optimization_stats_request,
    }

    events.extend(
        statistic_types_mapping[statistic_type](slot_number, port_number)
        for statistic_type in statistic_types_to_fetch
    )

    return events


def get_events(client: Client, params: dict, args: dict) -> list[dict]:
    """
    Args:
        client (Client): NetQuest client to use.
        params (dict)
        args (dict)
    Returns:
        events (list[dict]): A list of events (number of events equal to the number of statistic types given)
        that will be created in XSIAM.
    """

    # validate the input
    statistic_types_to_fetch = argToList(args.get("statistic_types_to_fetch", [])
                                         or params.get("statistic_types_to_fetch", []))  # arg overrides the param

    for statistic_type in statistic_types_to_fetch:
        if statistic_type not in StatType._value2member_map_:
            raise DemistoException(f"{statistic_types_to_fetch} is not a valid type."
                                   f" Valid types are {list(StatType._value2member_map_.keys())}."
                                   f" Execute the command get-events again with valid input.")

    # execute the command
    events = fetch_events(
        client=client,
        slot_number=params["slot"],  # a required param
        port_number=params["port"],  # a required param
        statistic_types_to_fetch=statistic_types_to_fetch
    )

    return events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
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
            # This is the call made when pressing the integration Test button - it returns 'ok' (success) if the client was built.
            return_results('ok')

        elif command in commands:
            return_results(commands[command](client, args))

        elif command == "fetch-events":
            events = fetch_events(
                client=client,
                slot_number=params["slot"],  # a required param (used only for urls, so it will remain a string)
                port_number=params["port"],  # a required param (used only for urls, so it will remain a string)
                statistic_types_to_fetch=argToList(params.get("statistic_types_to_fetch", []))
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.debug(f'fetched and sent {len(events)} events to xsiam.')

        elif command == "get-events":
            events = get_events(client, params, args)

            return_results(
                CommandResults(
                    readable_output=tableToMarkdown(f"{VENDOR} Events:", events),
                    outputs=events
                )
            )

            if argToBoolean(args["should_push_events"]):
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # prints the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
