import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from keepercommander import api
from keepercommander.params import KeeperParams
from keepercommander.auth.login_steps import LoginStepDeviceApproval, DeviceApprovalChannel, LoginStepPassword
from keepercommander import utils, crypto
from keepercommander.loginv3 import LoginV3Flow, LoginV3API, InvalidDeviceToken
from keepercommander.proto import APIRequest_pb2

""" CONSTANTS """

VENDOR = "Keeper"
PRODUCT = "Secrets Manager"
LOG_LINE = f"{VENDOR}_{PRODUCT}:"
DEFAULT_MAX_FETCH = 1000

""" Fetch Events Classes"""
LAST_RUN = "Last Run"

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


""" HELPER FUNCTIONS """

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):  # TODO: make sure you capture authentication errors
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    dummy = args.get("dummy", None)
    if not dummy:
        raise ValueError("dummy not specified")

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


class LastRun:
    def __init__(
        self,
        start_time: datetime | None = None,
        last_ids: set | None = None,
    ) -> None:
        self.last_run_timestamp = start_time if start_time else datetime.now()
        self.last_ids = last_ids if last_ids else set()

    def set_last_ids(self, ids: set[str]) -> None:
        self.last_ids = set(ids) if isinstance(ids, list) else ids

    def to_demisto_last_run(self) -> dict:
        # if not self.event_types:
        #     return {}
        # data = {
        #     LAST_RUN: {
        #         event_type.name: self.__getattribute__(
        #             event_type.name
        #         ).to_demisto_last_run()
        #         for event_type in self.event_types
        #     }
        # }
        # return data
        ...

    def add_event_type(
        self,
        event_type: str,
        start_time: datetime,
        last_ids: set,
        event_types: list[str],
    ) -> None:
        # setattr(self, event_type, self.LastRunEvent(start_time, last_ids))
        # event_type_from_str = next(filter(lambda x: x.name == event_type, event_types))
        # self.event_types.append(event_type_from_str)
        ...


def get_last_run_from_dict(data: dict, event_types: list[str]) -> LastRun:
    new_last_run = LastRun()
    demisto.debug(f"{LOG_LINE} - Starting to parse last run from server: {str(data.get(LAST_RUN, 'Missing Last Run key'))}")

    for event_type in data.get(LAST_RUN, {}):
        demisto.debug(f"{LOG_LINE} - Parsing {event_type=}")

        time = datetime.fromisoformat(data[LAST_RUN].get(event_type, {}).get("last_fetch_timestamp"))
        ids = set(data[LAST_RUN].get(event_type, {}).get("last_fetch_last_ids", []))
        demisto.debug(f"{LOG_LINE} - found id and timestamp in data, adding. \n {ids=}, {time=}")

        new_last_run.add_event_type(event_type, time, ids, event_types)

    demisto.debug(f"{LOG_LINE} - last run was loaded successfully.")

    return new_last_run


class DeviceApproval(LoginStepDeviceApproval):
    def __init__(
        self,
        params: KeeperParams,
    ):
        self.params = params

    @property
    def username(self):
        pass

    def cancel(self):
        pass

    def send_push(self, channel: DeviceApprovalChannel, encryptedDeviceToken: bytes, encryptedLoginToken: bytes):
        LoginV3Flow.verifyDevice(
            self.params, encryptedDeviceToken, encryptedLoginToken, approval_action="push", approval_channel=channel
        )

    def send_code(self, channel: DeviceApprovalChannel, encryptedDeviceToken: bytes, encryptedLoginToken: bytes, code: str):
        LoginV3Flow.verifyDevice(
            self.params,
            encryptedDeviceToken,
            encryptedLoginToken,
            approval_action="code",
            approval_channel=channel,
            approval_code=code,
        )

    def resume(self):
        pass


class PasswordStep(LoginStepPassword):
    def __init__(self, params: KeeperParams, salt_bytes, salt_iterations):
        self.params = params
        self.salt_bytes = salt_bytes
        self.salt_iterations = salt_iterations

    @property
    def username(self):
        pass

    def forgot_password(self):
        pass

    def verify_password(self, params: KeeperParams, encryptedLoginToken: bytes) -> APIRequest_pb2.LoginResponse:
        params.auth_verifier = crypto.derive_keyhash_v1(params.password, self.salt_bytes, self.salt_iterations)  # type: ignore
        return LoginV3API.validateAuthHashMessage(params, encryptedLoginToken)

    def verify_biometric_key(self, biometric_key):
        pass

    def cancel(self):
        pass


def start_registering_device(device_approval: DeviceApproval, params: KeeperParams, new_device: bool = False):
    encryptedDeviceToken = LoginV3API.get_device_id(params, new_device)
    resp: APIRequest_pb2.LoginResponse = LoginV3API.startLoginMessage(
        params, encryptedDeviceToken, cloneCode=None, loginType="NORMAL"
    )

    append_to_integration_context(
        {
            "device_private_key": params.device_private_key,
            "device_token": params.device_token,
            "login_token": utils.base64_url_encode(resp.encryptedLoginToken),  # type: ignore
        }
    )

    if resp.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:  # type: ignore # client goes to “standard device approval”.
        device_approval.send_push(
            DeviceApprovalChannel.Email,
            encryptedDeviceToken,
            resp.encryptedLoginToken,  # type: ignore
        )
    elif resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:  # type: ignore
        raise DemistoException("Try running the finish registration device command without supplying a code")
    else:
        raise DemistoException(f"Unknown login state {resp.loginState}")  # type: ignore


def finish_registering_device(
    device_approval: DeviceApproval, params: KeeperParams, encrypted_login_token: bytes, code: str = ""
):
    encrypted_device_token = utils.base64_url_decode(params.device_token)  # type: ignore
    if code:
        device_approval.send_code(
            DeviceApprovalChannel.Email,
            encrypted_device_token,
            encrypted_login_token,
            code,
        )
    resp = LoginV3API.startLoginMessage(params, encrypted_device_token)
    if resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:  # type: ignore
        salt = api.get_correct_salt(resp.salt)  # type: ignore
        password_step = PasswordStep(params, salt_bytes=salt.salt, salt_iterations=salt.iterations)
        verify_password_response = password_step.verify_password(params, encrypted_login_token)
        if verify_password_response.loginState == APIRequest_pb2.LOGGED_IN:  # type: ignore
            LoginV3Flow.post_login_processing(params, verify_password_response)
        else:
            raise DemistoException(f"Unknown login state after verify password {verify_password_response.loginState}")  # type: ignore
    else:
        raise DemistoException(f"Unknown login state {resp.loginState}")  # type: ignore


def start_login(device_approval: DeviceApproval, params: KeeperParams):
    try:
        start_registering_device(device_approval, params)
    except InvalidDeviceToken:
        logging.warning("Registering new device")
        start_registering_device(device_approval, params, new_device=True)


def complete_login(device_approval: DeviceApproval, params: KeeperParams, code: str):
    integration_context = get_integration_context()
    encrypted_login_token = utils.base64_url_decode(integration_context["login_token"])
    finish_registering_device(device_approval, params, encrypted_login_token, code)
    append_to_integration_context(
        {
            "session_token": params.session_token,
            "clone_code": params.clone_code,
        }
    )


""" MAIN FUNCTION """


def load_integration_context_into_keeper_params(
    username: str,
    password: str,
    server_url: str,
):
    integration_context = get_integration_context()
    keeper_params = KeeperParams()
    keeper_params.user = username
    keeper_params.password = password
    keeper_params.server = server_url

    # To allow requests to bypass proxy
    keeper_params.rest_context.certificate_check = False

    keeper_params.device_token = integration_context.get("device_token")
    keeper_params.device_private_key = integration_context.get("device_private_key")
    keeper_params.session_token = integration_context.get("session_token")
    keeper_params.clone_code = integration_context.get("clone_code")
    return keeper_params


def append_to_integration_context(context_to_append: dict[str, Any]):
    integration_context = get_integration_context()
    integration_context |= context_to_append
    set_integration_context(integration_context)


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_audit_logs(keeper_params: KeeperParams, start_event_time: int, max_fetch_limit: int, last_fetched_ids: set[str]):
    last_fetched_ids = {"11099258860", "11099258861", "11099258862"}
    max_fetch_limit = 9
    # start_event_time -> UNIX epoch time in seconds

    continue_fetching = True
    events_to_return = []
    start_time_to_fetch = start_event_time
    next_run_fetched_ids = last_fetched_ids
    limit = max_fetch_limit
    rq = {
        "command": "get_audit_event_reports",
        "report_type": "raw",
        "scope": "enterprise",
        "limit": limit,
        "order": "ascending",
    }

    rq["filter"] = {
        "created": {"min": 0}  # return audit events starting start_event_time
    }
    while continue_fetching:
        rq["limit"] = limit
        rq["filter"] = {
            "created": {"min": start_time_to_fetch}  # return audit events starting start_event_time
        }
        # rs = api.communicate(keeper_params, rq)
        # audit_events = rs["audit_event_overview_report_rows"]
        audit_events: list[dict[str, Any]] = load_json("mocked_data_2.json")
        audit_events_count = len(audit_events)
        demisto.debug(f"{LOG_LINE} got {len(audit_events)} events from API")
        if audit_events:
            # dedup
            dedupped_audit_events = dedup_events(audit_events, last_fetched_ids)
            if audit_events_count == limit and dedupped_audit_events:
                dedupped_events_count = len(dedupped_audit_events)
                # We need to make up for dedupped events by running another fetch
                limit = audit_events_count - dedupped_events_count
            else:
                continue_fetching = False

            events_to_return.extend(dedupped_audit_events)

            # Getting last events's creation date, assuming asc order
            start_time_to_fetch: int = int(dedupped_audit_events[-1]["created"])
            # We get the event IDs that have the same creation time as the latest event in the response
            # We use them to dedup in the next run
            next_run_fetched_ids: set[str] = {
                str(audit_event["id"])
                for audit_event in dedupped_audit_events
                if int(audit_event["created"]) == start_time_to_fetch
            }
        else:
            continue_fetching = False
    demisto.setLastRun({"last_fetch_epoch_time": str(start_time_to_fetch), "last_fetch_ids": list(next_run_fetched_ids)})


def dedup_events(audit_events: list[dict[str, Any]], last_fetched_ids: set[str]) -> list[dict[str, Any]]:
    dedupped_audit_events = list(
        filter(
            lambda audit_event: str(audit_event["id"]) not in last_fetched_ids,
            audit_events,
        )
    )
    return dedupped_audit_events


def fetch_events(keeper_params: KeeperParams, last_run: dict[str, Any], max_fetch_limit: int):
    demisto.debug(f"last_run: {last_run}" if last_run else "last_run is empty")
    # We save the last_fetch_epoch_time in string format, to gracefully handle how the backend server handles
    # data saved to the last run object
    last_fetch_epoch_time: int = int(last_run.get("last_fetch_epoch_time", "0"))

    # (if 0) returns False
    last_fetch_epoch_time = int(last_fetch_epoch_time) if last_fetch_epoch_time else int(datetime.now().timestamp())
    last_fetched_ids: set[str] = set(last_run.get("last_fetch_ids", []))
    audit_log = get_audit_logs(
        keeper_params=keeper_params,
        start_event_time=last_fetch_epoch_time,
        max_fetch_limit=max_fetch_limit,
        last_fetched_ids=last_fetched_ids,
    )


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    username = params.get("credentials", {})["identifier"]
    password = params.get("credentials", {})["password"]
    server_url = params.get("url") or "keepersecurity.com"
    keeper_params = load_integration_context_into_keeper_params(username, password, server_url)
    device_approval = DeviceApproval(keeper_params)
    # start_login(device_approval, keeper_params)
    # complete_login(device_approval, keeper_params, "")
    if not keeper_params.session_token:
        exit(1)
    print("logged in")
    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get("insecure", False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(base_url=server_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif command == "baseintegration-dummy":
            events = []
            finished = False
            # UNIX epoch time in seconds
            last_event_time = 0
            logged_ids = set()
            finished = True
            rq = {
                "command": "get_audit_event_reports",
                "report_type": "raw",
                "scope": "enterprise",
                "limit": 1000,
                "order": "ascending",
            }

            if last_event_time > 0:
                rq["filter"] = {
                    "created": {"min": last_event_time}  # return audit events starting last_event_time
                }

            rs = api.communicate(keeper_params, rq)
            audit_events = rs["audit_event_overview_report_rows"]
            demisto.info(len(rs))
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            fetch_events(
                keeper_params=keeper_params,
                last_run=last_run,
                max_fetch_limit=DEFAULT_MAX_FETCH,
            )
            # next_run, events = collector.fetch_command(demisto_last_run=last_run)
            # demisto.debug(f"{events=}")
            # send_events_to_xsiam(events, VENDOR, PRODUCT)
            # demisto.setLastRun(next_run)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
