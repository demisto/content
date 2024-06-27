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

""" HELPER FUNCTIONS """


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


""" CLIENT CLASS """


class Client:
    class DeviceApproval(LoginStepDeviceApproval):
        @property
        def username(self):
            pass

        def cancel(self):
            pass

        def send_push(
            self,
            params: KeeperParams,
            channel: DeviceApprovalChannel,
            encryptedDeviceToken: bytes,
            encryptedLoginToken: bytes,
        ):
            LoginV3Flow.verifyDevice(
                params, encryptedDeviceToken, encryptedLoginToken, approval_action="push", approval_channel=channel
            )

        def send_code(
            self,
            params: KeeperParams,
            channel: DeviceApprovalChannel,
            encryptedDeviceToken: bytes,
            encryptedLoginToken: bytes,
            code: str,
        ):
            LoginV3Flow.verifyDevice(
                params,
                encryptedDeviceToken,
                encryptedLoginToken,
                approval_action="code",
                approval_channel=channel,
                approval_code=code,
            )

        def resume(self):
            pass

    class PasswordStep(LoginStepPassword):
        def __init__(self, salt_bytes: bytes, salt_iterations: int):
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

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
    ) -> None:
        self.keeper_params: KeeperParams = load_integration_context_into_keeper_params(
            username=username,
            password=password,
            server_url=server_url,
        )

    def start_registering_device(self, device_approval: DeviceApproval, new_device: bool = False):
        encryptedDeviceToken = LoginV3API.get_device_id(self.keeper_params, new_device)
        resp: APIRequest_pb2.LoginResponse = LoginV3API.startLoginMessage(
            self.keeper_params, encryptedDeviceToken, cloneCode=None, loginType="NORMAL"
        )

        append_to_integration_context(
            {
                "device_private_key": self.keeper_params.device_private_key,
                "device_token": self.keeper_params.device_token,
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
            raise DemistoException("Try running the 'complete-authentication' command without supplying a code argument")
        else:
            raise DemistoException(f"Unknown login state {resp.loginState}")  # type: ignore

    def finish_registering_device(self, device_approval: DeviceApproval, encrypted_login_token: bytes, code: str = ""):
        encrypted_device_token = utils.base64_url_decode(params.device_token)  # type: ignore
        if code:
            device_approval.send_code(
                self.keeper_params,
                DeviceApprovalChannel.Email,
                encrypted_device_token,
                encrypted_login_token,
                code,
            )
        resp = LoginV3API.startLoginMessage(self.keeper_params, encrypted_device_token)
        if resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:  # type: ignore
            salt = api.get_correct_salt(resp.salt)  # type: ignore
            password_step = self.PasswordStep(salt_bytes=salt.salt, salt_iterations=salt.iterations)
            verify_password_response = password_step.verify_password(self.keeper_params, encrypted_login_token)
            if verify_password_response.loginState == APIRequest_pb2.LOGGED_IN:  # type: ignore
                LoginV3Flow.post_login_processing(self.keeper_params, verify_password_response)
            else:
                raise DemistoException(f"Unknown login state after verify password {verify_password_response.loginState}")  # type: ignore
        else:
            raise DemistoException(f"Unknown login state {resp.loginState}")  # type: ignore

    def start_login(self):
        device_approval = self.DeviceApproval()
        try:
            self.start_registering_device(device_approval)
        except InvalidDeviceToken:
            demisto.info("Registering new device")
            self.start_registering_device(device_approval, new_device=True)

    def complete_login(self, code: str):
        device_approval = self.DeviceApproval()
        integration_context = get_integration_context()
        encrypted_login_token = utils.base64_url_decode(integration_context["login_token"])
        self.finish_registering_device(device_approval, encrypted_login_token, code)
        append_to_integration_context(
            {
                "session_token": self.keeper_params.session_token,
                "clone_code": self.keeper_params.clone_code,
            }
        )
        if not self.keeper_params.session_token:
            raise DemistoException("Could not find session token")

    def query_audit_logs(self, limit: int, start_event_time: int) -> dict[str, Any]:
        request_query = {
            "command": "get_audit_event_reports",
            "report_type": "raw",
            "scope": "enterprise",
            "limit": limit,
            "order": "ascending",
            "filter": {"min": start_event_time},
        }
        return api.communicate(self.keeper_params, request_query)


def test_module() -> None:
    raise DemistoException(
        "In order to authorize the instance, first run the command `!ksm-event-collector-auth-start`."
        " A code will be sent to your email, copy it and paste that value in the command"
        " `!ksm-event-collector-auth-complete` as an argument to finish the process."
    )


""" MAIN FUNCTION """


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_audit_logs(
    client: Client, start_event_time: int, max_fetch_limit: int, last_fetched_ids: set[str]
) -> list[dict[str, Any]]:
    max_fetch_limit = 9
    continue_fetching = True
    events_to_return: list[dict[str, Any]] = []
    # start_event_time -> UNIX epoch time in seconds
    start_time_to_fetch = start_event_time
    fetched_ids = last_fetched_ids
    limit = max_fetch_limit
    while continue_fetching:
        # query_response = client.query_audit_logs(limit=limit, start_event_time=start_time_to_fetch)
        # audit_events = query_response["audit_event_overview_report_rows"]
        audit_events: list[dict[str, Any]] = load_json("mocked_data_2.json")
        audit_events_count = len(audit_events)
        demisto.debug(f"{LOG_LINE} got {audit_events_count} events from API")
        if audit_events:
            # dedup
            dedupped_audit_events = dedup_events(audit_events, fetched_ids)
            if audit_events_count == limit and dedupped_audit_events:
                # We fetched the maximum amount, and we fetched new events
                # We need to make up for dedupped events by running another fetch
                dedupped_events_count = len(dedupped_audit_events)
                limit = audit_events_count - dedupped_events_count
            else:
                # We did not reach the limit, or all events have been dropped
                # No need to continue fetching
                continue_fetching = False
            if dedupped_audit_events:
                events_to_return.extend(dedupped_audit_events)

                # Getting last events's creation date, assuming asc order
                start_time_to_fetch: int = int(dedupped_audit_events[-1]["created"])
                # We get the event IDs that have the same creation time as the latest event in the response
                # We use them to dedup in the next run
                fetched_ids: set[str] = {
                    str(audit_event["id"])
                    for audit_event in dedupped_audit_events
                    if int(audit_event["created"]) == start_time_to_fetch
                }
        else:
            continue_fetching = False
    demisto.setLastRun({"last_fetch_epoch_time": str(start_time_to_fetch), "last_fetch_ids": list(fetched_ids)})
    return events_to_return


def dedup_events(audit_events: list[dict[str, Any]], last_fetched_ids: set[str]) -> list[dict[str, Any]]:
    dedupped_audit_events = list(
        filter(
            lambda audit_event: str(audit_event["id"]) not in last_fetched_ids,
            audit_events,
        )
    )
    return dedupped_audit_events


def fetch_events(client: Client, last_run: dict[str, Any], max_fetch_limit: int):
    demisto.debug(f"last_run: {last_run}" if last_run else "last_run is empty")
    # We save the last_fetch_epoch_time in string format, to gracefully handle how the backend server handles
    # data saved to the last run object
    last_fetch_epoch_time: int = int(last_run.get("last_fetch_epoch_time", "0"))

    # (if 0) returns False
    last_fetch_epoch_time = last_fetch_epoch_time if last_fetch_epoch_time else int(datetime.now().timestamp())
    last_fetched_ids: set[str] = set(last_run.get("last_fetch_ids", []))
    audit_log = get_audit_logs(
        client=client,
        start_event_time=last_fetch_epoch_time,
        max_fetch_limit=max_fetch_limit,
        last_fetched_ids=last_fetched_ids,
    )


def test_authorization(
    client: Client,
) -> CommandResults:
    client.query_audit_logs(limit=1, start_event_time=0)
    return CommandResults(readable_output="Successful connection.")


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    username = params.get("credentials", {})["identifier"]
    password = params.get("credentials", {})["password"]
    server_url = params.get("url") or "keepersecurity.com"
    client = Client(
        server_url=server_url,
        username=username,
        password=password,
    )
    client.start_login()
    # client.complete_login(device_approval, keeper_params, "")
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module())
        elif command == "ksm-event-collector-auth-start":
            client.start_login()
        elif command == "ksm-event-collector-auth-complete":
            client.complete_login(code=args.get("code", ""))
        elif command == "ksm-event-collector-auth-test":
            return_results(test_authorization(client=client))
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            fetch_events(
                client=client,
                last_run=last_run,
                max_fetch_limit=DEFAULT_MAX_FETCH,
            )
            # next_run, events = collector.fetch_command(demisto_last_run=last_run)
            # demisto.debug(f"{events=}")
            # send_events_to_xsiam(events, VENDOR, PRODUCT)
            # demisto.setLastRun(next_run)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
