import urllib3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from keepercommander.params import KeeperParams
from keepercommander.auth.login_steps import LoginStepDeviceApproval, DeviceApprovalChannel, LoginStepPassword
from keepercommander import utils, crypto, api
from keepercommander.loginv3 import LoginV3Flow, LoginV3API, InvalidDeviceToken
from keepercommander.proto import APIRequest_pb2
from datetime import datetime

""" CONSTANTS """

# We fetch from the Keeper Security Admin Console, so the Product is not "Security", but we assigned it as such
# so the dataset could have the name keeper_security_raw
VENDOR = "Keeper"
PRODUCT = "Security"
LOG_LINE = f"{VENDOR}_{PRODUCT}:"
DEFAULT_MAX_FETCH = 10000
API_MAX_FETCH = 1000
SESSION_TOKEN_TTL = 3600  # In seconds
REGISTRATION_FLOW_MESSAGE = (
    "In order to authorize the instance, first run the command `!keeper-security-register-start`."
    " A code will be sent to your email, copy it and paste that value in the command"
    " `!keeper-security-register-complete` as an argument to finish the process."
)
DEVICE_ALREADY_REGISTERED = (
    "Device is already registered, try running the 'keeper-security-register-complete'"
    " command without supplying a code argument."
)
SSO_REDIRECT = (
    "Login was redirected to a cloud SSO. Please disable SSO redirect to continue."
)
LAST_RUN = "Last Run"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

# Disable insecure warnings
urllib3.disable_warnings()


""" HELPER FUNCTIONS """


def get_current_time_in_seconds() -> int:
    """A function to return time as an int number of seconds since the epoch

    Returns:
        int: Number of seconds since the epoch
    """
    return int(datetime.now().timestamp())


def load_integration_context_into_keeper_params(
    username: str,
    password: str,
    server_url: str,
):
    """Load data from the integration context into a KeeperParams instance, which is used
    to communicate with the product. We call it inside the init method of the Client that
    will be used to communicate with the product.

    Args:
        username (str): The username of the account.
        password (str): The password of the account.
        server_url (str): The server URL.

    Returns:
        KeeperParams: An instance that will be used to communicate with the product.
    """
    integration_context = get_integration_context()
    keeper_params = KeeperParams()
    keeper_params.user = username
    keeper_params.password = password
    keeper_params.server = server_url

    # To allow requests to bypass proxy
    # ref -> https://docs.keeper.io/en/v/secrets-manager/commander-cli/troubleshooting-commander-cli#ssl-certificate-errors
    keeper_params.rest_context.certificate_check = False

    keeper_params.device_token = integration_context.get("device_token")
    keeper_params.device_private_key = integration_context.get("device_private_key")
    keeper_params.session_token = integration_context.get("session_token")
    keeper_params.clone_code = integration_context.get("clone_code")
    return keeper_params


def append_to_integration_context(context_to_append: dict[str, Any]):
    """Appends data to the integration context DB.

    Args:
        context_to_append (dict[str, Any]): Context data to append
    """
    integration_context = get_integration_context()
    integration_context |= context_to_append
    set_integration_context(integration_context)


""" CLIENT CLASS """


class Client:
    class DeviceApproval(LoginStepDeviceApproval):
        """
        In charge of sending and verifying the code sent to the user's email when registering the device for the first time.
        LoginStepDeviceApproval is is an abstract class that must be implemented. Some of the abstract methods
        are not needed, therefore, we implement them by including a pass segment.
        """

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
        """
        In charge of verifying the user's password after verifying the device registration.
        LoginStepPassword is is an abstract class that must be implemented. Some of the abstract methods
        are not needed, therefore, we implement them by including a pass segment.
        """

        def __init__(self, salt_bytes: bytes, salt_iterations: int):
            self.salt_bytes = salt_bytes
            self.salt_iterations = salt_iterations

        @property
        def username(self):
            pass

        def forgot_password(self):
            pass

        def verify_password(self, params: KeeperParams, encryptedLoginToken: bytes) -> Any:
            # This function returns the data type APIRequest_pb2.LoginResponse
            params.auth_verifier = crypto.derive_keyhash_v1(params.password, self.salt_bytes, self.salt_iterations)
            return LoginV3API.validateAuthHashMessage(params, encryptedLoginToken)

        def verify_biometric_key(self, biometric_key: bytes):
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

    def refresh_session_token_if_needed(
        self,
    ) -> None:
        """Refresh the session token if needed.

        Raises:
            DemistoException: If saved the TTL of the session token, but it is not found in the
            integration's context.
        """
        integration_context = get_integration_context()
        valid_until = integration_context.get("valid_until", 0)
        current_time = get_current_time_in_seconds()
        if self.keeper_params.session_token and current_time >= valid_until - 10:
            demisto.info("Refreshing session token")
            encrypted_device_token = LoginV3API.get_device_id(self.keeper_params)
            resp = self.save_device_tokens(
                encrypted_device_token=encrypted_device_token,
            )
            encrypted_login_token: bytes = resp.encryptedLoginToken

            self.validate_device_registration(
                encrypted_device_token=encrypted_device_token,
                encrypted_login_token=encrypted_login_token,
            )
            self.save_session_token()
        else:
            demisto.info("No need to refresh session token")

    def save_device_tokens(self, encrypted_device_token: bytes) -> Any:
        """Save the devices' tokens when starting to verify the device registration.

        Args:
            encrypted_device_token (bytes): The encrypted device token.

        Returns:
            APIRequest_pb2.LoginResponse: The response that holds data about the API call.
        """
        # This function returns the data type APIRequest_pb2.LoginResponse
        resp = LoginV3API.startLoginMessage(self.keeper_params, encrypted_device_token, cloneCode=None, loginType="NORMAL")
        append_to_integration_context(
            {
                "device_private_key": self.keeper_params.device_private_key,
                "device_token": self.keeper_params.device_token,
                "login_token": utils.base64_url_encode(resp.encryptedLoginToken),
            }
        )
        return resp

    def start_registering_device(
        self,
        device_approval: DeviceApproval,
        new_device: bool = False,
    ):
        """Start the registration process of a new or old device.

        Args:
            device_approval (DeviceApproval): DeviceApproval instance that is in charge of sending the code to the
            user's email.
            new_device (bool, optional): If we should configure a new device. Defaults to False.

        Raises:
            DemistoException: If we try registering an already registered and authenticated device.
            DemistoException: If we get a response status that we don't know how to handle.
        """
        encryptedDeviceToken = LoginV3API.get_device_id(self.keeper_params, new_device)
        resp = self.save_device_tokens(
            encrypted_device_token=encryptedDeviceToken,
        )
        if resp.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:
            # client goes to “standard device approval”
            device_approval.send_push(
                self.keeper_params,
                DeviceApprovalChannel.Email,
                encryptedDeviceToken,
                resp.encryptedLoginToken,
            )
        elif resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
            raise DemistoException(DEVICE_ALREADY_REGISTERED)
        elif resp.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO:
            raise DemistoException(SSO_REDIRECT)
        else:
            raise DemistoException(f"Unknown login state {resp.loginState}")

    def validate_device_registration(
        self,
        encrypted_device_token: bytes,
        encrypted_login_token: bytes,
    ):
        """Verify the registration process of a new or old device. This method is also used as part of the
        mechanism to refresh the session token.

        Args:
            encrypted_device_token (bytes): The encrypted device token.
            encrypted_login_token (bytes): The encrypted login token.

        Raises:
            DemistoException: When trying to verify the user's password, and an error occurs.
            DemistoException: When trying to verify the device registration, and an error occurs.
        """
        resp = LoginV3API.startLoginMessage(self.keeper_params, encrypted_device_token)
        if resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
            salt = api.get_correct_salt(resp.salt)
            password_step = self.PasswordStep(salt_bytes=salt.salt, salt_iterations=salt.iterations)
            verify_password_response = password_step.verify_password(self.keeper_params, encrypted_login_token)
            # Disabling pylint due to external class declaration
            if verify_password_response.loginState == APIRequest_pb2.LOGGED_IN:  # pylint: disable=no-member
                LoginV3Flow.post_login_processing(self.keeper_params, verify_password_response)
            else:
                raise DemistoException(
                    "Unknown login state after verify"
                    # Disabling pylint due to external class declaration
                    f" password {verify_password_response.loginState}"  # pylint: disable=no-member
                )
        else:
            raise DemistoException(f"Unknown login state {resp.loginState}")

    def finish_registering_device(
        self,
        device_approval: DeviceApproval,
        encrypted_login_token: bytes,
        code: str = "",
    ):
        """Finish the registration process of a new or old device. If the code argument is given, then
        we are verifying the newly registered device.

        Args:
            device_approval (DeviceApproval): DeviceApproval instance that is in charge of verifying the code sent
            to user's email.
            encrypted_login_token (bytes): The encrypted login token.
            code (str, optional): The code sent to the user's email. Defaults to "".
        """
        encrypted_device_token = utils.base64_url_decode(self.keeper_params.device_token)
        if code:
            device_approval.send_code(
                self.keeper_params,
                DeviceApprovalChannel.Email,
                encrypted_device_token,
                encrypted_login_token,
                code,
            )
        self.validate_device_registration(
            encrypted_device_token=encrypted_device_token,
            encrypted_login_token=encrypted_login_token,
        )

    def start_registration(self):
        device_approval = self.DeviceApproval()
        try:
            self.start_registering_device(device_approval)
        except InvalidDeviceToken:
            demisto.info("Registering new device")
            self.start_registering_device(device_approval, new_device=True)

    def save_session_token(
        self,
    ):
        append_to_integration_context(
            {
                "session_token": self.keeper_params.session_token,
                "clone_code": self.keeper_params.clone_code,
                "valid_until": get_current_time_in_seconds() + SESSION_TOKEN_TTL,
            }
        )

    def complete_registration(self, code: str):
        device_approval = self.DeviceApproval()
        integration_context = get_integration_context()
        encrypted_login_token = utils.base64_url_decode(integration_context["login_token"])
        self.finish_registering_device(device_approval, encrypted_login_token, code)
        self.save_session_token()
        if not self.keeper_params.session_token:
            raise DemistoException("Could not find session token")

    def query_audit_logs(self, limit: int, start_event_time: int) -> dict[str, Any]:
        request_query = {
            "command": "get_audit_event_reports",
            "report_type": "raw",
            "scope": "enterprise",
            "limit": limit,
            "order": "ascending",
            "filter": {
                "created": {"min": start_event_time},
            },
        }
        return api.communicate(self.keeper_params, request_query)

    def test_registration(self) -> None:
        if not self.keeper_params.session_token:
            demisto.debug("No session token configured")
            raise DemistoException(REGISTRATION_FLOW_MESSAGE)
        self.query_audit_logs(limit=1, start_event_time=0)


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_audit_logs(
    client: Client, last_latest_event_time: int, max_fetch_limit: int, last_fetched_ids: set[str]
) -> list[dict[str, Any]]:
    continue_fetching = True
    events_to_return: list[dict[str, Any]] = []
    # last_latest_event_time -> UNIX epoch time in seconds
    start_time_to_fetch = last_latest_event_time
    fetched_ids = last_fetched_ids
    res_count = 0
    while continue_fetching and res_count < max_fetch_limit:
        query_response = client.query_audit_logs(
            limit=min(API_MAX_FETCH, max_fetch_limit - res_count), start_event_time=start_time_to_fetch
        )
        audit_events = query_response["audit_event_overview_report_rows"]
        audit_events_count = len(audit_events)
        demisto.debug(f"{LOG_LINE} got {audit_events_count} events from API")
        if audit_events:
            dedupped_audit_events = dedup_events(audit_events, fetched_ids)
            dedupped_events_count = len(dedupped_audit_events)
            demisto.debug(f"{LOG_LINE} Events count after dedup {dedupped_events_count}")
            if dedupped_audit_events:
                add_time_to_events(dedupped_audit_events)
                res_count += dedupped_events_count
                events_to_return.extend(dedupped_audit_events)
                # Getting last events's creation date, assuming asc order
                start_time_to_fetch = int(dedupped_audit_events[-1]["created"])
                # We get the event IDs that have the same creation time as the latest event in the response
                # We use them to dedup in the next run
                fetched_ids = {
                    str(audit_event["id"])
                    for audit_event in dedupped_audit_events
                    if int(audit_event["created"]) == start_time_to_fetch
                }
                # Last run of pagination, avoiding endless loop if all the page's results have the same time.
                # We do not have other eay to handle this case.
                if last_latest_event_time == start_time_to_fetch:
                    demisto.debug("Got equal start and end time, this was the last page.")
                    continue_fetching = False
            else:
                continue_fetching = False
        else:
            continue_fetching = False
    demisto.setLastRun({"last_fetch_epoch_time": str(start_time_to_fetch), "last_fetch_ids": list(fetched_ids)})
    return events_to_return


def add_time_to_events(audit_events: list[dict[str, Any]]):
    for audit_event in audit_events:
        audit_event["_time"] = audit_event["created"]


def dedup_events(audit_events: list[dict[str, Any]], last_fetched_ids: set[str]) -> list[dict[str, Any]]:
    dedupped_audit_events = list(
        filter(
            lambda audit_event: str(audit_event["id"]) not in last_fetched_ids,
            audit_events,
        )
    )
    return dedupped_audit_events


def fetch_events(client: Client, last_run: dict[str, Any], max_fetch_limit: int) -> list[dict[str, Any]]:
    demisto.debug(f"last_run: {last_run}" if last_run else "last_run is empty")
    # SDK's query uses Epoch time to filter events
    last_fetch_epoch_time = int(last_run.get("last_fetch_epoch_time", "0"))

    # (if 0) returns False
    last_fetch_epoch_time = last_fetch_epoch_time if last_fetch_epoch_time else int(datetime.now().timestamp())
    # last_fetch_epoch_time = 0
    last_fetched_ids = set(last_run.get("last_fetch_ids", []))
    audit_log = get_audit_logs(
        client=client,
        last_latest_event_time=last_fetch_epoch_time,
        max_fetch_limit=max_fetch_limit,
        last_fetched_ids=last_fetched_ids,
    )
    return audit_log


def start_registration_command(client: Client):
    client.start_registration()
    return CommandResults(readable_output="Code was sent successfully to the user's email")


def complete_registration_command(client: Client, code: str):
    client.complete_registration(code=code)
    return CommandResults(readable_output="Login completed")


def test_authorization(
    client: Client,
) -> CommandResults:
    client.test_registration()
    return CommandResults(readable_output="Successful connection")


def test_module() -> str:
    # We are unable to use client.test_registration(), since the method uses the integration context
    # and when we are running test-module, we don't have access to it
    raise DemistoException(REGISTRATION_FLOW_MESSAGE)


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
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
    client.refresh_session_token_if_needed()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if command == "test-module":
            return_results(test_module())
        elif command == "keeper-security-register-start":
            return_results(start_registration_command(client=client))
        elif command == "keeper-security-register-complete":
            return_results(complete_registration_command(client=client, code=args.get("code", "")))
        elif command == "keeper-security-register-test":
            return_results(test_authorization(client=client))
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            fetched_audit_logs = fetch_events(
                client=client,
                last_run=last_run,
                max_fetch_limit=arg_to_number(params.get("alerts_max_fetch")) or DEFAULT_MAX_FETCH,
            )
            demisto.debug(f"Events to send to XSIAM {fetched_audit_logs=}")
            send_events_to_xsiam(fetched_audit_logs, VENDOR, PRODUCT)
        else:
            raise NotImplementedError
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
