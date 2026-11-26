from abc import ABC, abstractmethod
from enum import Enum
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable, Iterator
from itertools import islice
from typing import Any, ClassVar
import requests


class CloudTypes(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    OCI = "OCI"


# Provider-specific account identifier names
PROVIDER_ACCOUNT_NAMES = {
    CloudTypes.GCP.value: "Project ID",
    CloudTypes.AWS.value: "AWS Account ID",
    CloudTypes.AZURE.value: "Subscription ID",
    CloudTypes.OCI.value: "Oracle Cloud Account ID",
}

# Platform API paths
GET_CTS_ACCOUNTS_TOKEN = "/cts/accounts/token"
GET_ONBOARDING_ACCOUNTS = "/onboarding/accounts"
GET_ONBOARDING_CONNECTORS = "/onboarding/connectors"


class HealthStatus(str):
    ERROR = "ERROR"
    WARNING = "WARNING"
    OK = "ok"


class ErrorType(str):
    CONNECTIVITY_ERROR = "Connectivity Error"
    PERMISSION_ERROR = "Permission Error"
    INTERNAL_ERROR = "Internal Error"


class HealthCheckError:
    def __init__(self, account_id: str, connector_id: str, message: str, error_type: str):
        self.account_id = account_id
        self.connector_id = connector_id
        self.message = message
        self.error_type = error_type
        # Determine classification based on error type
        self.classification = HealthStatus.WARNING if self.error_type == ErrorType.PERMISSION_ERROR else HealthStatus.ERROR

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "connector_id": self.connector_id,
            "message": self.message,
            "error": self.error_type,
            "classification": self.classification,
        }


class HealthCheck:
    """Health check results container for cloud connector."""

    def __init__(self, connector_id: str):
        self.errors: list[HealthCheckError] = []
        self.connector_id = connector_id

    def error(self, error: HealthCheckError | list[HealthCheckError]) -> None:
        """Adds a health check error or list of errors to the results.

        Args:
            error (HealthCheckError | list[HealthCheckError]): The error(s) to add to the results.
        """
        if isinstance(error, list):
            self.errors.extend(error)
        else:
            self.errors.append(error)

    def summarize(self) -> CommandResults | str:
        """Summarizes the health check results by calculating severity based on error classifications.

        Returns:
            CommandResults | str:
                - If errors exist: CommandResults object with severity level and error details, otherwise "ok".
        """

        def _calculate_severity() -> int:
            """
            Calculates the severity level based on error classifications.
            """
            return EntryType.ERROR if HealthStatus.ERROR in [error.classification for error in self.errors] else EntryType.WARNING

        if not self.errors:
            return HealthStatus.OK

        error_list = [error.to_dict() for error in self.errors]
        return CommandResults(entry_type=_calculate_severity(), content_format=EntryFormat.JSON, raw_response=error_list)


def get_connector_id() -> str | None:
    """
    Retrieves the connector ID from the calling context.

    This function extracts the connector ID from the CloudIntegrationInfo in the calling context.

    Returns:
        str | None: The connector ID if available in the context, otherwise None.
    """
    cloud_info_context = demisto.callingContext.get("context", {}).get("CloudIntegrationInfo", {})
    demisto.debug(f"[COOC API] Cloud credentials request context: {cloud_info_context}")

    if connector_id := cloud_info_context.get("connectorID"):
        demisto.debug(f"[COOC API] Retrieved connector ID from context: {connector_id}")
    else:
        demisto.debug("[COOC API] No connector ID found in context")

    return connector_id


def get_cloud_credentials(cloud_type: str, account_id: str, scopes: Optional[list] = None) -> dict:
    """Retrieves valid credentials for the specified cloud provider from CTS.

    Args:
        cloud_type (str): Cloud provider type ("GCP", "AWS", "AZURE", "OCI").
        account_id (str): Cloud account identifier - GCP: Project ID, AWS: Account ID,
                         AZURE: Subscription ID
        scopes (list, optional): Authorization scopes. Defaults to None.

    Returns:
        dict: Credentials dictionary for the specified cloud provider. The structure varies by cloud type:
            - For all providers:
                - 'expiration_time' (int): Expiration time in epoch time (milliseconds)
            - For GCP:
                - 'access_token' (str): Bearer token
            - For AWS:
                - 'access_token' (str): SecretAccessKey
                - 'session_token' (str): SessionToken
                - 'key' (str): AccessKeyId
            - For AZURE:
                - 'access_token' (str): JWT

    Raises:
        DemistoException: If token retrieval fails or response parsing fails.
        ValueError: If account_id is not provided.
    """
    if not account_id:
        name = PROVIDER_ACCOUNT_NAMES.get(cloud_type, "account identifier")
        raise ValueError(f"Missing {name} for {cloud_type}")

    if not isinstance(account_id, str):
        demisto.debug(f"[COOC API] account_id is not a string (type: {type(account_id)}). Converting to string.")
        account_id = str(account_id)

    cloud_info_context = demisto.callingContext.get("context", {}).get("CloudIntegrationInfo", {})

    request_data = {
        "connector_id": cloud_info_context.get("connectorID"),
        "account_id": account_id,
        "outpost_id": cloud_info_context.get("outpostID"),
        "cloud_type": cloud_type,
    }

    if scopes:
        request_data["scopes"] = scopes

    demisto.debug(f"[COOC API] Request data for credentials retrieval: {request_data}")
    response = None

    try:
        response = demisto._platformAPICall(path=GET_CTS_ACCOUNTS_TOKEN, method="POST", data={"request_data": request_data})
        raw_data = response.get("data")

        if not raw_data:
            raise ValueError(f"No 'data' field in CTS response: {response}")

        if isinstance(raw_data, str):
            res_json = json.loads(raw_data)
        elif isinstance(raw_data, dict):
            res_json = raw_data
        else:
            raise ValueError(f"Unexpected type for response['data']: {type(raw_data)}")

        credentials = res_json.get("data")
        if not credentials:
            raise KeyError("Did not receive any credentials from CTS.")

        expiration_time = credentials.get("expiration_time")
        demisto.debug(f"[COOC API] {account_id}: Received credentials. Expiration time: {expiration_time}")
        return credentials

    except Exception as e:
        demisto.debug(f"[COOC API] {account_id}: Error while retrieving credentials: {str(e)}. Response: {response}")
        raise DemistoException(f"Failed to get credentials from CTS: {str(e)}. Response: {response}")


def get_proxydome_token() -> str:
    """
    Retrieves a Proxydome identity token from the GCP metadata server.

    This function makes a request to the GCP metadata server to obtain an identity token
    that can be used for authentication with Proxydome services. It bypasses any configured
    proxies for this request.

    Returns:
        str: The identity token as a string.

    Raises:
        requests.RequestException: If the request to the metadata server fails.
    """
    url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
    params = {"audience": os.getenv("CORTEX_AUDIENCE")}
    headers = {"Metadata-Flavor": "Google"}
    proxies = {"http": "", "https": ""}

    response = requests.get(url, headers=headers, params=params, proxies=proxies)
    return response.text


def return_multiple_permissions_error(error_entries: list[Dict]) -> None:
    """
    Handles permission errors responses and exits the script execution.

    This function logs permission errors, formats them as Demisto error entries,
    and terminates script execution. It's used when cloud operations fail due to
    insufficient permissions or authentication issues.

    Args:
        error_entries (list): List of dictionaries containing error details with the following structure:
            - account_id (str): The cloud account identifier where the error occurred
            - message (str): The permission error message (including the name of the permission)
            - name (str): The RAW name of the permission itself that is missing, for example containers.list"

    Returns:
        None: This function does not return as it calls sys.exit(0)
    """
    # Input validation
    entries = []
    for entry in error_entries:
        error_entry = create_permissions_error_entry(entry.get("account_id"), entry.get("message"), entry.get("name"))
        entries.append(error_entry)
        # Log the permission error for security audit purposes
        demisto.debug(f"[COOC API] Permission error detected for account {error_entry.get('account_id')}: {error_entry}")

    # Return formatted error response
    demisto.results(
        {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["json"],
            "Contents": entries,
            "EntryContext": None,
        }
    )
    # Exit the script execution
    sys.exit(0)


def create_permissions_error_entry(account_id: Optional[str], message: Optional[str], name: Optional[str]) -> dict:
    """
    Creates a standardized error entry dictionary for permission-related errors.

    This function constructs a formatted error entry containing permission error details
    that can be used for logging and error handling in cloud operations. It validates
    input parameters and creates a consistent error structure.

    Args:
        account_id (Optional[str]): The cloud account identifier where the error occurred
        message (Optional[str]): The permission error message (including the name of the permission)
        name (Optional[str]): The RAW name of the permission itself that is missing, for example containers.list

    Returns:
        dict: A dictionary containing structured error information with keys:
            - account_id: The provided account identifier
            - message: The error message
            - name: The permission name
            - classification: Set to "WARNING"
            - error: Set to "Permission Error"
    """
    # Input validation
    error_entry = {"account_id": account_id, "message": message, "name": name}
    for var_name, var_value in error_entry.items():
        if not var_value or (isinstance(var_value, str) and not var_value.strip()):
            error_entry.update({var_name: "N/A"})
            demisto.info(f"[COOC API] Invalid entry was given to the permissions entry {var_name=}:{var_value=}.")

    error_entry.update({"classification": "WARNING", "error": "Permission Error"})
    # Log the permission error for security audit purposes
    demisto.debug(f"[COOC API] Permission error detected for account {error_entry.get('account_id')}: {error_entry}")

    # Return formatted error response
    return error_entry


def get_timeout(timeout: int | str | None) -> tuple[int, int]:
    """
    Parse the ``timeout`` integration parameter into ``(read_timeout, connect_timeout)``.

    Accepts either ``"<read>"`` (connect defaults to 10 s) or ``"<read>,<connect>"``.
    Mirrors ``AWSClient.get_timeout`` from ``AWSApiModule`` for behavioural parity with
    the legacy AWS-* packs. Intended for use by COOC integrations that support the
    XSOAR / XSIAM marketplace path.

    Args:
        timeout (int | str | None): The raw value from ``params.get("timeout")``. May be ``None``, an
            int, or a string.

    Returns:
        tuple[int, int]: ``(read_timeout, connect_timeout)`` in seconds.

    Raises:
        DemistoException: If the value is malformed.
    """
    if timeout is None or timeout == "":
        timeout = "60,10"
    try:
        if isinstance(timeout, int):
            if timeout < 0:
                raise DemistoException("Timeout values must not be negative.")
            return timeout, 10
        timeout_vals = str(timeout).split(",")
        if len(timeout_vals) > 2:
            raise DemistoException(
                f"Too many timeout values: expected 1 or 2, got {len(timeout_vals)}. "
                "You can specify just the read timeout (for example 60) or also the connect "
                "timeout followed after a comma (for example 60,10)."
            )
        read_timeout = int(timeout_vals[0])
        connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])
        if read_timeout < 0 or connect_timeout < 0:
            raise DemistoException("Timeout values must not be negative.")
        return read_timeout, connect_timeout
    except ValueError:
        raise DemistoException(
            "You can specify just the read timeout (for example 60) or also the connect "
            "timeout followed after a comma (for example 60,10). If a connect timeout is "
            "not specified, a default of 10 seconds will be used."
        )


class CloudIntegration(ABC):
    """Abstract base class that every CSP ApiModule must implement.

    Initialised once per command execution in ``main()``. Stores the
    command context (command name, args, params) and resolves the
    connector ID and account ID at construction time so that all
    subsequent method calls can use ``self.*`` without re-reading
    ``demisto.args()`` / ``demisto.params()`` repeatedly.

    Credentials are **not** fetched at construction time. They are fetched
    lazily via ``get_credentials()``, which CSP implementations call from
    ``get_client()``. This lets CSPs that need command-specific token scopes
    (e.g. Azure storage commands) request the correct scope.

    Args:
        command: The command name from ``demisto.command()``.
        args: Command arguments from ``demisto.args()``.
        params: Integration configuration parameters from ``demisto.params()``.

    Command flow:
        ``main()`` builds the integration and calls ``run(COMMANDS_MAPPING)``. ``run`` sends
        ``test-module`` to ``run_health_check`` (Cortex Platform) or ``test_module`` (marketplace),
        every other command to ``execute_command``. ``run`` logs the traceback of any error and
        passes the error to ``handle_error``.

    Command registration:
        New commands register themselves with ``@<CSP>Integration.register("<command-name>")``
        in the module where they are implemented, so adding a command does not require editing
        the integration's main file. ``execute_command`` checks the registry first and falls back
        to the ``commands_mapping`` passed by ``main()`` (kept for existing commands), which is
        executed by ``execute_mapped_command``.

    Attributes:
        cloud_type (str): Class attribute. The CSP identifier, set by each CSP subclass to
            ``CloudTypes.<CSP>.value`` (e.g. ``CloudTypes.AWS.value``).
        account_id_arg (str): Class attribute. Name of the argument holding the
            cloud account identifier. Override per CSP
            (AWS: ``account_id``, GCP: ``project_id``, Azure: ``subscription_id``).
        uses_proxy_env (bool): Class attribute. When ``True``, ``run`` calls ``handle_proxy()`` so the
            proxy settings are taken from the environment (AWS, Azure). GCP configures its proxy on
            the HTTP client instead.
        polling_commands (frozenset[str]): Class attribute. Existing (``commands_mapping``) commands that are
            decorated with ``@polling_function`` and therefore take ``args`` first (see ``is_polling_command``).
        command (str): The command name being executed.
        args (dict): Command arguments.
        params (dict): Integration configuration parameters.
        account_id (str): Cloud account identifier, resolved from ``args`` and
            falling back to ``params``.
        connector_id (str | None): Cortex connector ID, or ``None`` on the
            marketplace path.
        credentials (dict): CTS credentials cached by ``get_credentials()``.
            Empty until first fetched, and always empty on the marketplace path.
    """

    cloud_type: ClassVar[str]
    account_id_arg: ClassVar[str] = "account_id"
    uses_proxy_env: ClassVar[bool] = False
    polling_commands: ClassVar[frozenset[str]] = frozenset()
    # command name -> (handler, is_polling). Each subclass gets its own dict (see __init_subclass__).
    _registry: ClassVar[dict[str, tuple[Callable, bool]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls._registry = {}

    @classmethod
    def register(cls, command_name: str, polling: bool = False) -> Callable:
        """Decorator that registers a command handler on this integration class.

        Registered handlers always receive a ready client from ``get_client()``: ``(client, args)``,
        or ``(args, client)`` when ``polling=True``. On polling handlers place ``@register`` above
        ``@polling_function``; on service class methods place it below ``@staticmethod``
        (either order is accepted).

        Example:
            class S3:
                @staticmethod
                @AWSIntegration.register("aws-s3-bucket-get")
                def bucket_get_command(client, args): ...

        Args:
            command_name: The integration command name, as defined in the integration YAML.
            polling: Whether the handler is a polling command that takes ``args`` first.

        Raises:
            TypeError: If called on ``CloudIntegration`` itself, which would expose the command to every CSP.
            ValueError: If ``command_name`` is already registered on this class.
        """
        if cls is CloudIntegration:
            raise TypeError(
                f"Register '{command_name}' on a CSP integration class (for example AWSIntegration), not on CloudIntegration."
            )

        def decorator(func: Callable) -> Callable:
            handler = func.__func__ if isinstance(func, staticmethod) else func
            if command_name in cls._registry:
                raise ValueError(f"Command '{command_name}' is already registered on {cls.__name__}.")
            cls._registry[command_name] = (handler, polling)
            return func

        return decorator

    def get_registered_handler(self) -> tuple[Callable, bool] | None:
        """Return ``(handler, is_polling)`` for ``self.command`` if it was registered, else ``None``.

        Registrations made on a parent integration class are visible to its subclasses.
        """
        for klass in type(self).__mro__:
            registered = vars(klass).get("_registry", {}).get(self.command)
            if registered:
                return registered
        return None

    def __init__(self, command: str, args: dict, params: dict) -> None:
        self.command: str = command
        self.args: dict = args
        self.params: dict = params
        self.account_id: str = args.get(self.account_id_arg) or params.get(self.account_id_arg) or ""
        self.connector_id: Optional[str] = get_connector_id()
        self.credentials: dict = {}

    # ------------------------------------------------------------------
    # Concrete helpers — shared implementation for all CSPs
    # ------------------------------------------------------------------

    def get_credentials(self, scopes: Optional[list] = None) -> dict:
        """Fetch CTS credentials for ``self.account_id`` and cache them on ``self.credentials``.

        On the marketplace path (no connector ID) this returns ``{}`` without
        calling CTS — CSP implementations then authenticate with their
        configured integration parameters instead.

        When ``scopes`` is given, credentials are always re-fetched, because a
        cached token may have been issued for a different scope.

        Args:
            scopes: Optional authorization scopes to request from CTS
                    (used by Azure for scope-per-command tokens).

        Returns:
            The CTS credentials dict, or ``{}`` on the marketplace path.
        """
        if not self.connector_id:
            return {}
        if not self.credentials or scopes:
            self.credentials = get_cloud_credentials(self.cloud_type, self.account_id, scopes=scopes)
        return self.credentials

    def get_accounts(self, max_results: Optional[int] = 1) -> list:
        """Retrieve accounts associated with this connector.

        Args:
            max_results: Maximum number of accounts to return. ``None`` returns all accounts, and ``0`` returns none.
                         Pages are fetched only until ``max_results`` is reached.

        Returns:
            List of account dicts with at least ``account_id`` and
            optionally ``cloud_partition``.

        Raises:
            DemistoException: If the connector ID is not set or the API call fails.
        """
        accounts = self.iter_accounts()
        return list(accounts) if max_results is None else list(islice(accounts, max_results))

    def iter_accounts(self) -> Iterator[dict]:
        """Yield the accounts of ``self.connector_id`` from the onboarding API, one page at a time.

        The next page is requested only when the caller asks for more accounts, so a caller that
        stops iterating (for example after finding a specific account) does not fetch the rest.

        Yields:
            Account dicts of type ``ACCOUNT`` with at least ``account_id`` and optionally ``cloud_partition``.

        Raises:
            DemistoException: If the connector ID is not set or the API call fails.
        """
        if not self.connector_id:
            raise DemistoException(
                "Fetching the connector accounts requires a connector ID. "
                "This is only available on the Cortex Platform path."
            )
        next_token = ""
        while True:
            params: dict = {"entity_type": "connector", "entity_id": self.connector_id}
            if next_token:
                params["next_token"] = next_token
            try:
                result = demisto._platformAPICall(GET_ONBOARDING_ACCOUNTS, "GET", params)
                res_json = json.loads(result["data"])
            except Exception as e:
                raise DemistoException(f"Failed to fetch accounts for connector: {str(e)}")
            for account in res_json.get("values", []):
                if account.get("account_type") == "ACCOUNT" and account.get("account_id"):
                    yield account
            next_token = res_json.get("next_token", "")
            if not next_token:
                return

    def check_account(self, account_id: str, shared_creds: dict) -> "HealthCheckError | list[HealthCheckError] | None":
        """Run the health check for a single account and handle exceptions.

        Wraps ``self.health_check`` with exception handling so that a failure
        on one account does not abort the full health check loop.

        Args:
            account_id: The cloud account identifier to check.
            shared_creds: Pre-fetched CTS credentials to reuse.

        Returns:
            ``None`` if the account is healthy, a ``HealthCheckError`` or
            ``list[HealthCheckError]`` if the check fails or raises an exception.
        """
        try:
            return self.health_check(shared_creds, account_id, self.connector_id or "")
        except Exception as e:
            demisto.error(f"[COOC] Error checking account {account_id}: {str(e)}")
            return HealthCheckError(
                account_id=account_id,
                connector_id=self.connector_id or "",
                message=f"Failed to check account: {str(e)}",
                error_type=ErrorType.INTERNAL_ERROR,
            )

    def run_health_check(self) -> "str | CommandResults":
        """Run the health check for all accounts on this connector.

        Orchestrates the full health check flow:
        1. Fetch accounts via ``self.get_accounts()``.
        2. Fetch shared CTS credentials for the first account.
        3. Run ``self.check_account()`` for the first account.
        4. Summarise results via ``HealthCheck.summarize()``.

        Should only be called when ``self.connector_id`` is not ``None``
        (i.e. on the Cortex Platform path).

        Returns:
            ``"ok"`` if all accounts are healthy, or a ``CommandResults``
            object with error details if any account has connectivity issues.

        Raises:
            DemistoException: If called without a connector ID (marketplace path).
        """
        if not self.connector_id:
            raise DemistoException(
                "run_health_check() requires a connector ID. "
                "This method should only be called on the Cortex Platform path."
            )
        health_check_result = HealthCheck(self.connector_id)
        try:
            accounts = self.get_accounts()
            if not accounts:
                demisto.debug(f"[COOC] No accounts found for connector ID: {self.connector_id}")
                return HealthStatus.OK
            account_id = accounts[0]["account_id"]
            shared_creds = get_cloud_credentials(self.cloud_type, account_id)
            demisto.debug(f"[COOC] Retrieved shared {self.cloud_type} credentials for all accounts")
        except Exception as e:
            error_msg = f"Failed to retrieve {self.cloud_type} credentials for connector {self.connector_id}: {str(e)}"
            demisto.error(error_msg)
            health_check_result.error(
                HealthCheckError(
                    account_id="",
                    connector_id=self.connector_id,
                    message=error_msg,
                    error_type=ErrorType.CONNECTIVITY_ERROR,
                )
            )
            return health_check_result.summarize()

        result = self.check_account(account_id, shared_creds)
        if result is not None:
            health_check_result.error(result)

        demisto.debug(f"[COOC] Completed processing {account_id}")
        return health_check_result.summarize()

    # ------------------------------------------------------------------
    # Command flow — shared by all CSPs
    # ------------------------------------------------------------------

    def run(self, commands_mapping: dict) -> None:
        """Run the current command and return its results to the War Room. Called once from ``main()``.

        ``test-module`` runs the health check on the Cortex Platform path (connector ID present) and
        ``test_module`` on the marketplace path. Every other command runs through ``execute_command``.
        The traceback of any exception (including a proxy setup failure) is logged here, once for all CSPs,
        and the exception is then passed to ``handle_error``.

        Args:
            commands_mapping: Dict mapping existing command names to their handlers.
        """
        demisto.debug(f"[COOC] Command being called is {self.command}, {self.connector_id=}")
        try:
            if self.uses_proxy_env:
                handle_proxy()
            if self.command == "test-module":
                return_results(self.run_health_check() if self.connector_id else self.test_module())
            else:
                return_results(self.execute_command(commands_mapping))
        except Exception as e:
            demisto.error(traceback.format_exc())
            self.handle_error(e)

    def execute_command(self, commands_mapping: dict) -> Any:
        """Execute the current command against one account.

        1. **Registered commands** (see ``register``) get a ready client from ``get_client()``:
           ``(client, args)``, or ``(args, client)`` when registered with ``polling=True``.
        2. **Existing commands** from ``commands_mapping`` run through ``execute_mapped_command``,
           which each CSP overrides to match the signatures of its existing handlers.

        CSPs override this method only to add steps around this flow (e.g. the AWS multi-account
        fan-out, the Azure Gov endpoints and auth commands), and then call ``super().execute_command``.

        Args:
            commands_mapping: Dict mapping existing command names to their handlers.

        Returns:
            The result of the handler.

        Raises:
            NotImplementedError: If the command is neither registered nor in ``commands_mapping``.
        """
        if registered := self.get_registered_handler():
            handler, polling = registered
            client = self.get_client()
            return handler(self.args, client) if polling else handler(client, self.args)
        return self.execute_mapped_command(self.get_mapped_handler(commands_mapping))

    def execute_mapped_command(self, handler: Callable) -> Any:
        """Call an existing (``commands_mapping``) handler: ``(args, client)`` for polling commands
        (see ``is_polling_command``), ``(client, args)`` otherwise.

        CSPs override this method when their existing handlers use a different signature.

        Args:
            handler: The ``commands_mapping`` handler of ``self.command``.

        Returns:
            The result of the handler.
        """
        client = self.get_client()
        if self.is_polling_command():
            demisto.debug(f"[COOC] {self.command=} is a polling command, calling it with args as the first argument.")
            return handler(self.args, client)
        return handler(client, self.args)

    def is_polling_command(self) -> bool:
        """Return whether ``self.command`` is an existing polling command, which takes ``args`` first.

        Defaults to membership in ``polling_commands``. CSPs that detect polling differently override this method.
        """
        return self.command in self.polling_commands

    def get_mapped_handler(self, commands_mapping: dict) -> Callable:
        """Return the ``commands_mapping`` handler for ``self.command``.

        Raises:
            NotImplementedError: If ``self.command`` is not in ``commands_mapping``.
        """
        if self.command not in commands_mapping:
            raise NotImplementedError(f"Command '{self.command}' is not implemented.")
        return commands_mapping[self.command]

    def handle_error(self, error: Exception) -> None:
        """Return the error of the current command to the War Room.

        ``run`` has already logged the traceback. CSPs override this method to translate their native
        errors first (for example permission errors via ``return_multiple_permissions_error``), and call
        ``super().handle_error`` for the rest.

        Args:
            error: The exception raised while running the command.
        """
        return_error(f"Failed to execute {self.command} command.\nError:\n{error!s}")

    # ------------------------------------------------------------------
    # Abstract methods — each CSP ApiModule must implement these
    # ------------------------------------------------------------------

    @abstractmethod
    def get_client(self) -> Any:
        """Build and return a CSP-native client object.

        Implementations should call ``self.get_credentials()`` (optionally with
        command-specific scopes) and use ``self.params``, ``self.args``, and
        ``self.command`` to construct the client.

        Returns:
            A CSP-native client:

            - **AWS**: ``BotoClient`` (boto3 service client)
            - **GCP**: ``googleapiclient.discovery.Resource`` for the command's service
            - **Azure**: an ``AzureBaseClient`` (the ``client_class`` passed by the integration)
        """

    @abstractmethod
    def health_check(
        self,
        credentials: dict,
        account_id: str,
        connector_id: str,
    ) -> "HealthCheckError | list[HealthCheckError] | None":
        """Perform a CSP-specific connectivity check for one account.

        Called by ``check_account()`` (from ``run_health_check()``) with
        explicit credentials and account ID, because the health check account
        is resolved from the connector and may differ from ``self.account_id``.

        Args:
            credentials: Pre-fetched CTS credentials for this account.
            account_id: The cloud account identifier
                        (AWS account ID / GCP project ID / Azure subscription ID).
            connector_id: The Cortex connector ID.

        Returns:
            ``None`` if connectivity is healthy.
            ``HealthCheckError`` or ``list[HealthCheckError]`` if issues are found.
        """

    @abstractmethod
    def test_module(self) -> str:
        """Validate credentials on the marketplace (non-platform) path.

        Called when ``test-module`` is triggered without a connector ID.
        Uses ``self.params`` to authenticate.

        Returns:
            ``"ok"`` if credentials are valid.

        Raises:
            DemistoException: If credentials are invalid or the API call fails.
        """

