from collections.abc import Awaitable
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *  # noqa: F401

import asyncio

"""Unified HelloWorldV2 Integration for Cortex XSOAR and XSIAM

This integration is a good example on you can build a unified integration using
Python 3. Follow the documentation links below and make sure that the
integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

When building an integration that is reusable, a lot of effort must be placed
in the design. We recommend to fill a Design Document template, that allows you
to capture Use Cases, Requirements and Inputs/Outputs.

Example Design document for the this Integration (HelloWorldV2):
https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0


HelloWorld API
--------------

The HelloWorld API is a simple API that shows a realistic use case for an
integration.

This API has a few basic functions, including:

- Alerts - Returns mocked alerts and allows you to search based on
a number of parameters, such as severity. It
can also return a single alert by ID. This is used to create new alerts in
XSOAR by using the `fetch-incidents` command, which is by default invoked
every minute.

- Audits - Returns mocked records that capture user actions within the
HelloWorld system.

- IP Reputation - Returns a mock lookup response of the IP address given
as well as a reputation score (from 0 to 100) that is used to determine whether
the entity is malicious. This endpoint is called by reputation command  `ip`
that is run automatically every time an indicator is extracted in Cortex.
As a best practice of design, it is important to map and document the mapping
between a score in the original API format (0 to 100 in this case) to a score
in Cortex format (0 to 3). This score is called `DBotScore`, and is returned in the
context to allow automated handling of indicators based on their reputation.
More information: https://xsoar.pan.dev/docs/integrations/dbot

- Create Note - Demonstrates how to run commands that are not returning instant data,
the API provides a command simulates creating a new entity in the API.
This can be used for endpoints that take longer than a few seconds to complete with the
GenericPolling mechanism to implement the job polling loop. The results
can be returned in JSON or attachment file format.
Info on GenericPolling: https://xsoar.pan.dev/docs/playbooks/generic-polling

This integration also has a `say-hello` command for backward compatibility,
that doesn't connect to an API and just returns a `Hello {name}` string,
where name is the input value provided.


Integration File Structure
--------------------------

An integration usually consists of the following parts:
- Imports
- Constants
- Pydantic Models
- Client Class
- Helper Functions
- Command Functions
- Main Function
- Entry Point


Imports
-------

Here you can import Python module you need for your integration. If you need
a module that is not part of the default Docker images, you can add
a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by integrations:
- demistomock (imported as demisto): allows your code to work offline for
testing. The actual `demisto` module is provided at runtime when the
code runs on the tenant.
- CommonServerPython.py: contains a set of helper functions, base classes
and other useful components that will make your integration code easier
to maintain.
- CommonServerUserPython.py: includes a set of user defined commands that
are specific to a tenant. Do not use it for integrations that
are meant to be shared externally.
- ContentClientApiModule: contains a high-performance async-first HTTP
client for automation commands and event or incident fetching.

These imports are automatically loaded at runtime within the script runner,
so you shouldn't modify them

Constants
---------

Usually some constants that do not require user parameters or inputs, such
as the default API entry point for your service, or the maximum numbers of
alerts to fetch every time.

Use enums to group multiple possible values of a configuration parameter or
a command argument.



Define Pydantic models that inherit from `ContentBaseModel` and use them
to parse, validate, and clean configuration parameters or command arguments.


Client Class
------------

We recommend to use a Client class to wrap all the code that needs to interact
with your API. Moreover, we recommend, when possible, to inherit from the new
`ContentClient` class, defined in `ContentClientApiModule.py`. This class already
handles a lot of the work, such as system proxy settings, SSL certificate
verification and exception handling for HTTP errors.

Note that the Client class should NOT contain any Cortex tenant-specific code,
i.e. it should not use anything in the `demisto` class (functions such as
`demisto.args()` or `demisto.results()`) or even `return_results`, `return_error`,
or `CommandResults`.
You will use the Command Functions to handle inputs and outputs.

When calling an API, use methods like `ContentClient.get`, and
`ContentClient.post` and return the raw API response to the calling function
(usually a Command function).

Ideally, there should be one client method per API endpoint.

Look at the code and the commends of this specific class to better understand
the implementation details.


Helper Functions
----------------

Helper functions are usually used as utility functions that are used by several
command functions throughout your code. For example, formatting and creating
events or incidents. Many helper functions are already defined in
`CommonServerPython.py` and are often very handy.


Command Functions
-----------------

Command functions perform the mapping between inputs and outputs to the
Client class functions inputs and outputs. As a best practice, they should not
contain calls to `demisto.args()`, `demisto.results()`, `return_error`
and `demisto.command()` as those should be handled through the `main()` function.
However, in command functions, use `demisto` or `CommonServerPython.py`
artifacts, such as `demisto.debug()` or the `CommandResults` class and the
`Common.*` classes.
Usually, one command function is used per command, in addition to `test-module`,
and, if supported in the integration, `fetch-incidents`, `fetch-events` and
`fetch-indicators`. Each command function should invoke one specific function
of the Client class.

Command functions, when invoked through a command usually return data
using the `CommandResults` class, that is then passed to `return_results()`
in the `main()` function.
`return_results()` is defined in `CommonServerPython.py` to return
the data to war room. `return_results()` actually wraps `demisto.results()`.
You should never use `demisto.results()` directly.

Sometimes you will need to return values in a format that is not compatible
with `CommandResults` (for example files): in that case you must return a
data structure that is then pass passed to `return.results()`.

In any case you should never call `return_results()` directly from the
command functions.

When you use create the CommandResults object in command functions, you
usually pass some types of data:

- Human Readable: usually in Markdown format. This is what is presented to the
analyst in the War Room. You can use `tableToMarkdown()`, defined in
`CommonServerPython.py`, to convert lists and dicts in Markdown and pass it
to `return_results()` using the `readable_output` argument, or the
`return_results()` function will call `tableToMarkdown()` automatically for
you.

- Context Output: this is the machine readable data, JSON based, that XSOAR can
parse and manage in the Playbooks or Incident's War Room. The Context Output
fields should be defined in your integration YML file and is important during
the design phase. Make sure you define the format and follow best practices.
You can use `demisto-sdk json-to-outputs` to autogenerate the YML file
outputs section. Context output is passed as the `outputs` argument in `demisto_results()`,
and the prefix (i.e. `HelloWorld.Alert`) is passed via the `outputs_prefix`
argument.

More information on Context Outputs, Standards, DBotScore and demisto-sdk:
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/context-standards
https://xsoar.pan.dev/docs/integrations/dbot
https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/json_to_outputs/README.md

Also, when you write data in the Context, you want to make sure that if you
return updated information for an entity, to update it and not append to
the list of entities (i.e. in HelloWorld you want to update the status of an
existing `HelloWorld.Alert` in the context when you retrieve it, rather than
adding a new one if you already retrieved it). To update data in the Context,
you can define which is the key attribute to use, such as (using the example):
`outputs_key_field='alert_id'`. This means that you are using the `alert_id`
key to determine whether adding a new entry in the context or updating an
existing one that has the same ID. You can look at the examples to understand
how it works.
More information here:
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/dt

- Raw Output: this is usually the raw result from your API and is used for
troubleshooting purposes or for invoking your command from Automation Scripts.
If not specified, `return_results()` will use the same data as `outputs`.


Main Function
-------------

The `main()` function takes care of reading the integration parameters via
the `demisto.params()` function, initializes the Client class and checks the
different options provided to `demisto.commands()`, to invoke the correct
command function passing to it `demisto.args()` and returning the data to
`return_results()`. If implemented, `main()` also invokes the function
`fetch_incidents()`with the right parameters and passes the outputs to the
`demisto.incidents()` function. `main()` also catches exceptions and
returns an error message via `return_error()`.


Entry Point
-----------

This is the integration code entry point. It checks whether the `__name__`
variable is `__main__` , `__builtin__` (for Python 2) or `builtins` (for
Python 3) and then calls the `main()` function. Just keep this convention.

"""
import json
from enum import Enum
from typing import Any

from CommonServerUserPython import *
from pydantic import AnyUrl, BaseModel, Field, SecretStr, validator, root_validator, Extra, ValidationError

""" CONSTANTS """

MOCK_ALERT = (
    '"id": {id}, "severity": "{severity}", "user": "{user}", "action": "{action}", "date": "{date}", "status": "{status}"'
)

MOCK_ASSET = (
    '"id": {id}, "name": "{name}", "type": "{asset_type}", "status": "{status}", "created": "{created}"'
)

MOCK_VULN = (
    '"id": {id}, "cve_id": "{cve_id}", "severity": "{severity}", "description": "{description}", "published": "{published}"'
)

BASE_CONTEXT_OUTPUT_PREFIX = "HelloWorld"  # Context outputs from all commands will have this prefix


UNIX_TIMESTAMP = str(round(time.time() * 1000))

class PollingDefaults(int, Enum):
    INTERVAL_SECONDS = 30
    TIMEOUT_SECONDS = 60 * 10  # 10 minutes


class EventsDatasetConfigs(str, Enum):
    VENDOR = "Hello"
    PRODUCT = "WorldV2"
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    TIME_KEY = "_time"
    SOURCE_LOG_TYPE_KEY = "source_log_type"


class FetchAssetsStages(str, Enum):
    ASSETS = "assets"
    VULNS = "vulnerabilities"


class HelloWorldSeverity(str, Enum):
    """Helloworld severity options matching the YML configuration parameter options."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def all_values(cls) -> list[str]:
        """
        Get the string values of all enum members.

        Returns:
            list[str]: The values of the enum class members.
        """
        return [member.value for member in cls]

    @classmethod
    def convert_to_incident_severity(cls, raw_severity: str) -> int:
        """
        Convert HelloWorld API severity to Cortex XSOAR incident severity.

        Maps the HelloWorld alert severity levels ('low', 'medium', 'high', 'critical')
        to Cortex XSOAR incident severity integers (1-4).

        Args:
            raw_severity (str): Severity as returned from the HelloWorld API.

        Returns:
            int: Cortex XSOAR incident severity (0-4).
        """
        # INTEGRATION DEVELOPER TIP:
        # It is important to document the mapping between the API's severity
        # format and XSOAR's severity format. This mapping should be consistent
        # across the integration and clearly documented for users.
        mapping = {
            cls.LOW.value: IncidentSeverity.LOW,
            cls.MEDIUM.value: IncidentSeverity.MEDIUM,
            cls.HIGH.value: IncidentSeverity.HIGH,
            cls.CRITICAL.value: IncidentSeverity.CRITICAL,
            None: IncidentSeverity.UNKNOWN,
        }
        return mapping.get(raw_severity, IncidentSeverity.UNKNOWN)


DUMMY_VALID_API_KEY = "dummy-key"  # to mock API errors

SYSTEM = SystemCapabilities()


""" PYDANTIC MODELS """


class ContentBaseModel(BaseModel):
    """Base Pydantic model with user-friendly validation error formatting.

    INTEGRATION DEVELOPER TIP:
    This base class enhances Pydantic's default validation by:
    1. Catching ValidationError exceptions
    2. Formatting them in a user-friendly way
    3. Raising `DemistoException` with clear error messages

    All parameter and argument models should inherit from this class to provide
    consistent, readable error messages to users when validation fails.
    """

    def __init__(self, **data):
        try:
            super().__init__(**data)
        except ValidationError as e:
            # Format errors in a user-friendly way
            error_messages = []
            for error in e.errors():
                field = error["loc"][0] if error["loc"] else "unknown"
                msg = error["msg"]
                error_messages.append(f"- {field}: {msg}")

            raise DemistoException("Invalid Inputs:\n" + "\n".join(error_messages)) from e

    class Config:
        extra = Extra.ignore
        allow_population_by_field_name = True


class BaseParams(ContentBaseModel):
    """Base class for integration parameters with common connection settings.

    INTEGRATION DEVELOPER TIP:
    This class provides common parameters that most integrations need:
    - insecure: Whether to skip SSL certificate verification
    - proxy: Whether to use system proxy settings
    - verify: Computed property that returns the inverse of insecure

    Your integration's parameter class should inherit from this to get these
    common settings automatically.
    """

    insecure: bool = False
    proxy: bool = False

    @property
    def verify(self) -> bool:
        """Return SSL verification setting (inverse of insecure).

        Returns:
            bool: True if SSL certificates should be verified, False otherwise.
        """
        return not self.insecure


class HelloWorldLastRun(ContentBaseModel):
    """
    State management for fetch-incidents and fetch-events commands to ensure no
    data is missed or duplicated between invocations.
    """
    # The ID of the last fetched alert to use for offsetting.
    id_offset: int = 0
    
    def set(self):
        """Save the current state for the next fetch-incidents or fetch-events execution."""
        last_run = self.dict(by_alias=True)
        demisto.debug(f"[Last Run] Setting {last_run=}.")
        demisto.setLastRun(last_run)


class HelloWorldAssetsLastRun(ContentBaseModel):
    """
    State management for fetch-assets command to ensure no data is missed or
    duplicated between fetch invocations.
    """
    # Save the `stage` to denote the type of data to be fetched (assets or vulnerabilities)
    stage: FetchAssetsStages = FetchAssetsStages.ASSETS
    # The ID of the last fetched asset / vulnerability to use for offsetting.
    id_offset: int = 0
    # Keep a running total of fetched assets / vulnerabilities
    cumulative_count: int = 0
    # ID of snapshot in the dataset. Persist if ingestion is ongoing, reset once ingestion is done
    snapshot_id: int = Field(default=UNIX_TIMESTAMP)
    # `nextTrigger` instructs to the server when to trigger the next fetch invocation.
    next_trigger_in_seconds: str | None = Field(default=None, alias="nextTrigger")
    # `type` indicates to the server that the next fetch invocation is of type "assets" (1), rather than "events" (0)
    trigger_type: int = Field(default=1, alias="type")

    def set(self):
        """Save the current state for the next fetch-assets execution."""
        assets_last_run = self.dict(by_alias=True)
        demisto.debug(f"[Assets Last Run] Setting {assets_last_run=}.")
        demisto.setAssetsLastRun(assets_last_run)


class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    # Add `username: str` unless `hiddenusername: true` in the YML
    password: SecretStr


class HelloWorldParams(BaseParams):
    # Connection parameters (`proxy` and `insecure` are already in `BaseParams`)
    url: AnyUrl
    credentials: Credentials

    # Fetch parameters
    is_fetch: bool | None = Field(default=False, alias=("isFetchEvents" if SYSTEM.can_send_events else "isFetch"))
    max_fetch: int = Field(
        default=1000 if SYSTEM.can_send_events else 10,
        alias=("max_events_fetch" if SYSTEM.can_send_events else "max_incidents_fetch"),
    )
    severity: HelloWorldSeverity = HelloWorldSeverity.HIGH

    # Advanced parameters
    threshold_ip: int = 65
    integration_reliability: str = Field(default=DBotScoreReliability.C, alias="integrationReliability")

    @property
    def api_key(self):
        return self.credentials.password

    @validator("url", allow_reuse=True)
    def clean_url(cls, v):  # noqa: N805
        return v.rstrip("/")

    @validator("max_fetch", allow_reuse=True)
    def cap_max_fetch(cls, v: int):  # noqa: N805
        """Cap max_fetch to prevent manage rate of data flow."""
        max_fetch = cast(int, arg_to_number(v))
        max_fetch_cap = 100000 if SYSTEM.can_send_events else 200

        if max_fetch > max_fetch_cap:
            demisto.debug(f"[Param validation] Lowered configured {max_fetch=} to {max_fetch_cap=}")
            return max_fetch_cap
        return v


class HelloworldSayHelloArgs(ContentBaseModel):
    """Arguments for helloworld-say-hello command."""

    name: str


class HelloworldAlertListArgs(ContentBaseModel):
    """Arguments for helloworld-alert-list command."""

    alert_id: int | None = None
    limit: int = 10
    severity: HelloWorldSeverity | None = None

    @root_validator(allow_reuse=True)
    def check_alert_id_or_severity(cls, values: dict):  # noqa: N805
        has_alert_id = bool(values.get("alert_id"))
        has_severity = bool(values.get("severity"))

        if not (has_alert_id ^ has_severity):
            raise ValueError("Either 'alert_id' or 'severity' arguments need to be provided.")
        return values


class HelloworldAlertNoteCreateArgs(ContentBaseModel):
    """Arguments for helloworld-alert-note-create command."""

    alert_id: int
    note_text: str

    @validator("alert_id", allow_reuse=True)
    def validate_alert_id(cls, v):  # noqa: N805
        """Ensure alert_id is a valid positive integer."""
        if v is None or v <= 0:
            raise ValueError("[Args validation] Please provide a valid 'alert_id' argument (must be positive).")
        return v


class HelloWorldGetEventsArgs(ContentBaseModel):
    """Arguments for helloworld-get-events command."""

    severity: HelloWorldSeverity
    offset: int = 0
    limit: int = 10
    should_push_events: bool = False

    @validator("should_push_events", allow_reuse=True)
    def validate_should_push_events(cls, v):  # noqa: N805
        """Ensure alert_id is a valid positive integer."""
        should_push_events = argToBoolean(v)
        if should_push_events and not SYSTEM.can_send_events:
            raise ValueError("[Args validation] 'should_push_events' is not supported on this tenant.")
        return should_push_events


class HelloWorldJobSubmitArgs(ContentBaseModel):
    """Arguments for helloworld-job-submit command."""

    interval_in_seconds: int = PollingDefaults.INTERVAL_SECONDS
    timeout_in_seconds: int = PollingDefaults.TIMEOUT_SECONDS


class HelloWorldJobPollArgs(ContentBaseModel):
    """Arguments for helloworld-job-poll command."""

    job_id: str
    interval_in_seconds: int = PollingDefaults.INTERVAL_SECONDS
    timeout_in_seconds: int = PollingDefaults.TIMEOUT_SECONDS


class HelloWorldGetAssetsArgs(ContentBaseModel):
    """Arguments for helloworld-get-assets command."""

    limit: int = 10


class HelloWorldGetVulnerabilitiesArgs(ContentBaseModel):
    """Arguments for helloworld-get-vulnerabilities command."""

    limit: int = 10


class IpArgs(ContentBaseModel):
    """Arguments for ip command."""

    ip: str | list[str]  # Can be single IP or comma-separated list
    threshold: int | None = None

    @property
    def ips(self):
        """Returns list of IPs."""
        # Reputation commands usually support multiple inputs (i.e. arrays), so
        # they can be invoked once in Cortex. In case the API supports a single
        # IP at a time, we will cycle this for all the members of the array.
        # We use argToList(), implemented in CommonServerPython.py to automatically
        # return a list of a single element even if the provided input is a scalar.
        ips_list = argToList(self.ip) or []

        valid_ips = []
        invalid_ips = []
        for ip in ips_list:
            if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
                invalid_ips.append(ip)
                demisto.error(f"[Args validation] Invalid IP {ip=}, skipping")
            else:
                valid_ips.append(ip)
        if not valid_ips:
            raise ValueError(f"[Args validation] No valid IP(s) specified. Found invalid IPs: {', '.join(invalid_ips)}.")
        return valid_ips


class ExecutionConfig:
    """Centralized entry point for the integration that holds command, params, args, and last_run.

    This class encapsulates all the information needed to execute a command, including:
    - command: The command being executed
    - params: Integration parameters (validated via Pydantic)
    - args: Command-specific arguments (different per command, validated via Pydantic)
    - last_run: State from when the previous fetch ended (for fetch commands)
    """

    def __init__(self):
        # INTEGRATION DEVELOPER TIP:
        # Centralize all your `demisto` class usages in the `ExecutionConfig`
        # class constructor and create an instance of the class *once* in the
        # `main` function to avoid redundant system calls. Access the required
        # configurations as validated and type-safe properties.
        self._raw_command: str = demisto.command()
        self._raw_params: dict = demisto.params()
        self._raw_args: dict = demisto.args()
        self._raw_last_run: dict = demisto.getLastRun() if self._raw_command in FETCH_COMMANDS else {}
        self._raw_assets_last_run: dict = demisto.getAssetsLastRun() if self._raw_command == "fetch-assets" else {}

    @property
    def command(self) -> str:
        """Get the current command being executed.

        Returns:
            str: The command name (e.g., 'test-module', 'ip', 'fetch-incidents').
        """
        return self._raw_command

    @property
    def params(self) -> HelloWorldParams:
        """Get validated integration parameters.

        Returns:
            HelloWorldParams: Validated integration parameters with all configuration settings.
        """
        return HelloWorldParams(**self._raw_params)

    @property
    def ip_args(self) -> IpArgs:
        """Get validated arguments for the ip command.

        Returns:
            IpArgs: Validated arguments containing IP addresses and threshold.
        """
        return IpArgs(**self._raw_args)

    @property
    def get_events_args(self) -> HelloWorldGetEventsArgs:
        """Get validated arguments for the helloworld-get-events command.

        Returns:
            HelloWorldGetEventsArgs: Validated arguments containing limit, severity, start_time, and should_push_events.
        """
        return HelloWorldGetEventsArgs(**self._raw_args)

    @property
    def alert_list_args(self) -> HelloworldAlertListArgs:
        """Get validated arguments for the helloworld-alert-list command.

        Returns:
            HelloworldAlertListArgs: Validated arguments containing alert_id, limit, and severity.
        """
        return HelloworldAlertListArgs(**self._raw_args)

    @property
    def alert_note_create_args(self) -> HelloworldAlertNoteCreateArgs:
        """Get validated arguments for the helloworld-alert-note-create command.

        Returns:
            HelloworldAlertNoteCreateArgs: Validated arguments containing alert_id and note_text.
        """
        return HelloworldAlertNoteCreateArgs(**self._raw_args)

    @property
    def say_hello_args(self) -> HelloworldSayHelloArgs:
        """Get validated arguments for the helloworld-say-hello command.

        Returns:
            HelloworldSayHelloArgs: Validated arguments containing name.
        """
        return HelloworldSayHelloArgs(**self._raw_args)

    @property
    def job_submit_args(self) -> HelloWorldJobSubmitArgs:
        """Get validated arguments for the helloworld-job-submit command.

        Returns:
            HelloWorldJobSubmitArgs: Validated arguments containing polling interval and timeout.
        """
        return HelloWorldJobSubmitArgs(**self._raw_args)

    @property
    def job_poll_args(self) -> HelloWorldJobPollArgs:
        """Get validated arguments for the helloworld-job-poll command.

        Returns:
            HelloWorldJobPollArgs: Validated arguments containing job_id, interval, and timeout.
        """
        return HelloWorldJobPollArgs(**self._raw_args)

    @property
    def get_assets_args(self) -> HelloWorldGetAssetsArgs:
        """Get validated arguments for the helloworld-get-assets command.

        Returns:
            HelloWorldGetAssetsArgs: Validated arguments containing limit.
        """
        return HelloWorldGetAssetsArgs(**self._raw_args)

    @property
    def get_vulnerabilities_args(self) -> HelloWorldGetVulnerabilitiesArgs:
        """Get validated arguments for the helloworld-get-vulnerabilities command.

        Returns:
            HelloWorldGetVulnerabilitiesArgs: Validated arguments containing limit.
        """
        return HelloWorldGetVulnerabilitiesArgs(**self._raw_args)

    @property
    def last_run(self) -> HelloWorldLastRun:
        """Get the last_run state for fetch-incidents or fetch-events commands.

        Returns:
            HelloWorldLastRun: State from the previous fetch execution.
        """
        return HelloWorldLastRun(**self._raw_last_run)

    @property
    def assets_last_run(self) -> HelloWorldAssetsLastRun:
        """Get the last_run state for fetch-assets command.

        Returns:
            HelloWorldAssetsLastRun: State from the previous fetch-assets execution.
        """
        return HelloWorldAssetsLastRun(**self._raw_last_run)


""" CLIENT CLASS """


class HelloWorldAuthHandler(APIKeyAuthHandler):
    """Custom authentication handler for API key-based authentication for HelloWorldV2.

    INTEGRATION DEVELOPER TIP:
    You may define your custom `AuthHandler` if needed or use any of the
    included ones in `ContentClientApiModule` such as `APIKeyAuthHandler`,
    `BearerTokenAuthHandler`, or `BasicAuthHandler`.
    """

    def __init__(self, api_key: SecretStr):
        """Initialize the authentication handler.

        Args:
            api_key (SecretStr): The API key for authentication.
        """

        super().__init__(key=api_key._secret_value, header_name="X-HelloWorld-API-Key")
        self.validate_api_key()

    def validate_api_key(self) -> None:
        """Validate the API key.

        Raises:
            DemistoException: If the API key is invalid.
        """
        if self.key != DUMMY_VALID_API_KEY:
            # Simulate failed authentication
            raise DemistoException("Invalid Credentials. Please verify your API key.")


class HelloWorldClient(ContentClient):
    """
    HelloWorld client that extends `ContentClient` for API interactions.

    This client inherits from `ContentClient` to leverage built-in retry logic,
    rate limit handling, authentication, and thread safety.
    It adds HelloWorld-specific methods for mock / dummy API responses.
    For real API calls, see the `send_example_api_request` method.
    """

    def __init__(self, params: HelloWorldParams):
        """Initialize HelloWorld client with ContentClient capabilities.

        Args:
            params (HelloWorldParams): Integration parameters.
        """
        # Initialize parent ContentClient
        auth_handler = HelloWorldAuthHandler(params.api_key)
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            diagnostic_mode=is_debug_mode(),  # enable if commands are run with `debug-mode=true`
        )

    def send_example_api_request(self, item_id: str | int, params: dict) -> dict:
        """Example of calling a real specific API endpoint using ContentClient.

        Args:
            item_id (str | int): The ID of the item to retrieve.
            params (dict): Query parameters for the API request.

        Returns:
            dict: The API response.
        """
        # INTEGRATION DEVELOPER TIP:
        # For real API calls, use the inherited HTTP verb methods, for example:
        # - `self.get(endpoint, params)` for GET requests
        # - `self.post(endpoint, json_body)` for POST requests
        # Alternatively, call the legacy "_http_request" method:
        # - `self._http_request("GET", url_suffix=endpoint, params=params)`
        return self._http_request("GET", url_suffix=f"/api/endpoint/{item_id}", params=params)

    def get_ip_reputation(self, ip: str) -> dict[str, Any]:
        """Get IP reputation (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            ip (str): IP address to get the reputation for.

        Returns:
            dict[str, Any]: Dictionary containing the dummy IP reputation as it should be returned from the API.
        """
        mocked_response = {
            "attributes": {
                "as_owner": "EMERALD-ONION",
                "asn": 396507,
                "continent": "NA",
                "country": "US",
                "jarm": ":jarm:",
                "last_analysis_stats": {"harmless": 72, "malicious": 5, "suspicious": 2, "timeout": 0, "undetected": 8},
                "last_modification_date": 1613300914,
                "network": ":cidr:",
                "regional_internet_registry": "ARIN",
                "reputation": -4,
                "tags": [],
                "total_votes": {"harmless": 0, "malicious": 1},
                "whois_date": 1611870274,
            },
            "id": ip,
            "links": {"self": f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"},
            "type": "ip_address",
        }

        return mocked_response

    def say_hello(self, name: str) -> str:
        """Return a greeting string.

        Args:
            name (str): Name to append to the 'Hello' string.

        Returns:
            str: String containing 'Hello {name}'.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/hello"
        # data = {"name": name}
        # # If API response type is not JSON, specify the suitable type
        # resp_type = "text"  # Use any of the following: 'json', 'text', 'content', 'response', 'xml'
        # return self.post(endpoint, json_data=data, resp_type=resp_type)

        return f"Hello {name}"

    def get_alert_list(self, limit: int, severity: HelloWorldSeverity | None = None, id_offset: int = 0) -> list[dict]:
        """Get a list of alerts (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of items to generate.
            severity (HelloWorldSeverity | None): The severity value of the items returned.
            id_offset (int): The ID of the last fetched alert for pagination.

        Returns:
            list[dict]: Dummy data of items as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/alerts"
        # # Use `assign_params` params to remove potentially "empty" values (e.g. severity)
        # params = assign_params(
        #   limit=limit,
        #   severity=severity,
        #   query=f"id>{id_offset}",
        # )
        # return self.get(endpoint, params=params)

        mock_response: list[dict] = []
        for mock_number in range(limit):
            mock_alert_time = datetime(2026, 1, 15) + timedelta(seconds=id_offset + mock_number)
            mock_alert_id = id_offset + mock_number + 1
            is_even = mock_alert_id % 2 == 0
            item = MOCK_ALERT.format(
                id=mock_alert_id,
                severity=severity.value if severity else "",
                date=mock_alert_time.isoformat(),
                action="Testing",
                status="Success" if is_even else "Error",
                user="userA@test.com" if is_even else "userB@test.com",
            )
            dict_item = json.loads("{" + item + "}")
            mock_response.append(dict_item)

        return mock_response

    def get_alert(self, alert_id: int) -> dict:
        """Get a specific alert by ID (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            alert_id (int): The alert ID to retrieve.

        Returns:
            dict: Dummy data of the alert as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/alerts/{alert_id}"
        # return self.get(endpoint)

        item = MOCK_ALERT.format(
            id=alert_id,
            severity=HelloWorldSeverity.LOW.value,
            date=datetime(2023, 9, 14, 11, 30, 39, 882955).isoformat(),
            status="Testing",
        )
        return json.loads("{" + item + "}")

    def create_note(self, alert_id: int, comment: str) -> dict:
        """Create a new note in an alert.

        For real API calls, see the `send_example_api_request` method.

        Args:
            alert_id (int): The alert ID to add a note to.
            comment (str): The text comment to add to the alert as a note.

        Returns:
            dict: The summary of the newly created note from the API response.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/notes/{alert_id}"
        # data = {"comment": comment}
        # return self.post(endpoint, json_data=data)

        return {"status": "success", "msg": f"Note was created for alert #{alert_id} successfully with comment: {comment}"}

    def submit_job(self) -> dict[str, str]:
        """Submit a new job to the API.

        For real API calls, see the `send_example_api_request` method.

        Returns:
            dict[str, str]: The summary of the newly created job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/jobs/config-refresh"
        # return self.post(endpoint)
        return {"id": "abc-123", "status": "submitted", "type": "HelloWorldRefreshConfig"}

    def get_job_status(self, job_id: str) -> dict[str, str]:
        """Get the status of a job.

        For real API calls, see the `send_example_api_request` method.

        Args:
            job_id (str): The job ID to check status for.

        Returns:
            dict[str, str]: The status of the job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/jobs/{job_id}/status"
        # return self.get(endpoint)
        return {"id": job_id, "status": "complete"}

    def get_job_result(self, job_id: str) -> dict[str, str]:
        """Get the finished result of a job.

        For real API calls, see the `send_example_api_request` method.

        Args:
            job_id (str): The job ID to get results for.

        Returns:
            dict[str, str]: The end result of the job.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = f"/api/v1/jobs/{job_id}/result"
        # return self.get(endpoint)
        return {"id": job_id, "msg": "The configuration has successfully been updated."}

    def get_assets(self, limit: int, id_offset: int = 0) -> dict[str, Any]:
        """Get a list of assets (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of assets to retrieve.

        Returns:
            dict[str, Any]: Dummy data of assets as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/assets"
        # params = {"limit": limit}
        # return self.get(endpoint, params=params)

        mock_assets: list[dict] = []
        asset_types = ["server", "database", "storage", "network"]
        for mock_number in range(limit):
            asset_id = id_offset + mock_number + 1,
            asset_creation_time = datetime(2024, 1, 15) + timedelta(hours=mock_number)
            asset = MOCK_ASSET.format(
                id=asset_id,
                name=f"{asset_types[mock_number % len(asset_types)].capitalize()}-{mock_number + 1:02d}",
                asset_type=asset_types[mock_number % len(asset_types)],
                status="active",
                created=asset_creation_time.isoformat(),
            )
            asset_dict = json.loads("{" + asset + "}")
            mock_assets.append(asset_dict)

        # Assume our environment has no more assets batches after offset = 5000
        mock_has_more_data = True if id_offset < 5000 else False
        mock_response = {"has_more": mock_has_more_data, "data": mock_assets}
        return mock_response

    def get_vulnerabilities(self, limit: int, id_offset: int = 0) -> dict[str, Any]:
        """Get a list of vulnerabilities (dummy response for demonstration purposes).

        For real API calls, see the `send_example_api_request` method.

        Args:
            limit (int): The number of vulnerabilities to retrieve.

        Returns:
            dict[str, Any]: Dummy data of vulnerabilities as it would be returned from the API.
        """
        # INTEGRATION DEVELOPER TIP:
        # In a real implementation, you would make an HTTP request here using ContentClient:
        # endpoint = "/api/v1/vulnerabilities"
        # params = {"limit": limit}
        # return self.get(endpoint, params=params)

        mock_vulns: list[dict] = []
        severities = HelloWorldSeverity.all_values()
        descriptions = [
            "Remote code execution vulnerability",
            "SQL injection vulnerability",
            "Cross-site scripting vulnerability",
            "Information disclosure vulnerability",
        ]
        for mock_number in range(limit):
            vuln_id = id_offset + mock_number + 1
            vuln_published_time = datetime(2026, 1, 15) + timedelta(hours=mock_number)
            vuln = MOCK_VULN.format(
                id=vuln_id,
                cve_id=f"CVE-MOCK-{mock_number + 1:04d}",
                severity=severities[mock_number % len(severities)],
                description=descriptions[mock_number % len(descriptions)],
                published=vuln_published_time.isoformat(),
            )
            vuln_dict = json.loads("{" + vuln + "}")
            mock_vulns.append(vuln_dict)

        # Assume our environment has a limited number of vulnerabilities that can all be fetched in one requested
        mock_has_more_data = False
        mock_response = {"has_more": mock_has_more_data, "data": mock_vulns}
        return mock_response

    def log_optional_diagnostic_report(self) -> None:
        """Log diagnostic report for troubleshooting if diagnostic mode is enabled."""
        # INTEGRATION DEVELOPER TIP:
        # Adding diagnostic logs can help with troubleshooting bugs and common issues (authentication issues)

        if not self._diagnostic_mode:
            demisto.debug("[Client] Diagnostic mode is disabled. Skipping generating diagnostic report.")
            return

        try:
            report = self.get_diagnostic_report()
            demisto.debug(f"[Client] Diagnostic Report: {json.dumps(report.__dict__, default=str, indent=2)}")
            self.logger.log_metrics_summary()
        except Exception as e:
            demisto.debug(f"Failed to generate diagnostic report: {e}")


""" HELPER FUNCTIONS """


def format_as_incidents(
    alerts: list[dict[str, Any]],
    id_field: str,
    occurred_field: str,
    severity_field: str,
    custom_fields_mapping: dict | None = None,
) -> list[dict[str, Any]]:
    """Format alerts as XSOAR incident.

    Args:
        alerts (list[dict[str, Any]]): List of alert dictionaries from the API.
        id_field (str): The field name in the alert ID to use as part of the incident name.
        occurred_field (str): The field name in the alert to use as the occurred time.
        severity_field (str): The field name in the alert to use for severity.
        custom_fields_mapping (dict | None): Optional mapping for custom fields.

    Returns:
        list[dict[str, Any]]: List of incidents formatted for XSOAR.
    """
    custom_fields_mapping = custom_fields_mapping or {}
    return [
        {
            "name": f"XSOAR Test Alert #{alert[id_field]}",
            "occurred": alert[occurred_field],
            "rawJSON": json.dumps(alert),
            "type": "Hello World Alert",  # Map to a specific XSOAR incident type
            "severity": HelloWorldSeverity.convert_to_incident_severity(raw_severity=alert[severity_field]),
            "CustomFields": {
                field_name: demisto.get(custom_fields_mapping, field_value)
                for field_name, field_value in custom_fields_mapping.items()
            },
        }
        for alert in alerts
    ]


def format_as_events(
    alerts: list[dict[str, Any]],
    time_field: str,
) -> list[dict[str, Any]]:
    """Format alerts as XSIAM events.

    Args:
        alerts (list[dict[str, Any]]): List of alert dictionaries from the API.
        time_field (str): The field name in the audit to use as the event time.

    Returns:
        list[dict[str, Any]]: List of events formatted for XSIAM.
    """
    events: list[dict[str, Any]] = []
    for alert in alerts:
        event = alert.copy()
        event_time = cast(datetime, arg_to_datetime(event[time_field]))
        event[EventsDatasetConfigs.TIME_KEY.value] = event_time.strftime(EventsDatasetConfigs.TIME_FORMAT.value)
        # Important to declare source log type, especially if multiple event types are fetched
        event[EventsDatasetConfigs.SOURCE_LOG_TYPE_KEY.value] = "Alert"
        events.append(event)
    return events


async def get_alert_list(
    client: HelloWorldClient,
    start_offset: int,
    severity: HelloWorldSeverity,
    limit: int,
    should_push: bool,
) -> list[dict]:
    """Fetch raw alerts from the API in batches and optionally create XSOAR incidents or XSIAM events.

    INTEGRATION DEVELOPER TIP:
    This function fetches events from the API in batches. In when running on XSIAM, it uses asyncio to
    concurrently fetch the next alerts batch while pushing the formatted events to XSIAM to improve
    performance and scalability.

    Args:
        client (HelloWorldClient): HelloWorld client instance for API calls.
        start_offset (int): Start time for fetching events.
        limit (int): Maximum total number of events to fetch.
        should_push (bool): Whether to create incidents (XSOAR) or events (XSIAM).

    Returns:
        list[dict]: List of all raw alerts fetched.
    """
    demisto.debug(f"[Get alert list] Starting to fetch alerts with {severity=}, {start_offset=}, and {limit=}.")

    all_alerts: list[dict] = []
    async_push_tasks: list[Awaitable] = []
    offset: int = start_offset

    while len(all_alerts) < limit:
        remaining_alerts_count = limit - len(all_alerts)
        batch_limit = min(500, remaining_alerts_count)
        demisto.debug(f"[Get alert list] Request alerts batch using {offset=} and {batch_limit=}.")
        alerts_batch = client.get_alert_list(limit=batch_limit, id_offset=offset, severity=severity)
        all_alerts.extend(alerts_batch)
        offset += len(alerts_batch)

        if should_push:
            if SYSTEM.can_send_events:
                demisto.debug(
                    f"[Get alert list] Creating asynchronous XSIAM events sending from {len(alerts_batch)} alerts batch."
                )
                async_push_tasks.append(asyncio.to_thread(create_events, alerts_batch))
            else:
                demisto.debug(
                    f"[Get alert list] Calling synchronous XSOAR incidents creation flow from {len(alerts_batch)} alerts batch."
                )
                create_incidents(alerts_batch)

        # If the number of returned alerts is less than the requested batch limit, no more new alerts are available for fetching
        if len(alerts_batch) < batch_limit:
            demisto.debug(f"[Get alert list] No more alerts currently available for fetching after {offset=}. Breaking...")
            break

    if async_push_tasks:
        demisto.debug(f"[Get alert list] Awaiting XSIAM events sending to finish for all {len(all_alerts)} alerts.")
        await asyncio.gather(*async_push_tasks)

    demisto.debug(
        f"[Get alert list] Finished fetching {len(all_alerts)} total alerts with {severity=}, {start_offset=}, and {limit=}."
    )
    return all_alerts


def create_events(alerts: list[dict]) -> None:
    """Format alerts and send them to XSIAM.

    Args:
        audits (list[dict]): List of alert dictionaries from the API.

    Returns:
        None
    """
    demisto.debug(f"[Create events] Formatting and sending {len(alerts)} XSIAM events.")
    events = format_as_events(alerts, time_field="date")
    send_events_to_xsiam(
        events=events,
        vendor=EventsDatasetConfigs.VENDOR.value,
        product=EventsDatasetConfigs.PRODUCT.value,
        client_class=ContentClient,
    )
    demisto.debug(f"[Create events] Successfully sent {len(events)} XSIAM events.")


def create_incidents(alerts: list[dict]) -> None:
    """Format alerts as incidents and create them in XSOAR.

    Args:
        alerts (list[dict]): List of alert dictionaries from the API.

    Returns:
        None
    """
    demisto.debug(f"[Create incidents] Formatting and creating {len(alerts)} XSOAR incidents.")
    incidents = format_as_incidents(alerts, id_field="id", occurred_field="date", severity_field="severity")
    demisto.incidents(incidents)
    demisto.debug(f"[Create incidents] Successfully created {len(incidents)} XSOAR incidents.")


""" COMMAND FUNCTIONS """


def test_module(client: HelloWorldClient, params: HelloWorldParams) -> str:
    """Test API connectivity and authentication.

    When 'ok' is returned, it indicates the integration works as expected and the connection
    to the service is successful. Raises exceptions if something goes wrong.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        params (HelloWorldParams): Validated integration parameters containing configuration settings.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and fail the test.
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # The tenant will treat anything other than 'ok' as an error
    try:
        demisto.debug("[Testing] Testing API connectivity")
        client.say_hello(name="Test")
        demisto.debug("[Testing] API connectivity test passed")

        if params.is_fetch:
            demisto.debug("[Testing] Testing fetch flow.")
            fetch_alerts(client=client, max_fetch=1, last_run=HelloWorldLastRun(), severity=params.severity)
            demisto.debug("[Testing] Fetch flow test passed")

    except ContentClientAuthenticationError as e:
        demisto.error(f"[Testing] Authentication failed. Got error={e}.")
        return "AuthenticationError: make sure API Key is correctly set."

    demisto.debug("[Testing] All tests passed.")
    return "ok"


def say_hello_command(client: HelloWorldClient, args: HelloworldSayHelloArgs) -> CommandResults:
    """Execute helloworld-say-hello command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldSayHelloArgs): Validated command arguments containing:
            - name: The name to use in the greeting message.

    Returns:
        CommandResults: CommandResults object containing the hello world message.
    """

    # INTEGRATION DEVELOPER TIP
    # In this case 'name' is an argument set in the HelloWorldV2.yml file as mandatory,
    # so Pydantic will validate it's present before the function is called.
    # The validation happens automatically when HelloworldSayHelloArgs is instantiated.

    # Call the Client function and get the raw response
    result = client.say_hello(name=args.name)

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using `tableToMarkDown()` defined
    # in `CommonServerPython.py`
    readable_output = f"## {result}"

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a `CommandResults` object, and we want to pass a custom
    # markdown here, so the argument `readable_output` is explicit. If not
    # passed, `CommandResults`` will do a `tableToMarkdown()` do the data
    # to generate the readable output.
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Hello",
        outputs_key_field="name",
        outputs={"name": args.name},
    )


def fetch_alerts(
    client: HelloWorldClient,
    last_run: HelloWorldLastRun,
    severity: HelloWorldSeverity,
    max_fetch: int,
) -> HelloWorldLastRun:
    """Retrieve new alerts and format them as XSOAR incidents or XSIAM events.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        last_run (HelloWorldLastRun): State from the last fetch.
        severity (HelloWorldSeverity): Severity of the alerts to search for.
        max_fetch (int): Maximum number of alerts per fetch.

    Returns:
        HelloWorldLastRun: Next run state for the next fetch.
    """
    last_id_offset = last_run.id_offset
    demisto.debug(f"[Fetch] Starting fetch alerts with {severity=} and {last_id_offset=} using {max_fetch=}.")

    alerts = asyncio.run(
        get_alert_list(client, start_offset=last_id_offset, severity=severity, limit=max_fetch, should_push=True)
    )
    if not alerts:
        demisto.debug(f"[Fetch] No new alerts found. Keeping {last_id_offset=}.")
        return last_run

    next_id_offset = alerts[-1]["id"]
    next_run = HelloWorldLastRun(id_offset=next_id_offset)

    demisto.debug(f"[Fetch] Completed, fetched {len(alerts)} HelloWorld alerts. Updating {next_id_offset=}.")
    return next_run


def ip_reputation_command(client: HelloWorldClient, args: IpArgs, params: HelloWorldParams) -> list[CommandResults]:
    """Execute ip reputation command for a list of IPs.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (IpArgs): Validated command arguments containing:
            - ip: A list of IPs or a single IP.
            - threshold: Optional threshold to determine whether an IP is malicious.
        params (HelloWorldParams): Integration parameters containing default threshold and reliability.

    Returns:
        list[CommandResults]: List of CommandResults objects containing IP reputation data.
    """
    # It's a good practice to document the threshold you use to determine
    # if a score is malicious in your integration documentation.
    # Thresholds should also be possible to override, as in this case,
    # where threshold is an actual argument of the command.
    threshold = args.threshold or params.threshold_ip
    demisto.debug(f"[IP] Processing {len(args.ips)} IPs {threshold=}")

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    command_results: list[CommandResults] = []

    for ip in args.ips:
        demisto.debug(f"[IP] Getting reputation for {ip=}")
        ip_data = client.get_ip_reputation(ip)
        ip_data["ip"] = ip

        # This is an example of creating relationships in reputation commands.
        # We will create relationships between indicators only in case that the API returns information about
        # the relationship between two indicators.
        # See https://xsoar.pan.dev/docs/integrations/generic-commands-reputation#relationships

        relationships_list = []
        links = ip_data.get("links", {}).get("self", "")
        for link in links:
            relationships_list.append(
                EntityRelationship(
                    entity_a=ip,
                    entity_a_type=FeedIndicatorType.IP,
                    name="related-to",
                    entity_b=link,
                    entity_b_type=FeedIndicatorType.URL,
                    brand="HelloWorld",
                )
            )

        # We can use demisto.get to get nested values from dict.
        reputation = cast(int, arg_to_number(demisto.get(ip_data, "attributes.reputation", defaultParam=0)))

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation < threshold / 2:
            score = Common.DBotScore.BAD  # bad
        elif reputation < threshold:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (IP) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the HelloWorld Design Document

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name="HelloWorld",
            score=score,
            malicious_description=f"Hello World returned reputation {reputation}",
            reliability=params.integration_reliability,
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(ip=ip, asn=ip_data.get("asn"), dbot_score=dbot_score, relationships=relationships_list)

        # INTEGRATION DEVELOPER TIP
        # In the integration specific Context output (HelloWorld.IP) in this
        # example you want to provide a lot of information as it can be used
        # programmatically from within Cortex XSOAR in playbooks and commands.
        # On the other hand, this API is way to verbose, so we want to select
        # only certain keys to be returned in order not to clog the context
        # with useless information. What to actually return in the context and
        # to define as a command output is subject to design considerations.

        # INTEGRATION DEVELOPER TIP
        # To generate the Context Outputs on the YML use `demisto-sdk`'s
        # `json-to-outputs` option.

        # Define which fields we want to exclude from the context output as they are too verbose.
        # We will use attributes key separately. Just make sure to keep the whole response somewhere.
        ip_context_excluded_fields = ["whois", "attributes"]
        ip_data_outputs = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise `CommandResults()` will call `tableToMarkdown()`
        #  automatically.

        readable_attributes = tableToMarkdown("Attributes", ip_data["attributes"], is_auto_json_transform=True)
        readable_output = tableToMarkdown("IP (Sample Data)", ip_data_outputs)
        readable_output += readable_attributes

        # INTEGRATION DEVELOPER TIP
        # The output key will be `HelloWorld.IP`, using `ip` as the key field.
        # `indicator` is used to provide the context standard (IP)
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                raw_response=ip_data,
                outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.IP",
                outputs_key_field="ip",
                outputs=ip_data_outputs,
                indicator=ip_standard_context,
                relationships=relationships_list,
            )
        )
    return command_results


def alert_list_command(client: HelloWorldClient, args: HelloworldAlertListArgs) -> CommandResults:
    """Execute helloworld-alert-list command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldAlertListArgs): Validated command arguments containing:
            - alert_id: Optional alert ID to retrieve a specific alert.
            - severity: Optional severity filter for alerts (required if alert_id is not provided).
            - limit: Optional maximum number of results to return.

    Returns:
        CommandResults: CommandResults object containing alert data.
    """
    # Pagination params. See https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands
    demisto.debug(f"[Alerts list] Fetching alerts using {args.alert_id=}, {args.severity=}, and {args.limit=}.")

    if args.alert_id:  # If alert_id is provided, we only need one call to API and pagination is not needed.
        demisto.debug(f"[Alerts list] Fetching single alert {args.alert_id=}")
        full_res = client.get_alert(args.alert_id)
        full_res = [full_res] if isinstance(full_res, dict) else full_res

    elif args.severity:  # At this point, severity must be set (validated in __init__)
        demisto.debug(f"[Alerts list] Fetching alerts by severity {args.severity=} {args.limit=}")
        full_res = client.get_alert_list(limit=args.limit, severity=args.severity)

    demisto.debug(f"[Alerts list] Fetched {len(full_res)} alerts")
    readable_output = tableToMarkdown("Items List (Sample Data)", full_res)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Alert",
        outputs_key_field="id",
        outputs=full_res,
    )


def get_events_command(client: HelloWorldClient, args: HelloWorldGetEventsArgs) -> CommandResults:
    """Execute helloworld-get-events command.

    This demonstrates on-demand data collection, which is useful for commands
    that need to retrieve datasets from APIs.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetEventsArgs): Validated command arguments.

    Returns:
        CommandResults: CommandResults with collected events.
    """
    demisto.debug(f"[Get events] Getting events {args.severity=}, {args.offset=}, and {args.limit=}.")

    # Fetch events using the simplified approach
    events = asyncio.run(
        get_alert_list(
            client=client, limit=args.limit, start_offset=args.offset, severity=args.severity, should_push=args.should_push_events
        )
    )

    demisto.debug(f"[Get events] Fetched {len(events)} events")
    return CommandResults(readable_output=tableToMarkdown("HelloWorld Events", events))


def alert_note_create_command(client: HelloWorldClient, args: HelloworldAlertNoteCreateArgs) -> CommandResults:
    """Execute helloworld-alert-note-create command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloworldAlertNoteCreateArgs): Validated command arguments containing:
            - alert_id: The ID of the alert to add a note to (must be a positive integer).
            - note_text: The text content of the note to create.

    Returns:
        CommandResults: CommandResults object containing the note creation result.
    """
    demisto.debug(f"[Create note] Creating note for {args.alert_id=}")
    res_data = client.create_note(alert_id=args.alert_id, comment=args.note_text)

    demisto.debug(f"[Create note] Successfully created note for {args.alert_id=}")
    return CommandResults(
        readable_output="Note was created successfully.",
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Note",
        outputs_key_field="id",
        outputs=res_data,
    )


def job_submit_command(client: HelloWorldClient, args: HelloWorldJobSubmitArgs) -> CommandResults:
    """Execute helloworld-job-submit command and initiate polling.

    This command demonstrates the polling pattern for long-running operations.
    It submits a job to the remote API and returns a ScheduledCommand to poll for completion.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldJobSubmitArgs): Validated command arguments containing polling parameters.

    Returns:
        CommandResults: CommandResults with ScheduledCommand for polling.
    """
    demisto.debug("[Job submit] Submitting job to API")

    # Submit the job
    job_data = client.submit_job()
    job_id = job_data.get("id")

    if not job_id:
        demisto.error("[Job submit] No job ID returned from API")
        raise DemistoException("No job ID returned from API")

    demisto.debug(f"[Job submit] Successfully submitted {job_id=}")

    # Calculate polling parameters
    polling_interval = args.interval_in_seconds
    polling_timeout = args.timeout_in_seconds

    demisto.debug(f"[Job submit] Initiating polling {job_id=} {polling_interval=} {polling_timeout=}")

    # Prepare arguments for the polling command
    poll_args = {"job_id": job_id, **dict(args)}
    readable = f"Successfully submitted {job_id=}. Polling initiated, checking every {polling_interval} seconds."

    return CommandResults(
        readable_output=readable,
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
        outputs_key_field="id",
        outputs=job_data,
        scheduled_command=ScheduledCommand(
            command="helloworld-job-poll",
            args=poll_args,
            next_run_in_seconds=polling_interval,
            timeout_in_seconds=polling_timeout,
        ),
    )


@polling_function(name="helloworld-job-poll", interval=PollingDefaults.INTERVAL_SECONDS, timeout=PollingDefaults.TIMEOUT_SECONDS)
def job_poll_command(args: HelloWorldJobPollArgs | dict, client: HelloWorldClient) -> PollResult:
    """Poll the HelloWorld service for job status until complete.

    Periodically checks the job status and returns the final result when complete.

    Polling Flow:
    1. Status Check: Queries the job status (submitted/running/complete).
    2. Polling Continuation: If not complete, schedules the next poll.
    3. Final Result: If complete, fetches the job result.
    4. Result Compilation: Returns final CommandResults with job data.

    Args:
        args (HelloWorldJobPollArgs): Validated arguments containing 'job_id' and polling parameters.
        client (HelloWorldClient): The configured HelloWorldClient instance.

    Returns:
        PollResult: Contains polling status and final results if complete.
    """
    if isinstance(args, dict):
        args = HelloWorldJobPollArgs(**args)

    job_id = args.job_id
    polling_interval = args.interval_in_seconds

    demisto.debug(f"[Job polling] Polling for {job_id=} with {polling_interval=}.")

    # Check job status
    status_response = client.get_job_status(job_id)

    status = status_response.get("status", "")
    demisto.debug(f"[Job polling] Job status for {job_id=} {status=}")

    # Check if job is complete
    if status == "complete":
        demisto.debug(f"[Job polling] Job complete {job_id=}. Returning final result...")

        # Fetch the final job result
        job_result = client.get_job_result(job_id)

        # Create readable output
        readable = tableToMarkdown(
            f"HelloWorld Job {job_id} - Complete",
            job_result,
            headers=["id", "msg"],
            headerTransform=string_to_table_header,
        )

        final_results = CommandResults(
            readable_output=readable,
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
            outputs_key_field="id",
            outputs=job_result,
        )

        demisto.debug(f"[Job polling] Polling finished successfully {job_id=}")

        return PollResult(
            response=final_results,
            continue_to_poll=False,
            partial_result=CommandResults(readable_output=f"Job {job_id} completed successfully."),
        )

    # Job is still running - continue polling
    else:
        demisto.debug(f"[Job polling] Job still running {job_id=} {status=}, scheduling next poll in {polling_interval}s")

        readable = f"Scheduling next check in {polling_interval} seconds for {job_id=}."
        status_update = CommandResults(
            readable_output=readable,
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job",
            outputs_key_field="id",
            outputs={"id": job_id, "status": status},
        )

        return PollResult(
            response=None,
            args_for_next_run=dict(args),
            continue_to_poll=True,
            partial_result=status_update,
        )


def get_assets_command(client: HelloWorldClient, args: HelloWorldGetAssetsArgs) -> CommandResults:
    """Execute helloworld-get-assets command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetAssetsArgs): Validated command arguments containing:
            - limit: Maximum number of assets to retrieve.

    Returns:
        CommandResults: CommandResults object containing asset data.
    """
    demisto.debug(f"[Get assets] Fetching assets with {args.limit=}")

    # Fetch assets from the API
    raw_response = client.get_assets(limit=args.limit)
    assets = raw_response.get("data", [])

    demisto.debug(f"[Get assets] Fetched {len(assets)} assets")
    readable_output = tableToMarkdown("HelloWorld Assets", assets)

    return CommandResults(readable_output=readable_output)


def get_vulnerabilities_command(client: HelloWorldClient, args: HelloWorldGetVulnerabilitiesArgs) -> CommandResults:
    """Execute helloworld-get-vulnerabilities command.

    Args:
        client (HelloWorldClient): HelloWorld client to use.
        args (HelloWorldGetVulnerabilitiesArgs): Validated command arguments containing:
            - limit: Maximum number of vulnerabilities to retrieve.

    Returns:
        CommandResults: CommandResults object containing vulnerability data.
    """
    demisto.debug(f"[Get vulnerabilities] Fetching vulnerabilities with {args.limit=}")

    # Fetch vulnerabilities from the API
    raw_response = client.get_vulnerabilities(limit=args.limit)
    vulnerabilities = raw_response.get("data", [])

    demisto.debug(f"[Get vulnerabilities] Fetched {len(vulnerabilities)} vulnerabilities")
    readable_output = tableToMarkdown("HelloWorld Vulnerabilities", vulnerabilities)

    return CommandResults(readable_output=readable_output)


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Parse and validate configuration parameters and command arguments, then run commands."""
    execution = ExecutionConfig()
    params = execution.params
    command = execution.command

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as `demisto.debug()`, `demisto.info()`,
    # etc. to print information in the engine runner logs. You can set the log
    # level in the integration instance configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f"[Main] Starting to execute {command=}.")
    client = None
    try:
        client = HelloWorldClient(params)

        match execution.command:
            case "test-module":
                # This is the call made when pressing the integration Test button.
                return_results(test_module(client, params))

            case "ip":
                # Validate command arguments, such as the validity of `ip` addresses
                args = execution.ip_args
                # Run command and get its results
                return_results(ip_reputation_command(client, args, params))

            case "fetch-incidents" | "fetch-events":
                # Implement command(s) that are invoked when fetch is enabled in the integration instance configuration
                # Get last_run from the last time was invoked
                demisto.debug("[Main] Starting fetch")
                last_run = execution.last_run
                next_run = fetch_alerts(client, last_run, severity=params.severity, max_fetch=params.max_fetch)
                # Save next_run for the next time fetch is invoked
                next_run.set()
                demisto.debug("[Main] fetch completed")

            case "fetch-assets":
                demisto.debug("[Main] Starting fetch assets")
                assets_last_run = execution.assets_last_run
                assets_next_run = ...
                assets_last_run.set()
                demisto.debug("[Main] fetch assets")

            case "helloworld-get-events":
                # Validate command arguments
                args = execution.get_events_args
                # Run command and get a list of events and its results
                results = get_events_command(client, args)
                return_results(results)

            case "helloworld-get-assets":
                # Validate command arguments
                args = execution.get_assets_args
                # Run command and get its results
                return_results(get_assets_command(client, args))

            case "helloworld-get-vulnerabilities":
                # Validate command arguments
                args = execution.get_vulnerabilities_args
                # Run command and get its results
                return_results(get_vulnerabilities_command(client, args))
            
            case "helloworld-alert-list":
                # Validate command arguments, such as the existence of `alert_id` or `severity`
                args = execution.alert_list_args
                # Run command and get its results
                return_results(alert_list_command(client, args))

            case "helloworld-alert-note-create":
                # Validate command arguments, such as `alert_id` > 0
                args = execution.alert_note_create_args
                # Run command and get its results
                return_results(alert_note_create_command(client, args))

            case "helloworld-say-hello":
                # Validate command arguments, such as mandatory `name` string
                args = execution.say_hello_args
                # Run command and get its results
                return_results(say_hello_command(client, args))

            case "helloworld-job-submit":
                # Submit a job and initiate polling
                args = execution.job_submit_args
                # Run command and get its results
                return_results(job_submit_command(client, args))

            case "helloworld-job-poll":
                # Periodically polls the status of a process being executed on a remote host
                # When the the process execution is done, the final result is returned and polling stops
                args = execution.job_poll_args
                # Run command, schedule next polling run, and return final result when complete
                return_results(job_poll_command(args, client))

            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(f"[Main] Failed to execute {command=}: {str(e)}. {traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

    finally:
        demisto.debug(f"[Main] Generating diagnostic report after executing {command=}.")
        if client:
            client.log_optional_diagnostic_report()


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
