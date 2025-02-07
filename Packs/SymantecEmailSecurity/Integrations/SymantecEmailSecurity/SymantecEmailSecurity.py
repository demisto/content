import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401, F403 # pylint: disable=unused-wildcard-import

""" Imports """

import copy
import dataclasses
import functools
import http
from enum import Enum
from typing import Any, Callable

""" Global Variables """

INTEGRATION_PREFIX = "SymantecEmailSecurity"
COMMAND_PREFIX = "symantec-email-security"
MAX_INCIDENTS_TO_FETCH = 200
DEFAULT_LIMIT = 50
QUARANTINE_API_MAX_LIMIT = 10000

SEVERITY_MAPPING = {
    "UNSET_SEVERITY": IncidentSeverity.UNKNOWN,
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}


class APIListAction(str, Enum):
    MERGE = "MERGE"
    REPLACE = "REPLACE"
    IOC = "IOC"


class APIRowActionChoices(str, Enum):
    ADD = "A"
    UPDATE = "U"
    DELETE = "D"
    RENEW = "R"


class EmailDirectionChoices(str, Enum):
    INBOUND = "I"
    OUTBOUND = "O"
    BOTH = "B"


class RemediationActionChoices(str, Enum):
    BLOCK_AND_DELETE = "B"
    QUARANTINE = "Q"
    REDIRECT = "M"
    TAG_SUBJECT = "T"
    APPEND_HEADER = "H"


class AccessControl(str, Enum):
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class AccessControlAction(str, Enum):
    MERGE = "MERGE"
    DELETE = "DELETE"


class SortOrder(str, Enum):
    DESC = "desc"
    ASC = "asc"


class QuarantineType(str, Enum):
    SPAM = "SPAM"
    NEWSLETTER = "NEWSLETTER"
    CI = "CI"
    CO = "CO"
    II = "II"
    IO = "IO"
    COMPLIANCE = "COMPLIANCE"
    DLP = "DLP"


@dataclasses.dataclass
class IOC:
    IocType: str | None
    IocValue: str | None
    Description: str | None
    EmailDirection: EmailDirectionChoices | None
    APIRowAction: APIRowActionChoices | None = None
    IocBlacklistId: str | None = None
    RemediationAction: RemediationActionChoices | None = None
    api_list_action: APIListAction | None = None  # Store the action for validation

    def __post_init__(self):
        """Automatically validate the instance after it's initialized."""
        if self.api_list_action:
            self.validate(self.api_list_action)

        # Delete api_list_action from the instance to avoid it being included in serialization
        del self.api_list_action

    def validate(self, api_list_action: APIListAction):
        """Validate the IOC based on the APIListAction and APIRowAction."""
        mandatory_fields = [self.IocType, self.IocValue, self.Description, self.EmailDirection]

        # Check that all mandatory fields are present
        if not all(mandatory_fields):
            raise DemistoException("Fields IocType, IocValue, Description, and EmailDirection are mandatory.")

        # Validate based on the APIListAction (MERGE, REPLACE, IOC)
        if api_list_action in [APIListAction.MERGE, APIListAction.REPLACE]:
            self._validate_merge_or_replace(api_list_action)
        elif api_list_action == APIListAction.IOC:
            self._validate_ioc()

        # Validate based on the specific APIRowAction if provided
        if self.APIRowAction:
            self._validate_row_action(self.APIRowAction)

    def _validate_merge_or_replace(self, api_list_action: APIListAction) -> None:
        """Validate for MERGE and REPLACE actions."""
        # Ensure APIRowAction and IocBlacklistId are not present
        if self.APIRowAction or self.IocBlacklistId:
            raise DemistoException(
                f"APIRowAction and IocBlacklistId should be omitted or blank for {api_list_action.value} requests."
            )

    def _validate_ioc(self) -> None:
        """Validate for the IOC action."""
        # Validation based on APIRowAction
        if not self.APIRowAction:
            raise DemistoException("APIRowAction must be present for action=ioc.")

        if self.APIRowAction == APIRowActionChoices.ADD:
            self._validate_add()
        elif not self.IocBlacklistId:  # For UPDATE, DELETE, and RENEW actions, IocBlacklistId must be present
            raise DemistoException(
                f"IocBlacklistId must be present for APIRowAction={self.APIRowAction and self.APIRowAction.value}."
            )

    def _validate_row_action(self, api_row_action: APIRowActionChoices) -> None:
        """Validate rules based on the APIRowAction."""
        validation_map: dict[APIRowActionChoices, Callable[[], None]] = {
            APIRowActionChoices.ADD: self._validate_add,
        } | dict.fromkeys(
            [
                APIRowActionChoices.UPDATE,
                APIRowActionChoices.DELETE,
                APIRowActionChoices.RENEW,
            ],
            self._validate_update_or_delete_or_renew,
        )

        validation_func = validation_map.get(api_row_action)

        if not validation_func:
            raise DemistoException(f"Unsupported APIRowAction: {api_row_action}")

        validation_func()

    def _validate_add(self) -> None:
        """Validate for the ADD APIRowAction."""
        if self.IocBlacklistId:
            raise DemistoException("IocBlacklistId should not be present for APIRowAction=A (Add).")

    def _validate_update_or_delete_or_renew(self) -> None:
        """Validate for the UPDATE APIRowAction."""
        if not self.IocBlacklistId:
            raise DemistoException(
                f"IocBlacklistId must be present for APIRowAction={self.APIRowAction and self.APIRowAction.value}"
                f" ({APIRowActionChoices(self.APIRowAction)})."
            )

    @staticmethod
    def _convert_to_enum(value: Any, expected_type: type) -> Enum | Any:
        """Convert value to Enum if expected_type is an Enum or Optional Enum."""
        enum_type = None

        # Handle Enum and None | Enum type using `__args__`
        if isinstance(expected_type, type) and issubclass(expected_type, Enum):
            enum_type = expected_type
        elif args := getattr(expected_type, "__args__", []):
            # Check if it's a `None | Enum` type
            enum_type = next(
                (t for t in args if isinstance(t, type) and issubclass(t, Enum)),
                None,
            )

        # Convert value to Enum if applicable
        if enum_type and isinstance(value, str):
            try:
                return enum_type(value)
            except ValueError:
                raise DemistoException(f"{value} is not a valid {enum_type.__name__}")

        return value

    @classmethod
    def from_dict(cls, env: dict, api_list_action: APIListAction) -> "IOC":
        """Creates an instance of the IOC class from a dictionary,
        converting dictionary values to Enum members where applicable.
        """
        field_types = {f.name: f.type for f in dataclasses.fields(cls)}
        processed_env = {
            key: cls._convert_to_enum(value, field_types[key])  # type: ignore[arg-type]
            for key, value in env.items()
            if key in field_types
        }

        ioc = cls(**processed_env)  # type: ignore[arg-type]  # Doesn't recognize arguments typing in pre-commit
        ioc.validate(api_list_action)

        return ioc


""" Decorators """


def pagination(items_key: str) -> Callable:
    """Pagination decorator wrapper to control functionality within the decorator.

    Args:
        items_key (str): A key to the inner list of items.

    Returns:
        Callable: Pagination decorator.
    """

    def dec(func: Callable) -> Callable:
        """Pagination decorator holding the callable function.

        Args:
            func (Callable): API request for GET command.

        Returns:
            Callable: inner function that handles the pagination request.
        """

        def _manual(self, page: int, page_size: int = DEFAULT_LIMIT, *args, **kwargs) -> dict[str, Any]:
            page = max(page, 1)
            start_index = (page - 1) * page_size
            page_size = min(page_size, QUARANTINE_API_MAX_LIMIT)
            demisto.debug(f"Making manual pagination call with {start_index=}, {page_size=}.")

            return func(self, start_index=start_index, page_size=page_size, *args, **kwargs)

        def _automatic(self, limit: int = DEFAULT_LIMIT, *args, **kwargs) -> dict[str, Any]:
            response: dict[str, Any] = {}
            remaining_items = limit
            start_index = None
            demisto.debug("Starting automatic pagination...")

            # Keep calling the API until the required amount of items have been met.
            while remaining_items > 0:
                page_size = min(remaining_items, QUARANTINE_API_MAX_LIMIT)
                demisto.debug(f"Making call with {start_index=}, {page_size=}.")
                current_response = func(self, start_index=start_index, page_size=page_size, *args, **kwargs)

                # Initialize response on the first call, preserving all outer fields
                if not response:
                    demisto.debug("Got first response from API.")
                    response = copy.deepcopy(current_response)  # Copy to avoid overwriting current_response's key.
                    response[items_key] = []

                items = current_response.get(items_key, [])
                response[items_key] += items
                received_items = len(items)
                demisto.debug(f"Received {received_items} from the response.")

                # API exhausted, no items returned or number of items returned is lower than requested.
                if not items or received_items < page_size:
                    demisto.debug(
                        "Ending automatic pagination, no items were returned or received less than requested."
                    )
                    break

                # Calculate the start_index and limit for the next run.
                remaining_items -= received_items
                start_index = (start_index or 0) + received_items
                demisto.debug(f"Next run: {remaining_items=}, {start_index=}.")

            return response

        @functools.wraps(func)
        def wrapper(
            self,
            page: int | None = None,
            page_size: int | None = None,
            limit: int = DEFAULT_LIMIT,
            *args,
            **kwargs,
        ) -> dict[str, Any]:
            """Handle pagination arguments to return multiple response from an API.

            Args:
                page (int | None, optional): Page number to return.
                    Defaults to None.
                page_size (int | None, optional): Number of items to return in a page.
                    Defaults to None.
                limit (int, optional): Number of items to return.
                    Defaults to DEFAULT_LIMIT.

            Returns:
                dict[str, Any]: Paginated response.
            """
            if page is not None:
                return _manual(self, page, page_size or DEFAULT_LIMIT, *args, **kwargs)

            return _automatic(self, limit, *args, **kwargs)

        return wrapper

    return dec


def validate_response(func: Callable) -> Callable:
    """Validate the response's status from the API and raise an error in case of failure.

    Args:
        func (Callable): API request to validate.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> dict[str, Any]:
        """Validate the response's status from the API and raise an error in case of failure.

        Raises:
            DemistoException: The response status wasn't SUCCESS.

        Returns:
            dict[str, Any]: The original API response.
        """
        response = func(*args, **kwargs)

        if response.get("status") != "SUCCESS":
            raise DemistoException(f"The API request failed for the following reason: {response}", res=response)

        return response

    return wrapper


""" Client """


class Client(BaseClient):
    """Client class to interact with the Symantec email security API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of API.
            username (str): The username used for authentication.
            password (str): The password used for authentication.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to True.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        super().__init__(
            base_url=base_url,
            auth=(username, password),
            verify=verify,
            proxy=proxy,
            headers={"Accept": "application/json"},
        )

    def list_ioc(self, domain: str = "global") -> list[dict[str, Any]]:
        """Download the list of IOCs that apply to a specific domain or to all domains.

        Args:
            domain (str): Run the command for a specific domain or all domains with 'global'.
                Defaults to "global".

        Returns:
            list[dict[str, Any]]: The API response.
        """
        return self._http_request("GET", url_suffix=f"domains/{domain}/iocs/download")

    def action_ioc(
        self,
        iocs: list[IOC],
        domain: str = "global",
        api_list_action: APIListAction = APIListAction.IOC,
    ) -> list[dict[str, Any]]:
        """Add, update, delete and renew multiple IOCs.

        Args:
            iocs (list[IOC]): List of IOCs to set the action upon.
            domain (str): Run the command for a specific domain or all domains with 'global'.
                Defaults to "global".
            api_list_action (str, optional): Defines the action for IOCs:
                - MERGE: to merge or update IOCs without APIRowAction and IocBlacklistId.
                - REPLACE: to delete and replace IOCs without APIRowAction and IocBlacklistId;
                - IOC: to add (without IocBlacklistId), update, delete, or renew (with IocBlacklistId)
                    IOCs based on APIRowAction.
                Defaults to "IOC".

        Returns:
            list[dict[str, Any]]: The API response.
        """
        return self._http_request(
            "POST",
            url_suffix=f"domains/{domain}/iocs/upload",
            params={"api-list-action": api_list_action.value},
            json_data=remove_empty_elements([dataclasses.asdict(ioc) for ioc in iocs]),
        )

    def renew_ioc(self, domain: str = "global") -> None:
        """Renew all IOCs previously uploaded and still in the database, whether active or inactive,
        for a specific domain or all domains.

        The default retention period for IOCs is 7 days and the maximum is 30 days.
        After 30 days IOCs are retained in an inactive state for another 14 days.
        If an organization receives new email containing previously block listed IOCs,
        then the IOCs can renewed in the block list within this grace period.
        Thereafter, IOCs are removed from the system and must be uploaded again to remain in the block list.

        Args:
            domain (str): Run the command for a specific domain or all domains with 'global'.
                Defaults to "global".
        """
        response: requests.Response = self._http_request(
            "POST",
            url_suffix=f"domains/{domain}/iocs/renewall",
            resp_type="response",
        )

        if response.headers.get("x-status") != "SUCCESS":
            raise DemistoException(f"Failed to renew IOCs, reason: {response.headers.get('x-diagnostics-info')}.")

    def list_data(
        self,
        feed_type: str,
        reset: str | None = None,
        include: str | None = None,
    ) -> str | list[dict[str, Any]]:
        """Retrieves data feeds from Symantec Email Security.cloud.

        Available feeds:
            - all: metadata for all scanned email.
            - malware: malware-containing email data.
            - threat-isolation: events from URL and Attachment Isolation.
            - clicktime: metadata from end-user clicks on rewritten URLs.
            - anti-spam: spam detection metadata.
            - ec-reports: contextual information about emails blocked by Anti-Malware service.

        Args:
            feed_type (str): The name of the data feed to retrieve.
            reset (str, optional): A string representing the date from which to start reading metadata
                with the format YYYY-MM-ddThh:mm:ssZ. When calling the service for the first time,
                if you don't provide the reset option a 416 status code will be returned.
                The reset request itself returns a 200 status code, but no data items.
                Requests following the initial reset request will return the latest data.
                For example, using the URI https://datafeeds.emailsecurity.symantec.com/all?reset=2016-09-01T00:00:00Z
                would reset the cursor for the all feed to midnight on the first of September 2016 (UTC) and
                start returning data from that point onward.
                Default to None.
            include (str, optional): Only relevant to `all` feed.
                Contains metadata that describes both inbound and outbound email delivery to provide visibility
                into email tracing, TLS compliance, and routing.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "GET",
            url_suffix=feed_type,
            params=remove_empty_elements({"reset": reset, "include": include}),
            resp_type="text" if reset else "json",
        )

    def list_email_queue(self, domains: list[str] | None = None) -> dict[str, Any]:
        """Returns a list of domains owned by the customer, with queue statistics for each domain.

        Args:
            domains (list[str] | None, optional): Limit responses to only contain results for provided domain.
                This argument can be repeated to specify multiple domains.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request("GET", url_suffix="stats", params=assign_params(domain=domains))


""" Quarantine Client """


class QuarantineClient(BaseClient):
    """Client class to interact with the Symantec email security quarantine API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of API.
            username (str): The username used for authentication.
            password (str): The password used for authentication.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to True.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        super().__init__(
            base_url=base_url,
            auth=(username, password),
            verify=verify,
            proxy=proxy,
        )

    @pagination("mail_list")
    @validate_response
    def list_quarantine_email(
        self,
        q: str | None = None,
        sort_column: str | None = None,
        sort_order: str | None = None,
        after: str | None = None,
        before: str | None = None,
        page_size: int | None = None,
        start_index: int | None = None,
        filter_type: str | None = None,
        include_deleted: str | None = None,
        user: str | None = None,
        admin_domain: str | None = None,
    ) -> dict[str, Any]:
        """Retrieves the metadata for quarantined emails belonging to the authenticated user.

        If the user is an administrator, the API provides options to retrieve the metadata for emails quarantined
        for another user under his administration.

        Args:
            q (str | None, optional): A search criterion that can be used to filter emails that
                match only certain conditions based on email metadata.
                The search syntax is built by a field name and search value enclosed by parenthesis and the operators:
                ''OR'', ''AND'' to combine multiple search criteria's or values, example: (email_subject:test).
                Acceptable field names are: ''dlp_message_id'', ''email_envelope_sender'',
                ''email_envelope_sender.raw'', ''email_sender'', ''email_envelope_recipient'',
                ''email_envelope_recipient.raw'', ''email_subject'', ''email_subject.raw''.
                Defaults to None.
            sort_column (str | None, optional): Specifies the column to use for sorting.
                Defaults to None.
            sort_order (str | None, optional): Specifies the order in which to sort.
                Defaults to None.
            after (str, optional): A Unix time stamp value in milliseconds that specifies that the API selects only
                emails that were quarantined after this time.
                Defaults to None.
            before (str | None, optional): A Unix time stamp value in milliseconds, to select only emails that were
                quarantined before this time.
                Defaults to None.
            page_size (int | None, optional): Number of entries to be returned in a response.
                Defaults to None.
            start_index (int | None, optional): The start index of the results.
                Defaults to None.
            filter_type (str | None, optional): A string used to filter emails based on the quarantine type.
                By default includes the emails quarantined for all types.
                Accepted values are: SPAM, NEWSLETTER, CI, CO, II, IO, COMPLIANCE: Includes Content control,
                DLP and Image control emails. DLP: Includes only DLP emails.
                Defaults to None.
            include_deleted (str, optional): Specifies whether to include items marked as deleted in the search results.
                Allowed values are YES and NO.
                Defaults to None
            user (str | None, optional): An email address. Returns only the quarantined emails of the user whose
                email address is specified.
                Defaults to None.
            admin_domain (str, optional): A string identifying a domain.
                Returns the emails quarantined for users in a particular domain.
                If this parameter is present and has a valid domain name, then items from only that domain are returned.
                If it has a value of ALL, then all domains administered by the user are searched and
                emails quarantined for users in those domains are returned.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "GET",
            url_suffix="v1/mails",
            params=remove_empty_elements(
                {
                    "q": q,
                    "sort_column": sort_column,
                    "sort_order": sort_order,
                    "after": after,
                    "before": before,
                    "page_size": page_size,
                    "start_index": start_index,
                    "filter_type": filter_type,
                    "include_deleted": include_deleted,
                    "user": user,
                    "admin_domain": admin_domain,
                }
            ),
        )

    @validate_response
    def preview_quarantine_email(self, q: str) -> dict[str, Any]:
        """Retrieves the contents of the email specified in the request.

        To preview an email the compliance policy must allow it.

        Args:
            q (str): The message ID of the email to preview.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request("GET", url_suffix="v1/mails/preview", params={"q": q})

    @validate_response
    def release_quarantine_email(
        self,
        mail_list: list[str],
        recipient: str | None = None,
        headers: list[str] | None = None,
        encrypt: str | None = None,
    ) -> dict[str, Any]:
        """Releases the set of emails specified in the request.

        Args:
            mail_list (list[str]): List of emails message IDs to release.
            recipient (str | None, optional): An email address to which the mails have to be released instead
                of the recipient users address.
                Defaults to None.
            recipient (str | None, optional): List of x-headers that will be added to the message on release.
                Defaults to None.
            recipient (str | None, optional): If true adds an 'x-encrypted-quarantine-release: true' to the released
                email. Customers have to configure a corresponding DP rule that triggers encryption.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            url_suffix="v1/mails/release",
            json_data=remove_empty_elements(
                {
                    "mail_list": mail_list,
                    "options": {
                        "recipient": recipient,
                        "headers": {f"x-header-{i + 1}": header for i, header in enumerate(headers or [])},
                        "encrypt": encrypt,
                    },
                }
            ),
        )

    @validate_response
    def delete_quarantine_email(self, message_ids: list[str]) -> None:
        """Deletes the set of quarantined emails specified in the request.

        The items are marked as deleted in the backend data store, but are not physically deleted.

        Args:
            message_ids (list[str]): List of emails message IDs to delete.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            url_suffix="v1/mails/delete",
            json_data=message_ids,
        )

    @pagination("items")
    @validate_response
    def list_item_allow_block_list(
        self,
        access_control: AccessControl,
        q: str | None = None,
        sort_column: str | None = None,
        sort_order: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        start_index: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        """Retrieve the allow/block list items.

        Args:
            access_control (AccessControl): The access control list to retrieve.
            q (str | None, optional): A string that at least some part of the allow/block list item must contain.
                Defaults to None.
            sort_column (str | None, optional): Specifies the column to use for sorting.
                Defaults to None.
            sort_order (str | None, optional): Specifies the order in which to sort.
                Defaults to None.
            from_date (str, optional): A Unix time stamp value used to select only SUDULS items that were created
                after this time.
                Defaults to None.
            to_date (str | None, optional): A Unix time stamp value used to select only SUDULS items that were created
                before this time.
                Defaults to None.
            start_index (int | None, optional): Starting entry index of the page.
                Defaults to None.
            page_size (int | None, optional): Number of entries to be returned in the response.
                Defaults to None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "GET",
            url_suffix=f"v1/users/{access_control}",
            params=remove_empty_elements(
                {
                    "q": q,
                    "sort_column": sort_column,
                    "sort_order": sort_order,
                    "from_date": from_date,
                    "to_date": to_date,
                    "start_index": start_index,
                    "page_size": page_size,
                }
            ),
        )

    @validate_response
    def action_item_allow_block_list(
        self,
        access_control: AccessControl,
        action: AccessControlAction,
        suduls_user: str | None = None,
        suduls_item_id: str | None = None,
        email_or_domain: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Allows a SUDULS user to add a new item to allow/block list, or to update/delete an existing item.

        Args:
            access_control (AccessControl): Path param that dictates whether the command is whitelist/blacklist.
            action (AccessControlAction): The action to take upon the allow/block list item.
            suduls_user (str): Email address of the user for whom the entry should be added in the allow/block list.
            suduls_item_id (str | None, optional): ID of SUDULS item to be added/updated/deleted.
                Not required when adding an item.
                Defaults to None.
            email_or_domain (str | None, optional): Email address or domain to be added in the allow/block list.
                Defaults None.
            description (str | None, optional): Description of the item to be added to the allow/block list.
                Defaults None.

        Returns:
            dict[str, Any]: The API response.
        """
        return self._http_request(
            "POST",
            url_suffix=f"v1/users/{access_control}",
            json_data=remove_empty_elements(
                {
                    "suduls_user": suduls_user,
                    "suduls_itemId": suduls_item_id,
                    "action": action,
                    "email_or_domain": email_or_domain,
                    "description": description,
                }
            ),
        )


""" Helpers """


def determine_clients(
    command: str,
    username: str | None,
    password: str | None,
    command_to_url: dict[str, Any],
    has_any_client_url: bool,
    quarantine_username: str | None,
    quarantine_password: str | None,
    url_quarantine: str | None,
    verify_certificate: bool,
    proxy: bool,
) -> tuple[Client | None, QuarantineClient | None]:
    """Determines and returns the appropriate client(s) for executing a command.

    Args:
        command (str): The command to be executed, mapped to a specific base URL.
        username (str | None): The username for regular client authentication.
        password (str | None): The password for regular client authentication.
        command_to_url (dict[str, Any]): A dictionary mapping commands to their respective base URLs.
        quarantine_username (str | None): The username for quarantine client authentication.
        quarantine_password (str | None): The password for quarantine client authentication.
        url_quarantine (str | None): The base URL for the quarantine client.
        verify_certificate (bool): Whether to verify the server's SSL certificate.
        proxy (bool): Whether to use a proxy when making requests.

    Raises:
        DemistoException:
            - Raised if only one of username/password or quarantine_username/quarantine_password is provided.
            - Raised if the URL of specific credentials weren't provided.

    Returns:
        tuple[Client | None, QuarantineClient | None]: A tuple containing:
            - A `Client` instance if regular credentials and a URL were provided, otherwise `None`.
            - A `QuarantineClient` instance if quarantine credentials and a URL were provided, otherwise `None`.
    """
    if bool(username) != bool(password) or bool(quarantine_username) != bool(quarantine_password):
        raise DemistoException("Both username and password must be present when adding credentials.")

    if not any((username, password, quarantine_username, quarantine_password)):
        raise DemistoException("At least one of the credentials must be filled.")

    client = None
    quarantine_client = None
    is_test_command = command == "test-module"

    if username and password and (is_test_command or command in command_to_url):
        if base_url := command_to_url.get(command):
            client = Client(
                base_url=base_url,
                username=username,
                password=password,
                verify=verify_certificate,
                proxy=proxy,
            )
        elif not (is_test_command and has_any_client_url):
            raise DemistoException(
                "Missing URL for 'Credentials', please fill the correct URL according to the mapping in 'Help'."
            )

    if quarantine_username and quarantine_password:
        if not url_quarantine:
            raise DemistoException("Missing URL for 'Quarantine Credentials', please fill 'Server URL - Quarantine'.")

        quarantine_client = QuarantineClient(
            base_url=url_quarantine,
            username=quarantine_username,
            password=quarantine_password,
            verify=verify_certificate,
            proxy=proxy,
        )

    return client, quarantine_client


def convert_datetime_string(dt_str: str | datetime) -> str:
    """Converts a datetime string to ISO 8601 format with microseconds set to zero and appends 'Z'.

    Args:
        dt_str (str | datetime): The datetime string to convert.

    Returns:
        str: The converted datetime string in ISO 8601 format with 'Z' appended.
    """
    dt = cast(datetime, arg_to_datetime(dt_str, required=True)) if not isinstance(dt_str, datetime) else dt_str
    dt = dt.replace(microsecond=0)

    # Remove timezone information if present
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)

    return dt.isoformat() + "Z"


def convert_to_epoch_timestamp(dt_str: datetime | str | None) -> str | None:
    """Converts a datetime string to an epoch timestamp in milliseconds.

    Args:
        dt_str (str | None): The datetime string to convert.

    Returns:
        str: If a valid date string was given, then an epoch timestamp, otherwise None.
    """
    dt = arg_to_datetime(dt_str) if not isinstance(dt_str, datetime) else dt_str

    if not dt:
        return None

    return str(int(dt.timestamp() * 1000))


def arg_to_optional_bool(arg: Any | None) -> None | bool:
    """Converts an argument to an optional boolean value.

    Args:
        arg (Any | None): The argument to be converted. Can be of any type or None.

    Returns:
        None | bool: Returns None if the argument is None; otherwise, returns the boolean representation of the arg.
    """
    return None if arg is None else argToBoolean(arg)


""" Commands """


@logger
def test_module(
    credentials: tuple | None = None,
    url_ioc: str | None = None,
    url_data_feeds: str | None = None,
    url_email_queue: str | None = None,
    quarantine_client: QuarantineClient | None = None,
) -> str:
    """Test the connection to the API only for clients that are present.

    Args:
        client (Client): Session to the API to run HTTP requests.
        quarantine_client (QuarantineClient): Session to the API to run HTTP requests.

    Raises:
        DemistoException: When an unknown HTTP error has occurred.

    Returns:
        str: returns "ok" which represents that the test connection to the client was successful.
            Otherwise, return an informative message based on the user's input.
    """
    if not any((credentials, quarantine_client)):
        return "At least one of the credentials must be filled."

    client_passed = False

    try:
        if credentials:
            if url_ioc:
                try:
                    Client(url_ioc, *credentials).list_ioc()
                except DemistoException as exc:
                    if exc.res and exc.res.status_code == http.HTTPStatus.NOT_FOUND:
                        return "The given URL for 'Server URL - IOC' is invalid. Please verify the URL."
                    raise exc

            if url_data_feeds:
                try:
                    Client(url_data_feeds, *credentials).list_data("all", convert_datetime_string("3 days"))
                except DemistoException as exc:
                    if exc.res and exc.res.status_code == http.HTTPStatus.NOT_FOUND:
                        return "The given URL for 'Server URL - Data Feeds' is invalid. Please verify the URL."
                    raise exc

            if url_email_queue:
                try:
                    Client(url_email_queue, *credentials).list_email_queue()
                except DemistoException as exc:
                    if exc.res and exc.res.status_code == http.HTTPStatus.NOT_FOUND:
                        return "The given URL for 'Server URL - Email Queue' is invalid. Please verify the URL."
                    raise exc

        client_passed = True

        if quarantine_client:
            try:
                quarantine_client.list_quarantine_email()
            except DemistoException as exc:
                if exc.res and exc.res.status_code == http.HTTPStatus.NOT_FOUND:
                    return "The given URL for 'Server URL - Quarantine' is invalid"
                raise exc
    except DemistoException as exc:
        if exc.res is not None:
            if exc.res.status_code == http.HTTPStatus.UNAUTHORIZED:
                return (
                    "Authorization Error: Invalid Credentials."
                    f" Please verify the {'Quarantine ' if client_passed else ''}credentials."
                )

        raise exc

    return "ok"


@logger
def list_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the IOCs that apply to a specific domain or to all domains.

    Args:
        client (Client): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    raw_response = client.list_ioc(args.get("domain", "global"))

    if not argToBoolean(args.get("all_results", False)):
        limit = arg_to_number(args.get("limit", 50))
        raw_response = raw_response[:limit]

    table = [
        {
            "ID": item.get("iocBlackListId"),
            "Type": item.get("iocType"),
            "Value": item.get("iocValue"),
            "Status": item.get("status"),
            "Description": item.get("description"),
            "Email Direction": (
                EmailDirectionChoices(item["emailDirection"]).name.lower() if item.get("emailDirection") else None
            ),
            "Remediation Action": (
                RemediationActionChoices(item["remediationAction"]).name.lower().replace("_", " ")
                if item.get("remediationAction")
                else None
            ),
            "Expiry Date": item.get("expiryDate"),
        }
        for item in raw_response
    ]

    readable_output = tableToMarkdown(
        name="IOC(s)",
        t=table,
        headers=[
            "ID",
            "Type",
            "Value",
            "Status",
            "Description",
            "Email Direction",
            "Remediation Action",
            "Expiry Date",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.IOC",
        outputs_key_field="iocBlackListId",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def action_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add, update, delete and renew multiple IOCs.

    Args:
        client (Client): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    domain = args.get("domain", "global")
    action = "IOC" if args["action"] == "upload_ioc_json" else args["action"].upper()

    api_row_action = None

    if action in APIListAction.__members__:
        api_list_action = APIListAction[action]
    else:  # action in APIRowActionChoices
        api_list_action = APIListAction.IOC
        api_row_action = APIRowActionChoices[action]

    iocs: list[IOC] = []

    if entry_id := args.get("entry_id"):  # Build IOCs from an entry file.
        if api_row_action:
            raise DemistoException("The field `entry_id` is only compatible with `action=merge/replace/ioc`.")

        file_entry = demisto.getFilePath(entry_id)

        with open(file_entry["path"], "rb") as handler:
            content = handler.read()

        iocs = [IOC.from_dict(ioc, api_list_action) for ioc in json.loads(content)]
    else:  # Build a single IOC from the given params.
        if action == APIListAction.IOC:
            raise DemistoException("`action=ioc` is only compatible with `entry_id`.")

        if email_direction := args.get("email_direction"):
            email_direction = EmailDirectionChoices[email_direction.upper()].value

        if remediation_action := args.get("remediation_action"):
            remediation_action = RemediationActionChoices[remediation_action.replace(" ", "_").upper()].value

        iocs.append(
            IOC(
                IocBlacklistId=args.get("ioc_id"),
                APIRowAction=api_row_action,
                IocType=args.get("ioc_type"),
                IocValue=args.get("ioc_value"),
                Description=args.get("description"),
                EmailDirection=email_direction,
                RemediationAction=remediation_action,
                api_list_action=api_list_action,
            )
        )

    raw_response = client.action_ioc(
        iocs=iocs,
        domain=domain,
        api_list_action=api_list_action,
    )

    readable_output = "## The following IOC(s) failed:" if raw_response else "## All IOC(s) were uploaded successfully."

    for item in raw_response:
        identifier = item.get("iocBlackListId") or f"{item.get('iocType')}-{item.get('iocValue')}"
        readable_output += f"\n- {identifier}: {item.get('failureReason')}"

    return CommandResults(readable_output=readable_output)


@logger
def renew_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Renew all IOCs previously uploaded and still in the database, whether active or inactive,
    for a specific domain or all domains.

    The default retention period for IOCs is 7 days and the maximum is 30 days.
    After 30 days IOCs are retained in an inactive state for another 14 days.
    If an organization receives new email containing previously block listed IOCs,
    then the IOCs can renewed in the block list within this grace period.
    Thereafter, IOCs are removed from the system and must be uploaded again to remain in the block list.

    Args:
        client (Client): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """

    client.renew_ioc(args.get("domain", "global"))
    return CommandResults(readable_output="## All IOC(s) were renewed.")


@logger
def list_data_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieves data feeds from Symantec Email Security.cloud.

    Available feeds:
    - all: metadata for all scanned email.
    - malware: malware-containing email data.
    - threat-isolation: events from URL and Attachment Isolation.
    - clicktime: metadata from end-user clicks on rewritten URLs.
    - anti-spam: spam detection metadata.
    - ec-reports: contextual information about emails blocked by Anti-Malware service.

    Args:
        client (Client): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    feed_type = args.get("feed_type", "all")

    # Reset data feed timer to given start time.
    client.list_data(
        feed_type=feed_type,
        reset=convert_datetime_string(args.get("start_from", "3 days")),
    )
    # Fetch email data feed from start time.
    raw_response = cast(
        list[dict[str, Any]],
        client.list_data(
            feed_type=feed_type,
            include="delivery" if feed_type == "all" and argToBoolean(args.get("include_delivery", False)) else None,
        ),
    )

    if raw_response:
        if argToBoolean(args.get("fetch_only_incidents", False)):
            raw_response = [item for item in raw_response or [] if item.get("incidents")]

        if not argToBoolean(args.get("all_results", False)):
            limit = arg_to_number(args.get("limit", 50))
            raw_response = raw_response[:limit]

    table = []

    for item in raw_response or []:
        row: dict[str, Any] = {"Incidents": []}

        if email_info := item.get("emailInfo"):
            row["Message Size"] = email_info.get("messageSize")
            row["Subject"] = email_info.get("subject")
            row["Envelope From"] = email_info.get("envFrom")
            row["Envelope To"] = email_info.get("envTo")
            row["Sender IP"] = email_info.get("senderIp")
            row["Sender Mail Server"] = email_info.get("senderMailserver")
            row["File/URLs With Risk"] = [
                f"{v.get('fileNameOrURL')}-{v.get('urlRiskScore')}" for v in email_info.get("filesAndLinks", [])
            ]

        for incident in item.get("incidents") or []:  # The key itself may contain null value.
            row["Incidents"].append(
                {
                    "Severity": incident.get("severity"),
                    "Security Service": incident.get("securityService"),
                    "Detection Method": incident.get("detectionMethod"),
                    "Verdict": incident.get("verdict"),
                    "Action": incident.get("action"),
                }
            )

        table.append(row)

    readable_output = tableToMarkdown(
        name="Email Data Feed(s)",
        t=table,
        headers=[
            "Message Size",
            "Subject",
            "Envelope From",
            "Envelope To",
            "Sender IP",
            "Sender Mail Server",
            "File/URLs With Risk",
            "Incidents",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.Data",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_email_queue_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Returns a list of domains owned by the customer, with queue statistics for each domain.

    Args:
        client (Client): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    raw_response = client.list_email_queue(argToList(args.get("domains")))
    domains = raw_response.get("Domains")

    readable_output = tableToMarkdown(
        name="Email Queue Statistic(s)",
        t=raw_response,
        headerTransform=string_to_table_header,
        headers=[
            "TotalMessagesInbound",
            "TotalMessagesOutbound",
            "MeanTimeInQueueInbound",
            "MeanTimeInQueueOutbound",
            "LongestTimeInInbound",
            "LongestTimeInOutbound",
        ],
        removeNull=True,
    )

    if not argToBoolean(args.get("all_results", False)) and domains:
        limit = arg_to_number(args.get("limit", 50))
        raw_response["Domains"] = domains = domains[:limit]

    if domains:
        readable_output += "\n" + tableToMarkdown(
            name="Domain Statistic(s)",
            t=domains,
            headerTransform=string_to_table_header,
            headers=[
                "Name",
                "ReceiveQueueCountInbound",
                "ReceiveQueueCountOutbound",
                "DeliveryQueueCountInbound",
                "DeliveryQueueCountOutbound",
            ],
            removeNull=True,
        )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.EmailQueue",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def list_quarantine_email_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Retrieves the metadata for quarantined emails belonging to the authenticated user.

    If the user is an administrator, the API provides options to retrieve the metadata for emails quarantined
    for another user under his administration.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    raw_response = client.list_quarantine_email(
        q=args.get("query"),
        sort_column=args.get("sort_column"),
        sort_order=args.get("sort_order", SortOrder.DESC.value),
        after=convert_to_epoch_timestamp(args.get("after")),
        before=convert_to_epoch_timestamp(args.get("before")),
        filter_type=args.get("filter_type"),
        include_deleted="YES" if arg_to_optional_bool(args.get("include_deleted")) else "NO",
        user=args.get("user_email"),
        admin_domain=args.get("admin_domain"),
        limit=arg_to_number(args.get("limit", DEFAULT_LIMIT), required=True),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
    )

    outputs = raw_response.get("mail_list", [])
    table = [
        remove_empty_elements(
            {
                "ID": item.get("id"),
                "Date Received": str(arg_to_datetime(dict_safe_get(item, ["metadata", "email_date_received"]))),
                "Direction": dict_safe_get(item, ["metadata", "quarantine_info", "direction"]),
                "Quarantine Type": dict_safe_get(item, ["metadata", "quarantine_info", "quarantine_type"]),
                "Is Released": dict_safe_get(item, ["metadata", "email_is_released"]),
                "Quarantine Reason": dict_safe_get(item, ["metadata", "quarantine_reason"]),
                "Sender": dict_safe_get(item, ["metadata", "email_sender"]),
                "Master Recipient": dict_safe_get(item, ["metadata", "master_recipient"]),
                "Subject": dict_safe_get(item, ["metadata", "email_subject"]),
            }
        )
        for item in outputs
    ]
    readable_output = tableToMarkdown(
        name="Quarantine Email(s)",
        t=table,
        headers=[
            "ID",
            "Date Received",
            "Direction",
            "Quarantine Type",
            "Is Released",
            "Quarantine Reason",
            "Sender",
            "Master Recipient",
            "Subject",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.QuarantineEmail",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def preview_quarantine_email_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Retrieves the contents of the email specified in the request.

    To preview an email the compliance policy must allow it.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    message_id = args["message_id"]
    raw_response = client.preview_quarantine_email(message_id)

    outputs = raw_response.get("details", {})
    outputs["message_id"] = message_id

    readable_output = tableToMarkdown(
        name="Quarantine Email Preview",
        t=outputs.get("headers", {}),
        headerTransform=string_to_table_header,
        headers=[
            "date",
            "from",
            "to",
            "subject",
        ],
    )

    if attachments := outputs.get("attachments"):
        readable_output += tableToMarkdown(
            name="Attachments",
            t=attachments,
            headerTransform=string_to_table_header,
            headers=[
                "name",
                "type",
            ],
        )

    if bodypart := outputs.get("bodypart"):
        readable_output += tableToMarkdown(
            name="Body Parts",
            t=bodypart,
            headerTransform=string_to_table_header,
            headers=[
                "content",
            ],
        )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.QuarantineEmailPreview",
        outputs_key_field="message_id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def release_quarantine_email_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Releases the set of quarantined emails specified in the request.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    client.release_quarantine_email(
        mail_list=argToList(args["message_ids"]),
        recipient=args.get("recipient"),
        headers=argToList(args.get("headers")),
        encrypt=arg_to_optional_bool(args.get("encrypt")),
    )
    return CommandResults(readable_output="## Successfully released all messages.")


@logger
def delete_quarantine_email_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Deletes the set of quarantined emails specified in the request.

    The items are marked as deleted in the backend data store, but are not physically deleted.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    client.delete_quarantine_email(argToList(args["message_ids"]))
    return CommandResults(readable_output="## Successfully deleted all messages.")


@logger
def list_item_allow_block_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Retrieve the allow/block list items.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    raw_response = client.list_item_allow_block_list(
        access_control=args["access_control"],
        q=args.get("query"),
        sort_column=args.get("sort_column"),
        sort_order=args.get("sort_order", SortOrder.DESC.value),
        from_date=convert_to_epoch_timestamp(args.get("after")),
        to_date=convert_to_epoch_timestamp(args.get("before")),
        limit=arg_to_number(args.get("limit", DEFAULT_LIMIT), required=True),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
    )

    outputs = raw_response.get("items", [])
    title = "Allow" if args["access_control"] == AccessControl.WHITELIST else "Block"

    readable_output = tableToMarkdown(
        name=f"{title} List Item(s)",
        t=outputs,
        headerTransform=string_to_table_header,
        headers=[
            "id",
            "type",
            "value",
            "description",
            "date_created",
            "date_amended",
        ],
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{title}",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def update_item_allow_block_list_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to
    add or update an item to the allow/block list.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    client.action_item_allow_block_list(
        access_control=args["access_control"],
        suduls_user=args["suduls_user"],
        action=AccessControlAction.MERGE.value,
        email_or_domain=args["email_or_domain"],
        description=args["description"],
        suduls_item_id=args.get("item_id"),
    )
    return CommandResults(readable_output="## The items were successfully merged.")


@logger
def delete_item_allow_block_list_command(client: QuarantineClient, args: dict[str, Any]) -> CommandResults:
    """Allows a SUDULS (allow quarantine users to maintain their own lists of email addresses or domains) user to delete
    an item from the allow/block list.

    Args:
        client (QuarantineClient): A session to run HTTP requests to the API.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: Outputs of the command that represent an entry in the warroom.
    """
    client.action_item_allow_block_list(
        access_control=args["access_control"],
        action=AccessControlAction.DELETE.value,
        suduls_item_id=args["item_id"],
    )
    return CommandResults(readable_output="## The items were successfully deleted.")


@logger
def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    first_fetch_time: datetime,
    max_results: int = MAX_INCIDENTS_TO_FETCH,
    accepted_severities: list | None = None,
    feed_type: str = "all",
    include_delivery: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """This function will execute each interval (default is 1 minute).

    Args:
        client (Client): A session to run HTTP requests to the API.
        last_run (dict[str, Any]): The greatest incident created_time we fetched from last fetch.
        first_fetch_time (datetime): If last_run is None then fetch all incidents since first_fetch_time.
        max_results (int, optional): Maximum numbers of incidents per fetch.
            Defaults to MAX_INCIDENTS_TO_FETCH.
        feed_type (str, optional): The name of the data feed to retrieve.
            Available feeds:
                - all: metadata for all scanned email.
                - malware: malware-containing email data.
                - threat-isolation: events from URL and Attachment Isolation.
                - clicktime: metadata from end-user clicks on rewritten URLs.
                - anti-spam: spam detection metadata.
                - ec-reports: contextual information about emails blocked by Anti-Malware service.
            Defaults to "all".
        include_delivery (bool, optional): Only relevant to `all` feed.
            Contains metadata that describes both inbound and outbound email delivery to provide visibility
            into email tracing, TLS compliance, and routing.
            Defaults to False

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]:
            - next_run: This will be last_run in the next fetch-incidents.
            - incidents: Incidents that will be created in Cortex XSOAR.
    """
    if last_fetch := last_run.get("last_fetch"):
        reset = last_fetch
    else:
        reset = first_fetch_time

    last_ids: list[str] = last_run.get("last_ids", [])
    incidents: list[dict[str, Any]] = []

    demisto.debug(f"New run {last_fetch=}, {last_ids=}.")

    # Reset data feed timer to given start time.
    client.list_data(
        feed_type=feed_type,
        reset=convert_datetime_string(reset),
    )
    # Fetch email data feed from start time.
    raw_response = cast(
        list[dict[str, Any]],
        client.list_data(
            feed_type=feed_type,
            include="delivery" if feed_type == "all" and include_delivery else None,
        ),
    )

    seen_ids = []
    items = raw_response or []
    demisto.debug(f"Received {len(items)} feed items from the server.")

    for item in items:
        if not (email_info := item.get("emailInfo")) or not (item_incidents := item.get("incidents")):
            continue

        incident_id = email_info.get("xMsgRef")
        seen_ids.append(incident_id)

        # Skip incident if occurred time is less than last fetch
        if incident_id in last_ids:
            continue

        worst_incident = max(
            item_incidents,
            key=lambda incident: SEVERITY_MAPPING.get(incident.get("severity"), IncidentSeverity.UNKNOWN),
        )
        severity = SEVERITY_MAPPING[worst_incident["severity"]]

        if accepted_severities and severity not in accepted_severities:
            continue

        last_fetch = str(email_info["mailProcessingStartTime"])
        demisto.debug(f"Found new incident: {incident_id}.")
        item["incident_type"] = "email_data_feed"

        incidents.append(
            {
                "name": f"{get_integration_name()} - Email Data Feeds - {worst_incident['verdict']} - {incident_id}",
                "occurred": timestamp_to_datestring(last_fetch),
                "severity": severity,
                "details": worst_incident["reason"],
                "rawJSON": json.dumps(item),
            }
        )

        if len(incidents) == max_results:
            break

    demisto.debug(f"Fetched {len(incidents)} incidents, setting next run to {last_fetch}.")
    next_run = {"email_data_feeds": {"last_fetch": last_fetch, "last_ids": seen_ids}}

    return next_run, incidents


@logger
def fetch_incidents_quarantine(
    client: QuarantineClient,
    last_run: dict[str, Any],
    first_fetch_time: datetime,
    max_results: int = MAX_INCIDENTS_TO_FETCH,
    query: str | None = None,
    filter_type: QuarantineType | None = None,
    admin_domain: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """This function will execute each interval (default is 1 minute).

    Args:
        client (Client): A session to run HTTP requests to the API.
        last_run (dict[str, Any]): The greatest incident created_time we fetched from last fetch.
        first_fetch_time (datetime): If last_run is None then fetch all incidents since first_fetch_time.
        max_results (int, optional): Maximum numbers of incidents per fetch.
            Defaults to MAX_INCIDENTS_TO_FETCH.
        query: (str | None, optional): A search criterion that can be used to filter emails that match only certain
            conditions based on email metadata.
            Defaults to None.
        filter_type: (QuarantineType | None, optional): A string used to filter emails based on the quarantine type.
            COMPLIANCE: Includes Content control, DLP and Image control emails. DLP: Includes only DLP emails.
            Defaults to None.
        admin_domain: (str | None, optional): Returns the emails quarantined for users in a particular domain.
            If this parameter is present and has a valid domain name, then items from only that domain are returned.
            If it has a value of `ALL`, then all domains administered by the user are searched and emails quarantined
            for users in those domains are returned. Note: Can only be used by an administrator user.
            Defaults to None.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]:
            - next_run: This will be last_run in the next fetch-incidents.
            - incidents: Incidents that will be created in Cortex XSOAR.
    """
    if last_fetch := last_run.get("last_fetch"):
        after = last_fetch
    else:
        after = convert_to_epoch_timestamp(first_fetch_time)

    last_ids: list[str] = last_run.get("last_ids", [])
    incidents: list[dict[str, Any]] = []

    demisto.debug(f"New run {last_fetch=}, {last_ids=}.")

    response = client.list_quarantine_email(
        q=query,
        sort_order=SortOrder.ASC.value,
        after=after,
        filter_type=filter_type,
        admin_domain=admin_domain,
        limit=max_results,
    )

    seen_ids = []
    items = response.get("mail_list", [])
    demisto.debug(f"Received {len(items)} quarantined emails from the server.")

    for item in items:
        incident_id = item.get("id")
        seen_ids.append(incident_id)

        # Skip incident if occurred time is less than last fetch
        if incident_id in last_ids:
            continue

        response = client.preview_quarantine_email(incident_id)
        item |= response.get("details", {})

        metadata = item.get("metadata", {})
        last_fetch = str(metadata.get("email_date_received"))
        demisto.debug(f"Found new incident: {incident_id}.")
        item["incident_type"] = "email_quarantine"

        incidents.append(
            {
                "name": (
                    f"{get_integration_name()}"
                    " - Email Quarantine"
                    f" - {dict_safe_get(metadata, ['quarantine_info', 'quarantine_type'])}"
                    f" - {incident_id}"
                ),
                "occurred": timestamp_to_datestring(last_fetch),
                "severity": IncidentSeverity.UNKNOWN,
                "details": f"Reason: {metadata.get('quarantine_reason')}",
                "rawJSON": json.dumps(item),
            }
        )

        if len(incidents) == max_results:
            break

    demisto.debug(f"Fetched {len(incidents)} incidents, setting next run to {last_fetch}.")
    next_run = {"email_quarantine": {"last_fetch": last_fetch, "last_ids": seen_ids}}

    return next_run, incidents


""" Entry Point """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    url_ioc: str | None = params.get("url_ioc")
    url_data_feeds: str | None = params.get("url_data_feeds")
    url_email_queue: str | None = params.get("url_email_queue")
    url_quarantine: str | None = params.get("url_quarantine")
    username: str = dict_safe_get(params, ["credentials", "identifier"])
    password: str = dict_safe_get(params, ["credentials", "password"])
    quarantine_username: str = dict_safe_get(params, ["quarantine_credentials", "identifier"])
    quarantine_password: str = dict_safe_get(params, ["quarantine_credentials", "password"])
    verify_certificate: bool = not argToBoolean(params.get("insecure", False))
    proxy: bool = argToBoolean(params.get("proxy", False))

    credentials_commands = {
        f"{COMMAND_PREFIX}-ioc-list": list_ioc_command,
        f"{COMMAND_PREFIX}-ioc-action": action_ioc_command,
        f"{COMMAND_PREFIX}-ioc-renew": renew_ioc_command,
        f"{COMMAND_PREFIX}-data-list": list_data_command,
        f"{COMMAND_PREFIX}-email-queue-list": list_email_queue_command,
    }
    quarantine_commands = {
        f"{COMMAND_PREFIX}-quarantine-email-list": list_quarantine_email_command,
        f"{COMMAND_PREFIX}-quarantine-email-preview": preview_quarantine_email_command,
        f"{COMMAND_PREFIX}-quarantine-email-release": release_quarantine_email_command,
        f"{COMMAND_PREFIX}-quarantine-email-delete": delete_quarantine_email_command,
        f"{COMMAND_PREFIX}-item-allow-list": list_item_allow_block_command,
        f"{COMMAND_PREFIX}-item-allow-list-update": update_item_allow_block_list_command,
        f"{COMMAND_PREFIX}-item-allow-list-delete": delete_item_allow_block_list_command,
        f"{COMMAND_PREFIX}-item-block-list": list_item_allow_block_command,
        f"{COMMAND_PREFIX}-item-block-list-update": update_item_allow_block_list_command,
        f"{COMMAND_PREFIX}-item-block-list-delete": delete_item_allow_block_list_command,
    }

    command_to_url = {
        "fetch-incidents": url_data_feeds,
        f"{COMMAND_PREFIX}-ioc-list": url_ioc,
        f"{COMMAND_PREFIX}-ioc-action": url_ioc,
        f"{COMMAND_PREFIX}-ioc-renew": url_ioc,
        f"{COMMAND_PREFIX}-data-list": url_data_feeds,
        f"{COMMAND_PREFIX}-email-queue-list": url_email_queue,
    }

    demisto.debug(f"Command being called is {command}")

    if "item-allow-list" in command:
        args["access_control"] = AccessControl.WHITELIST.value
    elif "item-block-list" in command:
        args["access_control"] = AccessControl.BLACKLIST.value

    try:
        client, quarantine_client = determine_clients(
            command=command,
            username=username,
            password=password,
            command_to_url=command_to_url,
            has_any_client_url=any((url_ioc, url_data_feeds, url_email_queue)),
            quarantine_username=quarantine_username,
            quarantine_password=quarantine_password,
            url_quarantine=url_quarantine,
            verify_certificate=verify_certificate,
            proxy=proxy,
        )

        is_fetch = command == "fetch-incidents"

        if command == "test-module":
            return_results(
                test_module(
                    credentials=(username, password) if username and password else None,
                    url_ioc=url_ioc,
                    url_data_feeds=url_data_feeds,
                    url_email_queue=url_email_queue,
                    quarantine_client=quarantine_client,
                )
            )
        elif is_fetch:
            fetch_type = params.get("fetch_type", "both")

            if any(
                (
                    fetch_type == "email_data_feed" and not client,
                    fetch_type == "email_quarantine" and not quarantine_client,
                    fetch_type == "both" and not (client and quarantine_client),
                )
            ):
                raise DemistoException("Credentials for the selected fetch type are missing.")

            first_fetch_time = arg_to_datetime(
                arg=params["first_fetch"],
                arg_name="First fetch time",
                required=True,
            )
            max_results = min(
                arg_to_number(
                    arg=params.get("max_fetch"),
                    arg_name="max_fetch",
                    required=False,
                ) or MAX_INCIDENTS_TO_FETCH,
                MAX_INCIDENTS_TO_FETCH,
            )
            last_run = demisto.getLastRun()

            both_next_run: dict[str, Any] = {}
            both_incidents: list[dict[str, Any]] = []

            if fetch_type in ["both", "email_data_feed"]:
                accepted_severities = [
                    getattr(IncidentSeverity, severity.upper()) for severity in argToList(params.get("severity"))
                ]
                feed_type = params.get("type", "all")
                include_delivery = argToBoolean(params.get("include_delivery", False))

                next_run, incidents = fetch_incidents(
                    client=client,
                    last_run=last_run.get("email_data_feed", {}),
                    first_fetch_time=first_fetch_time,
                    max_results=max_results,
                    accepted_severities=accepted_severities,
                    feed_type=feed_type,
                    include_delivery=include_delivery,
                )
                both_next_run |= next_run
                both_incidents += incidents

            if fetch_type in ["both", "email_quarantine"]:
                next_run, incidents = fetch_incidents_quarantine(
                    client=quarantine_client,
                    last_run=last_run.get("email_quarantine", {}),
                    first_fetch_time=first_fetch_time,
                    max_results=max_results,
                    query=params.get("query_quarantine"),
                    filter_type=params.get("type_quarantine"),
                    admin_domain=params.get("admin_domain_quarantine"),
                )
                both_next_run |= next_run
                both_incidents += incidents

            demisto.setLastRun(both_next_run)
            demisto.incidents(both_incidents)
        elif command in credentials_commands:
            if not client:
                raise DemistoException(
                    f"To execute the {command} command, please ensure that 'Credentials' are provided and valid."
                )

            return_results(credentials_commands[command](client, args))
        elif command in quarantine_commands:
            if not quarantine_client:
                raise DemistoException(
                    f"To execute the {command} command, please ensure 'Quarantine Credentials' are provided and valid."
                )

            return_results(quarantine_commands[command](quarantine_client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
