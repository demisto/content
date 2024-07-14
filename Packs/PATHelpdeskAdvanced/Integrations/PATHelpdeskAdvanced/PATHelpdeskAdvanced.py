import contextlib
from json import JSONDecodeError
from pathlib import Path
from typing import Literal, NamedTuple
from collections.abc import Iterable, Callable
import more_itertools
from requests import Response


import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "HelpdeskAdvanced"
OPERATORS = ("eq", "gt", "lt", "ge", "le", "sw", "nw", "ne")
FILTER_CONDITION_REGEX = re.compile(
    rf"\A\"(?P<key>.*?)\" (?P<op>{'|'.join(OPERATORS)}) (?P<value>(?:\".*?\"|null))\Z"
)
PAT_DATE_FORMAT_REGEX = re.compile(r"/Date\((\d+)\)/")
HTML_H_TAG_REGEX = re.compile(r"<h\d>(.*?)<\/h\d>", flags=re.S)


class Field:
    _special_cases = {"unread": "UnRead", "id": "ID", "html": "HTML"}

    def __init__(self, demisto_name: str) -> None:
        title_parts = []
        for part in demisto_name.split("_"):
            if edge_case := Field._special_cases.get(part):
                title_parts.append(edge_case)
            else:
                title_parts.append(part.title())

        self.demisto_name = demisto_name  # lower_case
        self.hda_name = "".join(title_parts)  # PascalCase

    def __repr__(self) -> str:
        return self.hda_name


OBJECT_TYPE_ID = Field("object_type_id")
TICKET_STATUS_ID = Field("ticket_status_id")
TICKET_PRIORITY_ID = Field("ticket_priority_id")
TICKET_CLASSIFICATION_ID = Field("ticket_classification_id")
TICKET_TYPE_ID = Field("ticket_type_id")
OBJECT_DESCTIPTION = Field("object_description")
OBJECT_ENTITY = Field("object_entity")
CONTACT_ID = Field("contact_id")
SUBJECT = Field("subject")
PROBLEM = Field("problem")
SITE = Field("site")
ID = Field("id")
IS_NEW = Field("is_new")
EXPIRATION_DATE = Field("expiration_date")
FIRST_UPDATE_USER_ID = Field("first_update_user_id")
OWNER_USER_ID = Field("owner_user_id")
ASSIGNED_USER_ID = Field("assigned_user_id")
SOLUTION = Field("solution")
SERVICE_ID = Field("service_id")
LOCATION_ID = Field("location_id")
PROBLEM_HTML = Field("problem_html")
NEXT_EXPIRATION_ID = Field("next_expiration_id")
TASK_EFFORT = Field("task_effort")
SUPPLIER_ID = Field("supplier_id")
SOLUTION_HTML = Field("solution_html")
ESTIMATED_TASK_START_DATE = Field("estimated_task_start_date")
ACCOUNT_ID = Field("account_id")
MAIL_BOX_ID = Field("mail_box_id")
CLOSURE_DATE = Field("closure_date")
BILLED_TOKENS = Field("billed_tokens")
PARENT_TICKET_ID = Field("parent_ticket_id")
CUSTOMER_CONTRACT_ID = Field("customer_contract_id")
KNOWN_ISSUE = Field("known_issue")
LANGUAGE_ID = Field("language_id")
ASSET_ID = Field("asset_id")
DATE = Field("date")
URGENCY_ID = Field("urgency_id")
SCORE = Field("score")
ESTIMATED_TASK_DURATION = Field("estimated_task_duration")
SITE_UNREAD = Field("site_unread")
SOLICITS = Field("solicits")
CALENDAR_ID = Field("calendar_id")
LAST_EXPIRATION_DATE = Field("last_expiration_date")
NEXT_EXPIRATION_DATE = Field("next_expiration_date")
ASSIGNED_USER_OR_GROUP_ID = Field("next_user_or_group_id")
PARENT_OBJECT = Field("parent_object")
PARENT_OBJECT_ID = Field("parent_object_id")
TICKET_ID = Field("ticket_id")
TICKET_STATUS = Field("ticket_status")
TEXT_HTML = Field("text_html")
SITE_VISIBLE = Field("site_visible")
DESCRIPTION = Field("description")
TICKET_PRIORITY = Field("ticket_priority")
FILE_NAME = Field("file_name")
CONTENT_TYPE = Field("content_type")
LAST_UPDATE = Field("last_update")
OPERATION_TYPE_ID = Field("operation_type_id")
HISTORY_ID = Field("history_id")
OPERATION_DESCRIPTION = Field("operation_description")
UPDATE_DATE = Field("update_date")
FULL_NAME = Field("full_name")
USER_NAME = Field("user_name")

# Underscored fields are not real in HDA but used for the integration
_PRIORITY = Field("priority")
_TICKET_SOURCE = Field("ticket_source")
_OBJECT_ID = Field("object_id")
_TICKET = Field("ticket")
_ATTACHMENT_ID = Field("attachment_id")
_GROUP_ID = Field("group_id")
ID_DESCRIPTION_COLUMN_NAMES = str([field.hda_name for field in (ID, DESCRIPTION)])


class Filter(NamedTuple):
    key: str
    operator: str  # See OPERATORS
    value: str | None  # none only when the value is null and without quotes

    @staticmethod
    def _parse(string: str) -> "Filter":
        if not (match := FILTER_CONDITION_REGEX.match(string)):
            raise DemistoException(
                f"Cannot parse {string}. "
                'Expected a phrase of the form ["key" operator "value"] or ["key" operator null]'
            )
        return Filter(
            key=match["key"],
            operator=match["op"],
            value=None if ((value := match["value"]) == "null") else value.strip('"'),
        )

    @staticmethod
    def parse_list(strings: Iterable[str] | str) -> List["Filter"]:
        return [
            Filter._parse(string) for string in more_itertools.always_iterable(strings)
        ]

    @property
    def dict(self):
        return {"property": self.key, "op": self.operator, "value": self.value}

    @staticmethod
    def dumps_list(filters: Union[Iterable["Filter"], "Filter"]) -> str:
        """
        Dumps a one or more Filter objects to a JSON string, as list (per API requirements).

        Args:
            filters (Union[Iterable[Filter], Filter]): The Filter object(s) to dump.

        Returns:
            str: The JSON string representation of the filters, as list.
        """
        return json.dumps(
            [
                filter.dict
                for filter in more_itertools.always_iterable(filters, base_type=Filter)
            ]
        )


def safe_arg_to_number(argument: str | None, argument_name: str) -> int:
    # arg_to_number is typed as if it returns Optional[int], which causes mypy issues down the road.
    # this method solves them
    if (result := arg_to_number(argument)) is None:
        raise ValueError(f"cannot parse number from {argument_name}={argument}")
    return result


def create_params_dict(
    required_fields: tuple[Field, ...] = (),
    optional_fields: tuple[Field, ...] = (),
    **kwargs,
) -> dict[str, Any]:
    return {field.hda_name: kwargs[field.demisto_name] for field in required_fields} | {
        field.hda_name: kwargs[field.demisto_name]
        for field in optional_fields
        if field.demisto_name in kwargs
    } | {
        # an exception to the rule
        PROBLEM_HTML.hda_name: kwargs["problem"],
    }


class RequestNotSuccessfulError(DemistoException):
    def __init__(self, response: Response, attempted_action: str):
        json_response = {}
        with contextlib.suppress(JSONDecodeError):
            json_response = response.json()

        suffix = (
            f": {description}."
            if (description := json_response.get("result", {}).get("desc"))
            else "."
        )
        super().__init__(
            f"{attempted_action.capitalize()} failed{suffix}", res=response
        )


def map_id_to_description(response: dict) -> dict[str, str]:
    return {item[ID.hda_name]: item[DESCRIPTION.hda_name] for item in response["data"]}


def convert_response_dates(response: dict) -> dict:
    def convert_value(value: str) -> str | datetime:
        if (
            isinstance(value, str)
            and value
            and (match := PAT_DATE_FORMAT_REGEX.match(value))
        ):
            return datetime.fromtimestamp(
                int(match[1][:-3]),  # :-3 omits miliseconds
                tz=timezone.utc,
            ).strftime(DATETIME_FORMAT)
        return value

    def convert_recursively(
        value,
    ):  # no typing as the cases are complex and confuse mypy
        if isinstance(value, dict):
            return {k: convert_recursively(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [convert_recursively(v) for v in value]
        return convert_value(value)

    return convert_recursively(response)


class Client(BaseClient):
    class Token(NamedTuple):
        refresh_token: str
        request_token: str
        expiry_utc: datetime

        @staticmethod
        def from_response(response: dict):
            return Client.Token(
                refresh_token=response["refreshToken"],
                request_token=response["requestToken"],
                expiry_utc=datetime.utcnow() + timedelta(seconds=response["expiresIn"]),
            )

        def write_to_integration_context(self) -> None:
            demisto.setIntegrationContext(
                demisto.getIntegrationContext()
                | {
                    "refresh_token": self.refresh_token,
                    "request_token": self.request_token,
                    "token_expiry_utc": str(self.expiry_utc),
                }
            )

    def http_request(
        self,
        url_suffix: str,
        method: Literal["GET", "POST"],
        attempted_action: str,
        require_success_true: bool = True,
        **kwargs,
    ) -> dict:
        response = self._http_request(
            method,
            url_suffix,
            resp_type="response",
            **kwargs,
        )
        try:
            response_body = json.loads(response.text)
            if (require_success_true or ("success" in response_body)) and (
                response_body["success"] is not True
            ):
                # Some endpoints only contain the `success` key on failure ¯\_(ツ)_/¯
                raise RequestNotSuccessfulError(response, attempted_action)
            return response_body

        except JSONDecodeError:
            if error_parts := HTML_H_TAG_REGEX.findall(response.text):
                raise DemistoException(". ".join(error_parts), res=response)
            raise ValueError(f"API returned non-JSON response: {response.text}")

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        username: str,
        password: str,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token: Client.Token = self._reuse_or_create_token(username, password)
        self._headers = {"Authorization": f"Bearer {self.token.request_token}"}

    def _reuse_or_create_token(self, username: str, password: str) -> "Client.Token":
        # should only be called from __init__
        def generate_new_refresh_token() -> Client.Token:
            return Client.Token.from_response(
                self.http_request(
                    method="POST",
                    url_suffix="Authentication/LoginEx",
                    attempted_action="logging in using username and password",
                    params={"username": username, "password": password},
                    headers={"Content-Type": "multipart/form-data"},
                )
            )

        def generate_using_refresh_token(refresh_token: str) -> Client.Token:
            return Client.Token.from_response(
                self.http_request(
                    method="POST",
                    url_suffix="Authentication/RefreshToken",
                    params={"token": refresh_token},
                    attempted_action="generating request token using refresh token",
                    headers={"Content-Type": "multipart/form-data"},
                )
            )

        # Check integration context
        integration_context = demisto.getIntegrationContext()
        previous_refresh_token = integration_context.get("refresh_token")
        raw_previous_expiry_utc: str | None = integration_context.get(
            "token_expiry_utc"
        )

        # Do we need to log in again, or can we just refresh?
        if (
            raw_previous_expiry_utc
            and (token_expiry_utc := dateparser.parse(raw_previous_expiry_utc))
            and token_expiry_utc > (datetime.utcnow() + timedelta(seconds=5))
        ):
            try:
                demisto.debug(
                    "refresh token is valid, using it to generate a request token"
                )
                return generate_using_refresh_token(previous_refresh_token)

            except RequestNotSuccessfulError:
                demisto.debug(
                    "failed using refresh token, getting a new one using username and password"
                )
                return generate_new_refresh_token()

        else:
            demisto.debug(
                "refresh token expired or missing, logging in with username and password. {token.expiry_utc=}"
            )
            return generate_new_refresh_token()

    def create_ticket(self, **kwargs) -> dict:
        data = create_params_dict(
            required_fields=(
                OBJECT_TYPE_ID,
                TICKET_STATUS_ID,
                TICKET_PRIORITY_ID,
            ),
            optional_fields=(
                OBJECT_DESCTIPTION,
                TICKET_CLASSIFICATION_ID,
                TICKET_TYPE_ID,
                CONTACT_ID,
                SUBJECT,
                SITE,
            ),
            **kwargs,
        )

        return self.http_request(
            "WSC/Set",
            "POST",
            data={
                "entity": "Incident",
                "data": json.dumps(data),
            },
            attempted_action="creating ticket",
        )

    def list_tickets(self, **kwargs) -> dict:
        columns = str(
            [
                field.hda_name
                for field in (
                    OBJECT_DESCTIPTION,
                    OBJECT_ENTITY,
                    SOLUTION,
                    TICKET_CLASSIFICATION_ID,
                    SERVICE_ID,
                    PROBLEM_HTML,
                    CONTACT_ID,
                    NEXT_EXPIRATION_ID,
                    TASK_EFFORT,
                    ID,
                    SUPPLIER_ID,
                    SOLUTION_HTML,
                    IS_NEW,
                    EXPIRATION_DATE,
                    LOCATION_ID,
                    ESTIMATED_TASK_START_DATE,
                    FIRST_UPDATE_USER_ID,
                    ACCOUNT_ID,
                    MAIL_BOX_ID,
                    CLOSURE_DATE,
                    BILLED_TOKENS,
                    TICKET_TYPE_ID,
                    OWNER_USER_ID,
                    PARENT_TICKET_ID,
                    CUSTOMER_CONTRACT_ID,
                    LANGUAGE_ID,
                    KNOWN_ISSUE,
                    ASSET_ID,
                    DATE,
                    URGENCY_ID,
                    SCORE,
                    SUBJECT,
                    ESTIMATED_TASK_DURATION,
                    SOLICITS,
                    SITE,
                    CALENDAR_ID,
                    LAST_EXPIRATION_DATE,
                    SITE_UNREAD,
                    PROBLEM,
                    NEXT_EXPIRATION_DATE,
                    ASSIGNED_USER_OR_GROUP_ID,
                )
            ]
        )

        params: dict[str, str | list | int | None] = {
            "entity": "Ticket",
            "filter": None,
            "columnExpressions": columns,
            "columnNames": columns,
            "start": safe_arg_to_number(kwargs.get("start", 0), "start"),
            "limit": safe_arg_to_number(kwargs["limit"], "limit"),
        }

        if (raw_filter := kwargs.get("filter")) and (
            custom_filter := Filter.parse_list(raw_filter)
        ):
            params["filter"] = Filter.dumps_list(custom_filter)

        if ticket_id := kwargs.get(TICKET_ID.demisto_name):
            if raw_filter:
                raise DemistoException(
                    "The ticket_id and filter arguments cannot be used at the same time."
                )
            # if only ticket_id is passed, use it to filter
            params["filter"] = Filter.dumps_list(Filter(ID.hda_name, "eq", ticket_id))

        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing tickets",
            params=params,
        )

    def add_ticket_attachment(self, entry_ids: list[str], **kwargs) -> dict:
        return self.http_request(
            url_suffix="Ticket/UploadNewAttachment",
            method="POST",
            attempted_action="uploading a new attachment",
            data={
                "entity": "Ticket",
                "entityID": kwargs["ticket_id"],
            },
            files=[
                (
                    f"TicketAttachment_{i+1}",
                    (
                        (file_entry := demisto.getFilePath(entry_id))["name"],
                        Path(file_entry["path"]).open("rb"),
                    ),
                )
                for i, entry_id in enumerate(entry_ids)
            ],
        )

    def list_ticket_attachments(self, **kwargs) -> dict:
        ticket_id = kwargs["ticket_id"]
        params = {
            "entity": "Attachments",
            "start": 0,
            "limit": safe_arg_to_number(kwargs["limit"], "limit"),
            "filter": Filter.dumps_list(
                (
                    Filter(PARENT_OBJECT.hda_name, "eq", _TICKET.hda_name),
                    Filter(PARENT_OBJECT_ID.hda_name, "eq", ticket_id),
                )
            ),
        }

        return self.http_request(
            url_suffix="/WSC/List",
            method="POST",
            params=params,
            attempted_action="listing ticket attachments",
        )

    def add_ticket_comment(self, **kwargs) -> dict:
        return self.http_request(
            url_suffix="WSC/Set",
            method="POST",
            data={
                "entity": "TicketConversationItem",
                "data": json.dumps(
                    {
                        TICKET_ID.hda_name: kwargs[TICKET_ID.demisto_name],
                        TEXT_HTML.hda_name: kwargs["comment"],
                        SITE_VISIBLE.hda_name: argToBoolean(
                            kwargs[SITE_VISIBLE.demisto_name]
                        ),
                        OBJECT_TYPE_ID.hda_name: "90",  # hardcoded by design. 90 marks ObjectTypeIDField
                    }
                ),
            },
            attempted_action="adding ticket comment",
        )

    def list_ticket_statuses(self, limit: int | None) -> dict:
        data = {
            "entity": TICKET_STATUS.hda_name,
            "start": 0,
            "columnNames": ID_DESCRIPTION_COLUMN_NAMES,
            "columnExpressions": ID_DESCRIPTION_COLUMN_NAMES,
        }

        if limit is not None:
            # Sending without a limit _seems_ to return all records (was only able to test with 20)
            # XSOAR automatically adds this argument to the *command*, to not spam context with a long list of values.
            # However, this method is called internally in change_ticket_status, for which we *do* want all statuses.
            data["limit"] = limit

        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing ticket statuses",
            data=data,
        )

    def change_ticket_status(
        self,
        status_id: str,
        ticket_id: str,
        note: str | None = None,
    ) -> dict:
        allowed_id_values = tuple(
            item[ID.hda_name] for item in self.list_ticket_statuses(limit=None)["data"]
        )

        if status_id not in allowed_id_values:
            raise DemistoException(
                f"Invalid {status_id=}. Possible values are {','.join(sorted(allowed_id_values))}"
            )

        params = {
            "ticketID": ticket_id,
            "ticketStatusID": status_id,
        }

        if note:
            params["note"] = note

        return self.http_request(
            url_suffix="Ticket/DoChangeStatus",
            method="POST",
            attempted_action="changing ticket status",
            params=params,
        )

    def list_ticket_priorities(self) -> dict:
        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing ticket priorities",
            data={
                "entity": TICKET_PRIORITY.hda_name,
                "columnExpressions": ID_DESCRIPTION_COLUMN_NAMES,
                "columenNames": ID_DESCRIPTION_COLUMN_NAMES,
            },
        )

    def list_ticket_sources(self, limit: int) -> dict:
        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing ticket priorities",
            data={
                "entity": _TICKET_SOURCE.hda_name,
                "columnExpressions": ID_DESCRIPTION_COLUMN_NAMES,
                "columenNames": ID_DESCRIPTION_COLUMN_NAMES,
                "start": 0,
                "limit": limit,
            },
        )

    def get_ticket_history(self, ticket_id: str) -> dict:
        # Note: this endpoint has a different structure than the rest:
        #   1. no `data` (results are returned directly in the root).
        #   2. the `success` field only returned on failure. (hence require_succes_true=False)
        return self.http_request(
            url_suffix=f"Ticket/History?{_OBJECT_ID.hda_name}={ticket_id}",
            method="GET",
            attempted_action="getting ticket history",
            require_success_true=False,
        )

    def list_users(self, **kwargs):
        columns = str(
            [
                "ID",
                "User.FirstName",
                "User.LastName",
                "User.EMail",
                "User.Phone",
                "User.Mobile",
            ]
        )

        pagination = paginate(**kwargs)
        params = {
            "entity": "Users",
            "columnExpressions": columns,
            "columnNames": columns,
            "start": pagination.start,
            "limit": pagination.limit,
        }

        if user_ids := argToList(kwargs.get("user_id")):
            params["filter"] = Filter.dumps_list(
                tuple(Filter(ID.hda_name, "eq", id_) for id_ in user_ids)
            )

        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing user(s)",
            params=params,
        )

    def list_groups(self, **kwargs) -> dict:
        columns = str([column.hda_name for column in (ID, DESCRIPTION, OBJECT_TYPE_ID)])

        params = {
            "entity": "UserGroup",
            "columnExpressions": columns,
            "columnNames": columns,
            "start": (pagination := paginate(**kwargs)).start,
            "limit": pagination.limit,
        }

        if group_id := kwargs.get("group_id"):
            params["filter"] = Filter.dumps_list(Filter(ID.hda_name, "eq", group_id))

        return self.http_request(
            url_suffix="WSC/Projection",
            method="POST",
            attempted_action="listing group(s)",
            params=params,
        )


class PaginateArgs(NamedTuple):
    start: int
    limit: int


def paginate(**kwargs) -> PaginateArgs:
    limit = safe_arg_to_number(kwargs["limit"], "limit")

    page = kwargs.get("page")
    page_size = kwargs.get("page_size")

    none_arg_count = sum((page is None, page_size is None))

    if none_arg_count == 1:
        raise DemistoException(
            "To paginate, provide both `page` and `page_size` arguments."
            "To only get the first n results (without paginating), use the `limit` argument."
        )

    if none_arg_count == 2:  # neither page nor page_size provided
        return PaginateArgs(start=0, limit=limit)

    # here none_arg_count = 0, meaning both were provided
    page = safe_arg_to_number(page, "page")
    page_size = safe_arg_to_number(page_size, "page_size")

    return PaginateArgs(
        start=page * page_size,
        limit=min(limit, page_size),
    )


def pat_table_to_markdown(
    title: str,
    output: dict | list[dict],
    fields: tuple[Field, ...] | None,
    field_replacements: dict[Field, Field] | None = None,
    **kwargs,
) -> str:
    def replace_fields(item: Any):
        string_key_replacements = {
            k.hda_name: v.hda_name for k, v in (field_replacements or {}).items()
        }
        if isinstance(item, dict):
            return {
                string_key_replacements.get(key, key): value
                for key, value in item.items()
            }
        elif isinstance(item, list):
            return [replace_fields(v) for v in item]
        return item

    def filter_fields(item: dict | list[dict]) -> dict | list[dict]:
        def _filter_dict(dictionary: dict) -> dict:
            return {
                field.hda_name: dictionary[field.hda_name]
                # mypy doesn't notice fields can not be None here
                for field in fields  # type:ignore[union-attr]
                if field.hda_name in dictionary
            }

        if isinstance(item, dict):
            return _filter_dict(item)
        elif isinstance(item, list):
            # mypy is confused by the type union
            return [filter_fields(list_item) for list_item in item]  # type:ignore[misc]
        raise TypeError(f"cannot filter {type(item)}, expected dict|list[dict]")

    if field_replacements:
        output = replace_fields(output)

    if fields is not None:
        output = filter_fields(output)

    return tableToMarkdown(
        name=title,
        t=output,
        headerTransform=pascalToSpace,
        sort_headers=False,
        **kwargs,
    )


def create_ticket_command(client: Client, args: dict) -> CommandResults:
    raw_response = client.create_ticket(**args)
    response = convert_response_dates(raw_response)

    response_for_human_readable = response.copy()["data"]

    if not response_for_human_readable.get(SOLUTION.hda_name):
        # do not show empty or missing `Solution` value
        response_for_human_readable.pop(SOLUTION.hda_name, None)

    return CommandResults(
        outputs_prefix=f"{VENDOR}.Ticket",
        outputs_key_field=ID.hda_name,
        outputs=response,
        raw_response=raw_response,
        readable_output=pat_table_to_markdown(
            title="Ticket Created",
            output=response_for_human_readable,
            fields=(
                TICKET_ID,
                OBJECT_DESCTIPTION,
                OBJECT_ENTITY,
                SOLUTION,
                TICKET_CLASSIFICATION_ID,
                IS_NEW,
                EXPIRATION_DATE,
                FIRST_UPDATE_USER_ID,
                OWNER_USER_ID,
                DATE,
                ASSIGNED_USER_ID,
            ),
        ),
    )


def list_tickets_command(client: Client, args: dict) -> CommandResults:
    raw_response = client.list_tickets(**args)
    response = convert_response_dates(raw_response)

    return CommandResults(
        outputs=response["data"],
        raw_response=raw_response,
        outputs_prefix=f"{VENDOR}.Ticket",
        outputs_key_field=ID.hda_name,
        readable_output=pat_table_to_markdown(
            title="Tickets",
            output=response["data"],
            fields=(
                TICKET_ID,  # Replaced from ID
                SUBJECT,
                SOLUTION,
                DATE,
                SERVICE_ID,
                PROBLEM,
                CONTACT_ID,
                OWNER_USER_ID,
                ACCOUNT_ID,
            ),
            field_replacements={ID: TICKET_ID},
        ),
    )


def add_ticket_attachment_command(client: Client, args: dict) -> CommandResults:
    entry_ids = argToList(args.pop("entry_id", ()))
    ticket_id = args["ticket_id"]
    response = client.add_ticket_attachment(entry_ids, **args)
    return CommandResults(
        readable_output=f"Added Attachment ID {response['data']['attachmentID']} to ticket ID {ticket_id}"
        if len(entry_ids) == 1
        else f"Added {len(entry_ids)} attachments to ticket ID {ticket_id}",  # API only returns the last attachment ID
        raw_response=response,
    )


def list_ticket_attachments_command(client: Client, args: dict) -> CommandResults:
    response = client.list_ticket_attachments(**args)
    response = convert_response_dates(response)

    return CommandResults(
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.Ticket.Attachment",
        outputs_key_field=ID.hda_name,
        readable_output=pat_table_to_markdown(
            title=f"Attachments of {args['ticket_id']}",
            output=response["data"],
            fields=(
                ID,
                FILE_NAME,
                LAST_UPDATE,
                DESCRIPTION,
                OBJECT_DESCTIPTION,
                FIRST_UPDATE_USER_ID,
                OBJECT_ENTITY,
                CONTENT_TYPE,
            ),
            field_replacements={ID: _ATTACHMENT_ID},
        ),
        raw_response=response,
    )


def list_ticket_statuses_command(client: Client, args: dict) -> CommandResults:
    response = client.list_ticket_statuses(
        limit=safe_arg_to_number(args["limit"], "limit")
    )
    response = convert_response_dates(response)

    return CommandResults(
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.{TICKET_STATUS.hda_name}",
        raw_response=response,
    )


def add_ticket_comment_command(client: Client, args: dict) -> CommandResults:
    return CommandResults(
        readable_output=f"Comment was succesfully added to {args['ticket_id']}",
        raw_response=client.add_ticket_comment(**args),
    )


def change_ticket_status_command(client: Client, args: dict) -> CommandResults:
    response = client.change_ticket_status(**args)
    return CommandResults(
        readable_output=f"Changed status of ticket {args['ticket_id']} to {args['status_id']} successfully.",
        raw_response=response,
    )


def list_ticket_priorities_command(client: Client, _: dict) -> CommandResults:
    response = client.list_ticket_priorities()
    response = convert_response_dates(response)

    return CommandResults(
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.{_PRIORITY.hda_name}",
        readable_output=tableToMarkdown("HDA Ticket Priorities", response["data"]),
        raw_response=response,
    )


def list_ticket_sources_command(client: Client, args: dict) -> CommandResults:
    limit = safe_arg_to_number(args["limit"], "limit")

    response = client.list_ticket_sources(limit)
    response = convert_response_dates(response)

    outputs = map_id_to_description(response["data"])
    return CommandResults(
        outputs=outputs,
        outputs_prefix=f"{VENDOR}.{_TICKET_SOURCE.hda_name}",
        readable_output=tableToMarkdown(
            name="PAT HelpdeskAdvanced Ticket Sources",
            t=outputs,
            headers=["Source ID", "Source Description"],
        ),
        raw_response=response,
    )


def get_ticket_history_command(client: Client, args: dict) -> CommandResults:
    raw_response = client.get_ticket_history(ticket_id := args["ticket_id"])

    response = convert_response_dates(raw_response)
    response = [value | {TICKET_ID.hda_name: ticket_id} for value in response]
    return CommandResults(
        outputs=response,
        outputs_prefix=f"{VENDOR}.TicketHistory",
        outputs_key_field=HISTORY_ID.hda_name,
        raw_response=raw_response,
        readable_output=pat_table_to_markdown(
            title=f"Ticket History: {ticket_id}",
            output=response,
            fields=None,
            removeNull=True,
            is_auto_json_transform=True,
        ),
    )


def list_users_command(client: Client, args: dict) -> CommandResults:
    response = client.list_users(**args)
    response = convert_response_dates(response)

    if not (data := response["data"]):
        return CommandResults(readable_output="No data returned")

    data = [
        # removing the User. prefix - both for visual and context path (avoiding duplication in HelpdeskAdvanced.User.User.EMail)
        {key.removeprefix("User."): value for key, value in user.items()}
        for user in data
    ]
    return CommandResults(
        outputs=data,
        outputs_prefix=f"{VENDOR}.User",
        outputs_key_field=ID.hda_name,
        raw_response=response,
        readable_output=pat_table_to_markdown(
            title="PAT HelpDeskAdvanced Users",
            output=data,
            fields=None,
        ),
    )


def list_groups_command(client: Client, args: dict) -> CommandResults:
    response = client.list_groups(**args)
    response = convert_response_dates(response)

    if not (data := response["data"]):
        return CommandResults(readable_output="No data returned")

    return CommandResults(
        outputs=data,
        outputs_prefix=f"{VENDOR}.Group",
        outputs_key_field=ID.hda_name,
        raw_response=response,
        readable_output=pat_table_to_markdown(
            title="PAT HelpDeskAdvanced Groups",
            output=data,
            fields=(_GROUP_ID, DESCRIPTION, OBJECT_TYPE_ID),
            field_replacements={ID: _GROUP_ID},
        ),
    )


commands: dict[str, Callable] = {
    "hda-create-ticket": create_ticket_command,
    "hda-list-tickets": list_tickets_command,
    "hda-list-ticket-attachments": list_ticket_attachments_command,
    "hda-add-ticket-attachment": add_ticket_attachment_command,
    "hda-add-ticket-comment": add_ticket_comment_command,
    "hda-list-ticket-statuses": list_ticket_statuses_command,
    "hda-change-ticket-status": change_ticket_status_command,
    "hda-list-ticket-priorities": list_ticket_priorities_command,
    "hda-list-ticket-sources": list_ticket_sources_command,
    "hda-get-ticket-history": get_ticket_history_command,
    "hda-list-users": list_users_command,
    "hda-list-groups": list_groups_command,
}


def main() -> None:
    demisto.debug(f"Command being called is {demisto.command()}")
    params = demisto.params()

    try:
        client = Client(
            base_url=urljoin(params["base_url"].removesuffix("HDAPortal"), "HDAPortal"),
            username=params["credentials"]["identifier"],
            password=params["credentials"]["password"],
            verify=not params["insecure"],
            proxy=params["proxy"],
        )

        if (command := demisto.command()) == "test-module":
            client.list_ticket_statuses(limit=1)
            result = "ok"

        elif command in commands:
            result = commands[command](client, demisto.args())

        else:
            raise NotImplementedError

        return_results(result)

    except Exception as e:
        return_error(
            "\n".join(
                (
                    f"Failed to execute {demisto.command()}.",
                    f"Error: {e!s}",
                    traceback.format_exc(),
                )
            )
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
