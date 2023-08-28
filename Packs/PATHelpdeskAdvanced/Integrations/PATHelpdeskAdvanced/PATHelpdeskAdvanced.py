from pathlib import Path
from typing import Literal
from collections.abc import Callable
from collections.abc import Sequence

import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = "HelpdeskAdvanced"

FILTER_REGEX = re.compile(
    r"\A(?P<key>\".*?\") (?P<op>eq|gt|lt|ge|lt|sw|ne) (?P<value>(?:\".*?\"|null))\Z"
)


class Field:
    def __init__(self, demisto_name: str) -> None:
        title_parts = []
        for part in demisto_name.split("_"):
            if part == "unread":
                title_parts.append("UnRead")
            elif part in {"id", "html"}:
                title_parts.append(part.upper())
            else:
                title_parts.append(part.title())

        self.demisto_name = demisto_name
        self.hda_name = "".join(title_parts)


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
TICKET_ID = Field("ticket_id")
TICKET_STATUS = Field("ticket_status")
TEXT = Field("text")
SITE_VISIBLE = Field("site_visible")
DESCRIPTION = Field("description")
TICKET_PRIORITY = Field("ticket_priority")
_PRIORITY = Field("priority")

HARDCODED_COLUMNS = [
    # sent on every listing request
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

ID_DESCRIPTION_COLUMN_NAMES = [field.hda_name for field in (ID, DESCRIPTION)]


def safe_arg_to_number(argument: str, argument_name: str) -> int:
    # arg_to_number is typed as if it returns Optional[int], which causes mypy issues down the road.
    # this method solves them
    if (result := arg_to_number(argument)) is None:
        raise ValueError(f"cannot parse number from {argument_name}={argument}")
    return result


def parse_filter_conditions(strings: Sequence[str]) -> list[dict]:
    return [_parse_filter_condition(string) for string in strings]


def _parse_filter_condition(string: str) -> dict:
    if not (match := FILTER_REGEX.match(string)):
        raise DemistoException(
            f'Cannot parse {string}. Expected a phrase of the form "key" operator "value" or "key" operator null'
        )
    return {
        "property": match["key"],
        "op": match["op"],
        "value": None if ((value := match["value"]) == "null") else value,
    }


def create_params_dict(
    required_fields: tuple[Field, ...] = (),
    optional_fields: tuple[Field, ...] = (),
    **kwargs,
):
    result = {field.hda_name: kwargs[field.demisto_name] for field in required_fields}

    for field in optional_fields:
        if field.demisto_name in kwargs:
            result[field.hda_name] = kwargs[field.demisto_name]

    return result


class RequestNotSuccessfulError(DemistoException):
    def __init__(self, response: dict | str, attempted_action: str):
        suffix = (
            f": {description}."
            if (
                isinstance(response, dict)
                and (description := response["result"]["desc"])
            )
            else "."
        )
        super().__init__(
            f"{attempted_action.capitalize()} failed{suffix}", res=response
        )


def parse_ticket_status_mapping(response: dict) -> dict[str, str]:
    return {item[ID.hda_name]: item[DESCRIPTION.hda_name] for item in response["data"]}


class Client(BaseClient):
    def http_request(
        self,
        url_suffix: str,
        method: Literal["GET", "POST"],
        attempted_action: str,
        **kwargs,
    ):
        response = self._http_request(method, url_suffix, **kwargs)

        if (
            isinstance(response, str)
            and "A server error has occurred. Please, contact portal administrator"
            in response  # TODO test
        ) or (isinstance(response, dict) and response["success"] is not True):
            # request failed
            raise RequestNotSuccessfulError(response, attempted_action)

        return response

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        username: str,
        password: str,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._username = username
        self._password = password

        self.request_token: str | None = None
        self.token_expiry_utc: datetime | None = None

        self.__login()  # sets request_token and token_expiry_utc

    def __login(self):
        # should only be called from __init__
        def generate_new_token() -> dict:
            return self.http_request(
                method="POST",
                url_suffix="Authentication/LoginEx",
                attempted_action="logging in using username and password",
                params={"username": self._username, "password": self._password},
                headers={"Content-Type": "multipart/form-data"},
            )

        def refresh_request_token(refresh_token: str) -> dict:
            return self.http_request(
                method="POST",
                url_suffix="Authentication/RefreshToken",
                params={"token": refresh_token},
                attempted_action="renewing request token",
                headers={"Content-Type": "multipart/form-data"},
            )

        # Check integration context
        integration_context = demisto.getIntegrationContext()
        refresh_token = integration_context.get("refresh_token")
        token_expiry_utc: datetime | None = integration_context.get("token_expiry_utc")

        # Do we need to log in again, or can we just refresh?
        if token_expiry_utc and token_expiry_utc > (
            datetime.utcnow() + timedelta(seconds=5)
        ):  # refresh token is still valid
            response = refresh_request_token(refresh_token)
        else:  # must log in again using username and password
            response = generate_new_token()

        # Set self attributes
        self.request_token = response["requestToken"]
        self.refresh_token = response["refreshToken"]
        self.token_expiry_utc = datetime.utcnow() + timedelta(  # TODO is always there?
            seconds=response["expiresIn"]
        )

    def create_ticket(self, **kwargs) -> dict:
        required_fields = (
            OBJECT_TYPE_ID,
            TICKET_STATUS_ID,
            TICKET_PRIORITY_ID,
        )
        optional_fields = (
            OBJECT_DESCTIPTION,
            TICKET_CLASSIFICATION_ID,
            TICKET_TYPE_ID,
            CONTACT_ID,
            SUBJECT,
            PROBLEM,
            SITE,
        )
        data = create_params_dict(
            required_fields,
            optional_fields,
            **kwargs,
        )

        return self.http_request(
            "HDAPortal/WSC/Set",
            "POST",
            params={"entity": "Ticket", "data": data},
            attempted_action="creating ticket",
        )

    def list_tickets(self, **kwargs) -> dict:
        start = safe_arg_to_number(kwargs.get("start", 0), "start")
        limit = safe_arg_to_number(kwargs["limit"], "limit")

        params: dict[str, str | list | int] = {
            "entity": "Ticket",  # hardcoded
            "columnExpressions": HARDCODED_COLUMNS,  # hardcoded
            "columnNames": HARDCODED_COLUMNS,  # hardcoded
            "start": start,
            "limit": limit,
        }

        if filter_params := parse_filter_conditions(kwargs.get("filter") or ()):
            params["filter"] = filter_params

        return self.http_request(
            url_suffix="HDAPortal/WSC/Projection",
            method="POST",
            attempted_action="listing tickets",
            params=params,
        )

    def add_ticket_attachment(self, entry_ids: list[str], **kwargs) -> dict:
        return self.http_request(
            url_suffix="HDAPortal/Ticket/UploadNewAttachment",
            method="POST",
            attempted_action="uploading a new attachment",
            params={
                "entity": "Ticket",
                "entityID": kwargs["ticket_id"],
            }
            | {
                f"TicketAttachment_{i+1}": Path(
                    demisto.getFilePath(entry_id)["path"]
                ).read_text()
                for i, entry_id in enumerate(entry_ids)
            },
        )

    def list_ticket_attachments(self, **kwargs) -> dict:
        ticket_id = kwargs["ticket_id"]
        params = {
            "entity": "Attachments",
            "start": 0,  # TODO necessary?
            "limit": safe_arg_to_number(kwargs["limit"], "limit"),
            "filter": parse_filter_conditions(
                (
                    f'"{PARENT_OBJECT.hda_name}" eq "Ticket"',
                    f'"{PARENT_TICKET_ID.hda_name}" eq "{ticket_id}"',
                )
            ),
        }

        return self.http_request(
            url_suffix="/HDAPortal/WSC/List",
            method="POST",
            params=params,
            attempted_action="listing ticket attachments",
        )

    def add_ticket_comment(self, **kwargs) -> dict:
        return self.http_request(
            url_suffix="HDAPortal/WSC/Set",
            method="POST",
            params={
                "entity": "TicketConversationItem",
                "data": {
                    TICKET_ID.hda_name: kwargs[TICKET_ID.demisto_name],
                    TEXT.hda_name: kwargs["comment"],
                    SITE_VISIBLE.hda_name: kwargs[SITE_VISIBLE.demisto_name],
                    OBJECT_TYPE_ID.hda_name: "90",  # hardcoded by design. 90 marks ObjectTypeIDField
                },
            },
            attempted_action="adding ticket command",
        )

    def list_ticket_statuses(self, **kwargs) -> dict:
        return self.http_request(
            url_suffix="HDAPortal/WSC/Projection",
            method="POST",
            attempted_action="listing ticket statuses",
            params={
                "entity": TICKET_STATUS.hda_name,
                "start": 0,
                "limit": safe_arg_to_number(kwargs["limit"], "limit"),
                "columnNames": ID_DESCRIPTION_COLUMN_NAMES,
                "columnExpressions": ID_DESCRIPTION_COLUMN_NAMES,
            },
        )

    def change_ticket_status(self, **kwargs) -> dict:
        statuses_to_id = parse_ticket_status_mapping(
            self.list_ticket_statuses(limit=1000)
        )  # TODO 1000?

        # Find status ID matching the selected status
        if (status := statuses_to_id.get(kwargs["status"])) is None:
            demisto.debug(f"status to id mapping: {statuses_to_id}")
            raise DemistoException(
                f"Cannot find id for {status}."
                f"See debug log for the {len(statuses_to_id)} status mapping options found."
            )

        params = {
            "ticketID": kwargs["ticket_id"],
            "ticketStatusID": status,
        }

        if note := kwargs.get("note"):
            params["note"] = note

        return self.http_request(
            url_suffix="HDAPortal/Ticket/DoChangeStatus",
            method="POST",
            attempted_action="changing ticket status",
            params=params,
        )

    def list_ticket_priorities(self) -> dict:
        return self.http_request(
            url_suffix="HDAPortal/WSC/Projection",
            method="POST",
            attempted_action="listing ticket priorities",
            params={
                "entity": TICKET_PRIORITY.hda_name,
                "columnExpressions": ID_DESCRIPTION_COLUMN_NAMES,
                "columenNames": ID_DESCRIPTION_COLUMN_NAMES,
            },
        )


def create_ticket_command(client: Client, **kwargs) -> CommandResults:
    response = client.create_ticket(**kwargs)
    response_for_human_readable = response.copy()
    if not response_for_human_readable.get(SOLUTION.hda_name):
        # do not show empty or missing `Solution` value
        response_for_human_readable.pop(SOLUTION.hda_name, None)

    return CommandResults(
        outputs_prefix=f"{VENDOR}.Ticket",
        outputs_key_field=f"{VENDOR}.Ticket.{ID.hda_name}",
        outputs=response,  # todo check human readable, titles
        readable_output=tableToMarkdown(
            "Ticket Created", t=response_for_human_readable
        ),
    )


def list_tickets_command(client: Client, args: dict) -> CommandResults:
    response = client.list_tickets(**args)
    return CommandResults(
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.Ticket",
        outputs_key_field=f"{VENDOR}.Ticket.{ID.hda_name}",  # TODO choose fields for HR?
        raw_response=response,
    )


def add_ticket_attachment_command(client: Client, args: dict) -> CommandResults:
    entry_ids = args.pop("entry_id")
    response = client.add_ticket_attachment(entry_ids, **args)
    return CommandResults(
        readable_output=f"Added Attachment ID {response['attachmentId']} to ticket ID {args['ticket_id']}",
        raw_response=response,
    )


def list_ticket_attachments_command(client: Client, args: dict) -> CommandResults:
    response = client.list_ticket_attachments(**args)
    attachment_ids_str = ",".join(
        attachment[ID.hda_name] for attachment in response["data"]
    )
    return CommandResults(
        readable_output=f"Added attachment ID(s) {attachment_ids_str} to ticket {args['ticket_id']} succesfully",
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.Ticket.Attachment",
        outputs_key_field=f"{VENDOR}.Ticket.Attachment.{ID.hda_name}",
        raw_response=response,
    )


def list_ticket_statuses_command(client: Client, args: dict) -> CommandResults:
    response = client.list_ticket_statuses(**args)
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
        readable_output=f"Changed status of ticket {args['ticket_id']} to {args['status']} successfully.",
        raw_response=response,
    )


def list_ticket_priorities_command(client: Client, _: dict) -> CommandResults:
    response = client.list_ticket_priorities()
    return CommandResults(
        outputs=response["data"],
        outputs_prefix=f"{VENDOR}.{_PRIORITY.hda_name}",
        raw_response=response,
    )


def main() -> None:
    demisto.debug(f"Command being called is {demisto.command()}")
    params = demisto.params()

    commands: dict[str, Callable] = {
        "hda-create-ticket": create_ticket_command,
        "hda-list-tickets": list_tickets_command,
        "hda-add-ticket-comment": add_ticket_comment_command,
        "hda-add-ticket-attachment": add_ticket_attachment_command,
        "hda-list-ticket-attachments": list_ticket_attachments_command,
    }

    try:
        client = Client(
            base_url=params["server_url"],
            username=params["credentials"]["identifier"],
            password=params["credentials"]["password"],
            verify=not params["insecure"],
            proxy=params["proxy"],
        )

        if (command := demisto.command()) == "test-module":
            ...  # TODO

        elif command in commands:
            return_results((commands[command])(client, demisto.args()))

        else:
            raise NotImplementedError

    except Exception as e:
        return_error(
            "\n".join(
                (
                    f"Failed to execute {demisto.command()} command.",
                    "Error:",
                    str(e),
                )
            )
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
