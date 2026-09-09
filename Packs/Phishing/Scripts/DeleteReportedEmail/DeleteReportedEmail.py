import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, unquote

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DOCS_TROUBLESHOOTING_URL = "https://xsoar.pan.dev/docs/reference/scripts/delete-reported-email#troubleshooting"
EMAIL_INTEGRATIONS = [
    "Gmail",
    "EWSO365",
    "EWS v2",
    "Agari Phishing Defense",
    "MicrosoftGraphMail",
    "Microsoft Graph",
]
# RFC 5322 msg-id is <id-left@id-right> with a constrained charset
MESSAGE_ID_REGEX = re.compile(r"<[^\s<>]+@[^\s<>]+>")
seconds = time.time()

SUCCESS_MESSAGE = "Success - Purge initiated (it may take a few minutes for the email to be removed from the mailbox)"


class MissingEmailException(Exception):
    def __init__(self):
        super().__init__("Email not found in mailbox. It may have been manually deleted.")


class DeletionFailed(Exception):
    pass


class DeletionArgs:
    @staticmethod
    def gmail(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for Gmail integration.
        Args:
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        is_permanent = search_args["delete-type"] == "hard"
        gmail_message_id = search_result[0].get("id")
        return {
            "user-id": search_args["user-id"],
            "message-id": gmail_message_id,
            "permanent": is_permanent,
            "using-brand": search_args["using-brand"],
        }

    @staticmethod
    def msgraph(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for O365 - MSGraph integration.
        Args:
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        results = search_result[0].get("value", [])
        results = [res for res in results if res.get("internetMessageId") == search_args["message-id"]]
        if not results:
            raise MissingEmailException
        internal_id = results[0].get("id")
        return {
            "user_id": search_args["user_id"],
            "message_id": internal_id,
            "using-brand": search_args["using-brand"],
        }

    @staticmethod
    def agari(search_args: dict):
        """
        Parse the arguments needed for the delete operation for the Agari Phishing Defense integration.
        Args:
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        incident_info = demisto.incident()
        agari_message_id = incident_info.get("CustomFields", {}).get("apdglobalmessageid")
        return {
            "operation": "delete",
            "id": agari_message_id,
            "using-brand": search_args["using-brand"],
        }

    @staticmethod
    def ews(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for EWS integrations (EWS365, EWSv2).
        Args:
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        item_id = search_result[0].get("itemId")
        return {
            "item-ids": item_id,
            "delete-type": search_args["delete-type"],
            "target-mailbox": search_args["target-mailbox"],
            "using-brand": search_args["using-brand"],
        }


def check_demisto_version():
    """
    Check if the Cortex XSOAR version is suitable for performing the polling flow (6.2 and above)
    """
    if not is_demisto_version_ge("6.2.0"):
        raise DemistoException(
            "Deleting an email using this script with the Microsoft Graph eDiscovery flow is not "
            "supported by this Cortex XSOAR server version. Please update your server version to 6.2.0 "
            "or later."
        )


def schedule_next_command(args: dict):
    """
    Handle the creation of the ScheduleCommand object
    Returns:
        ScheduleCommand object that will call this script again.
    """
    demisto.debug(f"Scheduling next command for Polling. Current args: {args}")
    polling_args = {
        "interval_in_seconds": 60,
        "polling": True,
        **args,
    }
    # The timeout was increased to 300 sec due to the slowness of the Microsoft eDiscovery process.
    return ScheduledCommand(
        command="DeleteReportedEmail",
        next_run_in_seconds=60,
        args=polling_args,
        timeout_in_seconds=300,
    )


def was_email_already_deleted(search_args: dict, e: str):
    """
    Checks if the email was already deleted by this script, using the context data information.
    Args:
        search_args: the command arguments
        e: error message indicating the email was not found

    Returns:
        'Success', if the email was previously deleted by this script
        'Skipped', if the email was not found in the mailbox and was not previously deleted by this script

    """
    delete_email_from_context = demisto.get(demisto.context(), "DeleteReportedEmail")
    if delete_email_from_context:
        if not isinstance(delete_email_from_context, list):
            delete_email_from_context = [delete_email_from_context]
        for item in delete_email_from_context:
            message_id = item.get("message_id")
            result_str = item.get("result", "")
            if message_id == search_args.get("message-id") and ("Success" in result_str or "Purge" in result_str):
                demisto.debug(f"Email {message_id} was already deleted successfully in a previous run.")
                return result_str, ""
    return "Skipped", e


def _extract_graph_objects(response: Any) -> list:
    """Safely extracts Graph objects from execute_command output whether it's a list, dict, or OData wrapper."""
    demisto.debug(f"_extract_graph_objects called with response type: {type(response)}")
    if isinstance(response, list):
        demisto.debug("Response is a list. Iterating...")
        objects = []
        for item in response:
            objects.extend(_extract_graph_objects(item))
        return objects
    if isinstance(response, dict):
        demisto.debug("Response is a dict.")
        if "value" in response and isinstance(response.get("value"), list):
            demisto.debug(f"Found 'value' array with {len(response.get('value', []))} items.")
            return _extract_graph_objects(response.get("value", []))
        return [response]
    demisto.debug("Response is neither list nor dict. Returning empty list.")
    return []


def msg_resolve_case(using_brand: str, case_name: str) -> str | None:
    """
    Get the ID of an existing eDiscovery case by its display name, creating the case if it does not exist.

    Args:
        using_brand: The brand (integration instance) used to run the eDiscovery commands.
        case_name: The display name of the eDiscovery case to resolve.

    Returns:
        The ID of the existing or newly created case, or None if the case could not be created.
    """
    demisto.debug(f"msg_resolve_case: Attempting to resolve case '{case_name}' using brand '{using_brand}'")
    cases_res = execute_command("msg-list-ediscovery-cases", {"using-brand": using_brand, "all_results": "true"})
    cases = _extract_graph_objects(cases_res)
    demisto.debug(f"msg_resolve_case: Found {len(cases)} existing cases.")

    for case in cases:
        if case.get("displayName") == case_name and case.get("id"):
            demisto.debug(f"msg_resolve_case: Found matching case ID: {case['id']}")
            return case["id"]

    demisto.debug(f"msg_resolve_case: Case '{case_name}' not found. Creating a new one...")
    new_case = execute_command("msg-create-ediscovery-case", {"using-brand": using_brand, "display_name": case_name})
    created_cases = _extract_graph_objects(new_case)
    new_case_id = created_cases[0].get("id") if created_cases else None
    demisto.debug(f"msg_resolve_case: Created new case with ID: {new_case_id}")
    return new_case_id


def microsoft_graph_security_delete_mail(
    args: dict, message_id: str, using_brand: str, delete_type: str, **kwargs
) -> tuple[str, ScheduledCommand | None]:
    """
    Delete an email using the Microsoft Graph eDiscovery flow, with polling between the search and the purge.

    Args:
        args: This script's arguments, also used to persist the case_id and search_id between polling runs.
        message_id: The RFC Message-ID of the email to delete.
        using_brand: The brand (integration instance) used to run the eDiscovery commands.
        delete_type: The deletion type, 'hard' for a permanent delete, otherwise a recoverable delete.
        **kwargs: Additional unused search arguments.

    Returns:
        A tuple of the deletion result ('Success' or 'In Progress') and the ScheduledCommand for the
        next polling run, or None when no further polling is needed.
    """
    demisto.debug(
        f"microsoft_graph_security_delete_mail starting. args: {args}, message_id: {message_id}, delete_type: {delete_type}"
    )
    check_demisto_version()

    already_deleted_res, _ = was_email_already_deleted({"message-id": message_id}, "")
    if already_deleted_res != "Skipped":
        demisto.debug("Email already deleted according to context. Exiting with Success.")
        return already_deleted_res, None

    case_name = "XSOAR Delete Reported Email"
    case_id = args.get("case_id")
    search_id = args.get("search_id")
    demisto.debug(f"Current State -> case_id: {case_id}, search_id: {search_id}")

    # ==========================================
    # STEP 1: First Run - Setup and Trigger Estimate
    # ==========================================
    if not case_id or not search_id:
        demisto.debug("First run detected (missing case_id or search_id). Initializing eDiscovery flow...")
        case_id = msg_resolve_case(using_brand, case_name)
        if not case_id:
            raise DemistoException("Failed to resolve or create an eDiscovery case. case_id is missing.")

        kql_query = f'Identifier:"{message_id}"'
        search_name = f"delete_search_{int(time.time())}"

        demisto.debug(f"Creating search with name '{search_name}' and KQL '{kql_query}' in case '{case_id}'")
        search_res = execute_command(
            "msg-create-ediscovery-search",
            {
                "using-brand": using_brand,
                "case_id": case_id,
                "display_name": search_name,
                "content_query": kql_query,
                "data_source_scopes": "allTenantMailboxes",
            },
        )
        search_objs = _extract_graph_objects(search_res)
        search_id = search_objs[0].get("id") if search_objs else None
        demisto.debug(f"Search created with ID: {search_id}")

        if not search_id:
            raise DemistoException("Failed to create eDiscovery search: No search_id returned.")

        demisto.debug(f"Triggering msg-run-estimate-statistics for case {case_id} and search {search_id}")
        execute_command("msg-run-estimate-statistics", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id})

        args["case_id"] = case_id
        args["search_id"] = search_id

        return "In Progress", schedule_next_command(args)

    # ==========================================
    # STEP 2: Polling Run - Check Estimate Status & Trigger Purge
    # ==========================================
    demisto.debug("Polling run detected. Checking estimate statistics status...")
    status_res = execute_command(
        "msg-get-last-estimate-statistics-operation", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id}
    )

    status_objs = _extract_graph_objects(status_res)
    raw_status = status_objs[0] if status_objs else {}
    status = str(raw_status.get("status", "")).lower()
    demisto.debug(f"Raw status object: {raw_status}")
    demisto.debug(f"Extracted estimate status string: '{status}'")

    if status in ["running", "notstarted", ""]:
        demisto.debug("Estimate operation still running or not started. Returning 'In Progress' to poll again.")
        return "In Progress", schedule_next_command(args)

    if status == "failed":
        demisto.debug(f"Estimate operation failed! Raising DeletionFailed exception for search_id: {search_id}")
        execute_command("msg-delete-ediscovery-search", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id})
        raise DeletionFailed(f"eDiscovery estimate statistics failed for search_id: {search_id}")

    indexed_items = int(raw_status.get("indexedItemCount") or 0)
    total_items = int(raw_status.get("totalItemCount") or 0)
    demisto.debug(f"Estimate operation completed. indexedItemCount: {indexed_items}, totalItemCount: {total_items}")

    if indexed_items == 0 and total_items == 0:
        demisto.debug("No items found. Cleaning up search and raising MissingEmailException.")
        execute_command("msg-delete-ediscovery-search", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id})
        raise MissingEmailException

    purge_type = "permanentlyDelete" if delete_type == "hard" else "recoverable"
    demisto.debug(f"Items found! Triggering msg-purge-ediscovery-data with purge_type '{purge_type}'.")

    try:
        execute_command(
            "msg-purge-ediscovery-data",
            {
                "using-brand": using_brand,
                "case_id": case_id,
                "search_id": search_id,
                "purge_type": purge_type,
                "purge_areas": "mailboxes",
            },
        )
    except Exception as e:
        demisto.debug(f"Purge command failed: {e}. Cleaning up search.")
        execute_command("msg-delete-ediscovery-search", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id})
        raise

    demisto.debug(f"Cleaning up eDiscovery search {search_id} post-purge trigger.")
    execute_command("msg-delete-ediscovery-search", {"using-brand": using_brand, "case_id": case_id, "search_id": search_id})

    demisto.debug("Deletion flow completed successfully via Fire-and-Forget.")
    return SUCCESS_MESSAGE, None


def extract_message_id(search_result: list, search_function: str) -> str | None:
    """Extract the RFC Message-ID from a search result based on the integration's response structure.

    Args:
        search_result: The list returned by ``execute_command`` for the search.
        search_function: The command name used for the search (e.g. ``"gmail-search"``).

    Returns:
        The RFC Message-ID string if available, or ``None`` when the
        result is empty, malformed, or the header is not present.
    """
    demisto.debug(f"extract_message_id: processing search function '{search_function}'")

    if not search_result or not isinstance(search_result, list):
        demisto.debug("extract_message_id: search_result is empty or not a list, returning None")
        return None

    first_result = search_result[0]
    if not isinstance(first_result, dict):
        demisto.debug("extract_message_id: first result is not a dict, returning None")
        return None

    match search_function:
        case "gmail-search":
            # Gmail stores the RFC Message-ID in payload.headers.
            headers = first_result.get("payload", {}).get("headers", [])
            message_id: str | None = None
            for header in headers:
                if header.get("name", "").lower() == "message-id":
                    message_id = header.get("value")
                    break
            demisto.debug(
                f"extract_message_id: Gmail Message-ID header {'found' if message_id else 'not found'} in payload.headers"
            )
            demisto.debug(f"extract_message_id: returning '{message_id}'")
            return message_id

        case "ews-search-mailbox":
            # EWS (O365 / v2) stores the RFC Message-ID under "messageId".
            result = first_result.get("messageId") or None
            demisto.debug(f"extract_message_id: returning '{result}'")
            return result

        case "msgraph-mail-list-emails":
            # MSGraph wraps results in a "value" array; RFC Message-ID is "internetMessageId".
            value_list = first_result.get("value")
            demisto.debug(
                f"extract_message_id: MSGraph value array has {len(value_list) if isinstance(value_list, list) else 'N/A'} items"
            )
            if not isinstance(value_list, list) or not value_list:
                demisto.debug("extract_message_id: returning None (empty or missing value array)")
                return None
            entry = value_list[0]
            if not isinstance(entry, dict):
                demisto.debug("extract_message_id: returning None (first entry is not a dict)")
                return None
            result = entry.get("internetMessageId") or None
            demisto.debug(f"extract_message_id: returning '{result}'")
            return result

        case _:
            demisto.debug(f"extract_message_id: unrecognized search function '{search_function}', returning None")
            return None


def delete_email(
    search_args: dict,
    search_function: str,
    delete_args_function: Callable[[dict, dict], dict] | Callable[[dict], dict],
    delete_function: str,
    deletion_error_condition: Callable[[str], bool] = lambda x: "successfully" not in x,
):
    """
    Generic function to perform the search and delete operations.
    Args:
        search_args: arguments needed to perform the search command.
        search_function: a string representing the search command.
        delete_args_function: a function that parses the arguments needed to perform the search command.
        delete_function: a string representing the delete command.
        deletion_error_condition: a condition to validate if the deletion was successful or not.
    Returns:
        Success if the deletion succeeded, fails otherwise
    """
    demisto.debug(f"Entering standard delete_email flow. search_function: {search_function}, delete_function: {delete_function}")
    if search_function:
        search_result = execute_command(search_function, search_args)
        demisto.debug(
            f"delete_email: search returned {type(search_result).__name__}"
            f" with {len(search_result) if isinstance(search_result, list) else 'N/A'} results"
        )
        if not search_result or isinstance(search_result, str):
            raise MissingEmailException

        will_trigger_guard = isinstance(search_result, list) and len(search_result) > 1
        demisto.debug(f"delete_email: multi-result guard will trigger: {will_trigger_guard}")
        if will_trigger_guard:
            raise DemistoException(
                f"Search returned {len(search_result)} results; expected exactly 1. Refusing delete to avoid ambiguity."
            )

        # verify the returned message matches the expected one
        expected_mid = search_args.get("message-id") or ""
        returned_mid = extract_message_id(search_result, search_function)
        demisto.debug(f"delete_email: returned message-id='{returned_mid}', expected message-id='{expected_mid}'")
        if returned_mid and returned_mid.strip("<>") != expected_mid.strip("<>"):
            raise DemistoException(f"Search returned message {returned_mid} but expected {expected_mid}; refusing delete")
        demisto.debug("delete_email: message-id comparison passed")

        delete_args = delete_args_function(search_result, search_args)  # type: ignore
    else:
        delete_args = delete_args_function(search_args)  # type: ignore

    demisto.debug(f"Executing standard delete command: {delete_function} with args: {delete_args}")
    resp = execute_command(delete_function, delete_args)
    if deletion_error_condition(resp):
        raise DeletionFailed(resp)
    return "Success"


def get_search_args(args: dict):
    """
    Get the parsed arguments needed for the search operation

    Args:
        args: this script's arguments.

    Returns: parsed arguments needed for the search operation
    """
    incident_info = demisto.incident()
    custom_fields = incident_info.get("CustomFields", {})
    message_id = custom_fields.get("reportedemailmessageid") or ""
    if message_id and not MESSAGE_ID_REGEX.fullmatch(message_id):
        raise DemistoException(f"Refusing suspicious Message-ID: {message_id!r}")
    user_id = custom_fields.get("reportedemailto")
    email_subject = custom_fields.get("reportedemailsubject")
    email_origin = custom_fields.get("reportedemailorigin")
    delete_type = args.get("delete_type", custom_fields.get("emaildeletetype", "soft"))
    delete_from_brand = delete_from_brand_handler(incident_info, args)

    missing_field_error_message = (
        f"'{{field_name}}' field could not be found.\nSee {DOCS_TROUBLESHOOTING_URL} for possible solutions."
    )

    if not email_origin or email_origin.lower() == "none":
        raise ValueError(missing_field_error_message.format(field_name="Reported Email Origin"))

    if not message_id:
        raise ValueError(missing_field_error_message.format(field_name="Reported Email Message ID"))

    if not user_id:
        raise ValueError(missing_field_error_message.format(field_name="Reported Email To"))

    if "," in user_id:
        raise ValueError(
            "Script is supporting only deleting mail from one recipient mailbox at a time."
            "Please make sure that there is only one 'Reported Email To' address."
        )

    search_args = {
        "delete-type": delete_type,
        "using-brand": delete_from_brand,
        "email_subject": email_subject,
        "message-id": message_id,
    }
    additional_args = {
        "Gmail": {"query": f'rfc822msgid:"{message_id}"', "user-id": user_id},
        "EWSO365": {"target-mailbox": user_id},
        "EWS v2": {"target-mailbox": user_id},
        "MicrosoftGraphMail": {
            "user_id": user_id,
            "odata": "$filter=internetMessageId eq '{}'".format(quote(unquote(message_id).replace("'", "''"), safe="")),
        },
        "Microsoft Graph": {"to_user_id": user_id},
    }

    search_args.update(additional_args.get(delete_from_brand, {}))
    demisto.debug(f"Generated search args: {search_args}")
    return search_args


def delete_from_brand_handler(incident_info: dict, args: dict):
    """
    Handle the delete_from_brand argument in the following logic:
    1. If the source brand exists in the 'emaildeletefrombrand' field, use it.
    2. If the field is empty, use the script's argument.
    3. If there is no argument given, use the incident's source brand.
    2. If the value is given (in any of the above ways) but it is not of a suitable integration, raise an error.
    Otherwise, use it.

    Args:
        incident_info: Incident info from the context data.
        args: the arguments of this script

    Returns:
        The suitable delete brand

    """
    delete_from_brand = incident_info.get("CustomFields", {}).get("emaildeletefrombrand")
    if not delete_from_brand or delete_from_brand == "Unspecified":
        delete_from_brand = args.get("delete_from_brand", incident_info.get("sourceBrand"))

    elif delete_from_brand not in EMAIL_INTEGRATIONS:
        raise DemistoException(f"Cannot delete the email using the chosen brand. The possible brands are: {EMAIL_INTEGRATIONS}")

    demisto.debug(f"Determined delete_from_brand: {delete_from_brand}")
    return delete_from_brand


def main():
    args = demisto.args()
    search_args = get_search_args(args)
    result, deletion_failure_reason, scheduled_command = "", "", None
    delete_from_brand = search_args["using-brand"]

    try:
        if delete_from_brand == "Microsoft Graph":
            demisto.debug("Routing to Microsoft Graph Security eDiscovery flow.")
            graph_security_args = {k.replace("-", "_"): v for k, v in search_args.items()}
            result, scheduled_command = microsoft_graph_security_delete_mail(args, **graph_security_args)

        else:
            demisto.debug(f"Routing to standard flow for brand: {delete_from_brand}")
            integrations_dict = {
                "Gmail": ("gmail-search", DeletionArgs.gmail, "gmail-delete-mail"),
                "EWSO365": ("ews-search-mailbox", DeletionArgs.ews, "ews-delete-items", lambda x: not isinstance(x, list)),
                "EWS v2": ("ews-search-mailbox", DeletionArgs.ews, "ews-delete-items", lambda x: not isinstance(x, list)),
                "Agari Phishing Defense": (None, DeletionArgs.agari, "apd-remediate-message"),
                "MicrosoftGraphMail": ("msgraph-mail-list-emails", DeletionArgs.msgraph, "msgraph-mail-delete-email"),
            }
            result = delete_email(search_args, *integrations_dict[delete_from_brand])  # type: ignore

    except MissingEmailException as e:
        result, deletion_failure_reason = was_email_already_deleted(search_args, str(e))
    except DeletionFailed as e:
        result, deletion_failure_reason = "Failed", f"Failed deleting email: {e!s}"
    except Exception as e:
        return_error(f"Failed to execute DeleteEmail. Error: {e!s}")

    finally:
        search_args.update({"result": result, "deletion_failure_reason": deletion_failure_reason})
        search_args = remove_empty_elements(replace_in_keys(search_args, "-", "_"))
        demisto.executeCommand("setIncident", {"emaildeleteresult": result, "emaildeletereason": deletion_failure_reason})
        return_results(
            CommandResults(
                readable_output=tableToMarkdown(
                    "Deletion Results",
                    search_args,
                    headerTransform=string_to_table_header,
                ),
                outputs_prefix="DeleteReportedEmail",
                outputs_key_field="message_id",
                raw_response="",
                outputs=search_args,
                scheduled_command=scheduled_command,
            )
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
