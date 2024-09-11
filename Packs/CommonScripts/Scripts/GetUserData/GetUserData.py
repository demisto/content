import demistomock as demisto
from CommonServerPython import *

import itertools
from typing import Any


class Modules:
    def __init__(self, modules: dict[str, Any]):
        self.modules_context = modules
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_available(self, brand_name: str) -> bool:
        """
        Check if a brand is available in the current context.

        Args:
            brand_name (str): The name of the brand to check.

        Returns:
            bool: True if the brand is available, False otherwise.
        """
        return brand_name in self._enabled_brands


def create_account(
    id: Optional[str] = None,
    username: Optional[str] = None,
    display_name: Optional[str] = None,
    email_address: Optional[str] = None,
    groups: Optional[list[str]] = None,
    type: Optional[str] = None,
    job_title: Optional[str] = None,
    office: Optional[str] = None,
    telephone_number: Optional[str] = None,
    is_enabled: Optional[bool] = None,
    manager_email: Optional[str] = None,
    manager_display_name: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create an account dictionary with the provided user information.

    Args:
        id (Optional[str]): The unique identifier for the account.
        username (Optional[str]): The username associated with the account.
        display_name (Optional[str]): The display name for the account.
        email_address (Optional[str]): The email address associated with the account.
        groups (Optional[list[str]]): A list of groups the account belongs to.
        type (Optional[str]): The type of the account.
        job_title (Optional[str]): The job title of the account holder.
        office (Optional[str]): The office location of the account holder.
        telephone_number (Optional[str]): The telephone number associated with the account.
        is_enabled (Optional[bool]): Whether the account is enabled or not.
        manager_email (Optional[str]): The email address of the account holder's manager.
        manager_display_name (Optional[str]): The display name of the account holder's manager.
        risk_level (Optional[str]): The risk level associated with the account.

    Returns:
        dict[str, Any]: A dictionary containing the non-empty account information.
    """
    account = {}
    if id:
        account = {
            "id": id,
            "username": username,
            "display_name": display_name,
            "email_address": email_address,
            "groups": groups,
            "type": type,
            "job_title": job_title,
            "office": office,
            "telephone_number": telephone_number,
            "is_enabled": is_enabled,
            "manager_email": manager_email,
            "manager_display_name": manager_display_name,
            "risk_level": risk_level,
        }
        for key, value in account.items():
            if isinstance(value, list) and len(value) == 1:
                account[key] = value[0]

    return remove_empty_elements(account)


def prepare_human_readable(
    command_name: str, args: dict[str, Any], human_readable: str, is_error: bool = False
) -> list[CommandResults]:
    """
    Prepare human-readable output for a command execution.

    Args:
        command_name (str): The name of the command executed.
        args (dict[str, Any]): The arguments passed to the command.
        human_readable (str): The human-readable output of the command.
        is_error (bool, optional): Whether the command resulted in an error. Defaults to False.

    Returns:
        list[CommandResults]: A list containing CommandResults objects with the formatted output.
    """
    result = []
    if human_readable:
        command = f'!{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
        if not is_error:
            result_message = f"#### Result for {command}\n{human_readable}"
            result.append(
                CommandResults(readable_output=result_message, mark_as_note=True)
            )
        else:
            result_message = f"#### Error for {command}\n{human_readable}"
            result.append(
                CommandResults(
                    readable_output=result_message,
                    entry_type=EntryType.ERROR,
                    mark_as_note=True,
                )
            )
    return result


def get_output_key(output_key: str, raw_context: dict[str, Any]) -> str:
    """
    Retrieves the full output key from the raw_context dictionary.

    This function searches for the output key in the raw_context dictionary. If an exact match is not found,
    it looks for a key that starts with the given output_key followed by an opening parenthesis.

    Args:
        output_key (str): The base output key to search for.
        raw_context (dict[str, Any]): The dictionary containing the raw_context.

    Returns:
        str: The full output key if found, otherwise an empty string.

    Example:
        raw_context = {
            "Account(val.ID == obj.ID)": [
                {
                    "Username": "john.doe",
                    "Email": "john.doe@example.com",
                    "DisplayName": "John Doe"
                }
            ]
        }
        output_key = "Account"
        result = get_outputs(output_key, raw_context)
        # result will be: "Account(val.Username == obj.Username)"
    """
    full_output_key = ""
    if raw_context:
        if output_key in raw_context:
            full_output_key = output_key
        else:
            for key in raw_context:
                if key.startswith(f"{output_key}("):
                    full_output_key = key
                    break
        if not full_output_key:
            demisto.debug(
                f"Output key {output_key} not found in entry context keys: {list(raw_context.keys())}"
            )
    return full_output_key


def get_outputs(output_key: str, raw_context: dict[str, Any]) -> dict[str, Any]:
    """
    Retrieves the output context for a given output key from the raw context.

    This function uses the get_output_key function to find the full output key,
    then extracts the corresponding context from the raw_context dictionary.
    If the context is a list, it returns the first item.

    Args:
        output_key (str): The base output key to search for.
        raw_context (dict[str, Any]): The raw context dictionary to search in.

    Returns:
        dict[str, Any]: The extracted context for the given output key,
        or an empty dictionary if not found.

    Example:
        raw_context = {
            "Account(val.Username == obj.Username)": [
                {
                    "Username": "john.doe",
                    "Email": "john.doe@example.com",
                    "DisplayName": "John Doe"
                }
            ]
        }
        output_key = "Account(val.Username == obj.Username)"
        result = get_outputs(output_key, raw_context)
        # result will be:
        # {
        #     "Username": "john.doe",
        #     "Email": "john.doe@example.com",
        #     "DisplayName": "John Doe"
        # }

    """
    context = {}
    if raw_context and output_key:
        context = raw_context.get(output_key, {})
        if isinstance(context, list):
            context = context[0]

    return context


def merge_accounts(accounts: list[dict[str, str]]) -> dict[str, Any]:
    """
    Merges multiple account dictionaries into a single Common.Account object.

    This function takes a list of account dictionaries and combines them into a single
    merged account. If there are conflicting values for the same key, it logs a debug
    message and keeps the first encountered value.

    Args:
        accounts (list[dict[str, str]]): A list of account dictionaries to merge.

    Returns:
        dict[str, Any]: A dictionary representation of the merged Common.Account object,
        or an empty dictionary if no accounts were provided.
    """
    merged_account: dict[str, Any] = {}
    for account in accounts:
        for key, value in account.items():
            if key not in merged_account:
                merged_account[key] = value
            elif merged_account[key] != value:
                demisto.debug(
                    f"Conflicting values for key '{key}': '{merged_account[key]}' vs '{value}'"
                )
    return (
        Common.Account(**merged_account).to_context()[Common.Account.CONTEXT_PATH]
        if merged_account
        else {}
    )


def run_execute_command(
    command_name: str, args: dict[str, Any]
) -> tuple[list[dict], str, list[CommandResults]]:
    """
    Executes a command and processes its results.

    This function runs a specified command with given arguments, handles any errors,
    and prepares the command results for further processing.

    Args:
        command_name (str): The name of the command to execute.
        args (dict[str, Any]): A dictionary of arguments to pass to the command.

    Returns:
        tuple[list[dict], str, list[CommandResults]]: A tuple containing:
            - A list of dictionaries representing the command's entry context.
            - A string containing the human-readable output of the command.
            - A list of CommandResults objects representing any errors that occurred.
    """
    demisto.debug(f"Executing command: {command_name}")
    res = demisto.executeCommand(command_name, args)
    errors_command_results = []
    if is_error(res):
        errors_command_results.extend(
            prepare_human_readable(command_name, args, get_error(res), is_error=True)
        )
    human_readable = "\n".join([entry.get("HumanReadable", "") for entry in res])
    entry_context = [entry.get("EntryContext", {}) for entry in res]
    demisto.debug(f"Finished executing command: {command_name}")
    return entry_context, human_readable, errors_command_results


def identityiq_search_identities_command(
    user_id: str, user_email: str
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "identityiq-search-identities"
    args = {"id": user_id, "email": user_email}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("IdentityIQ.Identity", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("id"),
        username=outputs.get("userName"),
        display_name=outputs.get("name", {}).get("formatted"),
        email_address=outputs.get("emails", {}).get("value"),
        is_enabled=outputs.get("active"),
    )

    return readable_outputs_list, account_output


def identitynow_get_accounts_command(
    user_id: str, user_name: str
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "identitynow-get-accounts"
    args = {"id": user_id, "name": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("IdentityNow.Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("id"),
        display_name=outputs.get("name"),
        is_enabled=not outputs.get("disabled"),
    )

    return readable_outputs_list, account_output


def ad_get_user_command(
    user_name: str, user_email: str
) -> tuple[list[CommandResults], dict[str, Any], str]:
    command_name = "ad-get-user"
    args = {"username": user_name, "email": user_email}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )

    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("ActiveDirectory.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("dn"),
        display_name=outputs.get("displayName"),
        email_address=outputs.get("mail"),
        groups=outputs.get("memberOf"),
        is_enabled=not outputs.get("userAccountControlFields", {}).get(
            "ACCOUNTDISABLE",
        ),
    )

    manager_dn = (outputs.get("manager") or [""])[0]
    return readable_outputs_list, account_output, manager_dn


def ad_get_user_manager_command(
    manager_dn: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "ad-get-user"
    args = {"dn": manager_dn}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("ActiveDirectory.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        manager_display_name=outputs.get("displayName"),
        manager_email=outputs.get("mail"),
    )

    return readable_outputs_list, account_output


def pingone_get_user_command(
    user_id: str, user_name: str
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "pingone-get-user"
    args = {"userId": user_id, "username": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("PingOne.Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("ID"),
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email"),
        is_enabled=outputs.get("Enabled"),
    )

    return readable_outputs_list, account_output


def okta_get_user_command(
    user_id: str, user_name: str
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "okta-get-user"
    args = {"userId": user_id, "username": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("ID"),
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email"),
        manager_display_name=outputs.get("Manager"),
        is_enabled=outputs.get("Status") == "ACTIVE",
    )

    return readable_outputs_list, account_output


def aws_iam_get_user_command(
    user_name: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "aws-iam-get-user"
    args = {"userName": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("AWS.IAM.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("UserId"),
        username=outputs.get("UserName"),
    )

    return readable_outputs_list, account_output


def msgraph_user_get_command(
    user_name: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "msgraph-user-get"
    args = {"user": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("ID"),
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email", {}).get("Address"),
        job_title=outputs.get("JobTitle"),
        office=outputs.get("Office"),
        telephone_number=outputs.get("TelephoneNumber"),
        type=outputs.get("Type"),
    )

    return readable_outputs_list, account_output


def msgraph_user_get_manager_command(
    user_name: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "msgraph-user-get-manager"
    args = {"user": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("MSGraphUserManager", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        manager_display_name=outputs.get("Manager", {}).get("DisplayName"),
        manager_email=outputs.get("Manager", {}).get("Mail"),
    )

    return readable_outputs_list, account_output


def xdr_list_risky_users_command(
    user_name: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    command_name = "xdr-list-risky-users"
    args = {"user_id": user_name}
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    output_key = get_output_key("PaloAltoNetworksXDR.RiskyUser", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("id"),
        risk_level=outputs.get("risk_level"),
    )

    return readable_outputs_list, account_output


def iam_get_user_command(
    user_id: str, user_name: str, user_email: str, domain: str
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    command_name = "iam-get-user"
    args = {
        "user-profile": {
            "id": user_id,
            "email": user_email,
            "username": f"{user_name}{domain if domain else ''}",
        }
    }
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command_name, args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command_name, args, human_readable)
    )
    account_outputs = []
    for output_entry in entry_context:
        output_key = get_output_key("IAM.Vendor", output_entry)
        outputs = get_outputs(output_key, output_entry)
        if outputs.get("success"):
            account_outputs.append(
                create_account(
                    id=outputs.get("id"),
                    username=outputs.get("username"),
                    email_address=outputs.get("email"),
                    is_enabled=outputs.get("active"),
                )
            )
    return readable_outputs_list, account_outputs


def debug_message_skip_command(command_name: str):
    demisto.debug(
        f"Skipping command '{command_name}' since no required arguments were provided or the command is not available."
    )


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        args = demisto.args()
        users_ids = argToList(args.get("user_id", []))
        users_names = argToList(args.get("user_name", []))
        users_emails = argToList(args.get("user_email", []))
        domain = args.get("domain", "")
        verbose = argToBoolean(args.get("verbose", False))
        modules = Modules(demisto.getModules())

        if domain and not users_names:
            raise ValueError(
                "When specifying the domain argument, the user_name argument must also be provided."
            )
        if not any((users_ids, users_names, users_emails)):
            raise ValueError(
                "At least one of the following arguments must be specified: user_id, user_name or user_email."
            )

        command_results_list: list[CommandResults] = []
        account_outputs_list: list[dict[str, Any]] = []
        users_not_found_list: list[str] = []

        for user_id, user_name, user_email in list(
            itertools.zip_longest(users_ids, users_names, users_emails, fillvalue="")
        ):
            #################################
            ### Running for a single user ###
            #################################
            single_user_outputs = []
            single_user_readable_outputs = []
            outputs: dict[str, Any] | list[dict[str, Any]]
            if "\\" not in user_name:  # If the user_name does not contain a domain
                if modules.is_brand_available("SailPointIdentityNow") and any(
                    (user_id, user_name)
                ):
                    readable_outputs, outputs = identitynow_get_accounts_command(
                        user_id, user_name
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                else:
                    debug_message_skip_command("identitynow-get-accounts")
                if modules.is_brand_available("Active Directory Query v2") and any(
                    (user_name, user_email)
                ):
                    readable_outputs, outputs, manager_dn = ad_get_user_command(
                        user_name, user_email
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                    if manager_dn:
                        readable_outputs, manager_outputs = ad_get_user_manager_command(
                            manager_dn
                        )
                        single_user_readable_outputs.extend(readable_outputs)
                        single_user_outputs.append(manager_outputs)
                else:
                    debug_message_skip_command("ad-get-user")
                if modules.is_brand_available("PingOne") and any((user_id, user_name)):
                    readable_outputs, outputs = pingone_get_user_command(
                        user_id, user_name
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                else:
                    debug_message_skip_command("pingone-get-user")
                if modules.is_brand_available("Okta v2") and any((user_id, user_name)):
                    readable_outputs, outputs = okta_get_user_command(
                        user_id, user_name
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                else:
                    debug_message_skip_command("okta-get-user")
                if modules.is_brand_available("AWS - IAM") and user_name:
                    readable_outputs, outputs = aws_iam_get_user_command(user_name)
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                else:
                    debug_message_skip_command("aws-iam-get-user")
                if modules.is_brand_available("Microsoft Graph User") and user_name:
                    readable_outputs, outputs = msgraph_user_get_command(user_name)
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                    if outputs:
                        readable_outputs, outputs = msgraph_user_get_manager_command(
                            user_name
                        )
                        single_user_readable_outputs.extend(readable_outputs)
                        single_user_outputs.append(outputs)
                else:
                    debug_message_skip_command("msgraph-user-get")
            else:
                demisto.debug(
                    f"Skipping commands that do not support domain in user_name: {user_name}"
                )
            if modules.is_brand_available("SailPointIdentityIQ") and any(
                (user_id, user_email)
            ):
                readable_outputs, outputs = identityiq_search_identities_command(
                    user_id, user_email
                )
                single_user_readable_outputs.extend(readable_outputs)
                single_user_outputs.append(outputs)
            else:
                debug_message_skip_command("identityiq-search-identities")
            if modules.is_brand_available("Cortex XDR - IR") and user_name:
                readable_outputs, outputs = xdr_list_risky_users_command(user_name)
                single_user_readable_outputs.extend(readable_outputs)
                single_user_outputs.append(outputs)
            else:
                debug_message_skip_command("xdr-list-risky-users")
            ### iam-get-user command implementation ###
            readable_outputs, outputs = iam_get_user_command(
                user_id, user_name, user_email, domain
            )
            single_user_readable_outputs.extend(readable_outputs)
            single_user_outputs.extend(outputs)

            if verbose:
                command_results_list.extend(single_user_readable_outputs)
            ### Merge single user account data ###
            merged_output = merge_accounts(single_user_outputs)
            if merged_output:
                account_outputs_list.append(merged_output)
            else:
                users_not_found_list.append(user_id or user_name or user_email)

        ##############################
        ### Complete for all users ###
        ##############################
        if users_not_found_list:
            users_not_found_str = "\n".join(users_not_found_list)
            command_results_list.append(
                CommandResults(
                    readable_output=f"The following user(s) were not found:\n{users_not_found_str}",
                )
            )
        if account_outputs_list:
            command_results_list.append(
                CommandResults(
                    outputs_prefix="Account",
                    outputs_key_field="Id",
                    outputs=account_outputs_list,
                    readable_output=tableToMarkdown(
                        name="User(s) Data",
                        t=account_outputs_list,
                        headers=["Id", "Username", "Email", "IsEnabled", "Message"],
                    ),
                )
            )
        return_results(command_results_list)
    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
