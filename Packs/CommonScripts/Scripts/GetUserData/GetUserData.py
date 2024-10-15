import demistomock as demisto
from CommonServerPython import *

import itertools
from typing import Any


class Command:
    def __init__(self, brand: str, name: str, args: dict) -> None:
        """
        Initialize a Command object.

        Args:
            brand (str): The brand associated with the command.
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
        """
        self.brand = brand
        self.name = name
        self.args = args


class Modules:
    def __init__(self, modules: dict[str, Any], brands_to_run: list[str]) -> None:
        """
        Initialize the Modules instance.

        Args:
            modules (dict[str, Any]): A dictionary containing module information.
            brands_to_run (list[str]): A list of brands to run.

        Attributes:
            modules_context (dict[str, Any]): The modules dictionary.
            _brands_to_run (list[str]): The list of brands to run.
            _enabled_brands (set[str]): A set of active brands extracted from the modules.
        """
        self.modules_context = modules
        self._brands_to_run = brands_to_run
        self._enabled_brands = {
            module.get("brand")
            for module in self.modules_context.values()
            if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        """
        Check if a brand is in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is in the list of brands to run, False otherwise.
        """
        is_in_brands_to_run = (
            command.brand in self._brands_to_run if self._brands_to_run else True
        )

        if not is_in_brands_to_run:
            demisto.debug(
                f"Skipping command '{command.name}' since the brand '{command.brand}' is not in the list of brands to run."
            )

        return is_in_brands_to_run

    def is_brand_available(self, command: Command) -> bool:
        """
        Check if a brand is available and in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is available and in the list of brands to run, False otherwise.
        """
        is_available = command.brand in self._enabled_brands
        if not is_available:
            demisto.debug(
                f"Skipping command '{command.name}' since the brand '{command.brand}' is not available."
            )
        elif not self.is_brand_in_brands_to_run(command):
            is_available = False

        return is_available


def is_valid_args(command: Command):
    """
    Validate if the command has valid arguments.

    Args:
        command (Command): The command object to validate.

    Returns:
        bool: True if the command has valid arguments, False otherwise.

    Note:
        If the command has no arguments, it is considered valid.
    """
    is_valid = any(command.args.values()) if command.args else True
    if not is_valid:
        demisto.debug(
            f"Skipping command '{command.name}' since no required arguments were provided."
        )

    return is_valid


def create_account(
    id: Optional[str] = None,
    source_id: Optional[str] = None,
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
        source_id (Optional[str]): The source identifier for the account.
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
    source_id = source_id if id else None
    account = {
        "id": {
            "Value": id,
            "Source": source_id,
        },
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
    if raw_context and output_key:
        context = raw_context.get(output_key, {})
        if isinstance(context, list):
            context = context[0]
    else:
        context = {}
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
            if key == "id":
                if key not in merged_account:
                    merged_account[key] = [value]
                else:
                    merged_account[key].append(value)
            elif key not in merged_account:
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
    human_readable_list = []
    entry_context_list = []
    for entry in res:
        entry_context_list.append(entry.get("EntryContext", {}))
        if is_error(entry):
            errors_command_results.extend(
                prepare_human_readable(
                    command_name, args, get_error(entry), is_error=True
                )
            )
        else:
            human_readable_list.append(entry.get("HumanReadable") or "")
    human_readable = "\n".join(human_readable_list)
    demisto.debug(f"Finished executing command: {command_name}")
    return entry_context_list, human_readable, errors_command_results


def identityiq_search_identities(
    command: Command,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("IdentityIQ.Identity", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("id"),
        source_id=command.brand,
        username=outputs.get("userName"),
        display_name=outputs.get("name", {}).get("formatted"),
        email_address=outputs.get("emails", {}).get("value"),
        is_enabled=outputs.get("active"),
    )

    return readable_outputs_list, account_output


def identitynow_get_accounts(
    command: Command,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("IdentityNow.Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    is_disabled = outputs.get("disabled")
    is_enabled = (not is_disabled) if isinstance(is_disabled, bool) else None
    account_output = create_account(
        id=outputs.get("id"),
        source_id=command.brand,
        username=outputs.get("name"),
        is_enabled=is_enabled,
    )

    return readable_outputs_list, account_output


def ad_get_user(command: Command) -> tuple[list[CommandResults], dict[str, Any], str]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )

    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("ActiveDirectory.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    account_disable = outputs.get("userAccountControlFields", {}).get("ACCOUNTDISABLE")
    is_enabled = (not account_disable) if isinstance(account_disable, bool) else None
    account_output = create_account(
        source_id=command.brand,
        username=outputs.get("sAMAccountName"),
        display_name=outputs.get("displayName"),
        email_address=outputs.get("mail"),
        groups=outputs.get("memberOf"),
        is_enabled=is_enabled,
    )

    manager_dn = (outputs.get("manager") or [""])[0]
    return readable_outputs_list, account_output, manager_dn


def ad_get_user_manager(
    command: Command,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("ActiveDirectory.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        manager_display_name=outputs.get("displayName"),
        manager_email=outputs.get("mail"),
    )

    return readable_outputs_list, account_output


def pingone_get_user(command: Command) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("PingOne.Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("ID"),
        source_id=command.brand,
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email"),
        is_enabled=outputs.get("Enabled"),
    )

    return readable_outputs_list, account_output


def okta_get_user(command: Command) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    is_enabled = (
        (outputs.get("Status") != "DEPROVISIONED") if outputs.get("Status") else None
    )
    account_output = create_account(
        id=outputs.get("ID"),
        source_id=command.brand,
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email"),
        manager_display_name=outputs.get("Manager"),
        is_enabled=is_enabled,
    )

    return readable_outputs_list, account_output


def aws_iam_get_user(command: Command) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("AWS.IAM.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("UserId"),
        source_id=command.brand,
        username=outputs.get("UserName"),
    )

    return readable_outputs_list, account_output


def msgraph_user_get(command: Command) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        id=outputs.get("ID"),
        source_id=command.brand,
        username=outputs.get("Username"),
        display_name=outputs.get("DisplayName"),
        email_address=outputs.get("Email", {}).get("Address"),
        job_title=outputs.get("JobTitle"),
        office=outputs.get("Office"),
        telephone_number=outputs.get("TelephoneNumber"),
        type=outputs.get("Type"),
    )

    return readable_outputs_list, account_output


def msgraph_user_get_manager(
    command: Command,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("MSGraphUserManager", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    account_output = create_account(
        manager_display_name=outputs.get("Manager", {}).get("DisplayName"),
        manager_email=outputs.get("Manager", {}).get("Mail"),
    )

    return readable_outputs_list, account_output


def xdr_list_risky_users(
    command: Command,
    user_name: str,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("PaloAltoNetworksXDR.RiskyUser", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    account_output = create_account(
        id=outputs.get("id"),
        source_id=command.brand,
        risk_level=outputs.get("risk_level"),
        username=user_name,
    )

    return readable_outputs_list, account_output


def iam_get_user_command(
    user_id: str, user_name: str, user_email: str, domain: str
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    command_name = "iam-get-user"
    if user_name and domain:
        user_name = f"{user_name}@{domain}"
    args = {
        "user-profile": {
            "id": user_id,
            "email": user_email,
            "username": user_name,
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
                    source_id=outputs.get("brand"),
                    username=outputs.get("username"),
                    email_address=outputs.get("email"),
                    is_enabled=outputs.get("active"),
                )
            )
    return readable_outputs_list, account_outputs


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_ids = argToList(args.get("user_id", []))
        users_names = argToList(args.get("user_name", []))
        users_emails = argToList(args.get("user_email", []))
        domain = args.get("domain", "")
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", []))
        modules = Modules(demisto.getModules(), brands_to_run)

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
            demisto.debug(
                f"Start getting user account data for user: {user_id=}, {user_name=}, {user_email=}"
            )
            single_user_outputs = []
            single_user_readable_outputs = []
            outputs: dict[str, Any] | list[dict[str, Any]]
            if "\\" not in (
                user_name or ""
            ):  # If the user_name does not contain a domain
                identitynow_get_accounts_command = Command(
                    brand="SailPointIdentityNow",
                    name="identitynow-get-accounts",
                    args={"id": user_id, "name": user_name},
                )
                if modules.is_brand_available(
                    identitynow_get_accounts_command
                ) and is_valid_args(identitynow_get_accounts_command):
                    readable_outputs, outputs = identitynow_get_accounts(
                        identitynow_get_accounts_command
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                ad_get_user_command = Command(
                    brand="Active Directory Query v2",
                    name="ad-get-user",
                    args={"username": user_name, "email": user_email},
                )
                if modules.is_brand_available(ad_get_user_command) and is_valid_args(
                    ad_get_user_command
                ):
                    readable_outputs, outputs, manager_dn = ad_get_user(
                        ad_get_user_command
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                    if manager_dn:
                        ad_get_user_manager_command = Command(
                            brand="Active Directory Query v2",
                            name="ad-get-user",
                            args={"dn": manager_dn},
                        )
                        readable_outputs, manager_outputs = ad_get_user_manager(
                            ad_get_user_manager_command
                        )
                        single_user_readable_outputs.extend(readable_outputs)
                        single_user_outputs.append(manager_outputs)
                pingone_get_user_command = Command(
                    brand="PingOne",
                    name="pingone-get-user",
                    args={"userId": user_id, "username": user_name},
                )
                if modules.is_brand_available(
                    pingone_get_user_command
                ) and is_valid_args(pingone_get_user_command):
                    readable_outputs, outputs = pingone_get_user(
                        pingone_get_user_command
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                okta_get_user_command = Command(
                    brand="Okta v2",
                    name="okta-get-user",
                    args={"userId": user_id, "username": user_name},
                )
                if modules.is_brand_available(okta_get_user_command) and is_valid_args(
                    okta_get_user_command
                ):
                    readable_outputs, outputs = okta_get_user(okta_get_user_command)
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                aws_iam_get_user_command = Command(
                    brand="AWS - IAM",
                    name="aws-iam-get-user",
                    args={"userName": user_name},
                )
                if modules.is_brand_available(
                    aws_iam_get_user_command
                ) and is_valid_args(aws_iam_get_user_command):
                    readable_outputs, outputs = aws_iam_get_user(
                        aws_iam_get_user_command
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                msgraph_user_get_command = Command(
                    brand="Microsoft Graph User",
                    name="msgraph-user-get",
                    args={"user": user_name},
                )
                if modules.is_brand_available(
                    msgraph_user_get_command
                ) and is_valid_args(msgraph_user_get_command):
                    readable_outputs, outputs = msgraph_user_get(
                        msgraph_user_get_command
                    )
                    single_user_readable_outputs.extend(readable_outputs)
                    single_user_outputs.append(outputs)
                    if outputs.get("id"):
                        msgraph_user_get_manager_command = Command(
                            brand="Microsoft Graph User",
                            name="msgraph-user-get-manager",
                            args={"user": user_name},
                        )
                        readable_outputs, outputs = msgraph_user_get_manager(
                            msgraph_user_get_manager_command
                        )
                        single_user_readable_outputs.extend(readable_outputs)
                        single_user_outputs.append(outputs)
            else:
                demisto.debug(
                    f"Skipping commands that do not support domain in user_name: {user_name}"
                )
            identityiq_search_identities_command = Command(
                brand="SailPointIdentityIQ",
                name="identityiq-search-identities",
                args={"id": user_id, "email": user_email},
            )
            if modules.is_brand_available(
                identityiq_search_identities_command
            ) and is_valid_args(identityiq_search_identities_command):
                readable_outputs, outputs = identityiq_search_identities(
                    identityiq_search_identities_command
                )
                single_user_readable_outputs.extend(readable_outputs)
                single_user_outputs.append(outputs)
            xdr_list_risky_users_command = Command(
                brand="Cortex XDR - IR",
                name="xdr-list-risky-users",
                args={"user_id": user_name},
            )
            if modules.is_brand_available(
                xdr_list_risky_users_command
            ) and is_valid_args(xdr_list_risky_users_command):
                readable_outputs, outputs = xdr_list_risky_users(
                    xdr_list_risky_users_command, user_name
                )
                single_user_readable_outputs.extend(readable_outputs)
                single_user_outputs.append(outputs)

            ### iam-get-user command implementation ###
            if modules.is_brand_in_brands_to_run(
                Command(brand="iam-get-user", name="iam-get-user", args={})
            ):
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
            command_results_list.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        name="User(s) not found",
                        headers=["User ID/Name/Email"],
                        t=users_not_found_list,
                    )
                )
            )
        if account_outputs_list:
            command_results_list.append(
                CommandResults(
                    outputs_prefix="Account",
                    outputs_key_field="Username",
                    outputs=account_outputs_list,
                    readable_output=tableToMarkdown(
                        name="User(s) Accounts data",
                        t=account_outputs_list,
                        headers=["ID", "Username", "Email", "IsEnabled", "Manager"],
                        removeNull=True,
                    ),
                )
            )
        return_results(command_results_list)
    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
