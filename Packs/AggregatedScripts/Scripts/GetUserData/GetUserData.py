from typing import Any
from collections.abc import Callable

import demistomock as demisto
from CommonServerPython import *


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
            module.get("brand") for module in self.modules_context.values() if module.get("state") == "active"
        }

    def is_brand_in_brands_to_run(self, command: Command) -> bool:
        """
        Check if a brand is in the list of brands to run.

        Args:
            command (Command): The command object containing the brand to check.

        Returns:
            bool: True if the brand is in the list of brands to run, False otherwise.
        """
        is_in_brands_to_run = command.brand in self._brands_to_run if self._brands_to_run else True

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
            demisto.debug(f"Skipping command '{command.name}' since the brand '{command.brand}' is not available.")
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
        demisto.debug(f"Skipping command '{command.name}' since no required arguments were provided.")

    return is_valid


def create_user(
    source: str,
    instance: Optional[str] = None,
    id: Optional[str] = None,
    username: Optional[str] = None,
    email_address: Optional[str] = None,
    risk_level: Optional[int] = None,
    additional_fields=False,
    **kwargs,
) -> dict[str, Any]:
    """
    Create a user dictionary with the provided user information.

    Args:
        id (Optional[str]): The unique identifier for the user.
        source (Optional[str]): The source identifier for the user.
        username (Optional[str]): The username associated with the user.
        email_address (Optional[str]): The email address associated with the user.
        risk_level (Optional[str]): The risk level associated with the user.
        additional_fields (bool): whether to add all the remaining outputs or not.
        kwargs: Additional key-value pairs to include in the user dictionary.

    Returns:
        dict[str, Any]: A dictionary containing the user information.
    """
    user = {
        "ID": id,
        "Username": username,
        "Email": email_address,
        "RiskLevel": risk_level,
    }
    if additional_fields:
        user["AdditionalFields"] = kwargs  # type: ignore
    return remove_empty_elements(user) | {
        "Source": source,
        "Brand": source,
        "Instance": instance,
    }


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
        formatted_args = []
        for arg, value in args.items():
            if value:
                if isinstance(value, dict):
                    value = json.dumps(value).replace('"', '\\\\"')
                formatted_args.append(f'{arg}="{value}"')
        command = f"!{command_name} {' '.join(formatted_args)}"
        if not is_error:
            result_message = f"#### Result for {command}\n{human_readable}"
            result.append(CommandResults(readable_output=result_message, mark_as_note=True))
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
            demisto.debug(f"Output key {output_key} not found in entry context keys: {list(raw_context.keys())}")
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


def run_execute_command(command_name: str, args: dict[str, Any]) -> tuple[list[dict], str, list[CommandResults]]:
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
        entry_context_list.append((entry.get("EntryContext") or {}) | {"instance": entry.get("ModuleName")})
        if is_error(entry):
            errors_command_results.extend(prepare_human_readable(command_name, args, get_error(entry), is_error=True))
        else:
            human_readable_list.append(entry.get("HumanReadable") or "")
    human_readable = "\n".join(human_readable_list)
    demisto.debug(f"Finished executing command: {command_name}")
    return entry_context_list, human_readable, errors_command_results


def ad_get_user(command: Command, additional_fields=False) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []
    command.args["attributes"] = demisto.args().get("attributes")
    sid = command.args.get("user_sid")
    if sid:
        demisto.debug(f"Using a user sid {sid}, inserting the custom-field-type args")
        command.args["custom-field-type"] = "objectSid"

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)

    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    user_outputs = []
    for output in entry_context:
        output_key = get_output_key("ActiveDirectory.Users", output)
        outputs = get_outputs(output_key, output)

        username = outputs.pop("sAMAccountName", None)
        if isinstance(username, list) and len(username) == 1:
            username = username[0]
        mail = outputs.pop("mail", None)
        if isinstance(mail, list) and len(mail) == 1:
            mail = mail[0]
        for k, v in outputs.items():
            if isinstance(v, list) and len(v) == 1:
                outputs[k] = v[0]
        user_outputs.append(
            create_user(
                source=command.brand,
                username=username,
                email_address=mail,
                additional_fields=additional_fields,
                instance=output.get("instance"),
                **outputs,
            )
        )
    return readable_outputs_list, user_outputs


def okta_get_user(command: Command, additional_fields=False) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    user_outputs = []
    for output in entry_context:
        output_key = get_output_key("Account", output)
        outputs = get_outputs(output_key, output)
        user_outputs.append(
            create_user(
                source=command.brand,
                id=outputs.pop("ID", None),
                username=outputs.pop("Username", None),
                email_address=outputs.pop("Email", None),
                additional_fields=additional_fields,
                instance=output.get("instance"),
                **outputs,
            )
        )

    return readable_outputs_list, user_outputs


def aws_iam_get_user(command: Command, additional_fields: bool) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    user_outputs = []
    for output in entry_context:
        output_key = get_output_key("AWS.IAM.Users", output)
        outputs = get_outputs(output_key, output)
        user_outputs.append(
            create_user(
                source=command.brand,
                id=outputs.pop("UserId", None),
                username=outputs.pop("UserName", None),
                additional_fields=additional_fields,
                instance=output.get("instance"),
                **outputs,
            )
        )
    return readable_outputs_list, user_outputs


def prisma_cloud_get_user(command: Command, additional_fields: bool) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    user_outputs = []
    for output in entry_context:
        output_key = get_output_key("PrismaCloud.Users", output)
        outputs = get_outputs(output_key, output)
        user_outputs.append(
            create_user(
                source=command.brand,
                username=outputs.pop("username", None),
                email_address=outputs.pop("email", None),
                additional_fields=additional_fields,
                instance=output.get("instance"),
                **outputs,
            )
        )

    return readable_outputs_list, user_outputs


def msgraph_user_get(command: Command, additional_fields: bool) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    user_outputs = []
    for output in entry_context:
        output_key = get_output_key("Account", output)
        outputs = get_outputs(output_key, output)
        user_outputs.append(
            create_user(
                source=command.brand,
                id=outputs.pop("ID", None),
                username=outputs.pop("Username", None),
                email_address=outputs.pop("Email", {}).get("Address", None),
                additional_fields=additional_fields,
                instance=output.get("instance"),
                **outputs,
            )
        )
    return readable_outputs_list, user_outputs


def msgraph_user_get_manager(command: Command) -> dict[str, Any]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("MSGraphUserManager", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    manager_output = {
        "ManagerDisplayName": outputs.get("Manager", {}).get("DisplayName"),
        "ManagerEmail": outputs.get("Manager", {}).get("Mail"),
    }

    return manager_output


def iam_get_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    account_outputs = []
    for output in entry_context:
        output_key = get_output_key("IAM.Vendor", output)
        outputs = get_outputs(output_key, output)
        account_outputs.append(
            create_user(
                source=command.brand,
                email_address=outputs.pop("email", None),
                instance=output.get("instance"),
                **outputs,
                additional_fields=additional_fields,
            )
            if outputs.get("success")
            else create_user(source=command.brand, instance=output.get("instance"))
        )
    return readable_outputs_list, account_outputs


def gsuite_get_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    account_outputs = []
    for output in entry_context:
        output_key = get_output_key("GSuite.User", output)
        outputs = get_outputs(output_key, output)
        account_outputs.append(
            create_user(
                source=command.brand,
                email_address=outputs.pop("primaryEmail", None),
                username=outputs.pop("fullName", None),
                instance=output.get("instance"),
                **outputs,
                additional_fields=additional_fields,
            )
        )
    return readable_outputs_list, account_outputs


def run_list_risky_users_command(list_risky_users_commands: list[Command], additional_fields: bool, outputs_key_field: str):
    """
    Handles all the logic for the core/xdr list-risky-users command

    Args:
        list_risky_users_commands (list[Command]): list of commands to run.
        additional_fields (bool): whether to add additional fields to the output.
        outputs_key_field (str): the key field to use for the output.
    Returns:
        tuple[list[CommandResults], list[dict[str, Any]]]: readable outputs list and users list.
    """
    readable_outputs_list = []
    users = []
    for list_risky_users_command in list_risky_users_commands:
        entry_context, human_readable, readable_errors = run_execute_command(
            list_risky_users_command.name, list_risky_users_command.args
        )
        readable_outputs_list.extend(readable_errors)
        readable_outputs_list.extend(
            prepare_human_readable(list_risky_users_command.name, list_risky_users_command.args, human_readable)
        )
        for output in entry_context:
            output_key = get_output_key(f"{outputs_key_field}.RiskyUser", output)
            outputs = get_outputs(output_key, output)
            user = create_user(
                source=list_risky_users_command.brand,
                id=outputs.get("id"),
                risk_level=outputs.pop("risk_level", None),
                username=outputs.pop("id", None),
                instance=output.get("instance"),
                email_address=outputs.pop("email", None),
                **outputs,
                additional_fields=additional_fields,
            )
            if set(user) == {"Source", "Brand", "Instance"}:  # contains only the source and brand keys
                user["Status"] = f"User not found - userId: {list_risky_users_command.args.get('user_id')}."
            else:
                user["Status"] = "found"
            users.append(user)

    return readable_outputs_list, users


def run_list_users_command(
    list_users_command: Command,
    additional_fields: bool,
    outputs_key_field: str,
    email_list: List[str],
    users: list[dict[str, Any]],
    readable_outputs_list: list[CommandResults],
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    """
    Handles all the logic for the core/xdr list-users command.

    Args:
        list_users_command (Command): The command to run.
        additional_fields (bool): whether to add additional fields to the output.
        outputs_key_field (str): the key field to use for the output.
        email_list (List[str]): the list of emails to search for.
        users (list[dict[str, Any]]): the list of users obtained from previous command.
        readable_outputs_list (list[CommandResults]): the list of readable outputs to append to.

    Returns:
        tuple[list[CommandResults], list[dict[str, Any]]]: the list of readable outputs and the list of users.
    """
    email_set = set(email_list)
    risky_users_email_set = set()
    for user in users:
        if mail := user.get("Email"):
            risky_users_email_set.add(mail)
    if additional_fields:
        email_set.update(risky_users_email_set)
    if email_set:
        entry_context, _, readable_errors = run_execute_command(list_users_command.name, list_users_command.args)
        readable_outputs_list.extend(readable_errors)
        for output in entry_context:
            output_key = get_output_key(f"{outputs_key_field}.User", output)
            if isinstance(output, dict):
                outputs = output.get(output_key, [])
            else:
                outputs = []
            demisto.debug(f"found {len(outputs)} users")
            for output in outputs:  # type: ignore[assignment]
                if (mail := output.get("user_email", "")) and mail in email_set:
                    demisto.debug(f"found user with email: {mail}")
                    email_set.remove(mail)
                    found = False
                    for user in users:
                        if (mail := user.get("Email")) and mail == output.get("user_email"):
                            demisto.debug(f"found user with email in results from risky-users: {mail}")
                            found = True
                            if additional_fields:
                                demisto.debug(f"adding additional fields to user with email: {mail}")
                                output.pop("user_email")
                                user["AdditionalFields"].update(output)
                            break
                    if not found:
                        demisto.debug(f"User with {mail} was not found in previous results, creating new user.")
                        user = create_user(
                            source=list_users_command.brand,
                            id=output.get("id"),
                            risk_level=output.pop("risk_level", None),
                            username=output.pop("id", None),
                            instance=output.get("instance"),
                            email_address=output.pop("user_email", None),
                            **output,
                            additional_fields=additional_fields,
                        )
                        user["Status"] = "found"
                        users.append(user)
                    if not email_set:
                        demisto.debug("all given users were found, breaking")
                        break
    else:
        demisto.debug("Did not recieve any email to search for, skipping list users command.")
    # Update the list of non found users.
    for mail in email_set:
        if mail not in risky_users_email_set:
            user = create_user(
                source=list_users_command.brand,
                instance=output.get("instance"),
                email_address=mail,
                additional_fields=additional_fields,
            )
            user["Status"] = "not found"
            users.append(user)
    return readable_outputs_list, users


def xdr_and_core_list_all_users(
    list_risky_users_commands: list[Command],
    list_users_command: Command,
    outputs_key_field: str,
    additional_fields: bool,
    list_non_risky_users: bool,
    email_list: List[str],
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list, users = run_list_risky_users_command(list_risky_users_commands, additional_fields, outputs_key_field)
    if list_non_risky_users:
        readable_outputs_list, users = run_list_users_command(
            list_users_command, additional_fields, outputs_key_field, email_list, users, readable_outputs_list
        )

    return readable_outputs_list, users


def azure_get_risky_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))

    account_outputs = []
    for output in entry_context:
        output_key = get_output_key("AzureRiskyUsers.RiskyUser", output)
        outputs = get_outputs(output_key, output)

        account_outputs.append(
            create_user(
                source=command.brand,
                id=outputs.get("id"),
                risk_level=outputs.pop("riskLevel", None),
                username=outputs.pop("id", None),
                instance=output.get("instance"),
                **outputs,
                additional_fields=additional_fields,
            )
        )

    return readable_outputs_list, account_outputs


def get_command_results(
    command: Command, cmd_to_run: Callable, modules: Modules, additional_fields: bool
) -> tuple[list[CommandResults], list[dict[str, Any]]] | None:
    if modules.is_brand_available(command) and is_valid_args(command):
        return cmd_to_run(command, additional_fields)
    return None


def get_data(
    modules: Modules,
    brand_name: str,
    command_name: str,
    arg_name: str,
    arg_value: str,
    cmd: Callable,
    additional_fields: bool,
) -> tuple[list[str], list[dict]]:
    get_user_command = Command(
        brand=brand_name,
        name=command_name,
        args={arg_name: arg_value, "using-brand": brand_name},
    )
    if modules.is_brand_available(get_user_command) and is_valid_args(get_user_command):
        demisto.debug(f"calling {command_name} command with brand {brand_name}")
        readable_outputs, outputs = cmd(get_user_command, additional_fields)
        for output in outputs:
            if set(output) == {"Source", "Brand", "Instance"}:  # contains only the source and brand keys
                output["Status"] = f"User not found - userId: {arg_value}."
            else:
                output["Status"] = "found"
        return readable_outputs, outputs
    return [], []


def get_core_and_xdr_data(
    modules: Modules,
    brand_name: str,
    first_command: str,
    second_command: str,
    user_names: List[str],
    additional_fields: bool,
    list_non_risky_users: bool = False,
    email_list: List[str] = [],
    outputs_key_field: str = "",
) -> tuple[list[CommandResults], list[dict[str, Any]]]:
    # prepare both commands
    first_commands = []
    for user_name in user_names:
        first_commands.append(
            Command(
                brand=brand_name,
                name=first_command,
                args={"user_id": user_name, "using-brand": brand_name},
            )
        )
        if auto_detect_indicator_type(user_name) == FeedIndicatorType.Email:
            email_list.append(user_name)
    second_command = Command(
        brand=brand_name,
        name=second_command,
        args={"using-brand": brand_name},
    )

    if (first_commands and modules.is_brand_available(first_commands[0]) and is_valid_args(first_commands[0])) or (
        email_list and modules.is_brand_available(second_command)
    ):
        demisto.debug(f"Starting execution flow for list-users for {brand_name}")
        readable_outputs, outputs = xdr_and_core_list_all_users(
            first_commands,
            second_command,
            outputs_key_field=outputs_key_field,
            additional_fields=additional_fields,
            list_non_risky_users=list_non_risky_users,
            email_list=email_list,
        )
        return readable_outputs, outputs
    return [], []


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_ids = argToList(args.get("user_id", []))
        users_names = argToList(args.get("user_name", []))
        users_emails = argToList(args.get("user_email", []))
        users_sid = argToList(args.get("user_sid", []))
        domain = args.get("domain", "")
        verbose = argToBoolean(args.get("verbose", False))
        brands_to_run = argToList(args.get("brands", []))
        additional_fields = argToBoolean(args.get("additional_fields") or False)
        modules = Modules(demisto.getModules(), brands_to_run)
        list_non_risky_users = argToBoolean(args.get("list_non_risky_users") or False)

        if domain and not users_names:
            raise ValueError("When specifying the domain argument, the user_name argument must also be provided.")
        if not any((users_ids, users_names, users_emails, users_sid)):
            raise ValueError(
                "At least one of the following arguments must be specified:" " user_id, user_name, user_email or users_sid."
            )

        command_results_list: list[CommandResults] = []
        users_outputs: list[dict] = []
        users_readables: list = []

        #################################
        ### Running for Usernames ###
        #################################
        for user_name in users_names:
            demisto.debug(f"Start getting user data for {user_name=}")
            if "\\" not in (user_name or ""):
                #################################
                ### Running for Active Directory Query v2 ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="Active Directory Query v2",
                    command_name="ad-get-user",
                    arg_name="username",
                    arg_value=user_name,
                    cmd=ad_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for Okta v2 ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="Okta v2",
                    command_name="okta-get-user",
                    arg_name="username",
                    arg_value=user_name,
                    cmd=okta_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for AWS - IAM ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="AWS - IAM",
                    command_name="aws-iam-get-user",
                    arg_name="userName",
                    arg_value=user_name,
                    cmd=aws_iam_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for Microsoft Graph User ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="Microsoft Graph User",
                    command_name="msgraph-user-get",
                    arg_name="user",
                    arg_value=user_name,
                    cmd=msgraph_user_get,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    for output in outputs:
                        if output.get("ID") and additional_fields:
                            msgraph_user_get_manager_command = Command(
                                brand="Microsoft Graph User",
                                name="msgraph-user-get-manager",
                                args={"user": user_name},
                            )
                            manager_output = msgraph_user_get_manager(msgraph_user_get_manager_command)
                            output["AdditionalFields"].update(manager_output)
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for Prismacloud v2 ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="PrismaCloud v2",
                    command_name="prisma-cloud-users-list",
                    arg_name="usernames",
                    arg_value=user_name,
                    cmd=prisma_cloud_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for Okta IAM ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="Okta IAM",
                    command_name="iam-get-user",
                    arg_name="user-profile",
                    arg_value=f'{{"login":"{user_name}"}}',
                    cmd=iam_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

                #################################
                ### Running for AWS-ILM ###
                #################################
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="AWS-ILM",
                    command_name="iam-get-user",
                    arg_name="user-profile",
                    arg_value=f'{{"login":"{user_name}"}}',
                    cmd=iam_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

            else:
                demisto.debug(f"Skipping commands that do not support domain in user_name: {user_name}")

            #################################
            ### Running for Active Directory Query v2 ###
            #################################
            if "\\" in (user_name or ""):
                readable_output, outputs = get_data(
                    modules=modules,
                    brand_name="Active Directory Query v2",
                    command_name="ad-get-user",
                    arg_name="username",
                    arg_value=user_name.split("\\")[1],
                    cmd=ad_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.extend(outputs)
                    users_readables.extend(readable_output)

        #################################
        ### Running for Users IDs ###
        #################################
        for user_id in users_ids:
            demisto.debug(f"Start getting user data for {user_id=}")

            #################################
            ### Running for Okta v2 ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Okta v2",
                command_name="okta-get-user",
                arg_name="userId",
                arg_value=user_id,
                cmd=okta_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for Microsoft Graph User ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Microsoft Graph User",
                command_name="msgraph-user-get",
                arg_name="user",
                arg_value=user_id,
                cmd=msgraph_user_get,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                for output in outputs:
                    if output.get("ID") and additional_fields:
                        msgraph_user_get_manager_command = Command(
                            brand="Microsoft Graph User",
                            name="msgraph-user-get-manager",
                            args={"user": user_id},
                        )
                        manager_output = msgraph_user_get_manager(msgraph_user_get_manager_command)
                        output["AdditionalFields"].update(manager_output)
                users_readables.extend(readable_output)
                users_outputs.extend(outputs)

            #################################
            ### Running for Azure Risky User ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="AzureRiskyUsers",
                command_name="azure-risky-user-get",
                arg_name="id",
                arg_value=user_id,
                cmd=azure_get_risky_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for Okta IAM ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Okta IAM",
                command_name="iam-get-user",
                arg_name="user-profile",
                arg_value=f'{{"id":"{user_id}"}}',
                cmd=iam_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for AWS-ILM ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="AWS-ILM",
                command_name="iam-get-user",
                arg_name="user-profile",
                arg_value=f'{{"id":"{user_id}"}}',
                cmd=iam_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for GSuiteAdmin ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="GSuiteAdmin",
                command_name="gsuite-user-get",
                arg_name="user",
                arg_value=user_id,
                cmd=gsuite_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

        #################################
        ### Running for Users SID ###
        #################################
        for user_sid in users_sid:
            demisto.debug(f"Start getting user data for {user_sid=}")

            #################################
            ### Running for Active Directory Query v2 ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Active Directory Query v2",
                command_name="ad-get-user",
                arg_name="custom-field-data",
                arg_value=user_sid,
                cmd=ad_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

        #################################
        ### Running for Users Emails ###
        #################################
        for user_email in users_emails:
            demisto.debug(f"Start getting user data for {user_email=}")

            #################################
            ### Running for Okta v2 ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Okta v2",
                command_name="okta-get-user",
                arg_name="userEmail",
                arg_value=user_email,
                cmd=okta_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for Active Directory Query v2 ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Active Directory Query v2",
                command_name="ad-get-user",
                arg_name="email",
                arg_value=user_email,
                cmd=ad_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for Okta IAM ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Okta IAM",
                command_name="iam-get-user",
                arg_name="user-profile",
                arg_value=f'{{"email":"{user_email}"}}',
                cmd=iam_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for AWS-ILM ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="AWS-ILM",
                command_name="iam-get-user",
                arg_name="user-profile",
                arg_value=f'{{"email":"{user_email}"}}',
                cmd=iam_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for GSuiteAdmin ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="GSuiteAdmin",
                command_name="gsuite-user-get",
                arg_name="user",
                arg_value=user_email,
                cmd=gsuite_get_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.extend(outputs)
                users_readables.extend(readable_output)

        if verbose:
            command_results_list.extend(users_readables)

        #################################
        ### Running for XDR ###
        #################################
        readable_output, outputs = get_core_and_xdr_data(  # type: ignore[assignment]
            modules=modules,
            brand_name="Cortex XDR - IR",
            first_command="xdr-list-risky-users",
            second_command="xdr-list-users",
            user_names=users_names,
            additional_fields=additional_fields,
            list_non_risky_users=list_non_risky_users,
            email_list=users_emails,
            outputs_key_field="PaloAltoNetworksXDR",
        )
        # we don't expect xdr-list-users to return readable outputs.
        if readable_output or outputs:
            users_outputs.extend(outputs)
            users_readables.extend(readable_output)

        #################################
        ### Running for Core ###
        #################################
        readable_output, outputs = get_core_and_xdr_data(  # type: ignore[assignment]
            modules=modules,
            brand_name="Cortex Core - IR",
            first_command="core-list-risky-users",
            second_command="core-list-users",
            user_names=users_names,
            additional_fields=additional_fields,
            list_non_risky_users=list_non_risky_users,
            email_list=users_emails,
            outputs_key_field="Core",
        )
        # we don't expect core-list-users to return readable outputs.
        if readable_output or outputs:
            users_outputs.extend(outputs)
            users_readables.extend(readable_output)

        command_results_list.append(
            CommandResults(
                outputs_prefix="UserData",
                outputs_key_field=["Username", "Instance"],
                outputs=users_outputs,
                readable_output=tableToMarkdown(
                    name="User(s) data",
                    t=users_outputs,
                    headers=["Source", "Instance", "ID", "Username", "Email", "Status"],
                    removeNull=False,
                ),
            )
        )
        return_results(command_results_list)

    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
