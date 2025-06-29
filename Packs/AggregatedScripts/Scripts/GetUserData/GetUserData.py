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
        dict[str, Any]: A dictionary containing the non-empty user information.
    """
    user = {
        "Source": source,
        "ID": id,
        "Username": username,
        "Email": email_address,
        "RiskLevel": risk_level,
    }
    if additional_fields:
        user["AdditionalFields"] = kwargs  # type: ignore
    user = remove_empty_elements(user)

    return user


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
        entry_context_list.append(entry.get("EntryContext", {}))
        if is_error(entry):
            errors_command_results.extend(prepare_human_readable(command_name, args, get_error(entry), is_error=True))
        else:
            human_readable_list.append(entry.get("HumanReadable") or "")
    human_readable = "\n".join(human_readable_list)
    demisto.debug(f"Finished executing command: {command_name}")
    return entry_context_list, human_readable, errors_command_results


def ad_get_user(command: Command, additional_fields=False) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []
    command.args["attributes"] = demisto.args().get("attributes")
    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)

    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("ActiveDirectory.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    username = outputs.pop("name", None)
    if isinstance(username, list) and len(username) == 1:
        username = username[0]
    mail = outputs.pop("mail", None)
    if isinstance(mail, list) and len(mail) == 1:
        mail = mail[0]
    for k, v in outputs.items():
        if isinstance(v, list) and len(v) == 1:
            outputs[k] = v[0]
    user_output = create_user(
        source=command.brand,
        username=username,
        email_address=mail,
        additional_fields=additional_fields,
        **outputs,
    )

    return readable_outputs_list, user_output


def okta_get_user(command: Command, additional_fields=False) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    user_output = create_user(
        source=command.brand,
        id=outputs.pop("ID", None),
        username=outputs.pop("Username", None),
        email_address=outputs.pop("Email", None),
        additional_fields=additional_fields,
        **outputs,
    )

    return readable_outputs_list, user_output


def aws_iam_get_user(command: Command, additional_fields: bool) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("AWS.IAM.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    user_output = create_user(
        source=command.brand,
        id=outputs.pop("UserId", None),
        username=outputs.pop("UserName", None),
        additional_fields=additional_fields,
        **outputs,
    )

    return readable_outputs_list, user_output


def prisma_cloud_get_user(command: Command, additional_fields: bool) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("PrismaCloud.Users", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    user_output = create_user(
        source=command.brand,
        username=outputs.pop("username", None),
        email_address=outputs.pop("email", None),
        additional_fields=additional_fields,
        **outputs,
    )

    return readable_outputs_list, user_output


def msgraph_user_get(command: Command, additional_fields: bool) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("Account", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    user_output = create_user(
        source=command.brand,
        id=outputs.pop("ID", None),
        username=outputs.pop("Username", None),
        email_address=outputs.pop("Email", {}).get("Address", None),
        additional_fields=additional_fields,
        **outputs,
    )

    return readable_outputs_list, user_output


def msgraph_user_get_manager(command: Command, additional_fields: bool) -> dict[str, Any]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("MSGraphUserManager", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])
    manager_output = {
        "manager_display_name": outputs.get("Manager", {}).get("DisplayName"),
        "manager_email": outputs.get("Manager", {}).get("Mail"),
    }

    return manager_output


def xdr_list_risky_users(
    command: Command,
    outputs_key_field: str,
    additional_fields: bool,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key(f"{outputs_key_field}.RiskyUser", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    account_output = create_user(
        source=command.brand,
        id=outputs.get("id"),
        risk_level=outputs.pop("risk_level", None),
        username=outputs.pop("id", None),
        **outputs,
        additional_fields=additional_fields,
    )

    return readable_outputs_list, account_output


def xdr_get_risky_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], dict[str, Any]]:
    return xdr_list_risky_users(command, outputs_key_field="PaloAltoNetworksXDR", additional_fields=additional_fields)


def core_get_risky_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], dict[str, Any]]:
    return xdr_list_risky_users(command, outputs_key_field="Core", additional_fields=additional_fields)


def azure_get_risky_user(
    command: Command,
    additional_fields: bool,
) -> tuple[list[CommandResults], dict[str, Any]]:
    readable_outputs_list = []
    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    output_key = get_output_key("AzureRiskyUsers.RiskyUser", entry_context[0])
    outputs = get_outputs(output_key, entry_context[0])

    account_output = create_user(
        source=command.brand,
        id=outputs.get("id"),
        risk_level=outputs.pop("riskLevel", None),
        username=outputs.pop("id", None),
        **outputs,
        additional_fields=additional_fields,
    )

    return readable_outputs_list, account_output


def get_command_results(
    command: Command, cmd_to_run: Callable, modules: Modules, additional_fields: bool
) -> tuple[list[CommandResults], dict[str, Any]] | None:
    if modules.is_brand_available(command) and is_valid_args(command):
        return cmd_to_run(command, additional_fields)
    return None


def get_data(
    modules: Modules, brand_name: str, command_name: str, arg_name: str, arg_value: str, cmd: Callable, additional_fields: bool
):
    get_user_command = Command(
        brand=brand_name,
        name=command_name,
        args={arg_name: arg_value},
    )
    if modules.is_brand_available(get_user_command) and is_valid_args(get_user_command):
        demisto.debug(f"calling {command_name} command with brand {brand_name}")
        readable_outputs, outputs = cmd(get_user_command, additional_fields)
        if len(outputs) == 1:  # contains only the source key
            outputs["Status"] = f"User not found - userId: {arg_value}."
        else:
            outputs["Status"] = "found"
        return readable_outputs, outputs
    return [], {}


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
        additional_fields = argToBoolean(args.get("additional_fields") or False)
        modules = Modules(demisto.getModules(), brands_to_run)

        if domain and not users_names:
            raise ValueError("When specifying the domain argument, the user_name argument must also be provided.")
        if not any((users_ids, users_names, users_emails)):
            raise ValueError("At least one of the following arguments must be specified: user_id, user_name or user_email.")

        command_results_list: list[CommandResults] = []
        user_outputs_list: list[dict[str, Any]] = []
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
                    arg_name="name",
                    arg_value=user_name,
                    cmd=ad_get_user,
                    additional_fields=additional_fields,
                )
                if readable_output and outputs:
                    users_outputs.append(outputs)
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
                    users_outputs.append(outputs)
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
                    users_outputs.append(outputs)
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
                    users_readables.extend(readable_output)
                    if outputs.get("id") and additional_fields:
                        msgraph_user_get_manager_command = Command(
                            brand="Microsoft Graph User",
                            name="msgraph-user-get-manager",
                            args={"user": user_name},
                        )
                        manager_output = msgraph_user_get_manager(msgraph_user_get_manager_command, additional_fields)
                        outputs["AdditionalFields"].extend(manager_output)
                    users_outputs.append(outputs)

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
                    users_outputs.append(outputs)
                    users_readables.extend(readable_output)

            else:
                demisto.debug(f"Skipping commands that do not support domain in user_name: {user_name}")

            #################################
            ### Running for Cortex XDR - IR (XDR) ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Cortex XDR - IR",
                command_name="xdr-list-risky-users",
                arg_name="user_id",
                arg_value=user_name,
                cmd=xdr_get_risky_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.append(outputs)
                users_readables.extend(readable_output)

            #################################
            ### Running for Cortex XDR - IR (Core) ###
            #################################
            readable_output, outputs = get_data(
                modules=modules,
                brand_name="Cortex Core - IR",
                command_name="core-list-risky-users",
                arg_name="user_id",
                arg_value=user_name,
                cmd=core_get_risky_user,
                additional_fields=additional_fields,
            )
            if readable_output and outputs:
                users_outputs.append(outputs)
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
                users_outputs.append(outputs)
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
                users_readables.extend(readable_output)
                if outputs.get("id") and additional_fields:
                    msgraph_user_get_manager_command = Command(
                        brand="Microsoft Graph User",
                        name="msgraph-user-get-manager",
                        args={"user": user_id},
                    )
                    manager_output = msgraph_user_get_manager(msgraph_user_get_manager_command, additional_fields)
                    outputs["AdditionalFields"].extend(manager_output)
                users_outputs.append(outputs)

            #################################
            ### Running for Azure Risky Users	 ###
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
                users_outputs.append(outputs)
                users_readables.extend(readable_output)

        #################################
        ### Running for Users Emails ###
        #################################
        for user_email in users_emails:
            demisto.debug(f"Start getting user data for {user_email=}")

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
                users_outputs.append(outputs)
                users_readables.extend(readable_output)

        if verbose:
            command_results_list.extend(users_readables)

        demisto.debug(f"users list: {user_outputs_list}")
        command_results_list.append(
            CommandResults(
                outputs_prefix="UserData",
                # because if source1 and source2 got the same username, we don't want any of the sources to overrides the other
                outputs_key_field=["Username", "Source"],
                outputs=users_outputs,
                readable_output=tableToMarkdown(
                    name="User(s) data",
                    t=users_outputs,
                    headers=["Source", "ID", "Username", "Email", "Status"],
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
