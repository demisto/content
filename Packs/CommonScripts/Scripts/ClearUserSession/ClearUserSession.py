import demistomock as demisto
from CommonServerPython import *

from typing import Any
# print(f"{demisto.args()=}")


DEFAULT_BRANDS = ['Okta v2', 'Microsoft Graph User']


class Command:
    def __init__(self, name: str, args: dict, brand: Optional[str] = None) -> None:
        """
        Initialize a Command object.

        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str, optional): The brand associated with the command. Default is None.
        """
        self.brand = brand
        self.name = name
        self.args = args


def is_valid_args(command: Command) -> bool:
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


def prepare_human_readable(  # for debug
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
    # print(res)
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


def remove_system_user(users_names: list[str]) -> tuple[list, dict]:
    system_users = {"administrator", "system"}
    data_user = {}
    filtered_users = []
    for user in users_names:
        if user in system_users:
            demisto.debug(f"Skipping user: '{user}' is a system user.")
            data_user[user] = {
                "Result": "Failed",
                "Message": "Unable to clear system user",
                "Brands": ""
            }
        else:
            filtered_users.append(user)

    return filtered_users, data_user


def extract_usernames_with_ids(data: dict, output_key: str) -> dict:
    user_id_mapping = {}
    users = data.get(output_key, [])
    for user in users:
        username = user.get("Username")
        id_info = user.get("ID", [])
        if username and id_info:
            user_id_mapping[username] = id_info

    return user_id_mapping


def get_user_data(command: Command) -> tuple[list[CommandResults], dict]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    output_key = get_output_key("Account", entry_context[0])
    id_info = extract_usernames_with_ids(entry_context[0], output_key)

    return readable_outputs_list, id_info


def get_user_id(users_ids: dict, brand_name: str, user_name: str) -> str:
    """
    Returns the ID from a list of dictionaries where the 'Source' matches the specified source name.

    Args:
        data (list[dict]): A list of dictionaries containing 'Source' and 'Value' keys.
        brand_name (str): The source name to look for.

    Returns:
        str: The ID associated with the specified source, or an empty string if not found.
    """
    ids_info = users_ids.get(user_name, [])
    for item in ids_info:
        if brand_name == item.get("Source", ""):
            return item.get("Value", "")

    demisto.debug(
        f"Skipping user session clearance for user '{user_name}' and brand '{brand_name}' - user name not found."
    )
    return ""


def okta_clear_user_sessions(
    command: Command,
) -> tuple[list[CommandResults], str]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    return readable_outputs_list, human_readable


def msgraph_user_session_revoke(
    command: Command,
) -> tuple[list[CommandResults], str]:
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    return readable_outputs_list, human_readable


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_names = argToList(args.get("user_name", []))
        verbose = argToBoolean(args.get("verbose", False))
        brands = argToList(args.get("brands", [])) or DEFAULT_BRANDS

        command_results_list: list[CommandResults] = []

        users_names, outputs = remove_system_user(users_names)

        if users_names:
            get_user_data_command = Command(
                name="get-user-data",
                args={"user_name": users_names, "brands": brands, 'verbose': verbose},
            )
            readable_outputs, users_ids = get_user_data(get_user_data_command)

            if verbose:
                command_results_list.extend(readable_outputs)

            for user_name in users_names:
                #################################
                ### Running for a single user ###
                #################################

                demisto.debug(f"Start getting user account data for user: {user_name=}")

                user_output = {
                    "Entity": user_name,
                    "Result": "",
                    "Brands": "",
                    "Message": ""
                }
                readable_outputs_single_user = []

                if user_name not in users_ids:
                    user_output["Result"] = "Failed"
                    user_output["Message"] = "User name not found"
                    outputs[user_name] = user_output
                    continue

                # Okta v2
                if okta_v2_id := get_user_id(users_ids, 'Okta v2', user_name):
                    okta_clear_user_sessions_command = Command(
                        name="okta-clear-user-sessions",
                        args={"userId": okta_v2_id},
                        brand="Okta v2",
                    )
                    if is_valid_args(okta_clear_user_sessions_command):
                        readable_outputs, human_readable = okta_clear_user_sessions(okta_clear_user_sessions_command)

                        readable_outputs_single_user.extend(readable_outputs)
                        user_output["Result"] = "Success" if "User session was cleared" in human_readable else "Failed"
                        user_output["Message"] = human_readable
                        user_output["Brands"] = "Okta v2"

                # Microsoft Graph User
                if microsoft_graph_id := get_user_id(users_ids, brand_name='Microsoft Graph User', user_name=user_name):
                    msgraph_user_session_revoke_command = Command(
                        name="msgraph-user-session-revoke",
                        args={"user": microsoft_graph_id},
                        brand="Microsoft Graph User",
                    )
                    if is_valid_args(msgraph_user_session_revoke_command):
                        readable_outputs, human_readable = msgraph_user_session_revoke(msgraph_user_session_revoke_command)

                        readable_outputs_single_user.extend(readable_outputs)
                        user_output["Result"] = "Success" if "successfully" in human_readable else "Failed"
                        user_output["Message"] = human_readable
                        user_output["Brands"] = "Microsoft Graph User"

                outputs[user_name] = user_output

                if verbose:
                    command_results_list.extend(readable_outputs_single_user)

        ##############################
        ### Complete for all users ###
        ##############################
        data_users_list = [
            {
                "Entity": username,
                "Result": details["Result"],
                "Brands": details.get("Brands", ""),
                "Message": details["Message"]
            }
            for username, details in outputs.items()
        ]

        readable_output = tableToMarkdown(
            name="Users",
            t=data_users_list,
            headers=["Entity", "Result", "Brands", "Message"],
            removeNull=True
        )

        command_results_list.append(CommandResults(readable_output=readable_output,
                                    outputs=outputs, outputs_prefix='ClearUserSession'))

        return_results(command_results_list)
    except Exception as e:
        return_error(f"Failed to execute clear-user-session. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
