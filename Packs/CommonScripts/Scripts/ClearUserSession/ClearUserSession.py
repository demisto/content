import demistomock as demisto
from CommonServerPython import *

from typing import Any


OKTA_BRAND = "Okta v2"
MS_GRAPH_BRAND = "Microsoft Graph User"
DEFAULT_BRANDS = [OKTA_BRAND, MS_GRAPH_BRAND]
SYSTEM_USERS = {"administrator", "system"}
SUCCESS_MESSAGE = "User session was cleared."


class Command:
    def __init__(self, name: str, args: dict, brand: Optional[str] = None) -> None:
        """
        Initialize a Command object.

        Args:
            name (str): The name of the command.
            args (dict): A dictionary containing the command arguments.
            brand (str, optional): The brand associated with the command. Default is None.
        """
        self.brand = argToList(brand) or DEFAULT_BRANDS
        self.name = name
        self.args = args

    def is_valid_args(self) -> bool:
        """
        Validate if the command has valid arguments. If the command has no arguments, it is considered valid.

        Returns:
            bool: True if the command has valid arguments, False otherwise.
        """
        is_valid = any(self.args.values()) if self.args else True
        if not is_valid:
            demisto.debug(f"Skipping command '{self.name}' since no required arguments were provided.")
        return is_valid


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
        command = f'{command_name} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
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


def remove_system_user(users_names: list[str]) -> tuple[list, list]:
    """
    Filters out system users from the provided list of user names and returns the remaining users along with status details.

    Args:
        users_names (list[str]): A list of user names to be processed.

    Returns:
        tuple: A tuple containing:
            - list: A list of user names that are not system users.
            - dict: A dictionary containing information about users that were identified as system users,
            including their status and messages.
    """
    outputs = []
    filtered_users = []
    for user in users_names:
        if user in SYSTEM_USERS:
            demisto.debug(f"Skipping user: '{user}' is a system user.")
            outputs.append({
                "UserName": user,
                "Result": "Failed",
                "Message": "Skipping session clearing: User is a system user.",
                "Source": [],
            })
        else:
            filtered_users.append(user)

    return filtered_users, outputs


def extract_usernames_with_ids(context: dict, output_key: str) -> dict:
    """
    Extracts a mapping of usernames to their associated ID information from the given context.

    This function retrieves a list of users from the context using the specified output key.
    It then constructs a dictionary where each username is mapped to its corresponding list of ID information.

    Args:
        context (dict): The context dictionary containing user data.
        output_key (str): The key to access the list of users in the context.

    Returns:
        dict: A dictionary mapping usernames (str) to their associated ID information (list[dict]).
              For example:
              {
                  "user1@example.com": [{"Source": "Okta v2", "Value": "1234"}],
                  "user2@example.com": [{"Source": "Microsoft Graph User", "Value": "5678"}]
              }
    """
    user_id_mapping = {}
    users = context.get(output_key, [])
    for user in users:
        username = user.get("Username")
        id_info = user.get("ID", [])
        if username and id_info:
            user_id_mapping[username] = id_info

    return user_id_mapping


def get_user_data(command: Command) -> tuple[list[CommandResults], dict]:
    """
    Retrieves user data based on the specified command and returns the results.

    Args:
        command (Command): The command object containing the name and arguments for retrieving user data.

    Returns:
        tuple: A tuple containing:
            - list[CommandResults]: A list of CommandResults objects with human-readable outputs and any errors encountered.
            - dict: A dictionary containing extracted user identifiers and their associated information.
    """
    readable_outputs_list = []

    entry_context, human_readable, readable_errors = run_execute_command(
        command.name, command.args
    )

    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )

    output_key = get_output_key("Account", entry_context[-1])
    id_info = extract_usernames_with_ids(entry_context[-1], output_key)

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


def clear_user_sessions(command: Command) -> tuple[list[CommandResults], str, Optional[str]]:
    """
    Clears user sessions based on the specified command and returns the results.

    Args:
        command (Command): The command object containing the name and arguments for session clearance.

    Returns:
        tuple: A tuple containing:
            - list[CommandResults]: A list of CommandResults objects with the human-readable outputs and errors.
            - str: A summary of the human-readable results of the session clearance.
            - Optional[str]: An error message if any error occurs during execution, or None if there are no errors.
    """
    readable_outputs_list = []

    _, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(
        prepare_human_readable(command.name, command.args, human_readable)
    )
    error_message = readable_errors[0].readable_output if readable_errors else ""
    return readable_outputs_list, human_readable, error_message


def create_readable_output(outputs: list):
    """
    Generates a markdown table summarizing user session status.

    This function processes a dictionary of user session results and creates a
    markdown-formatted table to display the status, brand information, and any
    associated messages for each user.

    Args:
        outputs (dict): A dictionary where each key is a username and the value is
            another dictionary containing:
            - "Result" (str): The session result (e.g., Success, Failure).
            - "Source" (str, optional): The brand(s) associated with the session.
            - "Message" (str): A detailed message related to the session status.

    Returns:
        str: A markdown-formatted table summarizing user session statuses.
    """
    data_users_list = [
        {
            "User Name": details["UserName"],
            "Result": details["Result"],
            "Source": ", ".join(details.get("Source", [])),
            "Message": details["Message"],
        }
        for details in outputs
    ]

    readable_output = tableToMarkdown(
        name="User(s) Session Status",
        t=data_users_list,
        headers=["User Name", "Result", "Source", "Message"],
        removeNull=True,
    )
    return readable_output


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_names = argToList(args.get("user_name", ""))
        verbose = argToBoolean(args.get("verbose", False))
        brands = args.get("brands", "")

        outputs: list = []
        results_for_verbose: list[CommandResults] = []

        filtered_users_names, outputs = remove_system_user(users_names)

        # get ID for users
        get_user_data_command = Command(
            name="get-user-data",
            args={"user_name": filtered_users_names, "brands": brands},
        )

        if filtered_users_names:
            readable_outputs, users_ids = get_user_data(get_user_data_command)
            results_for_verbose.extend(readable_outputs)
        else:
            users_ids = {}
            demisto.debug(f"{filtered_users_names=} -> {users_ids=}")

        for user_name in filtered_users_names:
            #################################
            ### Running for a single user ###
            #################################

            demisto.debug(f"Start getting user account data for user: {user_name=}")

            user_output = {
                "UserName": "",
                "Result": "",
                "Source": [],
                "Message": "",
            }
            if user_name not in users_ids:
                user_output["Result"] = "Failed"
                user_output["Message"] = "Username not found or no integration configured."
                user_output["UserName"] = user_name
                outputs.append(user_output)
                continue

            brands_succeeded: list = []
            brands_failed: list = []
            failed_message = ""

            # Okta v2
            if okta_v2_id := get_user_id(users_ids, OKTA_BRAND, user_name):
                okta_clear_user_sessions_command = Command(
                    name="okta-clear-user-sessions",
                    args={"userId": okta_v2_id},
                    brand=OKTA_BRAND,
                )
                if okta_clear_user_sessions_command.is_valid_args():
                    readable_outputs, _, error_message = clear_user_sessions(okta_clear_user_sessions_command)
                    results_for_verbose.extend(readable_outputs)
                    if not error_message:
                        brands_succeeded.append(OKTA_BRAND)
                    else:
                        failed_message += f"Okta v2: {error_message.lstrip('#').strip()}"
                        demisto.debug(f"Failed to clear sessions for Okta user with ID {okta_v2_id}. "
                                      f"Error message: {error_message}. Response details: {readable_outputs}.")
                        brands_failed.append(OKTA_BRAND)

            # Microsoft Graph User
            if microsoft_graph_id := get_user_id(users_ids, brand_name=MS_GRAPH_BRAND, user_name=user_name):
                msgraph_user_session_revoke_command = Command(
                    name="msgraph-user-session-revoke",
                    args={"user": microsoft_graph_id},
                    brand=MS_GRAPH_BRAND,
                )
                if msgraph_user_session_revoke_command.is_valid_args():
                    readable_outputs, human_readable, _ = clear_user_sessions(msgraph_user_session_revoke_command)
                    results_for_verbose.extend(readable_outputs)
                    if "successfully" in human_readable:
                        brands_succeeded.append(MS_GRAPH_BRAND)
                    else:
                        brands_failed.append(MS_GRAPH_BRAND)
                        failed_message += f"\nMG User: {human_readable.lstrip('#').strip()}"
                        demisto.debug(f"Failed to clear sessions for Microsoft Graph user with ID {microsoft_graph_id}. "
                                      f"Response details: {readable_outputs}")

            if brands_succeeded:
                user_output["Result"] = "Success"
                user_output["Source"] = brands_succeeded
                user_output["Message"] = SUCCESS_MESSAGE
            else:
                user_output["Result"] = "Failed"
                user_output["Source"] = brands_failed
                user_output["Message"] = failed_message

            user_output["UserName"] = user_name
            outputs.append(user_output)

        ##############################
        ### Complete for all users ###
        ##############################

        command_results_list: list[CommandResults] = []
        if verbose:
            command_results_list.extend(results_for_verbose)

        command_results_list.append(
            CommandResults(
                readable_output=create_readable_output(outputs),
                outputs=outputs,
                outputs_prefix="SessionClearResults",
            )
        )

        return_results(command_results_list)
    except Exception as e:
        return_error(f"Failed to execute clear-user-session. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
