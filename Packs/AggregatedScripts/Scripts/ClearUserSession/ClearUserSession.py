import demistomock as demisto
from CommonServerPython import *
from collections import defaultdict
import re
from typing import Any

OKTA_BRAND = "Okta v2"
MS_GRAPH_BRAND = "Microsoft Graph User"
GSUITE_BRAND = "GSuiteAdmin"
DEFAULT_BRANDS = [OKTA_BRAND, MS_GRAPH_BRAND, GSUITE_BRAND]
SYSTEM_USERS = {"administrator", "system"}
COMMANDS_BY_BRAND = {
    OKTA_BRAND: "okta-clear-user-sessions",
    MS_GRAPH_BRAND: "msgraph-user-session-revoke",
    GSUITE_BRAND: "gsuite-user-signout",
}
ARG_NAME_BY_BRAND = {OKTA_BRAND: "userId", MS_GRAPH_BRAND: "user", GSUITE_BRAND: "user_key"}
USER_NOT_FOUND_ERROR_TYPE = "NOT_FOUND"
AUTH_AUTHZ_ERROR_TYPE = "AUTH_AUTHZ"
GENERAL_ERROR_TYPE = "GENERAL_ERROR"


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
            result.append(CommandResults(readable_output=result_message, mark_as_note=True))
        else:
            result_message = human_readable
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
            "UserData(val.ID == obj.ID)": [
                {
                    "Username": "john.doe",
                    "Email": "john.doe@example.com",
                    "DisplayName": "John Doe"
                }
            ]
        }
        output_key = "UserData"
        result = get_outputs(output_key, raw_context)
        # result will be: "UserData(val.Username == obj.Username)"
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
        if is_error_enhanced(entry):
            errors_command_results.extend(prepare_human_readable(command_name, args, get_error_enhanced(entry), is_error=True))
        else:
            human_readable_list.append(entry.get("HumanReadable") or "")
    human_readable = "\n".join(human_readable_list)
    demisto.debug(f"Finished executing command: {command_name}")
    return entry_context_list, human_readable, errors_command_results


def remove_system_user(users_names: list[str], brands: list[str]) -> tuple[list, list]:
    """
    Filters out system users from the provided list of user names and returns the remaining users along with status details.

    Args:
        users_names (list[str]): A list of user names to be processed.
        brands (list[str]): A list of brands to check.

    Returns:
        tuple: A tuple containing:
            - list: A list of user names that are not system users.
            - dict: A list of dictionaries containing information about users that were identified as system users,
            including their status, brand and messages.
    """
    outputs = []
    filtered_users = []
    for user in users_names:
        if user in SYSTEM_USERS:
            demisto.debug(f"Skipping user: '{user}' is a system user.")
            for brand in brands:
                outputs.append(
                    {
                        "Message": "Skipping session clearing: User is a system user.",
                        "Result": "Failed",
                        "Brand": brand,
                        "UserName": user,
                    }
                )
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
    user_id_mapping = defaultdict(list)
    users = context.get(output_key, [])
    for user in users:
        if user.get("Status") == "found":
            username = user.get("Username", "")
            id_info = user.get("ID", "")
            source = user.get("Source", "")
            user_id_mapping[username].append({"Source": source, "Value": id_info})
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

    entry_context, human_readable, readable_errors = run_execute_command(command.name, command.args)
    readable_outputs_list.extend(readable_errors)
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    id_info = {}

    for entry in entry_context:
        if entry:
            output_key = get_output_key("UserData", entry)
            id_info.update(extract_usernames_with_ids(entry, output_key))

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

    demisto.debug(f"Skipping user session clearance for user '{user_name}' and brand '{brand_name}' - user name not found.")
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
    readable_outputs_list.extend(prepare_human_readable(command.name, command.args, human_readable))
    error_message = readable_errors[0].readable_output if readable_errors else ""

    return readable_outputs_list, human_readable, error_message


def create_readable_output(outputs: list):
    data_users_list = [
        {
            "UserId": details.get("UserId"),
            "UserName": details.get("UserName"),
            "Message": details["Message"],
            "Result": details["Result"],
            "Brand": details["Brand"],
        }
        for details in outputs
    ]
    """
    Generates a markdown table summarizing user session status.

    This function processes a dictionary of user session results and creates a
    markdown-formatted table to display the status, brand information, and any
    associated messages for each user.

    Args:
        outputs (dict): A dictionary where each key is a username and the value is
            another dictionary containing:
            - "UserId" (str): The user id a session cleared for.
            - "Message" (str): A detailed message related to the session status.
            - "Result" (str): The session result (e.g., Success, Failure).
            - "Brand" (str): The brand associated with the session.


    Returns:
        str: A markdown-formatted table summarizing user session statuses.
    """

    readable_output = tableToMarkdown(
        name="User(s) Session Status",
        t=data_users_list,
        headers=["UserId", "UserName", "Message", "Result", "Brand"],
        removeNull=True,
    )

    return readable_output


def is_not_found_error(content_lower: str) -> bool:
    """
    Checks for patterns indicating a user, account, or session was not found.
    """

    not_found_patterns = [
        r".*404.*",  # Matches any string containing "404"
        r".*resource\s+not\s+found.*",  # Matches any string containing "resource not found"
        r".*user\s+.*?\s+does\s+not\s+exist",
        r".*user\s+.*?\s+not\s+found",
        r".*user\s+.*?\s+is\s+invalid",
        r".*could\s+not\s+find\s+user\s+.*",
        r".*no\s+user\s+found\s+.*",
        r".*invalid\s+user\s+.*",
        r".*user\s+.*?\s+lookup\s+failed",
        r".*username\s+.*?\s+not\s+found",
        r".*user\s+id\s+.*?\s+not\s+found",
        r".*session\s+.*\s+not\s+found",
        r".*account\s+.*\s+not\s+found",
    ]
    return any(re.search(pattern, content_lower) for pattern in not_found_patterns)


def is_auth_authz_error(content_lower: str) -> bool:
    """
    Checks for patterns indicating authentication or authorization failure (access, permission, credentials).
    """
    auth_authz_patterns = [
        # Auth/Authz Regex Patterns
        r".*access\s+denied\s+.*",  # "Access denied for user <id>"
        r".*permission\s+denied\s+.*",  # "Permission denied for <user>"
        r".*unauthorized\s+.*",  # "Unauthorized access for <user>"
        r".*authentication\s+failed\s+.*",  # "Authentication failed for <user>"
        r".*forbidden\s+.*",  # "Forbidden access for <user>"
        r".*invalid\s+credentials\s+.*",  # "Invalid credentials for <user>"
        r".*session\s+.*\s+expired",  # "Session <id> expired"
        r".*session\s+.*\s+invalid",  # "Session <id> invalid"
        r".*\s+does\s+not\s+have\s+.*\s+permission",  # "<user> does not have <action> permission"
        r".*account\s+.*\s+disabled",  # "Account <id> disabled"
        r".*account\s+.*\s+suspended",  # "Account <id> suspended"
        # Simple string indicators that are NOT covered by the regex above (e.g., a pure single word)
        r"access denied",  # Added as a simple match in case it's not followed by dynamic content
        r"permission denied",
        r"unauthorized",
        r"authentication failed",
        r"forbidden",
        r"invalid credentials",
    ]

    return any(re.search(pattern, content_lower) for pattern in auth_authz_patterns)


def is_general_error(content_lower: str) -> bool:
    """
    Checks for general error, exception, or bad/invalid request patterns.
    """
    general_patterns = [
        # General Error Regex Patterns
        r".*bad\s+request\s+.*",  # "Bad request for user <id>"
        r".*invalid\s+request\s+.*",  # "Invalid request for <user>"
        r".*failed\s+to\s+.*\s+user",  # "Failed to find user", "Failed to authenticate user"
        r".*error\s*:\s*.*",  # "error: user related message"
        r".*exception\s*:\s*.*",  # "exception: user related message"
        r".*unable\s+to\s+.*\s+user",  # "Unable to find user", "Unable to authenticate user"
        # Simple string indicators (must not duplicate those in Auth/Authz)
        r"error:",
        r"failed:",
        r"exception:",
        r"bad request",
        r"invalid request",
    ]

    return any(re.search(pattern, content_lower) for pattern in general_patterns)


def is_error_enhanced(entry: dict) -> bool:
    """
    Enhanced error detection that checks both the Type field and Content field.

    Args:
        entry (dict): The entry dictionary to check for errors.

    Returns:
        bool: True if the entry indicates an error, False otherwise.
    """
    # First check using the standard is_error function
    if is_error(entry):
        return True

    if (content := entry.get("Contents")) and isinstance(entry.get("Contents"), str):
        content_lower = str(content).lower()
        return is_not_found_error(content_lower) or is_auth_authz_error(content_lower) or is_general_error(content_lower)
    return False


def get_error_enhanced(entry: dict) -> str:
    """
    Enhanced error message extraction that tries the standard get_error function first,
    then falls back to extracting error information from the Content field.

    Args:
        entry (dict): The entry dictionary to extract error message from.

    Returns:
        str: The error message from the entry.

    Raises:
        ValueError: If no error is detected in the entry.
    """
    if not is_error_enhanced(entry):
        # If no error is detected, raise the original ValueError
        raise ValueError("execute_command result has no error entry. before using get_error_enhanced use is_error_enhanced")

    content = entry.get("Contents")
    if not isinstance(content, str):
        return f"Unknown error occurred: {content}"

    content_lower = entry.get("Contents").lower()
    # 1. Check for Not Found errors first, as they are very specific
    if is_not_found_error(content_lower):
        return "User not found."

    # 2. Check for Authentication/Authorization errors next
    if is_auth_authz_error(content_lower):
        return "Authentication failed."

    # 3. Resolve to general error
    return f"Unknown error occurred: {content}"


def run_command(
    user_id: str,
    results_for_verbose: list[CommandResults],
    brand: str,
    user_name: Optional[str] = None,
) -> tuple[str, str, str]:
    clear_user_sessions_command = Command(
        name=COMMANDS_BY_BRAND[brand],
        args={ARG_NAME_BY_BRAND[brand]: user_id},
        brand=brand,
    )
    if not clear_user_sessions_command.is_valid_args():
        return brand, "Failed", "Missing arguments"
    readable_outputs, _, error_message = clear_user_sessions(clear_user_sessions_command)
    results_for_verbose.extend(readable_outputs)

    if not error_message:
        return brand, "Success", f"User session was cleared for {user_name or user_id}"

    failed_message = f"{error_message.lstrip('#').strip()}"
    demisto.debug(
        f"Failed to clear sessions for {brand} user with ID {user_id}. "
        f"Error message: {error_message}. Response details: {readable_outputs}."
    )
    return brand, "Failed", failed_message


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_names = argToList(args.get("user_name", ""))
        user_ids_arg = argToList(args.get("user_id", ""))
        verbose = argToBoolean(args.get("verbose", False))
        brands = argToList(args.get("brands", DEFAULT_BRANDS))

        results_for_verbose: list[CommandResults] = []
        filtered_users_names, outputs = remove_system_user(users_names, brands)

        # Step 1: Get user IDs for usernames if any usernames provided
        users_ids: dict[str, list] = {}
        if filtered_users_names:
            get_user_data_command = Command(
                name="get-user-data",
                args={"user_name": filtered_users_names, "brands": brands},
            )
            readable_outputs, users_ids = get_user_data(get_user_data_command)
            results_for_verbose.extend(readable_outputs)

        demisto.debug(f"{filtered_users_names=} -> {users_ids=}")

        # Step 2: Create mapping of (user_id, brand) -> username
        # This handles cases where same user_id exists across brands with different usernames
        user_id_brand_to_username = {}
        processed_user_ids = set()

        # Add user_ids provided directly (no username, applies to all brands)
        for user_id in user_ids_arg:
            processed_user_ids.add(user_id)
            for brand in brands:
                user_id_brand_to_username[(user_id, brand)] = ""

        # Add user_ids from translated usernames
        for user_name in filtered_users_names:
            for brand in brands:
                user_id = get_user_id(users_ids, brand, user_name)
                if user_id:
                    # Only add if this (user_id, brand) combination hasn't been processed
                    if (user_id, brand) not in user_id_brand_to_username:
                        user_id_brand_to_username[(user_id, brand)] = user_name
                        processed_user_ids.add(user_id)
                else:
                    outputs.append(
                        {
                            "Message": "User not found or no integration configured.",
                            "Result": "Failed",
                            "Brand": brand,
                            "UserId": "",
                            "UserName": user_name,
                        }
                    )

        # Step 3: Process each unique (user_id, brand) combination
        user_results: dict[str, list] = {}  # Track results per user_id to group output

        for (user_id, brand), associated_username in user_id_brand_to_username.items():
            if brand not in brands:
                continue  # Skip brands not requested

            if user_id not in user_results:
                user_results[user_id] = []

            # Use the user_id directly since we already have the brand-specific mapping
            clear_session_results = run_command(user_id, results_for_verbose, brand, associated_username)

            user_results[user_id].append(clear_session_results)

        # Step 4: Generate outputs from collected results
        for user_id, clear_session_results in user_results.items():
            for brand, result, message in clear_session_results:
                # Find the username for this user_id and brand combination
                associated_username = user_id_brand_to_username.get((user_id, brand), "")

                user_output = {
                    "Message": message,
                    "Result": result,
                    "Brand": brand,
                    "UserId": user_id,
                    "UserName": associated_username,
                }
                outputs.append(user_output)

        ##############################
        ### Complete for all users ###
        ##############################

        if verbose:
            command_results_list: list[CommandResults] = []
            command_results_list.extend(results_for_verbose)
        else:
            command_results_list: list[CommandResults] = []

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
