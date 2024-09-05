import demistomock as demisto
from CommonServerPython import *

import itertools
from typing import Any
from collections.abc import Callable


SHARED_CONTEXT = {}


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


class Command:
    def __init__(
        self,
        name: str,
        args: dict,
        output_key: str,
        output_function: Callable[[dict[str, Any]], dict[str, Any]],
        update_args_fun: Optional[Callable[[], dict[str, Any]]] = None,
        brand: Optional[str] = None,
        is_generic: bool = False,
        is_enabled: bool = True,
    ):
        """
        Initialize a Command object.

        Args:
            name (str): The name of the command.
            args (dict): The arguments for the command.
            output_key (str): The key for the command output.
            output_function (Callable[[dict[str, Any]], dict[str, Any]]): Function to process the output.
            update_args_fun (Optional[Callable[[], dict[str, Any]]]): Function to update arguments before running.
            brand (Optional[str]): The brand associated with the command.
            is_generic (bool): Whether the command is generic or not.
            is_enabled (bool): Whether the command is enabled or not.

        Attributes:
            name (str): The name of the command.
            args (dict): The arguments for the command.
            brand (Optional[str]): The brand associated with the command.
            is_enabled (bool): Whether the command is enabled or not.
            is_generic (bool): Whether the command is generic or not.
            output_key (str): The key for the command output.
            command (CommandRunner.Command): The command runner object.
            output_function (Callable): Function to process the output.
            update_args_fun (Optional[Callable]): Function to update arguments before running.
        """
        self.name = name
        self.args = args
        self.brand = brand
        self.is_enabled = is_enabled
        self.is_generic = is_generic
        self.output_key = output_key
        self.command = CommandRunner.Command(
            commands=self.name,
            args_lst=self.args,
        )
        self.output_function = output_function
        self.update_args_fun = update_args_fun

    def _verify_args(self) -> bool:
        """
        Verify if any arguments are provided.

        Returns:
            bool: True if any argument has a value, or if no arguments are present.
                  False if all arguments are empty.
        """
        return any(self.args.values()) if self.args else True

    def _get_output_key(self, outputs: dict[str, Any]) -> str:
        """
        Get the output key from the outputs dictionary.

        Args:
            outputs (dict[str, Any]): The dictionary containing output keys and values.

        Returns:
            str: The output key if found, or an empty string if not found.
        """
        output_key = ""
        if self.output_key in outputs:
            output_key = self.output_key
        else:
            output_key = next(
                (key for key in outputs if key.startswith(f"{self.output_key}(")), ""
            )
        return output_key

    def _prepare_output(self, entry_context: dict[str, Any]) -> dict[str, Any]:
        """
        Prepares the output from the entry context.

        Args:
            entry_context (dict[str, Any]): The entry context containing the command output.

        Returns:
            dict[str, Any]: The processed output.

        This method extracts the relevant data from the entry context using the output key,
        processes it with the output function, and returns the result. If the output key
        is not found or the entry context is empty, it returns an empty dictionary.
        """
        output = {}
        if entry_context:
            output_key = self._get_output_key(entry_context)
            if output_key:
                context = entry_context[output_key]
                if isinstance(context, list):
                    context = context[0]
                output = self.output_function(context)
            else:
                demisto.debug(
                    f"Output key {self.output_key} not found in entry context keys: {list(entry_context.keys())}"
                )

        return output

    def _prepare_readable_output(
        self, response: dict, is_error: bool = False
    ) -> CommandResults:
        """
        Prepare a readable output for the command result.

        Args:
            response (dict): The response dictionary containing the command result.
            is_error (bool, optional): Flag indicating if the result is an error. Defaults to False.

        Returns:
            CommandResults: The prepared command results with readable output.

        This method formats the command result into a readable output, including the command that was executed.
        It handles both successful results and errors, creating appropriate CommandResults objects with
        formatted messages.
        """
        command = f'!{self.name} {" ".join([f"{arg}={value}" for arg, value in self.args.items() if value])}'
        if not is_error:
            readable_output = response["HumanReadable"]
            result_message = f"#### Result for {command}\n{readable_output}"
            result = CommandResults(readable_output=result_message, mark_as_note=True)
        else:
            result_message = f"#### Error for {command}\n{response}"
            result = CommandResults(
                readable_output=result_message,
                entry_type=EntryType.ERROR,
                mark_as_note=True,
            )
        return result

    def update_command_args(self, args: dict):
        """
        Update the command arguments with the provided dictionary.

        Args:
            args (dict): A dictionary containing new arguments to update.

        This method updates the existing arguments dictionary and replaces the
        command's argument list with the new arguments.
        """
        self.args.update(args)
        self.command.args_lst = [args]

    def execute(self) -> tuple[bool, list[CommandResults], list[dict]]:
        """
        Execute the command associated with this instance.

        Returns:
            tuple[bool, list[CommandResults], list[dict]]: A tuple containing:
                - status (bool): True if the command execution was successful, False otherwise.
                - return_results (list[CommandResults]): A list of CommandResults objects representing the command output.
                - return_outputs (list[dict]): A list of dictionaries containing the command outputs.

        This method checks if the command is enabled and if the required arguments are provided.
        If conditions are met, it executes the command, processes the results, and prepares the output.
        """
        status = False
        return_results = []
        return_outputs = []
        if not self.is_enabled:
            demisto.debug(f"Skipping command {self.name} since it is disabled.")
        elif not self._verify_args():
            demisto.debug(
                f"Skipping command {self.name} since no required arguments were provided for the command."
            )
        else:
            demisto.debug(f"Running command {self.name}")
            if self.update_args_fun:
                self.update_command_args(self.update_args_fun())
            results, errors = CommandRunner.execute_commands(
                command=self.command, extract_contents=False
            )
            for result in results:
                return_results.append(self._prepare_readable_output(result.result))
                return_outputs.append(
                    self._prepare_output(result.result["EntryContext"])
                )
            for error in errors:
                return_results.append(
                    self._prepare_readable_output(error.result, is_error=True)
                )
            if return_outputs:
                status = True
            demisto.debug(f"Finish running command={self.name} with {status=}")
        return status, return_results, return_outputs


class Task:
    def __init__(self, task_id: str, command: Optional[Command] = None):
        """
        Initialize a Task object.

        Args:
            task_id (str): A unique identifier for the task.
            command (Optional[Command]): The command associated with this task, if any.

        Attributes:
            task_id (str): The unique identifier of the task.
            command (Optional[Command]): The command associated with this task.
            status (Optional[bool]): The execution status of the task, initially set to None.
        """
        self.task_id = task_id
        self.command = command
        self.status: Optional[bool] = None

    def execute(self) -> tuple[list[CommandResults], list[dict]]:
        """
        Execute the task.

        This method runs the associated command if one exists, otherwise it sets the status to True.

        Returns:
            tuple[list[CommandResults], list[dict]]: A tuple containing two lists:
                - A list of CommandResults objects representing the results of the command execution.
                - A list of dictionaries containing the outputs of the command execution.
        """
        results: list[CommandResults] = []
        outputs: list[dict] = []
        if self.command:
            self.status, results, outputs = self.command.execute()
        else:
            self.status = True
        return results, outputs


class PlaybookGraph:
    def __init__(self):
        """
        Initialize the PlaybookGraph.
        The tasks are the nodes in the graph, and the connections are the edges.

        Attributes:
            args (dict[str, Any]): Dictionary to store arguments.
            tasks (dict[str, Task]): Dictionary to store tasks, with task_id as the key.
            connections (dict[str, list[tuple[str, Optional[Callable[[], bool]]]]]):
                Dictionary to store task connections, with task_id as the key and a list of
                tuples containing the connected task_id and an optional condition function.
            start_task_id (str): The ID of the starting task.
            outputs (list): List to store outputs.
            results (list): List to store results.
        """
        self.args: dict[str, Any] = {}
        self.tasks: dict[str, Task] = {}
        self.connections: dict[str, list[tuple[str, Optional[Callable[[], bool]]]]] = {}
        self.start_task_id: str = ""
        self.outputs = []
        self.results = []

    def add_task(self, task: Task):
        """
        Add a task to the PlaybookGraph.

        This method adds the given task to the tasks dictionary and initializes
        an empty list for its connections in the connections dictionary.

        Args:
            task (Task): The task to be added to the PlaybookGraph.
        """
        self.tasks[task.task_id] = task
        self.connections[task.task_id] = []

    def add_connection(
        self,
        from_task: Task,
        to_task: Task,
        condition: Callable[[], bool] = lambda: True,
    ):
        """
        Add a connection between two tasks in the PlaybookGraph.

        This method creates a connection from one task to another, with an optional condition.

        Args:
            from_task (Task): The task from which the connection originates.
            to_task (Task): The task to which the connection leads.
            condition (Callable[[], bool], optional): A function that returns a boolean
                indicating whether the connection should be followed. Defaults to a function
                that always returns True.
        """
        self.connections[from_task.task_id].append((to_task.task_id, condition))

    def run(self):
        """
        Execute the tasks in the PlaybookGraph.

        This method runs the tasks in the PlaybookGraph in a breadth-first manner,
        starting from the start_task_id. It executes each task, collects the results
        and outputs, and follows the connections to the next tasks based on their
        conditions. The execution continues until all reachable tasks have been processed.

        The method updates the PlaybookGraph's results and outputs lists with the
        collected data from each executed task.
        """
        current_task_ids = [self.start_task_id]
        executed_task_ids = set()

        while current_task_ids:
            next_task_ids = []
            for current_task_id in current_task_ids:
                task = self.tasks.get(current_task_id)
                if not task:
                    demisto.debug(f"Task {current_task_id} not found.")
                    continue
                demisto.debug(f"Current task: {task.task_id}")
                results, outputs = task.execute()
                self.results.extend(results)
                self.outputs.extend(outputs)
                executed_task_ids.add(task.task_id)
                next_tasks = self.connections.get(task.task_id, [])
                if task.status:
                    for next_task_id, condition in next_tasks:
                        if condition is None or condition():
                            next_task_ids.append(next_task_id)
                        else:
                            demisto.debug(
                                f"Skipping task {next_task_id} since condition check failed."
                            )

            current_task_ids = next_task_ids

        demisto.debug(f"All tasks executed: {executed_task_ids}")


def update_enabled_commands(commands: dict[str, Command]) -> None:
    """
    Updates the is_enabled attribute of the commands based on the availability of the brand.

    This function checks the availability of integration brands using the IsIntegrationAvailable
    script and updates the is_enabled attribute of each command accordingly.
    Generic commands are always enabled.

    Args:
        commands (dict[str, Command]): A dictionary of Command objects to update.

    Returns:
        None
    """
    brands = [command.brand for command in commands.values() if not command.is_generic]
    res = execute_command(
        command="IsIntegrationAvailable",
        args={"brandname": brands},
    )

    enabled_brands = [brand[0] for brand in list(zip(brands, res)) if brand[1] == "yes"]

    for command in commands.values():
        if command.is_generic:
            command.is_enabled = True
        else:
            command.is_enabled = command.brand in enabled_brands

    demisto.debug(
        f"Enabled commands: {[command.name for command in commands.values() if command.is_enabled]}"
    )


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


def setup_commands(playbook: PlaybookGraph) -> dict[str, Command]:
    user_id = playbook.args["user_id"]
    user_name = playbook.args["user_name"]
    user_email = playbook.args["user_email"]
    domain = playbook.args["domain"]
    """
    Sets up and returns a dictionary of Command objects.
    
    This function creates Command objects for different identity management systems and
    services.
    
    Returns:
        dict[str, Command]: A dictionary of Command objects, where the keys are task names
        and the values are the corresponding Command objects.
    """
    return {
        "identityiq_search_identities_task": Command(
            name="identityiq-search-identities",
            brand="SailPointIdentityIQ",
            args={
                "id": user_id,
                "email": user_email,
            },
            output_key="IdentityIQ.Identity",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                username=entry_context.get("userName"),
                display_name=entry_context.get("name", {}).get("formatted"),
                email_address=entry_context.get("emails", {}).get("value"),
                is_enabled=entry_context.get("active"),
            ),
        ),
        "identitynow_get_accounts_task": Command(
            name="identitynow-get-accounts",
            brand="SailPointIdentityNow",
            args={
                "id": user_id,
                "name": user_name,
            },
            output_key="IdentityNow.Account",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                display_name=entry_context.get("name"),
                is_enabled=not entry_context.get("disabled"),
            ),
        ),
        "ad_get_user_task": Command(
            name="ad-get-user",
            brand="Active Directory Query v2",
            args={
                "username": user_name,
                "email": user_email,
            },
            output_key="ActiveDirectory.Users",
            output_function=lambda entry_context: (
                create_account(
                    id=entry_context.get("dn"),
                    display_name=entry_context.get("displayName"),
                    email_address=entry_context.get("mail"),
                    groups=entry_context.get("memberOf"),
                    is_enabled=not entry_context.get(
                        "userAccountControlFields", {}
                    ).get("ACCOUNTDISABLE"),
                ),
                SHARED_CONTEXT.update(
                    {
                        "ad_get_user_task": {
                            "manager": (entry_context.get("manager") or [None])[0]
                        }
                    }
                ),
            )[0],
        ),
        "ad_get_user_manager_task": Command(
            name="ad-get-user",
            brand="Active Directory Query v2",
            args={},
            output_key="ActiveDirectory.Users",
            output_function=lambda entry_context: create_account(
                manager_display_name=entry_context.get("displayName"),
                manager_email=entry_context.get("mail"),
            ),
            update_args_fun=lambda: {
                "dn": SHARED_CONTEXT.get("ad_get_user_task", {}).get("manager")
            },
        ),
        "pingone_get_user_task": Command(
            name="pingone-get-user",
            brand="PingOne",
            args={
                "userId": user_id,
                "username": user_name,
            },
            output_key="PingOne.Account",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("ID"),
                username=entry_context.get("Username"),
                display_name=entry_context.get("DisplayName"),
                email_address=entry_context.get("Email"),
                is_enabled=entry_context.get("Enabled"),
            ),
        ),
        "okta_get_user_task": Command(
            name="okta-get-user",
            brand="Okta v2",
            args={
                "userId": user_id,
                "username": user_name,
            },
            output_key="Account",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("ID"),
                username=entry_context.get("Username"),
                display_name=entry_context.get("DisplayName"),
                email_address=entry_context.get("Email"),
                manager_display_name=entry_context.get("Manager"),
                is_enabled=entry_context.get("Status") == "ACTIVE",
            ),
        ),
        "aws_iam_get_user_task": Command(
            name="aws-iam-get-user",
            brand="AWS - IAM",
            args={
                "userName": user_name,
            },
            output_key="AWS.IAM.Users",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("UserId"),
                username=entry_context.get("UserName"),
            ),
        ),
        "msgraph_user_get_task": Command(
            name="msgraph-user-get",
            brand="Microsoft Graph User",
            args={
                "user": user_name,
            },
            output_key="Account",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("ID"),
                username=entry_context.get("Username"),
                display_name=entry_context.get("DisplayName"),
                email_address=entry_context.get("Email", {}).get("Address"),
                job_title=entry_context.get("JobTitle"),
                office=entry_context.get("Office"),
                telephone_number=entry_context.get("TelephoneNumber"),
                type=entry_context.get("Type"),
            ),
        ),
        "msgraph_user_get_manager_task": Command(
            name="msgraph-user-get-manager",
            brand="Microsoft Graph User",
            args={
                "user": user_name,
            },
            output_key="MSGraphUserManager",
            output_function=lambda entry_context: create_account(
                manager_display_name=entry_context.get("Manager", {}).get(
                    "DisplayName"
                ),
                manager_email=entry_context.get("Manager", {}).get("Mail"),
            ),
        ),
        "xdr_list_risky_users_task": Command(
            name="xdr-list-risky-users",
            brand="Cortex XDR - IR",
            args={"user_id": user_name},
            output_key="PaloAltoNetworksXDR.RiskyUser",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                risk_level=entry_context.get("risk_level"),
            ),
        ),
        "iam_get_user_task": Command(
            name="iam-get-user",
            args={
                "user-profile": {
                    "id": user_id,
                    "email": user_email,
                    "username": f"{user_name}{domain if domain else ''}",
                }
            },
            is_generic=True,
            output_key="IAM.Vendor",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                username=entry_context.get("username"),
                email_address=entry_context.get("email"),
                is_enabled=entry_context.get("active"),
            )
            if entry_context.get("success")
            else {},
        ),
    }


def setup_tasks(playbook: PlaybookGraph, commands: Dict[str, Command]):
    """
    Sets up tasks for the playbook.

    Args:
        playbook (PlaybookGraph): The playbook graph to add tasks to.
        commands (Dict[str, Command]): A dictionary of command names to Command objects.

    This function adds a start task and then creates tasks for each command in the provided dictionary.
    """
    playbook.add_task(Task("start_task"))
    for task_name, command in commands.items():
        playbook.add_task(Task(task_name, command))


def setup_connections(playbook: PlaybookGraph):
    """
    Sets up connections between tasks in the playbook graph.

    This function establishes the flow of execution between different tasks in the playbook.
    It adds connections from the start task to various user data retrieval tasks.
    It also sets up connections for retrieving manager information when available.

    Args:
        playbook (PlaybookGraph): The playbook graph to add connections to.

    Note:
        The function uses a shared context (SHARED_CONTEXT) to determine certain conditions.
    """
    is_domain_in_user_name = "\\" in playbook.args["user_name"]
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["identityiq_search_identities_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["identitynow_get_accounts_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["ad_get_user_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["pingone_get_user_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["okta_get_user_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["aws_iam_get_user_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["msgraph_user_get_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["start_task"], playbook.tasks["xdr_list_risky_users_task"]
    )
    playbook.add_connection(
        playbook.tasks["start_task"],
        playbook.tasks["iam_get_user_task"],
        lambda: not is_domain_in_user_name,
    )
    playbook.add_connection(
        playbook.tasks["ad_get_user_task"],
        playbook.tasks["ad_get_user_manager_task"],
        lambda: bool(
            SHARED_CONTEXT.get(playbook.tasks["ad_get_user_task"].task_id, {}).get(
                "manager"
            )
        ),
    )
    playbook.add_connection(
        playbook.tasks["msgraph_user_get_task"],
        playbook.tasks["msgraph_user_get_manager_task"],
        lambda: bool(playbook.tasks["msgraph_user_get_task"].status),
    )
    playbook.start_task_id = playbook.tasks["start_task"].task_id


def setup_playbook_graph(
    playbook: PlaybookGraph, user_id: str, user_name: str, user_email: str, domain: str
) -> None:
    """
    Sets up the playbook graph for user data retrieval.

    Args:
        playbook (PlaybookGraph): The playbook graph to set up.
        user_id (str): The ID of the user.
        user_name (str): The name of the user.
        user_email (str): The email of the user.
        domain (str): The domain of the user.

    Returns:
        None
    """
    playbook.args = {
        "user_id": user_id,
        "user_name": user_name,
        "user_email": user_email,
        "domain": domain,
    }
    commands = setup_commands(playbook)
    update_enabled_commands(commands)
    setup_tasks(playbook, commands)
    setup_connections(playbook)


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        users_ids = argToList(args.get("user_id", []))
        users_names = argToList(args.get("user_name", []))
        users_emails = argToList(args.get("user_email", []))
        domain = args.get("domain", "")

        if domain and not users_names:
            raise ValueError(
                "When specifying the domain argument, the user_name argument must also be provided."
            )

        for user_id, user_name, user_email in list(
            itertools.zip_longest(users_ids, users_names, users_emails, fillvalue="")
        ):
            try:
                if not any((user_id, user_name, user_email)):
                    raise ValueError(
                        "At least one of the following arguments must be specified: user_id, user_name or user_email."
                    )

                playbook = PlaybookGraph()
                setup_playbook_graph(playbook, user_id, user_name, user_email, domain)
                playbook.run()
                results = playbook.results

                merged_output = merge_accounts(playbook.outputs)
                if merged_output:
                    results.append(
                        CommandResults(
                            outputs_prefix="Account",
                            outputs_key_field="Id",
                            outputs=merged_output,
                            readable_output=tableToMarkdown(
                                name="User Data", t=merged_output, sort_headers=False
                            ),
                        )
                    )
                else:
                    results.append(
                        CommandResults(readable_output="No user data found.")
                    )
                return_results(results)
            except Exception as e:
                return_results(
                    CommandResults(
                        readable_output=(
                            "An error occurred while running the 'get-user-data' command with the arg values: "
                            f"{user_id=}, {user_name=}, {user_email=}, {domain=}. Error: {str(e)}"
                        ),
                        entry_type=EntryType.ERROR,
                    )
                )
    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
