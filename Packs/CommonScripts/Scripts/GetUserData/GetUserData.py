import demistomock as demisto
from CommonServerPython import *

from typing import Any
from collections.abc import Callable


SHARED_CONTEXT = {}


def prepare_readable_output(
    command: str, args: dict, status: bool, response: dict
) -> CommandResults:
    command = f'!{command} {" ".join([f"{arg}={value}" for arg, value in args.items() if value])}'
    if status:
        readable_output = response["HumanReadable"]
        result_message = f"#### Result for {command}\n{readable_output}"
        result = CommandResults(readable_output=result_message)
    else:
        result_message = f"#### Error for {command}\n{response}"
        result = CommandResults(
            readable_output=result_message, entry_type=EntryType.ERROR
        )
    return result


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
) -> dict[str, Any]:
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
    }
    for key, value in account.items():
        if isinstance(value, list) and value:
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
        return any(self.args.values()) if self.args else True

    def _get_output_key(self, outputs: dict[str, Any]) -> str:
        output_key = ""
        if self.output_key in outputs:
            output_key = self.output_key
        else:
            output_key = next(
                (key for key in outputs if key.startswith(f"{self.output_key}(")), ""
            )
        return output_key

    def _prepare_output(self, entry_context: dict[str, Any]) -> dict[str, Any]:
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
                    f"Output key {self.output_key} not found in entry context: {entry_context}"
                )

        return output

    def _prepare_readable_output(
        self, response: dict, is_error: bool = False
    ) -> CommandResults:
        command = f'!{self.name} {" ".join([f"{arg}={value}" for arg, value in self.args.items() if value])}'
        if not is_error:
            readable_output = response["HumanReadable"]
            result_message = f"#### Result for {command}\n{readable_output}"
            result = CommandResults(readable_output=result_message)
        else:
            result_message = f"#### Error for {command}\n{response}"
            result = CommandResults(
                readable_output=result_message, entry_type=EntryType.ERROR
            )
        return result

    def update_command_args(self, args: dict):
        self.command.args_lst = [args]

    def execute(self) -> tuple[bool, list[CommandResults], list[dict]]:
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
        """Base class for all tasks."""
        self.task_id = task_id
        self.command = command
        self.status = False

    def execute(self) -> tuple[list[CommandResults], list[dict]]:
        results: list[CommandResults] = []
        outputs: list[dict] = []
        if self.command:
            self.status, results, outputs = self.command.execute()
        else:
            self.status = True
        return results, outputs


class PlaybookGraph:
    """
    tasks: nodes
    connections: edges
    """

    def __init__(self):
        self.args: dict[str, Any] = {}
        self.tasks: dict[str, Task] = {}
        self.connections: dict[str, list[tuple[str, Optional[Callable[[], bool]]]]] = {}
        self.start_task_id: str = ""
        self.outputs = []
        self.results = []

    def add_task(self, task: Task):
        self.tasks[task.task_id] = task
        self.connections[task.task_id] = []

    def add_tasks(self, tasks: list[Task]):
        for task in tasks:
            self.add_task(task)

    def add_connection(
        self,
        from_task: Task,
        to_task: Task,
        condition: Callable[[], bool] = lambda: True,
    ):
        self.connections[from_task.task_id].append((to_task.task_id, condition))

    def run(self):
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
    This function updates the is_enabled attribute of the commands based on the availability of the brand.
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
    return {
        "identityiq_search_identities_command": Command(
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
        "identitynow_get_accounts_command": Command(
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
        "ad_get_user_command": Command(
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
                            "manager": entry_context.get("manager", [])[0]
                        }
                    }
                ),
            )[0],
        ),
        "ad_get_user_manager_command": Command(
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
        "pingone_get_user_command": Command(
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
        "okta_get_user_command": Command(
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
        "aws_iam_get_user_command": Command(
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
        "msgraph_user_get_command": Command(
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
        "msgraph_user_get_manager_command": Command(
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
        "xdr_list_risky_users_command": Command(
            name="xdr-list-risky-users",
            brand="Cortex XDR - IR",
            args={"user_id": user_id},
            output_key="PaloAltoNetworksXDR.RiskyUser",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                type=entry_context.get("type"),
            ),
        ),
        # TODO: Update the outputs
        "iam_get_user_command": Command(
            name="iam-get-user",
            args={
                "user-profile": {"id": user_id}
                if user_id
                else {"email": f"{user_name}@{domain}"}
                if domain and user_name
                else {"username": user_name}
                if user_name
                else {"email": user_email}
                if user_email
                else None,
            },
            is_generic=True,
            output_key="Account",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                type=entry_context.get("type"),
            ),
        ),
    }


def setup_tasks(playbook: PlaybookGraph, commands: Dict[str, Command]):
    playbook.add_task(Task("start_task"))
    for command_name, command in commands.items():
        task_name = command_name.replace("_command", "_task")
        playbook.add_task(Task(task_name, command))


def setup_connections(playbook: PlaybookGraph):
    is_domain_in_user_name = "/" in playbook.args["user_name"]
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
        lambda: playbook.tasks["msgraph_user_get_task"].status,
    )
    playbook.start_task_id = playbook.tasks["start_task"].task_id


def setup_playbook_graph(
    playbook: PlaybookGraph, user_id: str, user_name: str, user_email: str, domain: str
) -> None:
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
        user_id = args.get("user_id", "")
        user_name = args.get("user_name", "")
        user_email = args.get("user_email", "")
        domain = args.get("domain", "")

        if not any((user_id, user_name, user_email)):
            raise ValueError(
                "At least one of the following arguments must be specified: user_id, user_name or user_email."
            )
        if domain and not user_name:
            raise ValueError(
                "When specifying the domain argument, the user_name argument must also be provided."
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
            results.append(CommandResults(readable_output="No user data found."))
        return_results(results)
    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
