import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

from typing import Any
from collections.abc import Callable


# def run_execute_command(
#     command: str, args: dict[str, Any], extract_contents: bool = False
# ) -> tuple[bool, dict | str]:
#     status, res = execute_command(
#         command=command,
#         args=args,
#         extract_contents=extract_contents,
#         fail_on_error=False,
#     )
#     demisto.debug(f"Command {command} finished with status {status} and result {res}")
#     if status and isinstance(res, list):
#         res = res[0]

#     return status, res


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
    manager_display_name: Optional[str] = None
) -> dict[str, Any]:
    return {
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
        "manager_display_name": manager_display_name
    }
    formatted_values = {}
    for key, value in locals().items():
        if isinstance(value, list):
            formatted_values[key] = value[0] if value else ""
        else:
            formatted_values[key] = value
    formatted_values.pop("formatted_values")
    return Common.Account(**formatted_values).to_context()


class Command:
    def __init__(
        self,
        name: str,
        args: dict,
        output_key: str,
        output_function: Callable[[dict[str, Any]], dict[str, Any]],
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
        self.raw_outputs = {}
        self.outputs = []
        self.results = []
        self.command = CommandRunner.Command(
            commands=self.name,
            args_lst=self.args,
        )
        self.output_function = output_function

    def _verify_args(self) -> bool:
        if self.args:
            return any(self.args.values())
        else:
            return True

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

    def execute(self) -> bool:
        status = False
        if not self.is_enabled:
            demisto.debug(f"Command {self.name} is disabled, skipping...")
        elif not self._verify_args():
            demisto.debug(
                f"Skipping command {self.name} since no required arguments were provided for the command."
            )
        else:
            demisto.debug(f"Running command {self.name}")
            results, errors = CommandRunner.execute_commands(
                command=self.command, extract_contents=False
            )
            for result in results:
                self.results.append(self._prepare_readable_output(result.result))
                self.outputs.append(self._prepare_output(result.result["EntryContext"]))
                self.raw_outputs = result.result["EntryContext"]
            for error in errors:
                self.results.append(
                    self._prepare_readable_output(error.result, is_error=True)
                )
            if results:
                status = True
            demisto.debug(f"Finish running command={self.name} with {status=}")
        return status


class Task:
    def __init__(self, command: Optional[Command] = None):
        """Base class for all tasks."""
        self.command = command
        self.children: list[Task] = []
        self.conditions: list[Optional[Callable[[Any], bool]]] = []
        self.pre_execute_children = []

    def add_child(self, task, condition: Optional[Callable[[Any], bool]] = None, pre_execute_child: Optional[Callable[[Command, Command], None]] = None):
        """
        Add a child task with an optional condition.

        :param task: The child task to add.
        :param condition: A callable that takes a result and returns a boolean.
        """
        self.children.append(task)
        self.conditions.append(condition)
        self.pre_execute_children.append(pre_execute_child)

    def execute(self, result=None):
        status = True
        if self.command:
            status = self.command.execute()
            result = self.command.raw_outputs

        """Evaluate conditions and execute the appropriate child tasks."""
        if status:
            for child, condition, pre_execute_child in zip(self.children, self.conditions, self.pre_execute_children):
                if condition is None or condition(result):
                    if pre_execute_child:
                        pre_execute_child(self.command, child.command)
                    child.execute()
                else:
                    demisto.debug("Skipping child task since condition check failed.")


# class CommandTask(Task):
#     def __init__(self, command: Command):
#         """
#         Initialize a flow task with a command.

#         :param command: The command associated with this task.
#         """
#         super().__init__()
#         self.command = command

#     def execute(self):
#         """Execute the command and conditionally proceed to child tasks."""
#         status = self.command.execute()
#         outputs = self.command.outputs

#         if status:
#             # Logic to determine the next task(s) to execute based on conditions
#             for child, condition in zip(self.children, self.conditions):
#                 if condition is None or condition(outputs):
#                     child.execute()
#                 else:
#                     demisto.debug(f"Skipping child task {child.__class__.__name__} since condition check failed.")


# class Decisiontask(Task):
#     def __init__(self):
#         """Initialize a decision task."""
#         super().__init__()

#     def execute(self, result=None):
#         """Evaluate conditions and execute the appropriate child tasks."""
#         for child, condition in zip(self.children, self.conditions):
#             if condition is None or condition(result):
#                 child.execute()


# class Flow:
#     def __init__(self, root_task: Task):
#         """
#         Initialize the flow.

#         :param root_task: The root task of the flow.
#         """
#         self.root_task = root_task

#     def execute(self):
#         """Start executing the flow from the root task."""
#         demisto.debug("Starting flow execution...")
#         self.root_task.execute()
#         demisto.debug("Flow execution completed.")


""" COMMAND FUNCTION """


def update_enabled_commands(commands: list[Command]) -> None:
    """
    This function updates the is_enabled attribute of the commands based on the availability of the brand.
    """
    brands = [command.brand for command in commands if not command.is_generic]
    res = execute_command(
        command="IsIntegrationAvailable",
        args={"brandname": brands},
    )

    enabled_brands = [brand[0] for brand in list(zip(brands, res)) if brand[1] == "yes"]

    for command in commands:
        if command.is_generic:
            command.is_enabled = True
        else:
            command.is_enabled = command.brand in enabled_brands

    demisto.debug(
        f"Enabled commands: {[command.name for command in commands if command.is_enabled]}"
    )


def merge_accounts(accounts: list[dict[str, str]]) -> dict[str, Any]:
    merged_account = {}
    for account in accounts:
        for key, value in account.items():
            if key not in merged_account:
                merged_account[key] = value
            elif merged_account[key] != value:
                demisto.debug(
                    f"Conflicting values for key '{key}': '{merged_account[key]}' vs '{value}'"
                )
    return Common.Account(**merged_account).to_context()[Common.Account.CONTEXT_PATH] if merged_account else {}


""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        user_id = args.get("user_id", "")
        user_name = args.get("user_name", "")
        user_email = args.get("user_email", "")
        domain = args.get("domain", "")
        is_domain_in_user_name = "/" in user_name

        if not any((user_id, user_name, user_email)):
            raise ValueError(
                "At least one of the following arguments must be specified: user_id, user_name or user_email."
            )

        identityiq_search_identities_command = Command(
            name="identityiq-search-identities",
            brand="SailPointIdentityIQ",
            args={
                "id": user_id,
                "email": user_email,
            },
            output_key="IdentityIQ.Identity",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                username=entry_context.get("name", {}).get("formatted"),
                display_name=entry_context.get("DisplayName"),
                email_address=entry_context.get("emails", {}).get("value"),
                is_enabled=entry_context.get("active"),
            ),
        )
        identitynow_get_accounts_command = Command(
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
        )
        ad_get_user_command = Command(
            name="ad-get-user",
            brand="Active Directory Query v2",
            args={
                "username": user_name,
                "email": user_email,
            },
            output_key="ActiveDirectory.Users",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("dn"),
                display_name=entry_context.get("displayName", [])[0] if entry_context.get("displayName") else "",
                email_address=entry_context.get("mail", [])[0] if entry_context.get("mail") else "",
                groups=entry_context.get("memberOf"),
                # manager=entry_context.get("Manager"),
                is_enabled=not entry_context.get("userAccountControlFields", {}).get(
                    "ACCOUNTDISABLE"
                ),
            ),
        )
        ad_get_user_manager_command = Command(
            name="ad-get-user",
            brand="Active Directory Query v2",
            args={},
            output_key="ActiveDirectory.Users",
            output_function=lambda entry_context: create_account(
                manager_display_name=entry_context.get("displayName", [])[0] if entry_context.get("displayName") else "",
                manager_email=entry_context.get("mail", [])[0] if entry_context.get("mail") else "",
            ),
        )
        pingone_get_user_command = Command(
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
        )
        okta_get_user_command = Command(
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
                is_enabled=entry_context.get("Status"),
            ),
        )
        aws_iam_get_user_command = Command(
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
        )
        msgraph_user_get_command = Command(
            name="msgraph-user-get",
            brand="Microsoft Graph User",
            args={
                "user": user_id,
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
        )
        xdr_list_risky_users_command = Command(
            name="xdr-list-risky-users",
            brand="Cortex XDR - IR",
            args={"user_id": user_id},
            output_key="PaloAltoNetworksXDR.RiskyUser",
            output_function=lambda entry_context: create_account(
                id=entry_context.get("id"),
                type=entry_context.get("type"),
            ),
        )
        iam_get_user_command = Command(
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
        )

        list_commands = [
            identityiq_search_identities_command,
            identitynow_get_accounts_command,
            ad_get_user_command,
            pingone_get_user_command,
            okta_get_user_command,
            aws_iam_get_user_command,
            msgraph_user_get_command,
            xdr_list_risky_users_command,
            iam_get_user_command,
            ad_get_user_manager_command,
        ]
        update_enabled_commands(list_commands)

        start_task = Task()
        identityiq_search_identities_task = Task(
            identityiq_search_identities_command
        )
        identitynow_get_accounts_task = Task(identitynow_get_accounts_command)
        ad_get_user_task = Task(ad_get_user_command)
        ad_get_user_manager_task = Task(ad_get_user_manager_command)
        pingone_get_user_task = Task(pingone_get_user_command)
        okta_get_user_task = Task(okta_get_user_command)
        aws_iam_get_user_task = Task(aws_iam_get_user_command)
        msgraph_user_get_task = Task(msgraph_user_get_command)
        xdr_list_risky_users_task = Task(xdr_list_risky_users_command)
        iam_get_user_task = Task(iam_get_user_command)
        start_task.add_child(identityiq_search_identities_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(identitynow_get_accounts_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(ad_get_user_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(pingone_get_user_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(okta_get_user_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(aws_iam_get_user_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(msgraph_user_get_task, lambda _: not is_domain_in_user_name)
        start_task.add_child(xdr_list_risky_users_task)
        start_task.add_child(iam_get_user_task, lambda _: not is_domain_in_user_name)

        def pre_execute_child_ad_get_user_task(father_task: Command, child_task: Command):
            child_task.args = {
                "dn": father_task.raw_outputs.get(father_task._get_output_key(father_task.raw_outputs), {})[0].get("manager")[0]
            }
        ad_get_user_task.add_child(
            ad_get_user_manager_task,
            lambda output: bool(
                output.get(ad_get_user_command._get_output_key(output), {})[0].get("manager")),
            pre_execute_child_ad_get_user_task
        )
        start_task.execute()
        # flow = Flow(root_task=start_task)
        # flow.execute()
        results = []
        outputs = []
        for command in list_commands:
            results.extend(command.results)
            outputs.extend(command.outputs)
        merged_output = merge_accounts(outputs)
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
                CommandResults(
                    readable_output="No user data found."
                )
            )
        return_results(results)
    except Exception as e:
        return_error(f"Failed to execute get-user-data. Error: {str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
