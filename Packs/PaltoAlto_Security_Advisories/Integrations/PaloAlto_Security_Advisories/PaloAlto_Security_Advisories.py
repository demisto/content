import demistomock as demisto1
from CommonServerPython import *

from typing import Callable, List, Dict
from dataclasses import dataclass


class Client(BaseClient):
    """The client that conects to the advisories API"""
    PRODUCTS_ENDPOINT = "/products"
    ADVISORIES_ENDPOINT = "/advisories"

    def __init__(self, base_url, api_timeout=60, verify=True, proxy=False,
                 ok_codes=tuple(), headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.api_timeout = api_timeout

    def get_products(self):
        """
        Gets the list of Supported Products by the Advisories API
        """
        return self._http_request(
            method='GET',
            url_suffix=Client.PRODUCTS_ENDPOINT,
            timeout=self.api_timeout
        )

    def get_advisories(self, product: str, params: dict):
        """
        Gets the list of advisories
        :product: Required Product name to list advisories for
        :params: Optional list of GET parameters to include in the request.
        """
        params = params or {}
        return self._http_request(
            method='GET',
            url_suffix=f"{Client.PRODUCTS_ENDPOINT}/{product}{Client.ADVISORIES_ENDPOINT}",
            timeout=self.api_timeout,
            params=params
        )


class CommandRegister:
    commands: dict[str, Callable] = {}
    file_commands: dict[str, Callable] = {}

    def command(self, command_name: str):
        """
        Register a normal Command for this Integration. Commands always return CommandResults.

        :param command_name: The XSOAR integration command
        """

        def _decorator(func):
            self.commands[command_name] = func

            def _wrapper(topology, demisto_args=None):
                return func(topology, demisto_args)

            return _wrapper

        return _decorator

    def file_command(self, command_name: str):
        """
        Register a file command. file commands always return FileResults.

        :param command_name: The XSOAR integration command
        """

        def _decorator(func):
            self.file_commands[command_name] = func

            def _wrapper(topology, demisto_args=None):
                return func(topology, demisto_args)

            return _wrapper

        return _decorator

    def run_command_result_command(self, command_name: str, func: Callable,
                                   demisto_args: dict) -> CommandResults:
        """
        Runs the normal XSOAR command and converts the returned dataclas instance into a CommandResults
        object.
        """
        result = func(**demisto_args)
        if command_name == "test-module":
            return_results(result)

        if not result:
            command_result = CommandResults(
                readable_output="No results.",
            )
            return_results(command_result)
            return command_result

        if type(result) is list:
            outputs = [vars(x) for x in result]
            summary_list = [vars(x) for x in result]
            title = result[0]._title
            output_prefix = result[0]._output_prefix
        else:
            outputs = vars(result)
            summary_list = [vars(result)]
            title = result._title
            output_prefix = result._output_prefix

        extra_args = {}
        if hasattr(result, "_outputs_key_field"):
            extra_args["outputs_key_field"] = getattr(result, "_outputs_key_field")

        readable_output = tableToMarkdown(title, summary_list)
        command_result = CommandResults(
            outputs_prefix=output_prefix,
            outputs=outputs,
            readable_output=readable_output,
            **extra_args
        )
        return_results(command_result)
        return command_result

    def run_file_command(self, func: Callable,
                         demisto_args: dict) -> dict:

        file_result: dict = func(**demisto_args)
        return_results(file_result)
        return file_result

    def is_command(self, command_name: str) -> bool:
        if command_name in self.commands or command_name in self.file_commands:
            return True

        return False

    def run_command(
            self,
            command_name: str,
            demisto_args: dict
    ) -> Union[CommandResults, dict]:
        """
        Runs the given XSOAR command.
        :param command_name: The name of the decorated XSOAR command.
        :param demisto_args: Result of demisto.args()
        """
        if command_name in self.commands:
            func = self.commands.get(command_name)
            return self.run_command_result_command(command_name, func, demisto_args)  # type: ignore

        if command_name in self.file_commands:
            func = self.file_commands.get(command_name)
            return self.run_file_command(func, demisto_args)  # type: ignore

        raise DemistoException("Command not found.")


# This is the store of all the commands available to this integration
COMMANDS = CommandRegister()


@dataclass
class DemistoParameters:
    """
    Demisto Parameters
    :param url: Default URL for PAN-OS advisories website
    """
    url: str = "https://security.paloaltonetworks.com/api/v1/"
