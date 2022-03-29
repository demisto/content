import demistomock as demisto1
from CommonServerPython import *

from typing import Callable, List, Dict
from dataclasses import dataclass
import enum


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

    def run_command_result_command(self, client: Client, command_name: str, func: Callable,
                                   demisto_args: dict) -> CommandResults:
        """
        Runs the normal XSOAR command and converts the returned dataclas instance into a CommandResults
        object.
        """
        result = func(client, **demisto_args)
        if command_name == "test-module":
            return_results(result)

        if not result:
            command_result = CommandResults(
                readable_output="No results.",
            )
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
        return command_result

    def is_command(self, command_name: str) -> bool:
        if command_name in self.commands or command_name in self.file_commands:
            return True

        return False

    def run_command(
            self,
            client: Client,
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
            return self.run_command_result_command(client, command_name, func, demisto_args)  # type: ignore

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


@dataclass
class Advisory:
    data_type: str
    data_format: str
    cve_id: str
    cve_date_public: str
    cve_title: str


class SeverityEnum(enum.Enum):
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


def locals_to_dict(locals_data: dict) -> dict:
    """Removes all arguments with None values from the dictionary returned by locals()"""
    result_dict = {}
    for key, value in locals_data.items():
        if value:
            result_dict[key] = value

    return result_dict


def flatten_advisory_dict(advisory_dict) -> Advisory:
    """Given a dictionary advisory, return an `Advisory` object"""
    return Advisory(
        data_type=advisory_dict.get("data_type"),
        data_format=advisory_dict.get("data_format"),
        cve_id=advisory_dict.get("CVE_data_meta").get("ID"),
        cve_title=advisory_dict.get("CVE_data_meta").get("TITLE"),
        cve_date_public=advisory_dict.get("CVE_data_meta").get("DATE_PUBLIC"),
    )


@COMMANDS.command("pan-advisories-get-advisories")
def get_advisories(client: Client, product: str, sort: str = "-date", severity: SeverityEnum = None, q: str = "") \
        -> List[Advisory]:
    """
    Gets all the advisories for the given product.
    :param client: HTTP Client !no-auto-argument
    :param product: Product name to search for advisories
    :param sort: Sort returned advisories by this value, can be date, cvss, etc. Leading hyphpen (-) indicates reverse search.
    :param severity: Filter advisories to this severity level only.
    :param q: Text search query
    """
    params_dict = locals_to_dict(locals())
    advisory_data = client.get_advisories(product, params_dict).get("data")

    advisory_object_list: List[Advisory] = []
    for advisory_dict in advisory_data:
        advisory_object_list.append(flatten_advisory_dict(advisory_dict))

    return advisory_object_list


def main():
    demisto_params = DemistoParameters(**demisto.params())
    client = Client(
        base_url=demisto_params.url
    )
    return COMMANDS.run_command(client, demisto.command(), demisto.args())
