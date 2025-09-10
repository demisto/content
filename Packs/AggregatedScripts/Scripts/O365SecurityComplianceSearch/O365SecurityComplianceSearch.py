from CommonServerPython import *


SCRIPT_NAME = "o365-security-compliance-search"


class O365SearchRunner:
    # required integrations
    SEC_COMP_MODULE = "SecurityAndComplianceV2"

    # O365 commands
    CMD_GET_SEARCH = "o365-sc-get-search"
    CMD_NEW_SEARCH = "o365-sc-new-search"
    CMD_DEL_SEARCH = "o365-sc-remove-search"
    CMD_START_SEARCH = "o365-sc-start-search"
    CMD_NEW_SEARCH_ACTION = "o365-sc-new-search-action"
    CMD_GET_SEARCH_ACTION = "o365-sc-get-search-action"

    # context keys
    CONTEXT_MAIN_KEY = "O365SecurityAndComplianceSearch"
    CONTEXT_SEARCH_KEY = "Search"
    CONTEXT_PREV_KEY = "Preview"
    CONTEXT_NAME_KEY = "Name"
    CONTEXT_STATUS_KEY = "Status"
    CONTEXT_RESULTS_KEY = "Results"

    # default values
    DEFAULT_POLLING_INTERVAL = 30
    DEFAULT_POLLING_TIMEOUT = 300
    SEARCH_RESULT_PATTERN = r"(\w[\w\s]+?):\s*([^,;]+)"
    SEARCH_ACTION_SUFFIX = "_Preview"

    def __init__(self, args: dict, modules: dict):
        """
        Manages the Security and Compliance Search

        Args:
            args (dict): The arguments to pass to the script
            modules (dict): The modules in the environment
        """

        self.args = self._parse_args(args)
        self.modules = modules
        self.context: dict = {self.CONTEXT_SEARCH_KEY: {}, self.CONTEXT_PREV_KEY: {}}
        self.run_new_search = False

    def _parse_args(self, args: dict) -> dict:
        """
        Updates args to cast input strings as appropriate types

        Args:
            args (dict): The input arguments

        Returns:
            dict: The parsed arguments
        """

        expected_args = {
            "bool": ["force", "preview", "include_mailboxes"],
            "list": [
                "exchange_location",
                "exchange_location_exclusion",
                "public_folder_location",
                "share_point_location",
                "share_point_location_exclusion",
            ],
            "num": ["polling_interval", "polling_timeout"],
        }

        for arg_type in expected_args:
            for arg_name in expected_args[arg_type]:
                if arg_name in args:
                    try:
                        if arg_type == "bool":
                            args[arg_name] = argToBoolean(args[arg_name])
                        elif arg_type == "list":
                            args[arg_name] = argToList(args[arg_name])
                        elif arg_type == "num":
                            args[arg_name] = arg_to_number(args[arg_name])
                    except (TypeError, ValueError):
                        pass

        return args

    def _add_to_context(self, sub_key: str, new_key: str, new_value: str | list):
        """
        Add the value to the context under the specified sub-key

        Args:
            sub_key (str): Sub-key to nest under
            new_key (str): The key to add
            new_value (str | list): The value to add
        """

        for key, val in self.context.items():
            if isinstance(val, dict) and key == sub_key:
                self.context[sub_key][new_key] = new_value

    def _parse_results(self, search_results: str) -> list[dict]:
        """
        Parse results into a structured list of dictionaries for the context

        Args:
            search_results (str): The search results string

        Returns:
            list[dict]: The parsed search results
        """

        if not search_results:
            return [{}]

        parsed_results = []

        # remove brackets and carriage returns to normalize string
        search_results = search_results.replace("\r", "").replace("{", "").replace("}", "")

        # split results into lines and parse into dict
        results_list = search_results.split("\n")
        for entry in results_list:
            result_matches = re.findall(self.SEARCH_RESULT_PATTERN, entry)
            parsed_results.append({key.strip(): val.strip() for key, val in result_matches})

        return parsed_results

    def _wait_for_results(self, cmd: str) -> CommandResults:
        """
        Wait for results from o365-sc-get-search or o365-sc-get-search-action

        Args:
            cmd (str): The command to execute

        Returns:
            Union[dict, list]: Command execution results
        """

        interval = self.args.get("polling_interval", self.DEFAULT_POLLING_INTERVAL)
        timeout = self.args.get("polling_timeout", self.DEFAULT_POLLING_TIMEOUT)

        # verify the interval is not too small to avoid excessive API calls
        interval = interval if interval >= self.DEFAULT_POLLING_INTERVAL else self.DEFAULT_POLLING_INTERVAL

        start_time = time.time()
        while True:
            # timeout reached
            passed_time = time.time() - start_time
            if passed_time > timeout:
                raise DemistoException(f"Polling timed out after {int(passed_time)} seconds")

            # get search status and results
            results = execute_command(cmd, self.args)
            search_status = results.get("Status")  # type: ignore

            # if status and results show command finished, return
            if search_status == "Completed":
                return results  # type: ignore

            time.sleep(interval)  # pylint: disable=E9003

    def is_module_enabled(self):
        """
        Checks if the O365 Security and Compliance module is enabled in the current environment.

        Returns:
            bool: True if enabled, otherwise false.
        """
        for module in self.modules:
            if (self.modules[module].get("brand") == self.SEC_COMP_MODULE) and (self.modules[module].get("state") == "active"):
                return True

        return False

    def run_search(self) -> CommandResults:
        """
        Run the O365 security and compliance search with the current configuration

        Raises:
            DemistoException: If trying to run a new search without the 'kql_search' argument

        Returns:
            CommandResults: The search results
        """

        # check if search exists
        search_cmd_results = execute_command(self.CMD_GET_SEARCH, self.args)
        search_name = search_cmd_results.get("Name")  # type: ignore

        # if search does not exist - initiate a new search
        if not search_name:
            self.run_new_search = True

        # if search exists and force flag is used, remove search and make new one
        elif self.args.get("force", False):
            execute_command(self.CMD_DEL_SEARCH, self.args)
            self.run_new_search = True

        # create and start a new search
        if self.run_new_search:
            # validate arguments for new search
            if not self.args.get("kql_search", None):
                raise DemistoException("Running a new search requires the argument 'kql_search'.")

            execute_command(self.CMD_NEW_SEARCH, self.args)
            execute_command(self.CMD_START_SEARCH, self.args)
            search_cmd_results = self._wait_for_results(cmd=self.CMD_GET_SEARCH)

        # get updated search values)
        search_name = search_cmd_results.get("Name")  # type: ignore
        search_status = search_cmd_results.get("Status")  # type: ignore
        search_results = self._parse_results(search_cmd_results.get("SuccessResults"))  # type: ignore

        # add search values to context
        self._add_to_context(sub_key=self.CONTEXT_SEARCH_KEY, new_key=self.CONTEXT_NAME_KEY, new_value=search_name)
        self._add_to_context(sub_key=self.CONTEXT_SEARCH_KEY, new_key=self.CONTEXT_STATUS_KEY, new_value=search_status)
        self._add_to_context(sub_key=self.CONTEXT_SEARCH_KEY, new_key=self.CONTEXT_RESULTS_KEY, new_value=search_results)

        # if preview is False, return only search results
        if not self.args.get("preview", False):
            return CommandResults(
                outputs_prefix=self.CONTEXT_MAIN_KEY,
                outputs=self.context,
                readable_output=f"Search [{search_name}] returned with status [{search_status}]",
            )

        else:
            return self._get_preview(search_name=search_name, search_status=search_status)

    def _get_preview(self, search_name: str, search_status: str) -> CommandResults:
        """
        Get the preview for an O365 security and compliance search

        Args:
            search_name (_type_): _description_
            search_status (_type_): _description_
        """
        # start search action
        execute_command(self.CMD_NEW_SEARCH_ACTION, self.args)

        # add search_action_name and get preview
        self.args["search_action_name"] = search_name + self.SEARCH_ACTION_SUFFIX
        preview_cmd_results = self._wait_for_results(cmd=self.CMD_GET_SEARCH_ACTION)

        # get preview result values
        preview_name = preview_cmd_results.get("Name")  # type: ignore
        preview_status = preview_cmd_results.get("Status")  # type: ignore
        preview_results = self._parse_results(preview_cmd_results.get("Results"))  # type: ignore

        # add preview values to context
        self._add_to_context(sub_key=self.CONTEXT_PREV_KEY, new_key=self.CONTEXT_NAME_KEY, new_value=preview_name)
        self._add_to_context(sub_key=self.CONTEXT_PREV_KEY, new_key=self.CONTEXT_STATUS_KEY, new_value=preview_status)
        self._add_to_context(sub_key=self.CONTEXT_PREV_KEY, new_key=self.CONTEXT_RESULTS_KEY, new_value=preview_results)

        # return search and preview results
        return CommandResults(
            outputs_prefix=self.CONTEXT_MAIN_KEY,
            outputs=self.context,
            readable_output=f"Search [{search_name}] returned with status [{search_status}].\n"
            + f"Preview [{preview_name}] returned with status [{preview_status}].",
        )


def main():
    try:
        args = demisto.args()
        modules = demisto.getModules()
        search_runner = O365SearchRunner(args=args, modules=modules)

        if not search_runner.is_module_enabled():
            results = "Security and Compliance V2 module is not enabled"

        else:
            results = search_runner.run_search()

        return_results(results)

    except Exception as e:
        return_error(f"Failed to execute {SCRIPT_NAME}. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
