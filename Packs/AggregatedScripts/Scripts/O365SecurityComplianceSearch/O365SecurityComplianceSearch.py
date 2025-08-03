from CommonServerPython import *


# required integrations
SEC_COMP_MODULES = ["SecurityAndCompliance", "SecurityAndComplianceV2"]

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

# TODO
SEARCH_RESULT_PATTERN = r"(\w[\w\s]+?):\s*([^,]+)"


def str_to_bool(s: str) -> bool:
    """
    Parse strings 'true' and 'false' to boolean values

    Args:
        s (str): input string

    Returns:
        bool: Bool value
    """
    
    return s.lower() == "true"


def str_to_array(s: str) -> list[str] | str:
    """
    Parse string that can be either single item or comma separated list

    Args:
        s (str): input string

    Returns:
        list[str] | str: The single value or list of values
    """
    
    if "," in s:
        return [i.strip() for i in s.split(",")]
    
    return s


def parse_args(args: dict) -> dict:
    """
    Parse args to cast input strings as appropriate types

    Args:
        args (dict): Input args

    Returns:
        dict: Parsed args
    """
    
    if "force" in args:
        args["force"] = str_to_bool(args["force"])
        
    if "preview" in args:
        args["preview"] = str_to_bool(args["preview"])
    
    if "include_mailboxes" in args:
        args["include_mailboxes"] = str_to_bool(args["include_mailboxes"])
        
    if "exchange_location" in args:
        args["exchange_location"] = str_to_array(args["exchange_location"])
        
    if "exchange_location_exclusion" in args:
        args["exchange_location_exclusion"] = str_to_array(args["exchange_location_exclusion"])
        
    if "public_folder_location" in args:
        args["public_folder_location"] = str_to_array(args["public_folder_location"])
    
    if "share_point_location" in args:
        args["share_point_location"] = str_to_array(args["share_point_location"])
        
    if "share_point_location_exclusion" in args:
        args["share_point_location_exclusion"] = str_to_array(args["share_point_location_exclusion"])
        
    if "polling_interval" in args:
        args["polling_interval"] = int(args["polling_interval"])
        
    if "polling_timeout" in args:
        args["polling_timeout"] = int(args["polling_timeout"])
        
    return args
    
    
def get_search_context(context: list, key: str) -> str:
    """
    Get results from search context

    Args:
        context (list): The commands context
        key (str): The key to look for in the context

    Returns:
        str: The value of the key
    """
    return context[0].get("Contents", {}).get(key)


def add_to_context(context: dict, sub_key: str, new_key: str, new_value: str|list):
    """
    Add the value to the context dictionary under the specified sub-key

    Args:
        context (dict): The context
        sub_key (str): Sub-key to nest under
        new_key (str): The key to add
        new_value (str | list): The value to add
    """
    
    for key, val in context.items():
        if isinstance(val, dict):
            if key == sub_key:
                val[new_key] = new_value

            add_to_context(val, sub_key, new_key, new_value)
        
            
def parse_search_results(search_results: str) -> list[dict]:
    """
    Parse search results into a structured list of dictionaries for the context

    Args:
        search_results (str): The search results string

    Returns:
        list[dict]: The parsed search results
    """
    
    parsed_results = []
    
    # remove brackets and carriage returns to normalize string
    search_results = search_results.replace("\r", "").replace("{", "").replace("}", "")
    
    # split results into lines and parse into dict
    results_list = search_results.split("\n")
    for entry in results_list:
        result_matches  = re.findall(SEARCH_RESULT_PATTERN, entry)
        parsed_results.append({key.strip(): val.strip() for key, val in result_matches})
        
    return parsed_results


def main():
    try:
        # init variables
        args = parse_args(demisto.args())
        modules = demisto.getModules()
        context = {
            CONTEXT_SEARCH_KEY: {},
            CONTEXT_PREV_KEY: {}
            }
        
        # check if relevant integrations are enabled
        module_enabled = False
        for module in modules:
            if modules[module].get("brand") in SEC_COMP_MODULES:
                module_enabled = True
                break
        
        if not module_enabled:
            return_error("Security and Compliance module is not enabled")
            
        # check if search exists
        get_search_res = demisto.executeCommand(CMD_GET_SEARCH, args)
        search_name = get_search_context(get_search_res, "Name")
        
        run_new_search = False
        
        # if search does not exist - initiate a new search
        if not search_name:
            run_new_search = True
        
        # if search exists and force flag is used, remove search and make new one
        elif args.get("force", False):
            demisto.executeCommand(CMD_DEL_SEARCH, args)
            run_new_search = True
        
        # create the new search
        if run_new_search:
            # TODO - verify input params
            new_search_res = demisto.executeCommand(CMD_NEW_SEARCH, args)
            search_name = get_search_context(new_search_res, "Name")
            
            # start the new search
            if search_name == args.get("search_name"):
                demisto.executeCommand(CMD_START_SEARCH, args)
                
                # wait for search to complete
                time.sleep(120)  # TODO - replace with polling
                get_search_res = demisto.executeCommand(CMD_GET_SEARCH, args)
                search_status = get_search_context(get_search_res, "Status")
                
                if search_status != "Completed":
                    return_error(f"Failed to create new search. Search status: {search_status}")
                
        # get search values
        search_name = get_search_context(get_search_res, "Name")
        search_status = get_search_context(get_search_res, "Status")
        search_results = parse_search_results(get_search_context(get_search_res, "SuccessResults"))
        
        # add search values to context
        add_to_context(context=context, sub_key=CONTEXT_SEARCH_KEY, new_key=CONTEXT_NAME_KEY, new_value=search_name)
        add_to_context(context=context, sub_key=CONTEXT_SEARCH_KEY, new_key=CONTEXT_STATUS_KEY, new_value=search_status)
        add_to_context(context=context, sub_key=CONTEXT_SEARCH_KEY, new_key=CONTEXT_RESULTS_KEY, new_value=search_results)
        
        # if preview is False, don't proceed with search action
        if not args.get("preview", False):
            print("Done")
        
        # new_search_action_res = demisto.executeCommand(CMD_NEW_SEARCH_ACTION, args)
        # get_search_action_res = demisto.executeCommand(CMD_GET_SEARCH_ACTION, args)
        
        # add context to main key
        demisto.setContext(CONTEXT_MAIN_KEY, context)

    except Exception as e:
        return_error(f"Failed to execute o365-security-compliance-search. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
