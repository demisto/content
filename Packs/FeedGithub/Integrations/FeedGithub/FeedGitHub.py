import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from enum import Enum

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"



class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this Hello_World Feed implementation, no special attributes defined
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, owner: str, repo: str, headers: dict):
        base_url = urljoin(base_url, f"/repos/{owner}/{repo}/commits")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_list_commits(self,params= []) -> None:
        """
        Retrieves a list of commits from the GitHub repository.

        This method sends an HTTP GET request to the GitHub API endpoint
        to retrieve a list of commits from the repository specified by the
        base URL.

        Returns:
            None: This method does not return any value directly. The retrieved
            commits can be accessed using the `_http_request` method or other
            appropriate mechanisms.

        Raises:
            Any exceptions raised by the `_http_request` method.
        """
        res = self._http_request("GET", full_url=self._base_url, params=params)

        return res

    def get_files_per_commit(self, list_commits) -> dict[str, list]:
        """
        Retrieves a dictionary containing files changed per commit.

        This method takes a list of commits and sends an HTTP GET request to
        the GitHub API for each commit to retrieve the list of files changed.
        It constructs a dictionary where each key is the commit SHA and the
        corresponding value is a list of files changed in that commit.

        Args:
            list_commits (List[Dict[str, any]]): A list of dictionaries representing commits.
                Each dictionary should contain information about a single commit.

        Returns:
            Dict[str, List[str]]: A dictionary where keys are commit SHA strings and values
                are lists of file paths changed in each commit.

        Raises:
            Any exceptions raised by the `_http_request` method.
        """
        return {commit["sha"]: self._http_request("GET", commit["sha"]).get("files", []) for commit in list_commits[:2]}
    
    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self._http_request(
            "GET",
            url_suffix="",
            full_url=self._base_url,
            resp_type="text",
        )

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split("\n")

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append(
                        {
                            "value": indicator,
                            "type": auto_detect_indicator_type(indicator),
                            "FeedURL": self._base_url,
                        }
                    )

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f"Could not parse returned data as indicator. \n\nError message: {err}")
        return result

def parsing_files_by_status(commits_files: dict[str, list]) -> dict[str, list]:
    relevant_files: dict[str, list[dict]] = {}
    for commit, files in commits_files.items():
        raw_files_list = []
        for file in files:
            if file.get("status") == "added" or file.get("status") == "modified":
                raw_files_list.append(file)
        relevant_files[commit] = raw_files_list

    return relevant_files

def parsing_files_by_feed_type(client:Client, commits_files: dict[str, list], feed_type: str) -> dict[str, list]:
    relevant_files: dict[str, list[dict]] = {}
    for commit, files in commits_files.items():
        raw_files_data_list = []
        for file in files:
            format_file = file.get("filename").split(".")[-1]
            if format_file == feed_type:
                url = file.get("raw_url")
                res = client._http_request('GET', full_url=url)
                x = {file.get("filename"): res.text}
                raw_files_data_list.append(x)
                

                # raw_files_data_list.append({file.get("filename"): file.get("patch")})
        relevant_files[commit] = raw_files_data_list
    return relevant_files

        
def parse_yara(data: dict[str, list[dict[str,str]]]):
    mapping_result: dict[str, dict] = {}
    for commit_sha , files in data.items():
        for file in files:
            rules_result_per_file = {}
            for file_name, content in file.items():
                res = pars_and_map_yara_content(content)
                rules_result_per_file[file_name] = res
        mapping_result[commit_sha] = rules_result_per_file
    # demisto.results(mapping_result)
    return mapping_result
        
def pars_and_map_yara_content(content_item:str) -> list:
    pattern = re.compile(rf"(?={re.escape('rule')})")
    content_file = pattern.split(content_item)
    res = []
    for rule in content_file:
        res.append(mapping_yara_rule(rule))
    return res

def mapping_yara_rule(raw_rule: str) -> dict:
    raw_rule.replace("condition:\n+\t\t( ", "condition:")
    patterns = {
        "value": re.compile(r"rule\s+?(\S*?)\s"),
        "description": re.compile(r"description\s*?=\s*[\"](.*?)[\"]"),
        "author": re.compile(r"author\s*?=\s*[\"](.*?)[\"]"),
        "references": re.compile(r"reference\s*?=\s*[\"](.*?)[\"]"),
        "sourcetimestamp": re.compile(r"date\s*?=\s*[\"](.*?)[\"]"),
        "id": re.compile(r"id\s*?=\s*[\"](.*?)[\"]"),
        "rule_strings": re.compile(r"[$]s\d+?\s*=\s*?(\S.*?)$"),
        "condition": re.compile(r"condition:\s*?(\w.*?)(?:$|})"),
        # "raw_rule": r".*",  # For the entire text
    }
    results = {}
    for field, pattern in patterns.items():
        matches = pattern.findall(raw_rule, re.MULTILINE)
        results[field] = matches
    results["raw_rule"] = raw_rule
    return results

def get_commits_files(client: Client, feed_type: str) -> dict[str, list]:
    list_commits = client.get_list_commits()
    all_commits_files = client.get_files_per_commit(list_commits)
    relevant_files = parsing_files_by_status(all_commits_files)
    yara_files_data = parsing_files_by_feed_type(client, relevant_files, "yar")
    indicators = parse_yara(yara_files_data)
    return indicators # type: ignore


def get_yara_indicator(client: Client, feed_type: str = "AUTO"):
    pars_data = get_commits_files(client, feed_type)
    return pars_data
    # demisto.results(f"the gihub files result is: {json.dumps(pars_data)}")


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    client._http_request("GET", full_url=client._base_url)
    
    return "ok"


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get("value")
        type_ = item.get("type")
        raw_data = {
            "value": value_,
            "type": type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            # The indicator value.
            "value": value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            "type": type_,
            # The name of the service supplying this feed.
            "service": "github",
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            "fields": {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            "rawJSON": raw_data,
        }

        if feed_tags:
            indicator_obj["fields"]["tags"] = feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client, feed_type: str='AUTO') -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    args = demisto.args()

    indicators = {}
    try:
        if feed_type == "YARA":
            indicators=get_yara_indicator(client, feed_type)
            demisto.debug(indicators)

        if feed_type == "STIX":
            demisto.results("@@@@@@@@@")
        demisto.debug(f"undicators: {indicators}")
        return CommandResults(
            outputs_key_field="githubfeed",
            raw_response=indicators,
            outputs=indicators,
        )

    except Exception as err:
        demisto.debug(str(err))
        raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")
    # client.build_iterator()
    '''
    tlp_color = args.get("tlp_color")
    feed_tags = argToList(args.get("feedTags", ""))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    '''
    


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    indicators = fetch_indicators(client, tlp_color, feed_tags)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Get the service API url

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor

    command = demisto.command()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f"Command being called is {command}")
    base_url = str(params.get("url"))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    owner = str(params.get("owner"))
    repo = str(params.get("repo"))
    headers = {"Accept": "application/vnd.github+json"}
    feed_type = params.get("feedType")

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            owner=owner,
            repo=repo,
            headers=headers,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "github-get-indicators":
            return_results(get_indicators_command(client, feed_type)) # type: ignore

        elif command == "fetch-indicators":
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
