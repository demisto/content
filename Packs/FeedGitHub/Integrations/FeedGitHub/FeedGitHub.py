import demistomock as demisto
from CommonServerPython import *
from TAXII2ApiModule import *
import plyara
import plyara.utils
import tldextract

CONTEXT_PREFIX = "GITHUB"
RAW_RESPONSE = []


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, owner: str, repo: str, headers: dict):
        base_url = urljoin(base_url, f"/repos/{owner}/{repo}")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_commits_between_dates(self, since, until) -> list:
        """
        Retrieves the SHA of the base commit of the repository.

        This function fetches all commits of the repository and returns the SHA of the latest commit,
        which represents the base commit of the repository.

        Returns:
            str: The SHA of the base commit of the repository.
        """
        parsed_since = dateparser.parse(since)
        parsed_until = dateparser.parse(until)
        if not (parsed_since and parsed_until):
            response = self._http_request("GET", full_url=f"{self._base_url}/commits", resp_type="response")
        else:
            params = {
                "since": parsed_since.isoformat(),
                "until": parsed_until.isoformat(),
            }
            response = self._http_request("GET", full_url=f"{self._base_url}/commits", params=params, resp_type="response")
        demisto.debug(f"The base get_base_head_commits_sha() raw response: {response}")
        return [commit.get("sha") for commit in self._extract_commits(response)]

    def _extract_commits(self, response) -> list:
        all_commits = []
        if "next" not in response.links:
            all_commits.extend(response.json())
        while "next" in response.links:
            data = response.json()
            all_commits.extend(data)
            response = self._http_request("GET", full_url=response.links["next"]["url"], resp_type="response")
            all_commits.extend(response.json())
            demisto.debug(f"There are many comites currently bringing them all...,  currently exist:{response}")
        return all_commits

    def get_files_between_commits(self, base: str, head: str, include_base_commit: bool) -> tuple[
        list[dict[str, str]], str]:  # pragma: no cover  # noqa: E501
        """
        Retrieves the list of files changed between two commits and the SHA of the base commit.

        This function compares two commits in a repository to determine the files that have changed between them.
        Depending on the `include_base_commit` flag, it adjusts the comparison to include the base commit or not.
        If the comparison fails due to a "Not Found" error, the function handles this specific case by fetching
        the indicators including the first commit in the repository.

        :type base: ``str``
        :param base: The SHA of the base commit.

        :type head: ``str``
        :param head: The SHA of the head commit.

        :type include_base_commit: ``bool``
        :param include_base_commit: Flag to indicate if the base commit should be included in the comparison.

        :return: A tuple containing a list of files changed between the commits and the SHA of the base commit.
        :rtype: ``tuple[list, str]``

        :raises Exception: If an error occurs during the HTTP request.
        """
        url_suffix = f"/compare/{base}...{head}" if not include_base_commit else f"/compare/{base}^...{head}"
        try:
            response = self._http_request("GET", url_suffix)
        except Exception as e:
            if "Not Found" in str(e):
                demisto.debug("in get_files_between_commits func: Case: fetch indicators including the first commit in the repo")
                response = self._http_request("GET", f"/compare/{base}...{head}")
                response["files"] += self._http_request("GET", f"/commits/{base}")["files"]
            else:
                demisto.error(f"in get_files_between_commits func  error message: {e}")
                raise
        demisto.debug(f"The full response from 'get base...head' :{response}")
        if len(response["commits"]) == 0:
            base_sha = response["base_commit"]["sha"]
        else:
            base_sha = response["commits"][-1].get("sha")
        return response["files"], base_sha


def filter_out_files_by_status(commits_files: list, statuses=("added", "modified")) -> list:
    """
    Parses files from a list of commit files based on their status.

    Args:
        commits_files (list): A list of dictionaries representing commit files.

    Returns:
        list: A list of URLs for files that are added or modified.
    """
    relevant_files: list[dict] = []
    for file in commits_files:
        if file.get("status") in statuses:
            relevant_files.append(file.get("filename"))
    return relevant_files


def get_content_files_from_repo(client: Client, relevant_files: list[str], params: dict):
    """
    Retrieves content of relevant files based on specified extensions.

    Args:
        client (Client): An instance of the client used for HTTP requests.
        relevant_files (list): A list of URLs for relevant files.

    Returns:
        list: A list of file contents fetched via HTTP requests.
    """
    global RAW_RESPONSE
    extensions_to_fetch = argToList(params.get("extensions_to_fetch") or [])
    relevant_files = [file for file in relevant_files if any(file.endswith(ext) for ext in extensions_to_fetch)]
    raw_data_files = [
        {file: base64.b64decode(client._http_request("GET", url_suffix=f"/contents/{file}")["content"]).decode("utf-8")} for file
        in relevant_files]
    demisto.debug(f"list of all files raw_data :{raw_data_files}")
    RAW_RESPONSE = [list(file.values()) for file in raw_data_files]
    return raw_data_files


def get_commits_files(client: Client, base_commit, head_commit, is_first_fetch: bool) -> tuple[list, str]:
    """
    Retrieves relevant files modified between commits and the current repository head.

    Args:
        client (Client): An instance of the client used for interacting with the repository.
        last_commit_fetch (str): The SHA of the last fetched commit.

    Returns:
        tuple: A tuple containing a list of relevant file URLs and the SHA of the current repository head.
    """
    try:
        all_commits_files, current_repo_head_sha = client.get_files_between_commits(base_commit, head_commit, is_first_fetch)
        relevant_files = filter_out_files_by_status(all_commits_files)
        return relevant_files, current_repo_head_sha
    except IndexError:
        return [], base_commit


def parse_and_map_yara_content(content_item: dict[str, str]) -> list:
    """
    Parses YARA rules from a given content item and maps their attributes.

    Args:
        content_item (str): A string containing one or more YARA rules.

    Returns:
        list: A list of dictionaries representing parsed and mapped YARA rules.
              Each dictionary contains attributes such as rule name, description, author, etc.
    """

    text_content = list(content_item.values())[0]
    file_path = list(content_item.keys())[0]
    parsed_rules = []
    parser = plyara.Plyara()
    raw_rules = parser.parse_string(text_content)
    current_time = datetime.now().isoformat()
    for parsed_rule in raw_rules:
        try:
            metadata = {key: value for d in parsed_rule["metadata"] for key, value in d.items()}
            value_ = parsed_rule["rule_name"]
            type_ = "YARA Rule"
            mapper = {
                "value": value_,
                "description": metadata.get("description", ""),
                "author": metadata.get("author", ""),
                "rulereference": metadata.get("reference", ""),
                "sourcetimestamp": metadata.get("date", ""),
                "ruleid": metadata.get("id", ""),
                "rulestrings": make_grid_layout(parsed_rule.get("strings", {})),
                "condition": " ".join(parsed_rule["condition_terms"]),
                "references": file_path,
                "rawrule": f"```\n {plyara.utils.rebuild_yara_rule(parsed_rule)} \n```",
            }
            indicator_obj = {
                "value": value_,
                "type": type_,
                "service": "github",
                "fields": mapper,
                "score": Common.DBotScore.NONE,
                "firstseenbysource": current_time,
                "rawJSON": {"value": value_, "type": type_},
            }
            parsed_rules.append(indicator_obj)
        except Exception as e:
            demisto.error(f"Rull: {parsed_rule} cannot be processed. Error Message: {e}")
            continue
    return parsed_rules


def make_grid_layout(list_dict):
    return [
        {"index": d.get("name"), "string": d.get("value"), "type": d.get("type"), "modifiers": d.get("modifiers")}
        for d in list_dict
    ]


def get_yara_indicators(content: list[dict]):
    """
    Retrieves YARA indicators from a list of content items.

    Args:
        content (list): A list of strings containing YARA rules.

    Returns:
        list: A list of dictionaries representing parsed and mapped YARA rules for each content item.
    """
    return [rule for item in content for rule in parse_and_map_yara_content(item)]


def detect_domain_type(domain: str):
    """
    Detects the type of an indicator (e.g., Domain, DomainGlob) using tldextract library.

    Args:
        domain (str): The indicator value to be analyzed.

    Returns:
        Optional[FeedIndicatorType]: The type of the indicator, or None if detection fails.
    """
    try:
        no_cache_extract = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None)  # type: ignore

        if no_cache_extract(domain).suffix:
            if "*" in domain:
                return FeedIndicatorType.DomainGlob
            return FeedIndicatorType.Domain

    except Exception:
        demisto.debug(f"tldextract failed to detect indicator type. indicator value: {domain}")
    return None


ipv4Regex = (
    r"(?P<ipv4>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[:]?(?P<port>\d+)?"
)
ipv4cidrRegex = r"([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))"
ipv6Regex = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"  # noqa: E501
ipv6cidrRegex = r"s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))"  # noqa: E501

regex_indicators = [
    (ipv4cidrRegex, FeedIndicatorType.CIDR),
    (ipv6Regex, FeedIndicatorType.IPv6),
    (ipv6cidrRegex, FeedIndicatorType.IPv6CIDR),
    (emailRegex, FeedIndicatorType.Email),
    (re.compile(cveRegex, re.M), FeedIndicatorType.CVE),
    (md5Regex, FeedIndicatorType.File),
    (sha1Regex, FeedIndicatorType.File),
    (sha256Regex, FeedIndicatorType.File),
    (sha512Regex, FeedIndicatorType.File),
]

regex_with_groups = [
    (ipv4Regex, FeedIndicatorType.IP, "ipv4"),
    (urlRegex, FeedIndicatorType.URL, "url_with_path"),
    (domainRegex, detect_domain_type, "fqdn"),
]


def extract_text_indicators(content: dict[str, str], params):
    """
    Extracts indicators from text content using predefined regular expressions.

    Args:
        content (str): The text content to extract indicators from.

    Returns:
        list: A list of dictionaries representing extracted indicators.
              Each dictionary contains the indicator value and its type.
    """
    text_content = list(content.values())[0]
    file_path = list(content.keys())[0]
    text_content = text_content.replace("[.]", ".").replace("[@]", "@")  # Refang indicator prior to checking
    indicators = []
    for regex, type_ in regex_indicators:
        matches = re.finditer(regex, text_content)  # type: ignore
        if matches:
            indicators += [{"value": match.group(0), "type": type_} for match in matches]
    for regex, type_, group_name in regex_with_groups:
        matches = re.finditer(regex, text_content)  # type: ignore
        if matches:
            for match in matches:
                if regex in (ipv4Regex, urlRegex):
                    indicators.append({"value": match.group(group_name), "type": type_})
                elif regex == domainRegex:
                    regex_type = type_(match.group(group_name)) if callable(type_) else type_
                    if regex_type:
                        indicators.append({"value": match.group(group_name), "type": regex_type})
    indicators_to_xsoar = arrange_iocs_indicator_to_xsoar(file_path, indicators, params)
    return indicators_to_xsoar


def arrange_iocs_indicator_to_xsoar(file_path: str, parsed_indicators: list, params: dict):
    res = []
    owner = params.get("owner", "")
    repo = params.get("repo", "")
    current_time = datetime.now().isoformat()
    for indicator in parsed_indicators:
        value_ = indicator.get("value")
        type_ = indicator.get("type")
        raw_data = {"value": value_, "type": type_}
        indicator_obj = {
            "value": value_,
            "type": type_,
            "service": "github",
            "fields": {"references": file_path, "tags": {"owner": owner, "repo": repo}, "firstseenbysource": current_time},
            "rawJSON": raw_data,
        }
        res.append(indicator_obj)
    return res


def get_stix_indicators(repo_files_content):
    stix_client = STIX2XSOARParser({})
    generator_stix_files = create_stix_generator(repo_files_content)
    indicators = stix_client.load_stix_objects_from_envelope(generator_stix_files)  # type: ignore
    return indicators


def identify_json_structure(json_data) -> Any:
    """
    Identifies the structure of JSON data based on its content.

    Args:
        json_data : The JSON data to identify its structure.

    Returns:
        Union[str, Dict[str, Any], None]: The identified structure of the JSON data.
            Possible values are: "Bundle", "Envelope", or a dictionary with the key "objects".
            Returns None if the structure cannot be identified.
    """
    if isinstance(json_data, dict) and json_data.get("bundle"):
        return "Bundle"
    if isinstance(json_data, dict) and json_data.get("objects"):
        return "Envelope"
    if isinstance(json_data, dict) and all([json_data.get("type"), json_data.get("id")]):
        return "Envelope"
    if isinstance(json_data, list) and all([json_data[0].get("type"), json_data[0].get("id")]):
        return {"objects": json_data}
    return None


def filtering_stix_files(content_files: list) -> list:
    """
    Filters a list of content files to include only those in STIX format.

    Args:
        content_files (list): A list of JSON files or dictionaries representing STIX content.

    Returns:
        list: A list of STIX files or dictionaries found in the input list.
    """
    stix_files = []
    for file in content_files:
        for tab in file:
            file_type = identify_json_structure(tab)
            if file_type in ("Envelope", "Bundle"):
                stix_files.append(tab)
            if isinstance(file_type, dict):
                stix_files.append(file_type)
    return stix_files


def create_stix_generator(content_files: list[dict]):
    """
    Create a generator for iterating over STIX files.

    This function takes a list of JSON files, filters them to include only STIX files, and then
    creates a generator that yields each STIX file or object one at a time.

    Args:
        content_files (list): A list of JSON files.

    Returns:
        Generator: A generator that yields each STIX file from the filtered list one at a time.
    """
    content_files1 = [list(content_file.values())[0] for content_file in content_files]
    return get_stix_files_generator(filtering_stix_files(content_files1))


def get_stix_files_generator(json_files):
    yield from json_files


def test_module(client: Client, params) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    try:
        dateparser.parse(params.get("fetch_since"))
    except Exception as e:
        return str(f"error in 'First fetch time' parameter: {e}")
    try:
        client._http_request("GET", full_url=client._base_url)
    except Exception as e:
        if "Not Found" in str(e):
            return f"Not Found error please check the 'Owner / Repo' names  The error massage:{e}"
        elif "Bad credentials" in str(e):
            return f"Bad credentials error please check the API Token  The error massage:{e}"
        return str(f"{e}")
    return "ok"


def fetch_indicators(
    client: Client,
    last_commit_fetch,
    params,
    tlp_color: Optional[str] = None,
    feed_tags: List = [],
    limit: int = -1,
    enrichment_excluded: bool = False,
) -> List[Dict]:
    """
    Fetches indicators from a GitHub repository using the provided client.

    Args:
        client (Client): The GitHub client used to fetch indicators.
        last_commit_fetch: The last commit fetched from the repository.
        tlp_color (Optional[str]): The Traffic Light Protocol (TLP) color to assign to the fetched indicators.
        feed_tags (List): Tags to associate with the fetched indicators.
        limit (int): The maximum number of indicators to fetch. Default is -1 (fetch all).

    Returns:
        List[Dict]: A list of dictionaries representing the fetched indicators.
    """
    demisto.debug(f"Before fetch command last commit sha run: {last_commit_fetch}")
    since = params.get("fetch_since", "90 days ago")
    until = "now"
    is_first_fetch = not last_commit_fetch
    base_commit_sha = last_commit_fetch or client.get_commits_between_dates(since, until)[-1]
    head_commit = params.get("branch_head", "")
    iterator, last_commit_info = get_indicators(client, params, base_commit_sha, head_commit, is_first_fetch)
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        if feed_tags:
            item["fields"]["tags"] = feed_tags
        if tlp_color:
            item["fields"]["trafficlightprotocol"] = tlp_color
        if enrichment_excluded:
            item['enrichmentExcluded'] = enrichment_excluded
        indicators.append(item)
    demisto.debug(f"After fetch command last run: {last_commit_info}")
    if last_commit_info:
        demisto.setLastRun({"last_commit": last_commit_info})
    return indicators


def get_indicators(client: Client, params, base_commit_sha, head_commit, is_first_fetch: bool = True):
    relevant_files, last_commit_info = get_commits_files(client, base_commit_sha, head_commit, is_first_fetch)
    feed_type = params.get("feedType", "")
    repo_files_content = get_content_files_from_repo(client, relevant_files, params)
    try:
        if feed_type == "YARA":
            indicators = get_yara_indicators(repo_files_content)

        elif feed_type == "STIX":
            indicators = get_stix_indicators(repo_files_content)

        elif feed_type == "IOCs":
            indicators = []
            for file in repo_files_content:
                indicators += extract_text_indicators(file, params)

    except Exception as err:
        demisto.error(str(err))
        raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")
    demisto.debug(f"fetching {len(indicators)} indicators")
    return indicators, last_commit_info


def get_indicators_command(client: Client, params: dict, args: dict = {}) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Outputs.
    """
    limit = arg_to_number(args.get("limit"))
    enrichment_excluded = argToBoolean(params.get('enrichmentExcluded', False))
    indicators: list = []
    try:
        if limit and limit <= 0:
            raise ValueError("Limit must be a positive number.")
        since = args.get("since", "7 days ago")
        until = args.get("until", "now")
        all_commits = client.get_commits_between_dates(since, until)
        if not all_commits:
            indicators = []
            human_readable = "#### No commits were found in the given time range"
            demisto.debug("No commits were found in the given time range")
        else:
            base_commit_sha = all_commits[-1]
            head_commit_sha = all_commits[0]
            indicators, _ = get_indicators(client, params, base_commit_sha, head_commit_sha)
            hr_indicators = []
            if limit and limit > 0:
                indicators = indicators[:limit]
            for indicator in indicators:
                if enrichment_excluded:
                    indicator['enrichmentExcluded'] = enrichment_excluded

                hr_indicators.append(
                    {
                        "Value": indicator.get("value"),
                        "Type": indicator.get("type"),
                    }
                )

            human_readable = tableToMarkdown(
                "Indicators from GitHubFeed:", hr_indicators, headers=["Type", "Value"], removeNull=True
            )
        if not indicators:
            human_readable = "#### There are no indicators in the given timeframe"
        demisto.debug(f"human_readable for request indicators is: {human_readable}")
        demisto.debug(f"indicators: {indicators}")
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX + ".Indicators",
            outputs_key_field="githubfeed",
            raw_response=RAW_RESPONSE,
            outputs=indicators,
            readable_output=human_readable,
        )

    except Exception as err:
        demisto.error(str(err))
        raise ValueError(f"get_indicators_command return with error. \n\nError massage: {err}")


def fetch_indicators_command(client: Client, params: dict, args) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    enrichment_excluded = argToBoolean(params.get('enrichmentExcluded', False))
    limit = int(params.get("limit", -1))
    last_commit_fetch = demisto.getLastRun().get("last_commit")
    indicators = fetch_indicators(client, last_commit_fetch, params, tlp_color=tlp_color, feed_tags=feed_tags, limit=limit,
                                  enrichment_excluded=enrichment_excluded)
    return indicators


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is: {command}")
    base_url = str(params.get("url"))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    owner = params.get("owner", "")
    repo = params.get("repo", "")
    api_token = (params.get("api_token") or {}).get("password", "")
    headers = (
        {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {api_token}"}
        if api_token
        else {"Accept": "application/vnd.github+json"}
    )  # noqa: E501

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
            return_results(test_module(client, params))

        elif command == "github-get-indicators":
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params, args)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
