import urllib3

from CommonServerPython import *

RESPONSE_LINE_LENGTH = 8

urllib3.disable_warnings()

''' CONSTANTS '''

BASE_URL = 'http://data.phishtank.com'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
RELOAD_DATA_URL_SUFFIX = "data/online-valid.csv"

''' CLIENT CLASS '''


def handle_error(res: requests.models.Response):
    if res.status_code == 404 or res.status_code == 509:
        err_msg = f'PhishTankV2 - Error in API call {res.status_code} - {res.reason}'
        return_error(err_msg)


class Client(BaseClient):
    """
    Client to use in the PhisTankV2 integration. Overrides BaseClient.

        Args:
           proxy (bool): False if feed HTTPS server certificate will not use proxies, True otherwise.
           insecure (bool): False if feed HTTPS server certificate should be verified, True otherwise.
           verify (bool) : not insecure
           fetch_interval_hours (str) : Database refresh interval (hours)
   """

    def __init__(self, proxy: bool, verify: bool, fetch_interval_hours: str):
        super().__init__(proxy=proxy, verify=verify, base_url=BASE_URL)
        self.fetch_interval_hours = fetch_interval_hours

    def get_http_request(self, url_suffix: str):
        result = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            resp_type="text",
            error_handler=handle_error
        )
        return result


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'
    """
    data = reload(client)
    response_was_empty = len(data.keys()) == 0
    if response_was_empty:
        return_error("Error - could not fetch PhishTankV2 database, "
                     "API returned an empty response")
    return 'ok'


def was_phishtank_data_ever_reloaded(context: dict):
    """
    Checking if PhishTank data was ever reloaded by checking IntegrationContext. (IntegrationContext set during
    the reload command).

    Args:
        context (dict) : IntegrationContext that is empty / contains PhishTank data.

    Returns: True if context contains PhishTank data (from a previous reload). False otherwise.

    """
    was_phishtank_data_reloaded = context != dict()
    if was_phishtank_data_reloaded:
        return True
    return False


def is_phishtank_data_outdated(client: Client, context: dict):
    """
    Checks if last last reload was in the last fetch_interval_hours or not.

    Args:
        client: Client to use in the PhisTankV2 integration.
        context (dict):  IntegrationContext contains PhishTank data.

    Returns:
        True if last reload was much than fetch_interval_hours ago.
        False otherwise.

    """
    current_time = datetime.now()
    fetch_interval_seconds = timedelta(hours=float(client.fetch_interval_hours))
    return context["timestamp"] < date_to_timestamp(current_time - fetch_interval_seconds)


def is_reload_needed(client: Client, context: dict) -> bool:
    """

    Args:
        client: Client to use in the PhisTankV2 integration.
        context: IntegrationContext .
                - "list" contains data from http response
                - "timestamp" datatime of the last response

    Returns: True if DB can be loaded now. i.e DB was not loaded in the last fetch_interval hours.
            False otherwise.
    """
    return not was_phishtank_data_ever_reloaded(context) or is_phishtank_data_outdated(client, context)


def get_url_data(client: Client, url: str):
    url = remove_last_slash(url)
    integration_context = demisto.getIntegrationContext()
    current_data_url = None
    if is_reload_needed(client, integration_context):
        data = reload(client)
        current_date = date_to_timestamp(datetime.now(), DATE_FORMAT)
        context = {"list": data, "timestamp": current_date}
        demisto.setIntegrationContext(context)
        data_contains_url = url in data
        if data_contains_url:
            current_data_url = data[url]
    else:
        url_was_reloaded = url in integration_context["list"]
        if url_was_reloaded:
            current_data_url = integration_context["list"][url]
    return current_data_url, url


def url_data_to_dbot_score(url_data, url):
    if url_data["verified"] == "yes":
        dbot_score = 3
    else:
        dbot_score = 2
    return Common.DBotScore(url, DBotScoreType.URL, "PhishTankV2", dbot_score,
                            "Match found in PhishTankV2 database")


def create_verified_markdown(url_data, url):
    markdown = f'#### Found matches for URL {url} \n'
    markdown += tableToMarkdown('', url_data)
    phish_tank_url = f'http://www.phishtank.com/phish_detail.php?phish_id={url_data["phish_id"]}'
    markdown += f'Additional details at {phish_tank_url} \n'
    return markdown


def url_command(client: Client, url_list: list) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    for url in url_list:
        markdown = "### PhishTankV2 Database - URL Query \n"
        url_data, url = get_url_data(client, url)
        url_data_is_valid = url_data and "verified" in url_data.keys()
        if url_data_is_valid:
            dbot = url_data_to_dbot_score(url_data, url)
            markdown += create_verified_markdown(url_data, url)
        else:
            markdown += f'#### No matches for URL {url} \n'
            dbot = Common.DBotScore(url, DBotScoreType.URL, "PhishTankV2", 0)
        command_results.append(CommandResults(
            indicator=Common.URL(url, dbot)),
            readable_output=markdown,
        )

    return command_results


def phishtank_reload_command(client: Client):
    """
    Requests a csv file from PhishTank.
    Sets the response in IntegrationContext.
    Args:
        client:  Client to use in the PhisTankV2 integration.

    Returns: CommandResults:
            - readable_output (str): number of urls that reloaded during that reload.

    """
    parsed_response = reload(client)  # gets a parsed response
    current_date = date_to_timestamp(datetime.now(), DATE_FORMAT)
    context = {"list": parsed_response, "timestamp": current_date}
    demisto.setIntegrationContext(context)
    readable_output = 'PhishTankV2 Database reloaded \n'
    number_of_urls_loaded = len(parsed_response.keys())
    readable_output += f'Total **{number_of_urls_loaded}** URLs loaded.\n'
    last_load = datetime.utcfromtimestamp(context["timestamp"] / 1000.0).strftime("%a %b %d %Y %H:%M:%S (UTC)")
    output_to_context = {"value": last_load}
    return CommandResults(readable_output=readable_output, outputs=output_to_context,
                          outputs_prefix="LastReloadTime(obj)")


def phishtank_status_command():
    """
    Checks in IntegrationContext if data was reloaded so far or not.
    note : IntegrationContext updated in each reload command.

    Returns: CommandResults:
        - readable_output (str) : contains the number of urls that were reloaded in the last reload and the date
                                of the last reload.
    """
    data = demisto.getIntegrationContext()
    status = "PhishTankV2 Database Status\n"
    data_was_not_reloaded_yet = data == dict()
    last_load = ""
    if data_was_not_reloaded_yet:
        status += "Database not loaded.\n"
    else:
        last_load = datetime.utcfromtimestamp(data["timestamp"] / 1000.0).strftime("%a %b %d %Y %H:%M:%S (UTC)")
        number_of_urls_loaded = len(data["list"].keys())
        status += f'Total **{number_of_urls_loaded}** URLs loaded.\n' \
                  f'Last Load time **{last_load}**\n'
    output_to_context = {"value": last_load}
    return CommandResults(readable_output=status, outputs=output_to_context,
                          outputs_prefix="LastReloadTime(obj)")


def reload(client: Client) -> dict:
    """
    This function is responsible for:
     1. request a csv file from PhishTank API (calling to client.get_http_request)
     2. parsing an API response and saving all relevant information into a dictionary

    Args:
        client:
        (Client) : client to use in the PhisTankV2 integration.

    Returns:
        dictionary of parsed http response. Each url is a key and his values are:
            "id,submission_time,verified,verification_time,online,target"
    """
    response = client.get_http_request(RELOAD_DATA_URL_SUFFIX)
    response_is_empty = not response
    if response_is_empty:
        return dict()
    response = response.splitlines()
    parsed_response = {}
    columns = response[0].strip().split(",")  # get csv headers
    for index, line in list(enumerate(response))[1:]:
        line = line.split(",")
        line = parse_response_line(line, index, response)
        invalid_parsed_line = line is None
        if invalid_parsed_line:
            continue
        url = remove_last_slash(line[columns.index("url")])
        if url:
            parsed_response[url] = {
                "phish_id": line[columns.index("phish_id")].strip(),
                "submission_time": line[columns.index("submission_time")].strip(),
                "verified": line[columns.index("verified")].strip(),
                "verification_time": line[columns.index("verification_time")].strip(),
                "online": line[columns.index("online")].strip(),
                "target": line[columns.index("target")].strip(),
            }
    return parsed_response


def parse_response_line(current_line, index, response):
    """
    This function checks if current line is a valid line.
    note: there is a specific line in PhishTank csv response that is broken into 2 following lines. In this case,
            those 2 lines are concatenate into one complete line.
    Args:
        current_line (str): current response's line to be parsed
        index (int) : current line's index
        response (list) : list of PhishTank csv response

    Returns: line (str): the parsed line

    """
    current_line_length = len(current_line)
    # RESPONSE_LINE_LENGTH is the number of valid columns in csv
    line_is_broken = current_line_length < RESPONSE_LINE_LENGTH
    if line_is_broken:
        next_line = response[index + 1].strip().split(",")
        current_line_has_missing_columns = len(next_line) >= RESPONSE_LINE_LENGTH
        if current_line_has_missing_columns:
            # this next_line is not the second part of current_line.
            # i.e current_line is not valid  - because next_line is not the continuation of current line
            return None
        else:
            # this is the second part of broken line. i.e current_line + next_line should have been one complete line
            return current_line + next_line
    return current_line


def remove_last_slash(url: str) -> str:
    url = url.strip()
    if len(url) > 0 and url[-1] == os.sep:
        return url[:-1]
    return url


def is_number(fetch_interval_hours: str) -> bool:
    try:
        return float(fetch_interval_hours) > 0
    except ValueError:
        return False


''' MAIN FUNCTION '''


def main() -> None:
    proxy = demisto.params().get('proxy')
    verify = not demisto.params().get('insecure')
    fetch_interval_hours = demisto.params().get('fetchIntervalHours')

    if not is_number(fetch_interval_hours):
        return_error("PhishTankV2 error: Please provide a numeric value (and bigger than 0) for Database refresh "
                     "interval (hours)")

    # initialize a client
    client = Client(proxy, verify, fetch_interval_hours)

    command = demisto.command()
    demisto.debug(f'PhishTankV2: command is {command}')

    try:
        if demisto.command() == "test-module":
            return_results(test_module(client))

        elif demisto.command() == 'url':
            url = argToList(demisto.args().get("url"))
            url_command(client, url)

        elif demisto.command() == 'phishtank-reload':
            return_results(phishtank_reload_command(client))

        elif demisto.command() == 'phishtank-status':
            return_results(phishtank_status_command())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
