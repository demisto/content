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
    try:
        data = reload(client)
        if len(data.keys()) == 0:
            raise DemistoException("Error - could not fetch PhishTankV2 database, "
                                   "API returned an empty response")
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


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
    if not context or len(context["list"]) == 0 or not context["timestamp"]:
        # in case context was not loaded yet, the context dictionary will be empty
        # and therefore loaded is needed
        return True
    current_time = datetime.now()
    fetch_interval_seconds = timedelta(hours=float(client.fetch_interval_hours))
    return context["timestamp"] < date_to_timestamp(current_time - fetch_interval_seconds)


def get_url_data(client: Client, url: str):
    url = remove_last_slash(url)
    integration_context = demisto.getIntegrationContext()
    current_data_url = None
    if is_reload_needed(client, integration_context):
        data = reload(client)
        if url in data:
            current_data_url = data[url]
    else:
        if url in integration_context["list"]:
            current_data_url = integration_context["list"][url]
    return current_data_url, url


def create_dbot(url_data, url):
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


def url_command(client: Client, url: str):
    url_data, url = get_url_data(client, url)
    markdown = "### PhishTankV2 Database - URL Query \n"
    if url_data and "verified" in url_data.keys():
        dbot = create_dbot(url_data, url)
        output = Common.URL(url, dbot).to_context()
        markdown += create_verified_markdown(url_data, url)
    else:
        markdown += f'#### No matches for URL {url} \n'
        dbot = Common.DBotScore(url, DBotScoreType.URL, "PhishTankV2", 0)
        output = Common.URL(url, dbot).to_context()
    return CommandResults(readable_output=markdown, outputs=output)


def phishtank_reload_command(client: Client):
    data = reload(client)
    current_date = date_to_timestamp(datetime.now(), DATE_FORMAT)
    context = {"list": data, "timestamp": current_date}
    demisto.setIntegrationContext(context)
    output = 'PhishTankV2 Database reloaded \n'
    output += f'Total **{len(data.keys())}** URLs loaded.\n'
    return CommandResults(readable_output=output)


def phishtank_status_command():
    data = demisto.getIntegrationContext()
    status = "PhishTankV2 Database Status\n"
    if not data or len(data["list"]) == 0:
        status += "Database not loaded.\n"
    else:
        last_load = datetime.utcfromtimestamp(data["timestamp"] / 1000.0).strftime("%a %b %d %Y %H:%M:%S (UTC)")
        status += f'Total **{len(data["list"].keys())}** URLs loaded.\n' \
                  f'Last Load time **{last_load}**\n'
    return CommandResults(readable_output=status)


def reload(client: Client) -> dict:
    """
    This function is responsible for parsing an API response and saving all relevant
    information into a dictionary

    Args:
        client:
        (Client) : client to use in the PhisTankV2 integration.

    Returns:
        dictionary of http response. Each url is a key and his values are:
            "id,submission_time,verified,verification_time,online,target"
    """
    response = client.get_http_request(RELOAD_DATA_URL_SUFFIX)
    if not response:
        return dict()
    response = response.splitlines()
    parsed_response = {}
    columns = response[0].strip().split(",")  # get csv headers
    for index, line in list(enumerate(response))[1:]:
        line = line.split(",")
        current_line_length = len(line)
        if current_line_length < RESPONSE_LINE_LENGTH:
            next_line = response[index + 1].strip().split(",")
            if len(next_line) >= RESPONSE_LINE_LENGTH:
                # in case current line does not contain all details and following line is not the rest of this line
                # there is a specific line in the response csv that is broken into 2 following lines.
                # if this condition is True, the following line is NOT the rest of current line, so coninu
                continue
            else:
                # handle case of line that was cut into 2 following lines
                # here the first part of the line concat with the last part
                line = line + next_line
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
            url = demisto.args().get("url")
            return_results(url_command(client, url))

        elif demisto.command() == 'phishtank-reload':
            return_results(phishtank_reload_command(client))

        elif demisto.command() == 'phishtank-status':
            return_results(phishtank_status_command())

        elif demisto.command() is None:
            raise NotImplementedError(
                'Command "{}" is not implemented.'.format(command))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
