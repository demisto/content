import urllib3

from CommonServerPython import *

urllib3.disable_warnings()

''' CONSTANTS '''

BASE_URL = 'http://data.phishtank.com'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
FULL_URL = "data/online-valid.csv"

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
            raise DemistoException("Error - could not fetch PhishTankV2 database")
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
        return True
    current_time = datetime.now()
    fetch_interval_seconds = timedelta(hours=float(client.fetch_interval_hours))
    if context["timestamp"] < date_to_timestamp(current_time - fetch_interval_seconds):
        return True
    return False


def get_url_data(client: Client, url: str):
    url = remove_last_slash(url)
    data = demisto.getIntegrationContext()
    current_data_url = None
    if is_reload_needed(client, data):
        data = reload(client)
        if url in data:
            current_data_url = data[url]
    else:
        if url in data["list"]:
            current_data_url = data["list"][url]
    return current_data_url, url


def url_command(client: Client, url: str):
    url_data, url = get_url_data(client, url)
    mark_down = "### PhishTankV2 Database - URL Query \n"
    if url_data and "verified" in url_data.keys():
        if url_data["verified"] == "yes":
            d_bot_score = 3
        else:
            d_bot_score = 2
        d_bot = Common.DBotScore(url, DBotScoreType.URL, "PhishTankV2", d_bot_score,
                                 "Match found in PhishTankV2 database")
        output = Common.URL(url, d_bot).to_context()
        mark_down += f'#### Found matches for URL {url} \n'
        mark_down += tableToMarkdown('', url_data)
        phish_tank_url = f'http://www.phishtank.com/phish_detail.php?phish_id={url_data["phish_id"]}'
        mark_down += f'Additional details at {phish_tank_url} \n'
    else:
        mark_down += f'#### No matches for URL {url} \n'
        d_bot = Common.DBotScore(url, DBotScoreType.URL, "PhishTankV2", 0)
        output = Common.URL(url, d_bot).to_context()
    # res = {'url': url, 'match': True}
    return CommandResults(readable_output=mark_down, outputs=output)


def phishtank_reload_command(client: Client):
    data = reload(client)
    current_date = date_to_timestamp(datetime.now(), DATE_FORMAT)
    context = {"list": data, "timestamp": current_date}
    demisto.setIntegrationContext(context)
    output = 'PhishTankV2 Database reloaded \n'
    output += f'Total **{len(data.keys())}** URLs loaded.\n'
    demisto.debug(f'got here {output}')
    return CommandResults(readable_output=output)


def phishtank_status_command():
    data = demisto.getIntegrationContext()
    status = "PhishTankV2 Database Status\n"
    if not data or len(data["list"]) == 0:
        status += "Database not loaded.\n"
    else:
        status += f'Total **{len(data["list"].keys())}** URLs loaded.\n'
        last_load = datetime.utcfromtimestamp(data["timestamp"] / 1000.0).strftime("%a %b %d %Y %H:%M:%S (UTC)")
        status += f'Last Load time **{last_load}**\n'
    return CommandResults(readable_output=status)


def reload(client: Client) -> dict:
    """
    Args:
        client: Client to use in the PhisTankV2 integration.

    Returns: dictionary of http response. Each url is a key and his values are:
            "phish_id,submission_time,verified,verification_time,online,target"
    """
    res = client.get_http_request(FULL_URL)
    if not res:
        return dict()
    res = res.splitlines()
    data = {}
    columns = res[0].strip().split(",")  # get csv headers
    for index, line in list(enumerate(res))[1:]:
        line = line.split(",")
        if len(line) < 8 and len(res[index + 1].strip().split(",")) >= 8:
            # case that line does not have all details and following line is not the rest of this line
            continue
        elif len(line) < 8 and len(res[index + 1].strip().split(",")) < 8:
            # handle case of line that was cut into 2 following lines
            line = line + res[index + 1].strip().split(",")
        url = remove_last_slash(line[columns.index("url")])
        if url:
            data[url] = {
                "phish_id": line[columns.index("phish_id")].strip(),
                "submission_time": line[columns.index("submission_time")].strip(),
                "verified": line[columns.index("verified")].strip(),
                "verification_time": line[columns.index("verification_time")].strip(),
                "online": line[columns.index("online")].strip(),
                "target": line[columns.index("target")].strip(),
            }
    return data


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
