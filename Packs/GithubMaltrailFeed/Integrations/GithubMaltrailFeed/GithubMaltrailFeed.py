import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import base64
from datetime import datetime
import regex

# CONSTANTS
SOURCE_NAME = "Github Maltrail Feed"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
COMMIT_LIMIT = 100

# ############################## OVERWRITE REGEX FORMATTING ###############################
regexFlags = re.M  # Multi line matching
RGX_IP = r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"


class Client(BaseClient):

    def __init__(self, params: dict):
        self._verify: bool = not params.get('insecure', False)
        self.user = params.get('user')
        self.token = (params.get('api_token') or {}).get('password', '')
        self.repo = params.get('repository')
        self.url = params.get('base_url')
        # self.base_url = f'{self.url}/{self.user}/{self.repo}'
        self.base_url = urljoin(self.url, self.user)
        self.base_url = urljoin(self.base_url, self.repo)
        handle_proxy()

    def http_request_indicators(self):
        res = requests.get(
            url=self.base_url,
            verify=self._verify
        )
        try:
            res.raise_for_status()
        except Exception:
            demisto.info(f'Github Maltrail Feed - exception in request: {res.status_code!r} {res.content!r}')
            raise
        return res.text

    def getclienturl(self):
        return self.base_url

    def http_request(self, url_endpoint, params: dict = None):
        """The HTTP request for daily feeds.
        Returns:
            list. A list of indicators fetched from the feed.
        """
        self.headers = {
            'Authorization': "Bearer " + self.token
        }
        res = requests.request(
            method="GET",
            url=urljoin(self.base_url, url_endpoint),
            verify=self._verify,
            headers=self.headers,
            params=params
        )
        return res


def fetch_indicators(client: Client, url: str, limit: int = None, params: dict = None):
    if params:
        feed_tags = argToList(params.get('feedTags', []))
        tlp_color = params.get('tlp_color')
    else:
        feed_tags = None
        tlp_color = None
    response = client.http_request(url)
    indicators_list = []
    demisto.debug('Fetch of indicators started ###')

    if response.ok:
        content = response.json()["content"]
        file_content = base64.b64decode(content).decode("utf-8")
        lines = file_content.split("\n")
        for line in lines:
            if '#' not in line and line != '':
                type_ = auto_detect_indicator_type(line)
                if regex.search(RGX_IP, line):
                    if line.startswith('http://'):
                        line = line.removeprefix('http://')
                    elif line.startswith('https://'):
                        line = line.removeprefix('https://')
                    else:
                        line = line.split(':')[0]
                    type_ = "IP"
                elif type_ == "URL" and not line.startswith('http://') and not line.startswith('https://'):
                    line = 'http://' + line
                raw_data = {
                    'value': line,
                    'type': type_,
                }
                indicator_obj = {
                    'value': line,
                    'type': type_,
                    'service': "GitHub Maltrail Feed",
                    'fields': {},
                    'rawJSON': raw_data
                }
                if feed_tags:
                    indicator_obj['fields']['tags'] = feed_tags
                if tlp_color:
                    indicator_obj['fields']['trafficlightprotocol'] = tlp_color
                indicators_list.append(indicator_obj)
                # If limit is reached, break loop
                if limit and isinstance(limit, int) and len(indicators_list) >= limit:
                    break
    else:
        demisto.error(f"Error: {response.status_code} - {response.json()['message']}")
    return indicators_list


def get_last_commit_date(client):
    api_url = "/commits"
    response = client.http_request(api_url)
    last_commit_date = None
    if response.ok:
        commits = []
        page = 1
        while response.ok and page < COMMIT_LIMIT:
            commits.extend(response.json())
            link_header = response.headers.get('Link')
            if not link_header or 'rel="next"' not in link_header:
                break
            page += 1
            response = client.http_request(api_url, params={'page': page})
        for commit in commits:
            if 'qakbot' in commit['commit']['message']:
                commit_date = date_to_timestamp(parse_date_string(commit['commit']['author']['date'], DATE_FORMAT))
                if not last_commit_date:
                    last_commit_date = commit_date
                elif commit_date > last_commit_date:
                    last_commit_date = commit_date

    return last_commit_date


def fetch_indicators_command(client: Client, params: dict = None):
    integration_context = get_integration_context()
    api_url = "/contents/trails/static/malware/qakbot.txt"
    indicators_list = []
    # First Fetch
    if not integration_context:
        time_of_first_fetch = date_to_timestamp(datetime.now(), DATE_FORMAT)
        set_integration_context({'time_of_last_fetch': time_of_first_fetch})
        indicators_list = fetch_indicators(client, api_url, None, params)
    else:
        time_from_last_update = integration_context.get('time_of_last_fetch')
        now = date_to_timestamp(datetime.now(), DATE_FORMAT)
        last_commit_date = get_last_commit_date(client)
        if last_commit_date > time_from_last_update:
            indicators_list = fetch_indicators(client, api_url, None, params)
            set_integration_context({'time_of_last_fetch': now})
        else:
            demisto.debug('### Nothing to fetch')

    return indicators_list


def get_indicators_command(client: Client, params: dict, args: dict):
    try:
        limit = int(args.get('limit', 50))
    except ValueError:
        raise ValueError('The limit argument must be a number.')
    api_url = "/contents/trails/static/malware/qakbot.txt"
    indicators_list = fetch_indicators(client, api_url, limit, params)
    entry_result = indicators_list[:limit]
    human_readable = tableToMarkdown("Indicators from Github Maltrail:", entry_result,
                                     headers=['value', 'type', 'firstseenbysource', 'lastseenbysource', 'name'],
                                     removeNull=True)
    return human_readable, {}, entry_result


def test_module_command(client: Client, params: dict, args: dict):
    client.http_request_indicators()
    return 'ok', {}, {}


def main():
    params = demisto.params()
    args = demisto.args()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module_command,
        'gh-maltrail-get-indicators': get_indicators_command
    }

    try:
        client = Client(params)
        if command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, params, args)
            return_outputs(readable_output, outputs, raw_response)

    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
