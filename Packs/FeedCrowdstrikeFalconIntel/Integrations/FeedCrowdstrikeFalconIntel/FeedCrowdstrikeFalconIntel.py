import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
from datetime import datetime
import requests
from typing import List, Tuple, Optional

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

INDICATOR_FIELDS_MAPPER = {
    'stixid': 'id',
    'stixaliases': 'known_as',
    'stixdescription': 'short_description',
    'stixprimarymotivation': 'motivations',
    'aliases': 'known_as',
    'description': 'short_description',
    'primarymotivation': 'motivations',
    'creationdate': 'created_date',
    'updateddate': 'last_modified_date',
    'geocountry': 'origins',
    'region': 'region'
}


class Client(BaseClient):

    def __init__(self, params):
        self._client_id = params.get('client_id')
        self._client_secret = params.get('client_secret')
        self._verify_certificate = not demisto.params().get('insecure', False)
        self._server_url = params.get('server_url', "https://api.crowdstrike.com/")
        super().__init__(base_url=self._server_url, verify=self._verify_certificate,
                         ok_codes=tuple(), proxy=params.get('proxy', False))
        self._token = self._get_access_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}

    @staticmethod
    def _handle_errors(error_entry: dict) -> str:
        errors = error_entry.get("errors", [])
        error_messages = [f"{error['code']}: {error['message']}" for error in errors]
        error_messages_str = '\n'.join(error_messages)
        return error_messages_str

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)

    def _get_access_token(self) -> str:
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')

    def create_indicators_from_response(self, response, feed_tags: list, tlp_color: Optional[str]) -> list:
        parsed_indicators = []  # type:List
        indicator = {}
        for actor in response['resources']:
            if actor:

                fields = {field: actor.get(actor_key) for field, actor_key in INDICATOR_FIELDS_MAPPER.items()}
                fields['tags'] = feed_tags
                if tlp_color:
                    fields['trafficlightprotocol'] = tlp_color

                indicator = {
                    "type": FeedIndicatorType.indicator_type_by_server_version('STIX Threat Actor'),
                    "value": actor.get('name'),
                    "rawJSON": {
                        'type': 'STIX Threat Actor',
                        'value': actor.get('name'),
                        'service': 'List Actors Feed'
                    },
                    'fields': fields
                }

                indicator['rawJSON'].update(actor)
            parsed_indicators.append(indicator)

        return parsed_indicators

    def add_target_countries_to_filter(self, country):
        return f'target_countries%3A"{country}"%2B'

    def add_target_industries_to_filter(self, industry):
        return f'target_industries%3A"{industry}"%2B'

    def convert_countries_and_industries_to_url_shape(self, list_of_targets):
        """
        This function converts a list of targets into the form of a URL filter.
        (united states -> united%20states)

        Args:
            list_of_targets: List of countries or industries.

        Returns:
            The URL filter to filter with.
        """
        list_of_targets = list_of_targets.split(',')
        list_of_targets = [target.replace(' ', '%20') for target in list_of_targets if len(target) > 1]
        return list_of_targets

    def build_actors_filter(self, target_countries, target_industries, custom_filter):
        actors_filter = ''
        if custom_filter:
            actors_filter = custom_filter
            return actors_filter

        if target_countries:
            target_countries = self.convert_countries_and_industries_to_url_shape(target_countries)
            for country in target_countries:
                actors_filter += self.add_target_countries_to_filter(country)

        if target_industries:
            target_industries = self.convert_countries_and_industries_to_url_shape(target_industries)
            for industry in target_industries:
                actors_filter += self.add_target_industries_to_filter(industry)

        if actors_filter:
            actors_filter = '?filter=' + actors_filter[:-3]
        return actors_filter

    def build_url_suffix(self, params, actors_filter):
        url_suffix = "/intel/combined/actors/v1"
        if actors_filter:
            url_suffix = url_suffix + actors_filter
            if params:
                url_suffix = url_suffix + '%2B' + params
        elif params:
            url_suffix = url_suffix + '?filter=' + params
        return url_suffix

    def build_iterator(self, feed_tags: List, tlp_color: Optional[str], limit=None, offset=None, target_countries=None,
                       target_industries=None, custom_filter=None):
        """Builds a list of indicators.
        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        actors_filter = self.build_actors_filter(target_countries, target_industries, custom_filter)

        # for fetch_indicator_command only
        params = {}
        if not limit:
            params = self.get_last_modified_time()

        url_suffix_to_filter_by = self.build_url_suffix(params, actors_filter)
        response = self.http_request('GET', url_suffix_to_filter_by)
        parsed_indicators = self.create_indicators_from_response(response, feed_tags,
                                                                 tlp_color)  # list of dict of indicators

        # for get_indicator_command only
        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]
        return parsed_indicators

    def set_last_modified_time(self):
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        integration_context_to_set = {'last_modified_time': timestamp}
        set_feed_last_run(integration_context_to_set)

    def get_last_modified_time(self):
        integration_context = get_feed_last_run()
        if not integration_context:
            params = ''
            self.set_last_modified_time()
        else:
            last_modified_time = get_feed_last_run()
            relevant_time = int(last_modified_time['last_modified_time'])
            params = f"last_modified_date%3A%3E{relevant_time}"
            self.set_last_modified_time()
        return params


def test_module(client: Client, args: dict, feed_tags: list, tlp_color: Optional[str]):
    try:
        tags = argToList(demisto.params().get('feedTags'))
        client.build_iterator(tags, tlp_color, limit=1, offset=0)
    except Exception:
        raise Exception("Could not fetch CrowdStrike Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict, feed_tags: list, tlp_color: Optional[str]) \
        -> Tuple[str, dict, list]:
    """Initiate a single fetch-indicators

    Args:
        client(Client): The CrowdStrike Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags.
        tlp_color (str): Traffic Light Protocol color.
    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 150))
    target_countries = args.get('target_countries') if args.get('target_countries') \
        else demisto.params().get('target_countries')
    target_industries = args.get('target_industries') if args.get('target_industries') \
        else demisto.params().get('target_industries')
    custom_filter = args.get('custom_filter') if args.get('custom_filter') \
        else demisto.params().get('custom_filter')

    indicators = fetch_indicators(client, feed_tags, tlp_color, limit, offset, target_countries,
                                  target_industries, custom_filter)

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append({
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON'),
            'fields': indicator.get('fields'),
        })

    human_readable = tableToMarkdown("Indicators from CrowdStrike:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'], removeNull=True)

    return human_readable, {}, indicators


def fetch_indicators(client: Client, feed_tags: List, tlp_color: Optional[str], limit=None, offset=None,
                     target_countries=None, target_industries=None, custom_filter=None) -> list:
    """Fetch-indicators command from CrowdStrike Feeds

    Args:
        client(Client): CrowdStrike Feed client.
        feed_tags: The indicator tags.
        tlp_color (str): Traffic Light Protocol color.
        limit: limit the amount of indicators fetched.
        offset: the index of the first index to fetch.
        target_industries: the actor's target_industries.
        target_countries: the actor's target_countries.
        custom_filter: user actor's filter.
    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator(feed_tags, tlp_color, limit, offset, target_countries,
                                       target_industries, custom_filter)

    return indicators


def main():
    params = demisto.params()
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    target_countries = params.get('target_countries')
    target_industries = params.get('target_industries')
    custom_filter = params.get('custom_filter')
    client = Client(params)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': test_module,
        'crowdstrike-falcon-intel-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client, feed_tags, tlp_color, target_countries=target_countries,
                                          target_industries=target_industries, custom_filter=custom_filter)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args(),
                                                                       feed_tags, tlp_color)  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in CrowdStrike falcon intel Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
