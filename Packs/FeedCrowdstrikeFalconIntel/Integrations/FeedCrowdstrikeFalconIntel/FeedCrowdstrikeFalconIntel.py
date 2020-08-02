import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# IMPORTS
from datetime import datetime
import requests
from typing import List, Tuple, Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, params):
        self._client_id = params.get('client_id')
        self._client_secret = params.get('client_secret')
        super().__init__(base_url="https://api.crowdstrike.com/", verify=not params.get('insecure', False),
                         ok_codes=tuple(), proxy=params.get('proxy', False))
        self._token = self._generate_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}

    @staticmethod
    def _error_handler(error_entry: dict) -> str:
        errors = error_entry.get("errors", [])
        return '\n' + '\n'.join(f"{error['code']}: {error['message']}" for error in errors)

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')

    def check_quota_status(self, suffix_url_to_filter_by) -> dict:
        return self.http_request('GET', suffix_url_to_filter_by)

    def create_indicators_from_response(self, response, feed_tags: list) -> list:
        """
        Creates a list of indicators from a given response
        Args:
            response: List of dict that represent the response from the api
            feed_tags: The indicator tags
        Returns:
            List of indicators with the correct indicator type.
        """
        parsed_indicators = []  # type:List
        indicator = {}
        for actor in response['resources']:
            if actor:
                indicator = {
                    "type": 'Actor',
                    "value": actor.get('name'),
                    "rawJSON": {
                        'type': 'Actor',
                        'value': actor.get('name'),
                        'service': 'List Actors Feed'
                    },
                    'fields': {'tags': feed_tags, 'actor': actor.get('name'), 'region': actor.get('region'),
                               'actor_capability': actor.get('capability'), 'geo_country': actor.get('origins'),
                               'description': actor.get('short_description'), 'alias': actor.get('known_as'),
                               'creation_date': actor.get('created_date'), 'actor_motivation': actor.get('motivations'),
                               'updated_date': actor.get('last_modified_date'),
                               'actor_target_country': actor.get('target_countries'),
                               'actor_target_industry': actor.get('target_industries')}
                }
                indicator['rawJSON'].update(actor)
            parsed_indicators.append(indicator)

        return parsed_indicators

    def build_actors_filter(self, target_countries, target_industries, custom_filter):
        actors_filter = ''
        if custom_filter:
            actors_filter = custom_filter
            return actors_filter

        if target_countries:
            target_countries = target_countries.split(',')
            target_countries = [country.replace(' ', '%20') for country in target_countries if len(country) > 1]
            for country in target_countries:
                actors_filter += f'target_countries%3A"{country}"%2B'

        if target_industries:
            target_industries = target_industries.split(',')
            target_industries = [industry.replace(' ', '%20') for industry in target_industries if len(industry) > 1]
            for industry in target_industries:
                actors_filter += f'target_industries%3A"{industry}"%2B'

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

    def build_iterator(self, feed_tags: List, limit=None, offset=None, target_countries=None, target_industries=None,
                       custom_filter=None):
        """Builds a list of indicators.
        Returns:
            list. A list of JSON objects representing indicators fetched from a feed.
        """
        actors_filter = self.build_actors_filter(target_countries, target_industries, custom_filter)
        params = self.get_last_modified_time()
        suffix_url_to_filter_by = self.build_url_suffix(params, actors_filter)
        response = self.check_quota_status(suffix_url_to_filter_by)
        parsed_indicators = self.create_indicators_from_response(response, feed_tags)  # list of dict of indicators

        # for get_indicator_command only
        if limit:
            parsed_indicators = parsed_indicators[int(offset): int(offset) + int(limit)]
        return parsed_indicators

    def set_last_modified_time(self):
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        integration_context_to_set = {'last_modified_time': timestamp}
        demisto.setIntegrationContext(integration_context_to_set)

    def get_last_modified_time(self):
        # demisto.setIntegrationContext(None)
        integration_context = demisto.getIntegrationContext()
        if not integration_context:
            params = {}
            self.set_last_modified_time()
            demisto.setIntegrationContext(None)
        else:
            last_modified_time = demisto.getIntegrationContext()
            relevant_time = int(last_modified_time['last_modified_time'])
            params = f"last_modified_date%3A%3E{relevant_time}"
            self.set_last_modified_time()
            demisto.setIntegrationContext(None)
        return params


def module_test_command(client: Client, args: dict, feed_tags: list):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client(Client): CrowdStrike Feed client
        args(Dict): The instance parameters
        feed_tags: The indicator tags

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.build_iterator(argToList(demisto.params().get('feedTags')), 1, 0)
    except Exception:
        raise Exception("Could not fetch CrowdStrike Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok', {}, {}


def get_indicators_command(client: Client, args: dict, feed_tags: list) -> Tuple[str, dict, list]:
    """Initiate a single fetch-indicators

    Args:
        client(Client): The CrowdStrike Client.
        args(dict): Command arguments.
        feed_tags: The indicator tags
    Returns:
        str, dict, list. the markdown table, context JSON and list of indicators
    """
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 150))
    target_countries = args.get('target_countries') if args.get('target_countries') \
        else demisto.params().get('target_countries')
    target_industries = args.get('target_industries')
    custom_filter = args.get('custom_filter')

    indicators = fetch_indicators_command(client, feed_tags, limit, offset, target_countries, target_industries,
                                          custom_filter)

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

    if args.get('limit'):
        human_readable = human_readable
    return human_readable, {}, indicators


def fetch_indicators_command(client: Client, feed_tags: List, limit=None, offset=None, target_countries=None,
                             target_industries=None, custom_filter=None) -> list:
    """Fetch-indicators command from CrowdStrike Feeds

    Args:
        client(Client): CrowdStrike Feed client.
        feed_tags: The indicator tags
        limit: limit the amount of indicators fetched.
        offset: the index of the first index to fetch.
        target_industries: the actor's target_industries.
        target_countries: the actor's target_countries.
        custom_filter: user actor's filter.
    Returns:
        list. List of indicators.
    """
    indicators = client.build_iterator(feed_tags, limit, offset, target_countries, target_industries, custom_filter)

    return indicators


def main():
    params = demisto.params()
    feed_tags = argToList(params.get('feedTags'))
    target_countries = params.get('target_countries')
    target_industries = params.get('target_industries')
    custom_filter = params.get('custom_filter')
    client = Client(params)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'crowdstrike-falcon-intel-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, feed_tags, target_countries=target_countries,
                                                  target_industries=target_industries, custom_filter=custom_filter)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args(),
                                                                       feed_tags)  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in CrowdStrike falcon intel Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
