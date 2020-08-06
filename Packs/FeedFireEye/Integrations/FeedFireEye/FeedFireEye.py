from typing import Tuple, List, Dict

import urllib3
from requests.auth import HTTPBasicAuth

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'FireEye Feed'
API_URL = 'https://api.intelligence.fireeye.com'


class STIX21Processor:
    """
    https://oasis-open.github.io/cti-documentation/stix/intro.html
    """

    def __init__(self, raw_indicators: List, relationships: Dict, entities: Dict):
        self.raw_indicators = raw_indicators
        self.relationships = raw_indicators
        self.entities = raw_indicators

        self.type_to_processor = {
            'tool': self.process_tool,
            'note': self.process_note,
            'report': self.process_report,
            'opinion': self.process_opinion,
            'malware': self.process_malware,
            'campaign': self.process_campaign,
            'grouping': self.process_grouping,
            'identity': self.process_identity,
            'location': self.process_location,
            'sighting': self.process_sighting,
            'relationship': self.process_relationship,
            'threat_actor': self.process_threat_actor,
            'observed_data': self.process_observed_data,
            'vulnerability': self.process_vulnerability,
            'attack_pattern': self.process_attack_pattern,
            'infrastructure': self.process_infrastructure,
            'course_of_action': self.process_course_of_action,
            'malware_analysis': self.process_malware_analysis,
            'attack_intrusion_set': self.process_intrusion_set,
        }

    def process_indicators(self):
        processed_indicators = list()  # type: List

        for raw_data in self.raw_indicators:
            processed_indicator = self.process_indicator(raw_data)
            if processed_indicator:
                processed_indicators.append(processed_indicator)

        return processed_indicators

    @staticmethod
    def process_indicator_value(indicator_pattern_value: str) -> Tuple[str, str, Dict]:
        indicator_pattern_value = indicator_pattern_value[1:-1]

        if indicator_pattern_value.startswith('file'):
            hash_values = indicator_pattern_value.split('OR')
            hashes_dict = dict()  # type: Dict

            for h in hash_values:
                key, value = h.split('=')
                hashes_dict[key.strip().split('file:hashes.')[1].replace("'", '')] = value.strip().replace("'", '')

            return 'file', hashes_dict['MD5'], hashes_dict

        else:
            key, value = indicator_pattern_value.split(':value=')
            return key, value[1:-1], {}

    def process_indicator(self, raw_data):
        indicator = dict()

        _, value, hashes = self.process_indicator_value(raw_data.get('pattern'))

        indicator['type'] = auto_detect_indicator_type(value)
        if indicator['type']:
            indicator['value'] = value
            indicator['rawJSON'] = {
                'fireeye_id': raw_data.get('id'),
                'fireeye_labels': raw_data.get('labels'),
                'fireeye_revoked': raw_data.get('revoked'),
                'fireeye_created_date': raw_data.get('created'),
                'fireeye_confidence': raw_data.get('confidence'),
                'fireeye_valid_from': raw_data.get('valid_from'),
                'fireeye_modified_date': raw_data.get('modified'),
                'indicator_types': raw_data.get('indicator_types'),
                'fireeye_valid_until': raw_data.get('valid_until'),
                'fireeye_description': raw_data.get('description')
            }

            if hashes:
                indicator['rawJSON']['MD5'] = hashes['MD5']
                indicator['rawJSON']['SHA-1'] = hashes['SHA-1']
                indicator['rawJSON']['SHA-256'] = hashes['SHA-256']

            return indicator

        return None

    @staticmethod
    def process_attack_pattern(raw_data):
        pass

    @staticmethod
    def process_campaign(raw_data):
        pass

    @staticmethod
    def process_course_of_action(raw_data):
        pass

    @staticmethod
    def process_grouping(raw_data):
        pass

    @staticmethod
    def process_identity(raw_data):
        pass

    @staticmethod
    def process_infrastructure(raw_data):
        pass

    @staticmethod
    def process_intrusion_set(raw_data):
        pass

    @staticmethod
    def process_location(raw_data):
        pass

    @staticmethod
    def process_malware(raw_data):
        pass

    @staticmethod
    def process_malware_analysis(raw_data):
        pass

    @staticmethod
    def process_note(raw_data):
        pass

    @staticmethod
    def process_observed_data(raw_data):
        pass

    @staticmethod
    def process_opinion(raw_data):
        pass

    @staticmethod
    def process_report(raw_data):
        pass

    @staticmethod
    def process_threat_actor(raw_data):
        pass

    @staticmethod
    def process_tool(raw_data):
        pass

    @staticmethod
    def process_vulnerability(raw_data):
        pass

    @staticmethod
    def process_relationship(raw_data):
        pass

    @staticmethod
    def process_sighting(raw_data):
        pass


class Client(BaseClient):
    """Client to use in the FireEye Feed integration. Overrides BaseClient.

    Args:
        insecure (bool): False if feed HTTPS server certificate should be verified, True otherwise.
        proxy (bool): False if feed HTTPS server certificate will not use proxies, True otherwise.
    """

    def __init__(self, public_key: str, private_key: str,
                 polling_timeout: int = 20, insecure: bool = False, proxy: bool = False):
        super().__init__(base_url=API_URL, verify=not insecure, proxy=proxy)
        self.public_key = public_key
        self.private_key = private_key
        self._polling_timeout = polling_timeout

    @staticmethod
    def parse_access_token_expiration_time(expires_in: str) -> int:
        try:
            current_time = datetime.now()
            expiration_time = current_time + timedelta(seconds=int(expires_in))
            epoch_expiration_time = int(expiration_time.strftime('%s'))
        except ValueError:
            demisto.info('INFO - could not parse expiration time for access token.')
            epoch_expiration_time = 0

        return epoch_expiration_time

    def fetch_new_access_token(self):
        response = self._http_request(
            method='POST',
            url_suffix='token',
            data={'grant_type': 'client_credentials'},
            auth=HTTPBasicAuth(self.public_key, self.private_key),
            timeout=self._polling_timeout
        )

        auth_token = response.get('access_token')
        expires_in = response.get('expires_in')
        epoch_expiration_time = self.parse_access_token_expiration_time(expires_in)

        demisto.setIntegrationContext(
            {
                'auth_token': auth_token,
                'expiration_time': epoch_expiration_time
            }
        )

        return auth_token

    def get_access_token(self):
        last_token_fetched_expiration_time = demisto.getIntegrationContext().get('expiration_time')
        current_time = int(datetime.now().strftime('%s'))

        if last_token_fetched_expiration_time and last_token_fetched_expiration_time > current_time:
            auth_token = demisto.getIntegrationContext().get('auth_token')
        else:
            auth_token = self.fetch_new_access_token()

        return auth_token

    def fetch_all_indicators_from_api(self) -> Tuple[List, Dict, Dict]:
        raw_indicators = list()  # type: List
        relationships = dict()  # type: Dict
        stix_entities = dict()  # type: Dict

        headers = {
            'Accept': 'application/vnd.oasis.stix+json; version=2.1',
            'X-App-Name': 'content.xsoar.cortex.paloaltonetworks.v1.0',
            'Authorization': f'Bearer {self.get_access_token()}'
        }

        query_url = '/collections/indicators/objects?length=1000'
        while True:
            response = self._http_request(
                method='GET',
                url_suffix=query_url,
                headers=headers,
                timeout=self._polling_timeout,
                resp_type='response'
            )

            if response.status_code == 204:
                demisto.info(f'{INTEGRATION_NAME} info - '
                             f'API Status Code: {response.status_code} No Content Available for this timeframe.')
                return [], {}, {}

            if response.status_code != 200:
                demisto.debug(f'{INTEGRATION_NAME} debug - '
                              f'API Status Code: {response.status_code} Error Reason: {response.text}')
                return [], {}, {}

            if response.status_code == 200:
                objects_fetched = response.json().get('objects')

                for obj in objects_fetched:
                    if obj.get('type') == 'indicator':
                        raw_indicators.append(obj)
                    elif obj.get('type') == 'relationship':
                        relationships[obj.get('id')] = obj
                    else:
                        stix_entities[obj.get('id')] = obj
                try:
                    query_url = response.links['next']['url']
                    query_url = query_url.split('https://api.intelligence.fireeye.com')[1]
                except KeyError:
                    break

        return raw_indicators, relationships, stix_entities

    def build_iterator(self) -> List:
        raw_indicators, relationships, stix_entities = self.fetch_all_indicators_from_api()
        stix_processor = STIX21Processor(raw_indicators, relationships, stix_entities)
        return stix_processor.process_indicators()


def test_module(client: Client):
    client.get_access_token()
    auth_token = demisto.getIntegrationContext().get('auth_token')
    expiration_time = demisto.getIntegrationContext().get('expiration_time')
    return f'{auth_token} - {expiration_time}', {}, {}


def get_indicators_command(client: Client, feedTags: list):
    """Retrieves indicators from the feed to the war-room.

    Args:
        client (Client): Client object configured according to instance arguments.
        feedTags: The indicator tags.

    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. The raw data of the indicators.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators, raw_response = fetch_indicators_command(client, feedTags, limit)

    human_readable = tableToMarkdown('Indicators from FireEye Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': raw_response}


def fetch_indicators_command(client: Client, feedTags: list, limit: int = -1):
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client (Client): Client object configured according to instance arguments.
        limit (int): Maximum number of indicators to return.
        feedTags (list): Indicator tags
    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. Data to be entered to context.
            Dict. The raw data of the indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    raw_response = []

    if limit != -1:
        iterator = iterator[:limit]

    for indicator in iterator:
        indicators.append({
            'value': indicator['value'],
            'type': indicator['type'],
            'rawJSON': indicator
        })

        raw_response.append(indicator)

    return indicators, raw_response


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """

    public_key = demisto.params().get('credentials').get('identifier')
    private_key = demisto.params().get('credentials').get('password')

    feedTags = argToList(demisto.params().get('feedTags'))

    polling_arg = demisto.params().get('polling_timeout', '')
    polling_timeout = int(polling_arg) if polling_arg.isdigit() else 20
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    command = demisto.command()
    try:
        client = Client(public_key, private_key, polling_timeout, insecure, proxy)
        if command == 'test-module':
            return_outputs(*test_module(client))
        elif command == 'fireeye-get-indicators':
            if feedTags:
                feedTags['tags'] = feedTags
            return_outputs(*get_indicators_command(client, feedTags))
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators_command(client, feedTags)

            for single_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(single_batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception:
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
