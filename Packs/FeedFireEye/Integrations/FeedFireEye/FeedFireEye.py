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
        self.relationships = relationships
        self.entities = entities

        self.type_to_processor = {
            'tool': self.process_tool,
            'report': self.process_report,
            'opinion': self.process_opinion,
            'malware': self.process_malware,
            'campaign': self.process_campaign,
            'grouping': self.process_grouping,
            'identity': self.process_identity,
            'location': self.process_location,
            'sighting': self.process_sighting,
            'relationship': self.process_relationship,
            'threat-actor': self.process_threat_actor,
            'observed_data': self.process_observed_data,
            'vulnerability': self.process_vulnerability,
            'attack_pattern': self.process_attack_pattern,
            'infrastructure': self.process_infrastructure,
            'course-of-action': self.process_course_of_action,
            'malware-analysis': self.process_malware_analysis,
            'attack-intrusion-set': self.process_intrusion_set,
            'marking-definition': self.process_marking_definition,
        }

    def process_indicators(self):
        processed_indicators = list()  # type: List

        for raw_data in self.raw_indicators:
            processed_indicator = self.process_indicator(raw_data)
            if processed_indicator:
                processed_indicators += processed_indicator

        return processed_indicators

    @staticmethod
    def process_indicator_value(indicator_pattern_value: str) -> Tuple[List, List, Dict]:
        indicator_pattern_value = indicator_pattern_value[1:-1]

        if indicator_pattern_value.startswith('file'):
            hash_values = indicator_pattern_value.split('OR')
            hashes_dict = dict()  # type: Dict

            for h in hash_values:
                key, value = h.split('=')
                hashes_dict[key.strip().split('file:hashes.')[1].replace("'", '')] = value.strip().replace("'", '')

            return ['file'], [hashes_dict['MD5']], hashes_dict

        try:
            keys = list()  # type: List
            values = list()  # type: List
            for indicator_value in indicator_pattern_value.split('AND'):
                if indicator_value.startswith('email-message'):
                    key, value = indicator_value.split(':from_ref.value=')
                else:
                    try:
                        key, value = indicator_value.split(':value=')
                    except:
                        continue

                keys.append(key.strip().replace("'", '').replace('[', '').replace(']', ''))
                values.append(value.strip().replace("'", '').replace('[', '').replace(']', ''))
            return keys, values, {}
        except:
            return_error(indicator_pattern_value)
            return [], [], {}

    def process_indicator(self, raw_data):
        indicators = list()

        _, values, hashes = self.process_indicator_value(raw_data.get('pattern'))

        for value in values:
            indicator = dict()
            indicator['type'] = auto_detect_indicator_type(value)
            if indicator['type']:
                indicator['value'] = value
                indicator['fields'] = {}
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

                if 'MD5' in hashes:
                    indicator['rawJSON']['MD5'] = hashes['MD5']
                if 'SHA-1' in hashes:
                    indicator['rawJSON']['SHA-1'] = hashes['SHA-1']
                if 'SHA-256' in hashes:
                    indicator['rawJSON']['SHA-256'] = hashes['SHA-256']

                indicators.append(indicator)

        return indicators

    def process_stix_entities(self):
        processed_entities = list()  # type: List

        for entity_type, value in self.entities.items():
            if value.get('type') in self.type_to_processor:
                processed_entity = self.type_to_processor[value.get('type')](value)
                if processed_entity:
                    processed_entities.append(processed_entity)

        return processed_entities

    @staticmethod
    def process_attack_pattern(raw_data):
        pass

    @staticmethod
    def process_malware(raw_data):
        entity = dict()

        entity['type'] = 'STIX Malware'
        entity['value'] = raw_data.get('name')
        entity['fields'] = {
            'stixid': raw_data.get('id'),
            'stixdescription': raw_data.get('description'),
            'stixismalwarefamily': raw_data.get('is_family'),
            'stixmalwaretypes': raw_data.get('malware_types')
        }
        entity['rawJSON'] = {
            'fireeye_id': raw_data.get('id'),
            'fireeye_labels': raw_data.get('labels'),
            'fireeye_aliases': raw_data.get('aliases'),
            'fireeye_revoked': raw_data.get('revoked'),
            'fireeye_is_family': raw_data.get('is_family'),
            'fireeye_created_date': raw_data.get('created'),
            'fireeye_modified_date': raw_data.get('modified'),
            'fireeye_description': raw_data.get('description'),
            'fireeye_malware_types': raw_data.get('malware_types'),
            'fireeye_os_execution_envs': raw_data.get('os_execution_envs'),
            'fireeye_external_references': raw_data.get('external_references'),
        }

        return entity

    @staticmethod
    def process_report(raw_data):
        pass

    @staticmethod
    def process_threat_actor(raw_data):
        entity = dict()

        entity['type'] = 'STIX Threat Actor'
        entity['value'] = raw_data.get('name')
        entity['fields'] = {
            'stixid': raw_data.get('id'),
            'stixaliases': raw_data.get('aliases'),
            'stixdescription': raw_data.get('description'),
            'stixsophistication': raw_data.get('sophistication'),
            'stixprimarymotivation': raw_data.get('primary_motivation'),
            'stixsecondarymotivations': raw_data.get('secondary_motivations'),
        }
        entity['rawJSON'] = {
            'fireeye_id': raw_data.get('id'),
            'fireeye_labels': raw_data.get('labels'),
            'fireeye_aliases': raw_data.get('aliases'),
            'fireeye_revoked': raw_data.get('revoked'),
            'fireeye_created_date': raw_data.get('created'),
            'fireeye_modified_date': raw_data.get('modified'),
            'fireeye_description': raw_data.get('description'),
            'fireeye_sophistication': raw_data.get('sophistication'),
            'fireeye_primary_motivation': raw_data.get('primary_motivation'),
            'fireeye_threat_actor_types': raw_data.get('threat_actor_types'),
            'fireeye_object_marking_refs': raw_data.get('object_marking_refs'),
            'fireeye_secondary_motivations': raw_data.get('secondary_motivations'),
            'fireeye_intended_effect': raw_data.get('x_fireeye_com_intended_effect'),
            'fireeye_planning_and_operational_support': raw_data.get('x_fireeye_com_planning_and_operational_support'),
        }

        return entity

    @staticmethod
    def process_tool(raw_data):
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
    def process_malware_analysis(raw_data):
        pass

    @staticmethod
    def process_marking_definition(raw_data):
        pass

    @staticmethod
    def process_observed_data(raw_data):
        pass

    @staticmethod
    def process_opinion(raw_data):
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
        self.get_access_token()

        raw_indicators, relationships, stix_entities = self.fetch_all_indicators_from_api()
        stix_processor = STIX21Processor(raw_indicators, relationships, stix_entities)

        indicators = stix_processor.process_indicators()
        stix_indicators = stix_processor.process_stix_entities()
        return indicators + stix_indicators


def test_module(client: Client):
    client.build_iterator()
    return 'ok'


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
                                     headers=['value', 'type', 'rawJSON'], removeNull=True)

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
            'fields': indicator['fields'].update({
                'tags': feedTags
            }),
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

    feedTags = argToList(demisto.params().get('feedTags'), [])

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
