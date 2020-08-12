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

    def __init__(self, raw_indicators: List, relationships: Dict, entities: Dict, reports: List):
        self.raw_indicators = raw_indicators
        self.relationships = relationships
        self.entities = entities
        self.reports = reports

        self.type_to_processor = {
            'report': self.process_report,
            'malware': self.process_malware,
            'threat-actor': self.process_threat_actor,
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
        """Processes the `pattern` value from the feed response into indicator types according to FireEye, their values,
            and, in case of file type, it's hashes values.

        Args:
            indicator_pattern_value (str): The raw value of the `pattern` value from the feed response.

        Returns:
            Tuple[List, List, Dict]:
                indicator_types - List of indicator types according to FireEye classification.
                values - List of indicator values.
                hashes - Dict of `hash_type: hash_value`, in case of `file` indicator type.
        """
        indicator_pattern_value = indicator_pattern_value[1:-1]

        if indicator_pattern_value.startswith('file'):
            hash_values = indicator_pattern_value.split('OR')
            hashes_dict = dict()  # type: Dict

            for h in hash_values:
                key, value = h.split('=')
                hashes_dict[key.strip().split('file:hashes.')[1].replace("'", '')] = value.strip().replace("'", '')

            return ['file'], [hashes_dict['MD5']], hashes_dict

        try:
            indicator_types = list()  # type: List
            values = list()  # type: List
            for indicator_value in indicator_pattern_value.split('AND'):
                if indicator_value.startswith('email-message'):
                    key, value = indicator_value.split(':from_ref.value=')
                else:
                    try:
                        key, value = indicator_value.split(':value=')
                    except:
                        continue

                indicator_types.append(key.strip().replace("'", '').replace('[', '').replace(']', ''))
                values.append(value.strip().replace("'", '').replace('[', '').replace(']', ''))
            return indicator_types, values, {}
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

    def process_reports(self):
        processed_reports = list()  # type: List

        for raw_data in self.reports:
            processed_report = self.process_report(raw_data)
            if processed_report:
                processed_reports.append(processed_report)

        return processed_reports

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
    def process_report(raw_data):
        report = dict()

        report['type'] = 'STIX Report'
        report['value'] = raw_data.get('name')
        report['fields'] = {
            'stixid': raw_data.get('id'),
            'published': raw_data.get('published'),
            'stixdescription': raw_data.get('description'),
        }
        report['rawJSON'] = {
            'fireeye_id': raw_data.get('id'),
            'fireeye_labels': raw_data.get('labels'),
            'fireeye_threats': raw_data.get('threats'),
            'fireeye_revoked': raw_data.get('revoked'),
            'fireeye_published': raw_data.get('published'),
            'fireeye_created_date': raw_data.get('created'),
            'fireeye_modified_date': raw_data.get('modified'),
            'fireeye_description': raw_data.get('description'),
            'fireeye_report_types': raw_data.get('report_types'),
            'fireeye_metadata': raw_data.get('x_fireeye_com_metadata'),
            'fireeye_external_references': raw_data.get('external_references'),
            'fireeye_tracking_info': raw_data.get('x_fireeye_com_tracking_info'),
            'fireeye_exploitation_rating': raw_data.get('x_fireeye_com_exploitation_rating'),
            'fireeye_additional_description_sections': raw_data.get('x_fireeye_com_additional_description_sections'),
        }

        return report


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
        """Computes the expiration time of the new fetched authentication time.

        Args:
            expires_in (str): Amount of time the authentication token will be valid according to the API.

        Returns:
            int. Epoch time that represents the expiration timeof the token.
        """
        try:
            current_time = datetime.now()
            expiration_time = current_time + timedelta(seconds=int(expires_in))
            epoch_expiration_time = int(expiration_time.strftime('%s'))
        except ValueError:
            demisto.info('INFO - could not parse expiration time for access token.')
            epoch_expiration_time = 0

        return epoch_expiration_time

    def fetch_new_access_token(self) -> str:
        """Fetches new authentication token from the API.

        Returns:
            str. Authentication token.
        """
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

    def get_access_token(self) -> str:
        """Returns the current valid authentication token for the feed.

        Returns:
            str. Authentication token.
        """
        last_token_fetched_expiration_time = demisto.getIntegrationContext().get('expiration_time')
        current_time = int(datetime.now().strftime('%s'))

        if last_token_fetched_expiration_time and last_token_fetched_expiration_time > current_time:
            auth_token = demisto.getIntegrationContext().get('auth_token')
        else:
            auth_token = self.fetch_new_access_token()

        return auth_token

    def fetch_all_indicators_from_api(self) -> Tuple[List, Dict, Dict]:
        """Collects raw data of indicators and their relationships from the feed.

        Returns:
            Tuple[List, Dict, Dict].
                raw_indicators - List of STIX 2.1 indicators objects.
                relationships - Dict of `id: STIX 2.1 relationship object`.
                stix_entities - Dict of `id: STIX 2.1 entity object`.
        """
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

    def fetch_all_reports_from_api(self) -> List:
        """Collects reports raw data from the feed.

        Returns:
            List. List of STIX 2.1 reports objects.
        """
        raw_reports = list()  # type: List

        headers = {
            'Accept': 'application/vnd.oasis.stix+json; version=2.1',
            'X-App-Name': 'content.xsoar.cortex.paloaltonetworks.v1.0',
            'Authorization': f'Bearer {self.get_access_token()}'
        }

        query_url = '/collections/reports/objects?length=100'
        while True:
            response = self._http_request(
                method='GET',
                url_suffix=query_url,
                headers=headers,
                timeout=self._polling_timeout,
                resp_type='response'
            )

            if response.status_code != 200:
                demisto.debug(f'{INTEGRATION_NAME} debug - '
                              f'API Status Code: {response.status_code} Error Reason: {response.text}')
                return []

            if response.status_code == 200:
                raw_reports += [report for report in response.json().get('objects')]

                try:
                    query_url = response.links['next']['url']
                    query_url = query_url.split('https://api.intelligence.fireeye.com')[1]
                except KeyError:
                    break

        return raw_reports

    def build_iterator(self) -> List:
        self.get_access_token()

        raw_indicators, relationships, stix_entities = self.fetch_all_indicators_from_api()
        raw_reports = self.fetch_all_reports_from_api()

        stix_processor = STIX21Processor(raw_indicators, relationships, stix_entities, raw_reports)

        indicators = stix_processor.process_indicators()
        stix_indicators = stix_processor.process_stix_entities()
        reports = stix_processor.process_reports()

        return indicators + stix_indicators + reports


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

    feedTags = argToList(demisto.params().get('feedTags'), '')

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
