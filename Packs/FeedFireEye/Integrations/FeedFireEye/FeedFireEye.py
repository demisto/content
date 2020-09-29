from typing import Tuple, List, Dict, Any, Optional

import urllib3
from requests.auth import HTTPBasicAuth

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'FireEye Feed'
API_URL = 'https://api.intelligence.fireeye.com'

FE_CONFIDENCE_TO_REPUTATION = {
    Common.DBotScore.BAD: 70,
    Common.DBotScore.SUSPICIOUS: 30,
    Common.DBotScore.NONE: 0
}


class STIX21Processor:
    """Processing class for STIX 2.1 objects.

    Args:
        raw_indicators (List): List of STIX 2.1 indicators objects.
        relationships (Dict): Dict of `id: STIX 2.1 relationship object`.
        entities (Dict): Dict of `id: STIX 2.1 entity object`.
        reports (List): List of STIX 2.1 reports objects.
    """

    def __init__(self, raw_indicators: List, relationships: Dict, entities: Dict, reports: List,
                 malicious_threshold: int, reputation_interval: int):
        self.raw_indicators = raw_indicators
        self.relationships = relationships
        self.entities = entities
        self.reports = reports
        self.reputation_interval = reputation_interval

        self.type_to_processor = {
            'report': self.process_report,
            'malware': self.process_malware,
            'threat-actor': self.process_threat_actor,
        }

        FE_CONFIDENCE_TO_REPUTATION[Common.DBotScore.BAD] = malicious_threshold

    def process_indicators(self) -> List:
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
                    except Exception:
                        continue

                indicator_types.append(key.strip().replace("'", '').replace('[', '').replace(']', ''))
                values.append(value.strip().replace("'", '').replace('[', '').replace(']', ''))
            return indicator_types, values, {}
        except Exception:
            return [], [], {}

    @staticmethod
    def calculate_indicator_reputation(confidence: int, date: str, reputation_interval: int):
        """Calculates indicator reputation according to the threshold levels and dates.

        Args:
            confidence (int): FireEye feed confidence.
            date (str): Date in which the indicator was published.
            reputation_interval (int): If this amount of days passed since the indicator was created,
                                        then its reputation can be at most "Suspicious"

        Returns:
            int. DBot Score value

        Notes:
            In case the (current_date - publishing date of the indicator) < reputation_interval, the highest score the
            indicator can get is SUSPICIOUS.
        """
        current_date = datetime.now()
        published_date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')

        sorted_reputation_map = sorted(FE_CONFIDENCE_TO_REPUTATION.items(), reverse=True)

        if current_date - published_date < timedelta(days=reputation_interval):
            for score, threshold in sorted_reputation_map:
                if confidence > threshold:
                    return score

        else:
            for score, threshold in sorted_reputation_map:
                if confidence > threshold:
                    return min(score, Common.DBotScore.SUSPICIOUS)

    def process_indicator(self, raw_data):
        indicators = list()

        _, values, hashes = self.process_indicator_value(raw_data.get('pattern'))

        for value in values:
            indicator = dict()
            indicator['type'] = auto_detect_indicator_type(value)
            if indicator['type']:
                indicator['value'] = value

                indicator['score'] = self.calculate_indicator_reputation(
                    raw_data.get('confidence'),
                    raw_data.get('created'),
                    self.reputation_interval
                )

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

    def process_reports(self) -> List:
        processed_reports = list()  # type: List

        for raw_data in self.reports:
            processed_report = self.process_report(raw_data)
            if processed_report:
                processed_reports.append(processed_report)

        return processed_reports

    @staticmethod
    def process_malware(raw_data) -> Dict:
        entity = dict()  # type: Dict[str, Any]

        entity['type'] = 'STIX Malware'
        entity['value'] = raw_data.get('name')
        entity['fields'] = {
            'stixid': raw_data.get('id'),
            'stixdescription': raw_data.get('description', ''),
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
    def process_threat_actor(raw_data) -> Dict:
        entity = dict()  # type: Dict[str, Any]

        entity['type'] = 'STIX Threat Actor'
        entity['value'] = raw_data.get('name')
        entity['fields'] = {
            'stixid': raw_data.get('id'),
            'stixaliases': raw_data.get('aliases'),
            'stixdescription': raw_data.get('description', ''),
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
    def process_report(raw_data) -> Dict:
        report = dict()  # type: Dict[str, Any]

        report['type'] = 'STIX Report'
        report['value'] = raw_data.get('name')
        report['fields'] = {
            'stixid': raw_data.get('id'),
            'published': raw_data.get('published'),
            'stixdescription': raw_data.get('description', ''),
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
            'fireeye_risk_rating_justification': raw_data.get('x_fireeye_com_risk_rating_justification'),
            'fireeye_additional_description_sections': raw_data.get('x_fireeye_com_additional_description_sections'),
        }

        return report


class Client(BaseClient):
    """Client to use in the FireEye Feed integration. Overrides BaseClient.

    Args:
        insecure (bool): False if feed HTTPS server certificate should be verified, True otherwise.
        proxy (bool): False if feed HTTPS server certificate will not use proxies, True otherwise.
        tags (list): The indicator tags.
        tlp_color (str): Traffic Light Protocol color.
    """

    def __init__(self, public_key: str, private_key: str, malicious_threshold: int, reputation_interval: int,
                 polling_timeout: int = 20, insecure: bool = False, proxy: bool = False,
                 tags: list = [], tlp_color: Optional[str] = None):
        super().__init__(base_url=API_URL, verify=not insecure, proxy=proxy)
        self.public_key = public_key
        self.private_key = private_key
        self.reputation_interval = reputation_interval
        self.malicious_threshold = malicious_threshold
        self._polling_timeout = polling_timeout
        self.tags = tags
        self.tlp_color = tlp_color

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
        current_time = int(datetime.now().timestamp())

        if last_token_fetched_expiration_time and last_token_fetched_expiration_time > current_time:
            auth_token = demisto.getIntegrationContext().get('auth_token')
        else:
            auth_token = self.fetch_new_access_token()

        return auth_token

    def fetch_all_indicators_from_api(self, limit: int) -> Tuple[List, Dict, Dict]:
        """Collects raw data of indicators and their relationships from the feed.

        Args:
            limit (int): Amount of indicators to fetch. -1 means no limit.

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

        if limit == -1:
            query_url = '/collections/indicators/objects?length=1000'
        else:
            query_url = f'/collections/indicators/objects?length={min(limit, 1000)}'

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
                return_error(f'{INTEGRATION_NAME} indicators fetching - '
                             f'API Status Code: {response.status_code} Error Reason: {response.text}')

            objects_fetched = response.json().get('objects')
            for obj in objects_fetched:
                if obj.get('type') == 'indicator':
                    raw_indicators.append(obj)
                elif obj.get('type') == 'relationship':
                    relationships[obj.get('id')] = obj
                else:
                    stix_entities[obj.get('id')] = obj

            if limit != -1:
                break

            try:
                query_url = response.links['next']['url']
                query_url = query_url.split('https://api.intelligence.fireeye.com')[1]
            except KeyError:
                break

        return raw_indicators, relationships, stix_entities

    def fetch_all_reports_from_api(self, limit: int) -> List:
        """Collects reports raw data from the feed.

        Args:
            limit (int): Amount of reports to fetch. -1 means no limit.

        Returns:
            List. List of STIX 2.1 reports objects.
        """
        raw_reports = list()  # type: List

        headers = {
            'Accept': 'application/vnd.oasis.stix+json; version=2.1',
            'X-App-Name': 'content.xsoar.cortex.paloaltonetworks.v1.0',
            'Authorization': f'Bearer {self.get_access_token()}'
        }

        if limit == -1:
            query_url = '/collections/reports/objects?length=100'
        else:
            query_url = f'/collections/reports/objects?length={limit}'

        while True:
            response = self._http_request(
                method='GET',
                url_suffix=query_url,
                headers=headers,
                timeout=self._polling_timeout,
                resp_type='response'
            )

            if response.status_code != 200:
                return_error(f'{INTEGRATION_NAME} reports fetching - '
                             f'API Status Code: {response.status_code} Error Reason: {response.text}')

            raw_reports += [report for report in response.json().get('objects')
                            if report.get('type') == 'report']

            if limit != -1:
                break

            try:
                query_url = response.links['next']['url']
                query_url = query_url.split('https://api.intelligence.fireeye.com')[1]
            except KeyError:
                break

        return raw_reports

    def build_iterator(self, limit: int) -> List:
        self.get_access_token()

        raw_indicators, relationships, stix_entities = self.fetch_all_indicators_from_api(limit)
        raw_reports = self.fetch_all_reports_from_api(limit)

        stix_processor = STIX21Processor(raw_indicators, relationships, stix_entities, raw_reports,
                                         self.malicious_threshold, self.reputation_interval)

        indicators = stix_processor.process_indicators()
        stix_indicators = stix_processor.process_stix_entities()
        reports = stix_processor.process_reports()

        return indicators + stix_indicators + reports


def test_module(client: Client):
    client.build_iterator(limit=10)
    return 'ok', {}, {}


def get_indicators_command(client: Client):
    """Retrieves indicators from the feed to the war-room.

    Args:
        client (Client): Client object configured according to instance arguments.

    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. The raw data of the indicators.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators, raw_response = fetch_indicators_command(client, limit)

    human_readable = tableToMarkdown('Indicators from FireEye Feed:', indicators,
                                     headers=['value', 'type', 'rawJSON'], removeNull=True)

    return human_readable, {}, indicators


def add_fields_if_exists(client: Client, fields_dict: Dict):
    """Adds field mapping if they hold actual values

    Args:
        fields_dict: The fields entry of the indicator
        client (Client): Client object configured according to instance arguments.


    Returns:
        Dict. Updated field mapping
    """
    if client.tags:
        fields_dict.update({
            'tags': client.tags
        })

    if client.tlp_color:
        fields_dict.update({
            'trafficlightprotocol': client.tlp_color
        })

    return fields_dict


def fetch_indicators_command(client: Client, limit: int = -1):
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client (Client): Client object configured according to instance arguments.
        limit (int): Maximum number of indicators to return.
    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. Data to be entered to context.
            Dict. The raw data of the indicators.
    """
    iterator = client.build_iterator(limit)
    indicators = []
    raw_response = []

    for indicator in iterator:
        fields = add_fields_if_exists(client, indicator.get('fields', {}))

        indicators.append({
            'value': indicator['value'],
            'type': indicator['type'],
            'fields': fields,
            'rawJSON': indicator
        })

        raw_response.append(indicator)

    return indicators, raw_response


def verify_threshold_reputation_interval_types(threshold: str, reputation_interval: str):
    if not str.isdigit(threshold):
        return_error(f'{INTEGRATION_NAME} wrong parameter value - '
                     f'Parameter "Malicious Threshold" has to be a number')

    if not str.isdigit(reputation_interval):
        return_error(f'{INTEGRATION_NAME} wrong parameter value - '
                     f'Parameter "Reputation Interval" has to be a number')


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """

    public_key = demisto.params().get('credentials').get('identifier')
    private_key = demisto.params().get('credentials').get('password')
    threshold = demisto.params().get('threshold', '70')
    reputation_interval = demisto.params().get('reputation_interval', '30')
    verify_threshold_reputation_interval_types(threshold, reputation_interval)

    feedTags = argToList(demisto.params().get('feedTags'))
    tlp_color = demisto.params().get('tlp_color')

    polling_arg = demisto.params().get('polling_timeout', '')
    polling_timeout = int(polling_arg) if polling_arg.isdigit() else 20
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    command = demisto.command()
    try:
        client = Client(public_key, private_key, int(threshold), int(reputation_interval),
                        polling_timeout, insecure, proxy, feedTags, tlp_color)
        if command == 'test-module':
            return_outputs(*test_module(client))
        elif command == 'fireeye-get-indicators':
            return_outputs(*get_indicators_command(client))
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators_command(client)

            for single_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(single_batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception:
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
