import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
import traceback
from typing import Dict, Optional, List, Any, Callable, Collection

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
# Integration information
INTEGRATION_NAME = 'Analyst1'
INTEGRATION_CONTEXT_BRAND = 'Analyst1'
MALICIOUS_DATA: Dict[str, str] = {
    'Vendor': 'Analyst1',
    'Description': 'Analyst1 has determined that this indicator is malicious via internal analysis.'
}

''' HELPER FUNCTIONS '''


class IdNamePair(object):
    def __init__(self, unique_id: int, name: str):
        self.id = unique_id
        self.name = name

    def __str__(self):
        return f'id = {self.id}, name = {self.name}'


class EnrichmentOutput(object):
    def __init__(self, analyst1_context_data: dict, raw_data: dict, indicator_type: str) -> None:
        self.analyst1_context_data = analyst1_context_data
        self.raw_data = raw_data
        self.indicator_type = indicator_type
        self.reputation_context: dict = {}

    def get_human_readable_output(self) -> str:
        human_readable_data = self.analyst1_context_data.copy()
        human_readable_data['Actors'] = [IdNamePair(d['id'], d['name']) for d in human_readable_data['Actors']]
        human_readable_data['Malwares'] = [IdNamePair(d['id'], d['name']) for d in human_readable_data['Malwares']]

        return tableToMarkdown(
            t=human_readable_data,
            name=f'{INTEGRATION_NAME} {self.indicator_type.capitalize()} Information',
            removeNull=True
        )

    def build_analyst1_context(self) -> dict:
        return {
            f'{INTEGRATION_CONTEXT_BRAND}.{self.indicator_type.capitalize()}(val.ID && val.ID === obj.ID)':
                self.analyst1_context_data
        }

    def generate_reputation_context(
            self,
            primary_key: str,
            indicator_value: str,
            indicator_type: str,
            reputation_key: str,
            extra_context: Optional[dict] = None
    ):
        if self.has_context_data():
            reputation_context: Dict[str, Any] = {primary_key: indicator_value}

            if extra_context is not None:
                reputation_context.update(extra_context)

            malicious = Client.is_indicator_malicious(self.raw_data)
            if malicious:
                reputation_context['Malicious'] = MALICIOUS_DATA

            self.add_reputation_context(
                f'{reputation_key}(val.{primary_key} && val.{primary_key} === obj.{primary_key})',
                reputation_context
            )

            self.add_reputation_context('DBotScore', {
                'Indicator': indicator_value,
                'Score': 3 if malicious else 1,
                'Type': indicator_type,
                'Vendor': INTEGRATION_NAME
            })

    def build_all_context(self) -> dict:
        all_context = {}
        all_context.update(self.build_analyst1_context())
        if len(self.reputation_context) > 0:
            all_context.update(self.reputation_context)

        return all_context

    def return_outputs(self):
        # We need to use the underlying demisto.results function call rather than using return_outputs because
        # we need to add the IgnoreAutoExtract key to ensure that our analyst1 links are not marked as indicators
        entry = {
            "Type": entryTypes["note"],
            "HumanReadable": self.get_human_readable_output(),
            "ContentsFormat": formats["json"],
            "Contents": self.raw_data,
            "EntryContext": self.build_all_context(),
            "IgnoreAutoExtract": True
        }

        demisto.results(entry)

    def add_analyst1_context(self, key: str, data: Any):
        self.analyst1_context_data[key] = data

    def add_reputation_context(self, key: str, context: dict):
        self.reputation_context[key] = context

    def has_context_data(self):
        return len(self.analyst1_context_data) > 0


class Client(BaseClient):
    def __init__(self, server: str, username: str, password: str, insecure: bool, proxy: bool):
        # NB: 404 is a valid response since that just means no entries, and we want the UI to respect that and show "No Entries"
        super().__init__(
            base_url=f'https://{server}/api/1_0/',
            verify=not insecure,
            proxy=proxy,
            auth=(username, password),
            ok_codes=(200, 404)
        )

    def indicator_search(self, indicator_type: str, indicator: str) -> dict:
        params = {'type': indicator_type, 'value': indicator}
        return self._http_request(method='GET', url_suffix='indicator/match', params=params)

    def perform_test_request(self):
        data: dict = self._http_request(method='GET', url_suffix='')
        if data['links'] is None:
            raise DemistoException('Invalid URL or Credentials. JSON structure not recognized')

    def enrich_indicator(self, indicator: str, indicator_type: str) -> EnrichmentOutput:
        raw_data: dict = self.indicator_search(indicator_type, indicator)
        if raw_data is None:
            return EnrichmentOutput({}, {}, indicator_type)

        context_data = self.get_context_from_response(raw_data)
        return EnrichmentOutput(context_data, raw_data, indicator_type)

    @staticmethod
    def get_data_key(data: dict, key: str) -> Optional[Any]:
        return None if key not in data else data[key]

    @staticmethod
    def get_nested_data_key(data: dict, key: str, nested_key: str) -> Optional[Any]:
        top_level = Client.get_data_key(data, key)
        return None if top_level is None or nested_key not in top_level else top_level[nested_key]

    @staticmethod
    def get_data_key_as_date(data: dict, key: str, fmt: str) -> Optional[str]:
        value = Client.get_data_key(data, key)
        return None if value is None else datetime.fromtimestamp(value / 1000.0).strftime(fmt)

    @staticmethod
    def get_data_key_as_list(data: dict, key: str) -> List[Any]:
        data_list = Client.get_data_key(data, key)
        return [] if data_list is None or not isinstance(data[key], (list,)) else data_list

    @staticmethod
    def get_data_key_as_list_of_values(data: dict, key: str, value_key: str) -> List[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return [value_data[value_key] for value_data in data_list]

    @staticmethod
    def get_data_key_as_list_of_dicts(data: dict, key: str, dict_creator: Callable) -> Collection[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return {} if len(data_list) == 0 else [dict_creator(value_data) for value_data in data_list]

    @staticmethod
    def is_indicator_malicious(data: dict) -> bool:
        benign = Client.get_nested_data_key(data, 'benign', 'value')
        return False if benign is None or benign is True else True

    @staticmethod
    def get_context_from_response(data: dict) -> dict:
        result_dict = {
            'ID': Client.get_data_key(data, 'id'),
            'Indicator': Client.get_nested_data_key(data, 'value', 'name'),
            'EvidenceCount': Client.get_data_key(data, 'reportCount'),
            'Active': Client.get_data_key(data, 'active'),
            'HitCount': Client.get_data_key(data, 'hitCount'),
            'ConfidenceLevel': Client.get_nested_data_key(data, 'confidenceLevel', 'value'),
            'FirstHit': Client.get_data_key_as_date(data, 'firstHit', '%Y-%m-%d'),
            'LastHit': Client.get_data_key_as_date(data, 'lastHit', '%Y-%m-%d'),
            'ReportedDates': Client.get_data_key_as_list_of_values(data, 'reportedDates', 'date'),
            'ActivityDates': Client.get_data_key_as_list_of_values(data, 'activityDates', 'date'),
            'Malwares': Client.get_data_key_as_list_of_dicts(data, 'malwares', lambda d: {'id': d['id'], 'name': d['name']}),
            'Actors': Client.get_data_key_as_list_of_dicts(data, 'actors', lambda d: {'id': d['id'], 'name': d['name']}),
            'Benign': Client.get_nested_data_key(data, 'benign', 'value'),
            'Analyst1Link': None
        }

        links_list = Client.get_data_key_as_list(data, 'links')
        result_dict['Analyst1Link'] = next((
            link['href'].replace("api/1_0/indicator/", "indicators/")
            for link in links_list
            if 'rel' in link and link['rel'] == 'self' and 'href' in link
        ), None)

        return result_dict


def build_client(demisto_params: dict) -> Client:
    server: str = str(demisto_params.get('server'))
    proxy: bool = demisto_params.get('proxy', False)
    insecure: bool = demisto_params.get('insecure', False)
    credentials: dict = demisto_params.get('credentials', {})
    username: str = str(credentials.get('identifier'))
    password: str = str(credentials.get('password'))

    return Client(server, username, password, insecure, proxy)


''' COMMAND EXECUTION '''


def perform_test_module(client: Client):
    client.perform_test_request()


def domain_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    domains: List[str] = argToList(args.get('domain'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for domain in domains:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(domain, 'domain')
        if enrichment_data.has_context_data():
            extra_context = {}

            ip_resolution = Client.get_nested_data_key(enrichment_data.raw_data, 'ipResolution', 'name')
            if ip_resolution is not None:
                enrichment_data.add_analyst1_context('IpResolution', ip_resolution)
                extra_context['DNS'] = ip_resolution

            enrichment_data.generate_reputation_context('Name', domain, 'domain', 'Domain', extra_context)

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def email_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    emails: List[str] = argToList(args.get('email'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for email in emails:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(email, 'email')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('From', email, 'email', 'Email')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def ip_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    ips: List[str] = argToList(args.get('ip'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(ip, 'ip')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('Address', ip, 'ip', 'IP')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def file_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    files: List[str] = argToList(args.get('file'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for file in files:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(file, 'file')

        if enrichment_data.has_context_data():
            hash_type = get_hash_type(file)
            if hash_type != 'Unknown':
                enrichment_data.generate_reputation_context(hash_type.upper(), file, 'file', 'File')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def analyst1_enrich_string_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    strings: List[str] = argToList(args.get('string'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for string in strings:
        enrichment_data_list.append(client.enrich_indicator(string, 'string'))

    return enrichment_data_list


def analyst1_enrich_ipv6_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    ips: List[str] = argToList(args.get('ip'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data_list.append(client.enrich_indicator(ip, 'ipv6'))

    return enrichment_data_list


def analyst1_enrich_mutex_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    mutexes: List[str] = argToList(args.get('mutex'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for mutex in mutexes:
        enrichment_data_list.append(client.enrich_indicator(mutex, 'mutex'))

    return enrichment_data_list


def analyst1_enrich_http_request_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    http_requests: List[str] = argToList(args.get('http-request'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for http_request in http_requests:
        enrichment_data_list.append(client.enrich_indicator(http_request, 'httpRequest'))

    return enrichment_data_list


def url_command(client: Client, args: dict) -> List[EnrichmentOutput]:
    urls: List[str] = argToList(args.get('url'))
    enrichment_data_list: List[EnrichmentOutput] = []

    for url in urls:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(url, 'url')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('Data', url, 'url', 'URL')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


''' EXECUTION '''


def main():
    commands = {
        'domain': domain_command,
        'email': email_command,
        'file': file_command,
        'ip': ip_command,
        'url': url_command,
        'analyst1-enrich-string': analyst1_enrich_string_command,
        'analyst1-enrich-ipv6': analyst1_enrich_ipv6_command,
        'analyst1-enrich-mutex': analyst1_enrich_mutex_command,
        'analyst1-enrich-http-request': analyst1_enrich_http_request_command
    }

    command: str = demisto.command()
    LOG(f'command is {command}')

    try:
        client = build_client(demisto.params())

        if command == 'test-module':
            perform_test_module(client)
            demisto.results('ok')
        elif command in commands:
            enrichment_outputs: List[EnrichmentOutput] = commands[command](client, demisto.args())
            [e.return_outputs() for e in enrichment_outputs]
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]\nTrace:\n{traceback.format_exc()}'
        return_error(err_msg, error=e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
