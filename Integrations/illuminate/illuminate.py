import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
from typing import Dict, Optional, List, Any, Callable, Collection

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
# Integration information
INTEGRATION_NAME = 'Illuminate'
INTEGRATION_CONTEXT_BRAND = 'Illuminate'

''' HELPER FUNCTIONS '''


class EnrichmentOutput(object):
    def __init__(self, context_data: Dict, raw_data: Dict, indicator_type: str) -> None:
        self.context_data = context_data
        self.raw_data = raw_data
        self.indicator_type = indicator_type

    def get_human_readable_output(self) -> str:
        return tableToMarkdown(t=self.context_data, name=f'{INTEGRATION_NAME} {self.indicator_type.capitalize()} Information')

    def get_demisto_context(self) -> Dict:
        return {f'{INTEGRATION_CONTEXT_BRAND}.{self.indicator_type.capitalize()}(val.ID && val.ID === obj.ID)': self.context_data}

    def return_outputs(self):
        # We need to use the underlying demisto.results function call rather than using return_outputs because
        # we need to add the IgnoreAutoExtract key to ensure that our illuminate links are not marked as indicators
        entry = {
            "Type": entryTypes["note"],
            "HumanReadable": self.get_human_readable_output(),
            "ContentsFormat": formats["json"],
            "Contents": self.raw_data,
            "EntryContext": self.get_demisto_context(),
            "IgnoreAutoExtract": True
        }

        demisto.results(entry)

    def add_context(self, key: str, data: Any):
        self.context_data[key] = data

    def has_context_data(self):
        return len(self.context_data) > 0


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
    def get_data_key(data: Dict, key: str) -> Optional[Any]:
        return None if key not in data else data[key]

    @staticmethod
    def get_nested_data_key(data: Dict, key: str, nested_key: str) -> Optional[Any]:
        top_level = Client.get_data_key(data, key)
        return None if top_level is None or nested_key not in top_level else top_level[nested_key]

    @staticmethod
    def get_data_key_as_date(data: Dict, key: str, fmt: str) -> Optional[str]:
        value = Client.get_data_key(data, key)
        return None if value is None else datetime.fromtimestamp(value / 1000.0).strftime(fmt)

    @staticmethod
    def get_data_key_as_list(data: Dict, key: str) -> List[Any]:
        data_list = Client.get_data_key(data, key)
        return [] if data_list is None or not isinstance(data[key], (list,)) else data_list

    @staticmethod
    def get_data_key_as_list_of_values(data: Dict, key: str, value_key: str) -> List[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return [value_data[value_key] for value_data in data_list]

    @staticmethod
    def get_data_key_as_list_of_dicts(data: Dict, key: str, dict_creator: Callable) -> Collection[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return {} if len(data_list) == 0 else [dict_creator(value_data) for value_data in data_list]

    @staticmethod
    def get_context_from_response(data: Dict) -> Dict:
        result_dict = {
            'ID': Client.get_data_key(data, 'id'),
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
            'IlluminateLink': None
        }

        links_list = Client.get_data_key_as_list(data, 'links')
        result_dict['IlluminateLink'] = next((
            link['href'].replace("api/1_0/indicator/", "indicators/")
            for link in links_list
            if 'rel' in link and link['rel'] == 'self' and 'href' in link
        ), None)

        return result_dict


def build_client(demisto_params: dict) -> Client:
    server: str = str(demisto_params.get('server'))
    proxy: bool = demisto_params.get('proxy') == 'true'
    insecure: bool = demisto_params.get('insecure') == 'true'
    credentials: Dict = demisto_params.get('credentials', {})
    username: str = str(credentials.get('identifier'))
    password: str = str(credentials.get('password'))

    return Client(server, username, password, insecure, proxy)


''' COMMAND EXECUTION '''


def perform_test_module(client: Client):
    client.perform_test_request()


def domain_command(client: Client, args: dict) -> EnrichmentOutput:
    domain: str = str(args.get('domain'))
    enrichment_data: EnrichmentOutput = client.enrich_indicator(domain, 'domain')
    if enrichment_data.has_context_data():
        enrichment_data.add_context('IpResolution', Client.get_nested_data_key(enrichment_data.raw_data, 'ipResolution', 'name'))

    return enrichment_data


def email_command(client: Client, args: dict) -> EnrichmentOutput:
    email: str = str(args.get('email'))
    return client.enrich_indicator(email, 'email')


def ip_command(client: Client, args: dict) -> EnrichmentOutput:
    ip: str = str(args.get('ip'))
    return client.enrich_indicator(ip, 'ip')


def file_command(client: Client, args: dict) -> EnrichmentOutput:
    file: str = str(args.get('file'))
    return client.enrich_indicator(file, 'file')


def illuminate_enrich_string_command(client: Client, args: dict) -> EnrichmentOutput:
    string: str = str(args.get('string'))
    return client.enrich_indicator(string, 'string')


def illuminate_enrich_ipv6_command(client: Client, args: dict) -> EnrichmentOutput:
    ip: str = str(args.get('ip'))
    return client.enrich_indicator(ip, 'ipv6')


def illuminate_enrich_mutex_command(client: Client, args: dict) -> EnrichmentOutput:
    mutex: str = str(args.get('mutex'))
    return client.enrich_indicator(mutex, 'mutex')


def illuminate_enrich_http_request_command(client: Client, args: dict) -> EnrichmentOutput:
    http_request: str = str(args.get('http-request'))
    return client.enrich_indicator(http_request, 'httpRequest')


def url_command(client: Client, args: dict) -> EnrichmentOutput:
    url: str = str(args.get('url'))
    return client.enrich_indicator(url, 'url')


''' EXECUTION '''


def main():
    commands = {
        'domain': domain_command,
        'email': email_command,
        'file': file_command,
        'ip': ip_command,
        'url': url_command,
        'illuminate-enrich-string': illuminate_enrich_string_command,
        'illuminate-enrich-ipv6': illuminate_enrich_ipv6_command,
        'illuminate-enrich-mutex': illuminate_enrich_mutex_command,
        'illuminate-enrich-http-request': illuminate_enrich_http_request_command
    }

    command: str = demisto.command()
    LOG(f'command is {command}')

    try:
        client = build_client(demisto.params())

        if command == 'test-module':
            perform_test_module(client)
            demisto.results('ok')
        elif command in commands:
            enrichment_output: EnrichmentOutput = commands[command](client, demisto.args())
            enrichment_output.return_outputs()
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
