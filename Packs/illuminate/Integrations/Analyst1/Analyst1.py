import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''


import json
import requests
import urllib3
import traceback
from typing import Any
from collections.abc import Callable, Collection

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


# Integration information
INTEGRATION_NAME = 'Analyst1'
INTEGRATION_CONTEXT_BRAND = 'Analyst1'
MALICIOUS_DATA: dict[str, str] = {
    'Vendor': 'Analyst1',
    'Description': 'Analyst1 advises assessing the Indicator attributes for malicious context.'
}


''' HELPER FUNCTIONS '''


class IdNamePair:
    def __init__(self, unique_id: int, name: str):
        self.id = unique_id
        self.name = name

    def __str__(self):
        return f'id = {self.id}, name = {self.name}'


class EnrichmentOutput:
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
            extra_context: dict | None = None
    ):
        if self.has_context_data():
            reputation_context: dict[str, Any] = {primary_key: indicator_value}

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
                'Vendor': INTEGRATION_NAME,
                'Reliability': demisto.params().get('integrationReliability')
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
        super().__init__(
            base_url=f'https://{server}/api/1_0/',
            verify=not insecure,
            proxy=proxy,
            auth=(username, password)
        )

    def indicator_search(self, indicator_type: str, indicator: str) -> dict:
        params = {'type': indicator_type, 'value': indicator}
        return self._http_request(method='GET', url_suffix='indicator/match', params=params)

    def post_evidence(self, fileName: str, fileContent: str, fileEntryId: str,
                      evidenceFileClassification: str, tlp: str, sourceId: str) -> dict:
        # warRoomFileId: str, may want to be added in as a future capability
        # but access from those files were inconsistent, so current scope is only content or file entry
        data_to_submit = {
            'evidenceFileClassification': evidenceFileClassification,
            'tlp': tlp,
            'sourceId': sourceId
        }

        evidence_to_submit = None
        if fileContent is not None and fileContent and str(fileContent):
            # encode as UTF-8 to follow Python coding best practices; it works without the encode command
            evidence_to_submit = {'evidenceFile': (fileName, str(fileContent).encode('utf-8'))}
        elif fileEntryId is not None and fileEntryId:
            try:
                filePathToUploadToA1 = demisto.getFilePath(fileEntryId)
                evidenceOpened = open(filePathToUploadToA1['path'], 'rb')
                # rb for read binary is default
                evidence_to_submit = {'evidenceFile': (fileName, evidenceOpened.read())}
                # close what was read into the submission to allow good file system management
                evidenceOpened.close()
            except ValueError as vale:
                raise DemistoException('Possibly invalid File.EntryID provided to submission: ' + fileEntryId, vale)

        if evidence_to_submit is None:
            raise DemistoException("either fileContent, fileEntryId, or warRoomFileId must be specified to submit Evidence")

        x = requests.post(self._base_url + 'evidence', files=evidence_to_submit, data=data_to_submit, auth=self._auth)
        if x is not None and x.status_code == 200:
            return x.json()
        elif x is None:
            return {'message': 'Empty response'}
        else:
            return {'message': 'Error occurred. Status Code: ' + str(x.status_code) + ' Text: ' + x.text}

    def get_evidence_status(self, uuid: str) -> dict:
        x = requests.get(self._base_url + 'evidence/uploadStatus/' + uuid, auth=self._auth)
        if x is None:
            return {'message': 'Empty response'}
        elif x.status_code == 404:
            # convert general {"message":"Process not found."} to a better message
            return {'message': 'UUID ' + uuid + ' not known to this Analyst1 instance'}
        elif x.status_code == 200:
            return x.json()
        else:
            return {'message': 'Error occurred. Status Code: ' + str(x.status_code) + ' Text: ' + x.text}

    def get_batch_search(self, indicator_values_as_csv: str) -> dict:
        params = {'values': indicator_values_as_csv}
        return self._http_request(method='GET', url_suffix='batchCheck', params=params)

    def post_batch_search(self, indicator_values_as_file: str) -> dict:
        values_to_submit = {'values': indicator_values_as_file}
        # more data here for future maintainers: https://www.w3schools.com/python/module_requests.asp
        x = requests.post(self._base_url + 'batchCheck', files=values_to_submit, auth=self._auth)
        # need to check status here or error
        if x is not None and x.status_code == 200:
            return x.json()
        elif x is None:
            return {'message': 'Empty response'}
        else:
            return {'message': 'Error occurred. Status Code: ' + str(x.status_code) + ' Text: ' + x.text}

    def get_sensors(self, page: int, pageSize: int):
        raw_data: dict = self._http_request(method='GET', url_suffix='sensors?page=' + str(page) + '&pageSize=' + str(pageSize))
        return raw_data

    def get_sensor_taskings(self, sensor: str, timeout_input: int):
        if timeout_input is None:
            timeout_input = 500
        raw_data: dict = self._http_request(method='GET', timeout=int(timeout_input),
                                            url_suffix='sensors/' + sensor + '/taskings')
        return raw_data

    def get_sensor_config(self, sensor: str) -> str:
        return self._http_request(method='GET', resp_type='text', url_suffix='sensors/' + sensor + '/taskings/config')

    def get_sensor_diff(self, sensor: str, version: str, timeout_input: int):
        if timeout_input is None:
            timeout_input = 500
        raw_data: dict = self._http_request(method='GET', timeout=int(timeout_input),
                                            url_suffix='sensors/' + sensor + '/taskings/diff/' + version)
        # if raw_data is not None:
        return raw_data

    def perform_test_request(self):
        data: dict = self._http_request(method='GET', url_suffix='')
        if data.get('links') is None:
            raise DemistoException('Invalid URL or Credentials. JSON structure not recognized.')

    def enrich_indicator(self, indicator: str, indicator_type: str) -> EnrichmentOutput:
        raw_data: dict = self.indicator_search(indicator_type, indicator)
        if raw_data is None:
            return EnrichmentOutput({}, {}, indicator_type)

        context_data = self.get_context_from_response(raw_data)
        return EnrichmentOutput(context_data, raw_data, indicator_type)

    def get_indicator(self, ioc_id: str):
        if ioc_id is not None and ioc_id and type(ioc_id) is str:
            # remove unnwanted suffix for hash ids
            ioc_id = ioc_id.split('-')[0].split('_')[0]
        return self._http_request(method='GET', url_suffix='indicator/' + str(ioc_id))

    @staticmethod
    def get_data_key(data: dict, key: str) -> Any | None:
        return None if key not in data else data[key]

    @staticmethod
    def get_nested_data_key(data: dict, key: str, nested_key: str) -> Any | None:
        top_level = Client.get_data_key(data, key)
        return None if top_level is None or nested_key not in top_level else top_level[nested_key]

    @staticmethod
    def get_data_key_as_date(data: dict, key: str, fmt: str) -> str | None:
        value = Client.get_data_key(data, key)
        return None if value is None else datetime.fromtimestamp(value / 1000.0).strftime(fmt)

    @staticmethod
    def get_data_key_as_list(data: dict, key: str) -> list[Any]:
        data_list = Client.get_data_key(data, key)
        return [] if data_list is None or not isinstance(data[key], list) else data_list

    @staticmethod
    def get_data_key_as_list_of_values(data: dict, key: str, value_key: str) -> list[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return [value_data[value_key] for value_data in data_list]

    @staticmethod
    def get_data_key_as_list_of_dicts(data: dict, key: str, dict_creator: Callable) -> Collection[Any]:
        data_list = Client.get_data_key_as_list(data, key)
        return {} if len(data_list) == 0 else [dict_creator(value_data) for value_data in data_list]

    @staticmethod
    def is_indicator_malicious(data: dict) -> bool:
        benign = Client.get_nested_data_key(data, 'benign', 'value')
        return not (benign is None or benign is True)

    @staticmethod
    def get_context_from_response(data: dict) -> dict:
        result_dict = {
            'ID': Client.get_data_key(data, 'id'),
            'Indicator': Client.get_nested_data_key(data, 'value', 'name'),
            'EvidenceCount': Client.get_data_key(data, 'reportCount'),
            'Active': Client.get_data_key(data, 'active'),
            'HitCount': Client.get_data_key(data, 'hitCount'),
            'ConfidenceLevel': Client.get_nested_data_key(data, 'confidenceLevel', 'value'),
            'FirstHit': Client.get_data_key(data, 'firstHit'),
            'LastHit': Client.get_data_key(data, 'lastHit'),
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


def domain_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    domains: list[str] = argToList(args.get('domain'))
    enrichment_data_list: list[EnrichmentOutput] = []

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


def email_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    emails: list[str] = argToList(args.get('email'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for email in emails:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(email, 'email')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('From', email, 'email', 'Email')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def ip_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    ips: list[str] = argToList(args.get('ip'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(ip, 'ip')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('Address', ip, 'ip', 'IP')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def file_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    files: list[str] = argToList(args.get('file'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for file in files:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(file, 'file')

        if enrichment_data.has_context_data():
            hash_type = get_hash_type(file)
            if hash_type != 'Unknown':
                enrichment_data.generate_reputation_context(hash_type.upper(), file, 'file', 'File')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def analyst1_enrich_string_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    strings: list[str] = argToList(args.get('string'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for string in strings:
        enrichment_data_list.append(client.enrich_indicator(string, 'string'))

    return enrichment_data_list


def analyst1_enrich_ipv6_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    ips: list[str] = argToList(args.get('ip'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for ip in ips:
        enrichment_data_list.append(client.enrich_indicator(ip, 'ipv6'))

    return enrichment_data_list


def analyst1_enrich_mutex_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    mutexes: list[str] = argToList(args.get('mutex'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for mutex in mutexes:
        enrichment_data_list.append(client.enrich_indicator(mutex, 'mutex'))

    return enrichment_data_list


def analyst1_enrich_http_request_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    http_requests: list[str] = argToList(args.get('http-request'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for http_request in http_requests:
        enrichment_data_list.append(client.enrich_indicator(http_request, 'httpRequest'))

    return enrichment_data_list


def url_command(client: Client, args: dict) -> list[EnrichmentOutput]:
    urls: list[str] = argToList(args.get('url'))
    enrichment_data_list: list[EnrichmentOutput] = []

    for url in urls:
        enrichment_data: EnrichmentOutput = client.enrich_indicator(url, 'url')

        if enrichment_data.has_context_data():
            enrichment_data.generate_reputation_context('Data', url, 'url', 'URL')

        enrichment_data_list.append(enrichment_data)

    return enrichment_data_list


def argsToStr(args: dict, key: str) -> str:
    arg: Any | None = args.get(key)
    if arg is None:
        return ''
    return str(arg)


def argsToInt(args: dict, key: str, default: int) -> int:
    arg: Any | None = args.get(key)
    if arg is None:
        return default
    return int(arg)


def analyst1_get_indicator(client: Client, args) -> CommandResults | None:
    raw_data = client.get_indicator(argsToStr(args, 'indicator_id'))
    if len(raw_data) > 0:
        command_results = CommandResults(
            outputs_prefix='Analyst1.Indicator',
            outputs=raw_data
        )
        return_results(command_results)
        return command_results
    return None


def analyst1_batch_check_command(client: Client, args) -> CommandResults | None:
    raw_data = client.get_batch_search(argsToStr(args, 'values'))
    # assume succesful result or client will have errored
    if len(raw_data['results']) > 0:
        command_results = CommandResults(
            outputs_prefix='Analyst1.BatchResults',
            outputs_key_field='ID',
            outputs=raw_data['results']
        )
        return_results(command_results)
        return command_results
    return None


def analyst1_batch_check_post(client: Client, args: dict) -> dict | None:
    runpath = 'values'
    values = args.get('values')
    if values is None or not values:
        val_array = args.get('values_array')
        runpath = 'val_array_base'
        # process all possible inbound value array combinations
        if isinstance(val_array, str):
            # if a string, assume it is a viable string to become an array
            # have to check if it is a "false string" with quotes around it to hand some input flows
            val_array = val_array.strip()
            if not val_array.startswith('['):
                val_array = '[' + val_array
            if not val_array.endswith(']'):
                val_array = val_array + ']'
            val_array = '{"values": ' + val_array + '}'
            val_array = json.loads(val_array)
            runpath = 'val_array_str'
        elif isinstance(val_array, list):
            # if already an list, accept it
            val_array = {'values': val_array}
            runpath = 'val_array_list'
        # if none of the above assume it is json matching this format
        # pull values regardless of input form to newline text for acceptable submission
        values = '\n'.join(str(val) for val in val_array["values"])

    output_check_data = {
        'values': str(args.get('values')),
        'val_array': str(args.get('values_array')),
        'type': str(type(args.get('values_array'))),
        'runpath': runpath
    }

    raw_data = client.post_batch_search(values)
    # assume succesful result or client will have errored
    if len(raw_data['results']) > 0:
        command_results = CommandResults(
            outputs_prefix='Analyst1.BatchResults',
            outputs_key_field='ID',
            outputs=raw_data['results']
        )
        return_results(command_results)
        output_check: dict = {
            'command_results': command_results,
            'submitted_values': values,
            'original_data': output_check_data
        }
        return output_check
    return None


def analyst1_evidence_submit(client: Client, args: dict) -> CommandResults | None:
    raw_data = client.post_evidence(argsToStr(args, 'fileName'),
                                    argsToStr(args, 'fileContent'), argsToStr(args, 'fileEntryId'),
                                    argsToStr(args, 'fileClassification'), argsToStr(args, 'tlp'), argsToStr(args, 'sourceId'))
    # args.get('warRoomFileId'), may be added back in at a future time
    # for now it is left out on purpose
    command_results = CommandResults(
        outputs_prefix='Analyst1.EvidenceSubmit',
        outputs_key_field='uuid',
        outputs=raw_data
    )
    return_results(command_results)
    return command_results


def analyst1_evidence_status(client: Client, args: dict) -> CommandResults | None:
    raw_data = client.get_evidence_status(argsToStr(args, 'uuid'))

    if not raw_data or raw_data is None:
        raw_data = {"message": "UUID unknown"}
    elif 'id' in raw_data and raw_data.get('id') is not None and raw_data.get('id'):
        raw_data["processingComplete"] = True
    elif 'message' in raw_data and raw_data.get('message') is not None:
        raw_data["processingComplete"] = False
    else:
        raw_data["processingComplete"] = False

    command_results = CommandResults(
        outputs_prefix='Analyst1.EvidenceStatus',
        outputs_key_field='id',
        outputs=raw_data
    )
    return_results(command_results)
    return command_results


def a1_tasking_array_from_indicators(indicatorsJson: dict) -> list:
    taskings_list: list[dict] = []
    for ioc in indicatorsJson:
        # each IOC or each HASH gets insertd for outward processing
        # convert ID to STR to make output consistent
        listIoc: dict = {}
        if ioc.get('type') == 'File' and len(ioc.get('fileHashes')) > 0:
            for (key, value) in ioc.get('fileHashes').items():
                # hash algorithm is the key, so use it to create output
                listIoc = {
                    'category': 'indicator',
                    'id': str(ioc.get('id')) + '-' + key,
                    'type': 'File-' + key,
                    'value': value
                }
                taskings_list.append(listIoc)
        else:
            listIoc = {
                'category': 'indicator',
                'id': str(ioc.get('id')),
                'type': ioc.get('type'),
                'value': ioc.get('value')
            }
            taskings_list.append(listIoc)
    return taskings_list


def a1_tasking_array_from_rules(rulesJson: dict) -> list:
    taskings_list: list[dict] = []
    # convert ID to STR to make output consistent
    for rule in rulesJson:
        listRule = {
            'category': 'rule',
            'id': str(rule.get('id')),
            'signature': rule.get('signature')
        }
        taskings_list.append(listRule)
    return taskings_list


def analyst1_get_sensor_taskings_command(client: Client, args: dict) -> list[CommandResults]:
    raw_data = client.get_sensor_taskings(argsToStr(args, 'sensor_id'), argsToInt(args, 'timeout', 200))

    simplified_data: dict = raw_data.copy()
    if 'links' in simplified_data:
        del simplified_data['links']

    indicators_taskings: list = []
    if 'indicators' in simplified_data:
        indicators_taskings = a1_tasking_array_from_indicators(simplified_data['indicators'])
        del simplified_data['indicators']

    rules_taskings: list = []
    if 'rules' in simplified_data:
        rules_taskings = a1_tasking_array_from_rules(simplified_data['rules'])
        del simplified_data['rules']

    command_results_list: list[CommandResults] = []

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings',
        outputs=simplified_data,
        raw_response=raw_data
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.Indicators',
        outputs_key_field='id',
        outputs=indicators_taskings
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.Rules',
        outputs_key_field='id',
        outputs=rules_taskings
    )
    return_results(command_results)
    command_results_list.append(command_results)

    return command_results_list


def analyst1_get_sensors_command(client: Client, args: dict) -> CommandResults | None:
    sensor_raw_data = client.get_sensors(argsToInt(args, 'page', 1), argsToInt(args, 'pageSize', 50))
    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorList',
        outputs_key_field='id',
        outputs=sensor_raw_data['results'],
        raw_response=sensor_raw_data
    )
    return_results(command_results)
    return command_results


def analyst1_get_sensor_diff(client: Client, args: dict) -> list[CommandResults]:
    raw_data = client.get_sensor_diff(argsToStr(args, 'sensor_id'), argsToStr(args, 'version'), argsToInt(args, 'timeout', 200))
    # CommandResults creates both "outputs" and "human readable" in one go using updated XSOAR capabilities

    simplified_data = raw_data.copy()
    if 'links' in simplified_data:
        del simplified_data['links']

    indicators_added: list = []
    if 'indicatorsAdded' in simplified_data:
        indicators_added = a1_tasking_array_from_indicators(simplified_data['indicatorsAdded'])
        del simplified_data['indicatorsAdded']

    indicators_removed: list = []
    if 'indicatorsRemoved' in simplified_data:
        indicators_removed = a1_tasking_array_from_indicators(simplified_data['indicatorsRemoved'])
        del simplified_data['indicatorsRemoved']

    rules_added: list = []
    if 'rulesAdded' in simplified_data:
        rules_added = a1_tasking_array_from_rules(simplified_data['rulesAdded'])
        del simplified_data['rulesAdded']

    rules_removed: list = []
    if 'rulesRemoved' in simplified_data:
        rules_removed = a1_tasking_array_from_rules(simplified_data['rulesRemoved'])
        del simplified_data['rulesRemoved']

    command_results_list: list[CommandResults] = []

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings',
        outputs=simplified_data,
        raw_response=raw_data
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.IndicatorsAdded',
        outputs_key_field='id',
        outputs=indicators_added
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.IndicatorsRemoved',
        outputs_key_field='id',
        outputs=indicators_removed
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.RulesAdded',
        outputs_key_field='id',
        outputs=rules_added
    )
    return_results(command_results)
    command_results_list.append(command_results)

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.RulesRemoved',
        outputs_key_field='id',
        outputs=rules_removed
    )
    return_results(command_results)
    command_results_list.append(command_results)

    return command_results_list


def analyst1_get_sensor_config_command(client: Client, args):
    sensor_id = argsToStr(args, 'sensor_id')
    raw_data = client.get_sensor_config(sensor_id)
    warRoomEntry = fileResult('sensor' + str(sensor_id) + 'Config.txt', raw_data)
    outputOptions = {'warRoomEntry': warRoomEntry, 'config_text': raw_data}

    command_results = CommandResults(
        outputs_prefix='Analyst1.SensorTaskings.ConfigFile',
        outputs=outputOptions
    )
    return_results(command_results)
    return command_results


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
        # do not set demisto.results() because caller invokes updated command_results() internally
        if command == 'analyst1-evidence-submit':
            analyst1_evidence_submit(client, demisto.args())
        if command == 'analyst1-evidence-status':
            analyst1_evidence_status(client, demisto.args())
        if command == 'analyst1-get-sensor-taskings':
            analyst1_get_sensor_taskings_command(client, demisto.args())
        if command == 'analyst1-get-sensor-config':
            analyst1_get_sensor_config_command(client, demisto.args())
        if command == 'analyst1-batch-check':
            analyst1_batch_check_command(client, demisto.args())
        if command == 'analyst1-batch-check-post':
            analyst1_batch_check_post(client, demisto.args())
        if command == 'analyst1-get-sensors':
            analyst1_get_sensors_command(client, demisto.args())
        if command == 'analyst1-get-sensor-diff':
            # do not set demisto.results() because caller invokes updated command_results() internally
            analyst1_get_sensor_diff(client, demisto.args())
        if command == 'analyst1-indicator-by-id':
            analyst1_get_indicator(client, demisto.args())
        elif command in commands:
            enrichment_outputs: list[EnrichmentOutput] = commands[command](client, demisto.args())
            [e.return_outputs() for e in enrichment_outputs]
    except DemistoException as e:
        if '[404]' in str(e):
            demisto.results('No Results')
            return
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]\nTrace:\n{traceback.format_exc()}'
        return_error(err_msg, error=e)
    return


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
