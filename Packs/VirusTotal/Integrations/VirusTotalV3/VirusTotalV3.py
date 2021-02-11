from CommonServerPython import *
import demistomock as demisto

DBOT_SCORE = (Common.DBotScore.GOOD, Common.DBotScore.SUSPICIOUS, Common.DBotScore.BAD, Common.DBotScore.NONE)
INTEGRATION_NAME = "EWS extension"
COMMAND_PREFIX = "VT"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"


class ScoreCalculator:
    """
    Calculating DBotScore of files, ip, etc.
    """
    logs: List[str] = list()

    trusted_vendors_threshold: int
    trusted_vendors: List[str]

    file_threshold: int
    ip_threshold: int
    url_threshold: int
    domain_threshold: int

    def __init__(self, params: dict):
        self.trusted_vendors = argToList(params['preferredVendors'])
        self.trusted_vendors_threshold = int(params['preferredVendorsThreshold'])
        self.file_threshold = int(params['fileThreshold'])
        self.ip_threshold = int(params['ipThreshold'])
        self.url_threshold = int(params['urlThreshold'])
        self.domain_threshold = int(params['domainThreshold'])

    def is_preffered_vendors_pass_malicious(self, analysis_results: dict) -> bool:
        recent = analysis_results[:20]
        preferred_vendor_scores = {
            vendor: recent[vendor] for vendor in self.trusted_vendors if vendor in recent
        }
        malicious_trusted_vendors = [item for item in preferred_vendor_scores.values() if
                                     item['category'] == 'malicious']
        self.logs.append(
            f'{len(malicious_trusted_vendors)} trusted vendors found the hash malicious.\n'
            f'The trusted vendors threshold is {self.trusted_vendors_threshold}\n'
            f'Malicious check: {(len(malicious_trusted_vendors) >= self.trusted_vendors_threshold)=}'
        )

        if len(malicious_trusted_vendors) >= self.trusted_vendors_threshold:
            self.logs.append(f'Found malicious')
            return True
        self.logs.append('Not found malicious')
        return False

    def is_malicious_pass_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        total_malicious = analysis_stats['malicious']
        self.logs.append(
            f'{total_malicious} vendors found malicious.\n'
            f'The malicious threshold is {threshold}'
        )
        malicious_check = f'{(total_malicious >= threshold)=}'
        if total_malicious >= threshold:
            self.logs.append(f'Found as malicious. {malicious_check}')
            return True
        self.logs.append(f'Not found malicious {malicious_check}')
        return False

    def file_score(self, given_hash: str, file_response: dict) -> DBOT_SCORE:
        self.logs = list()
        self.logs.append(f'Analysing file hash {given_hash}')
        analysis_results = file_response['data']['attributes']['last_analysis_results']

        # Trusted vendors
        if self.is_preffered_vendors_pass_malicious(analysis_results):
            return Common.DBotScore.BAD

        if self.is_malicious_pass_threshold(analysis_results):
            return Common.DBotScore.BAD
        analysis_stats = file_response['data']['attributes']['last_analysis_stats']
        # Malicious by stats
        total_malicious = analysis_stats['malicious']
        if total_malicious >= self.file_threshold / 2:
            if False:  # TODO: Yara rules
                pass
            demisto.debug(
                f'Hash {given_hash} found suspicious.\n'
                f'{total_malicious} vendors found the hash malicious.\n'
                f'The file malicious threshold is {(self.file_threshold / 2)=}'
            )
            return Common.DBotScore.SUSPICIOUS
        if (total_suspicious := analysis_stats['suspicious']) >= self.file_threshold:
            demisto.debug(
                f'Hash {given_hash} found suspicious.\n'
                f'{total_suspicious} vendors found the hash suspicious.\n'
                f'The file suspicious threshold is {self.file_threshold}'
            )
            return Common.DBotScore.SUSPICIOUS
        demisto.debug(
            f'Hash {given_hash} found good.\n'
            f'{total_malicious} vendors found the hash malicious.\n'
            f'{total_suspicious} vendors found the hash suspicious.\n'
            f'None of them passed the threshold of {self.file_threshold}'
        )
        return Common.DBotScore.GOOD  # Nothing caught

    def ip_score(self, communicating_files: dict) -> DBOT_SCORE:
        pass

    def domain_score(self, communicating_files: dict) -> DBOT_SCORE:
        pass

    def url_score(self, communicating_files: dict) -> DBOT_SCORE:
        pass


class Client(BaseClient):
    def ip(self, ip: str) -> dict:
        suffix = f'ip_addresses/{ip}'
        return self._http_request(
            'GET',
            suffix
        )

    def file(self, file: str) -> dict:
        suffix = f'files/{file}'
        return self._http_request(
            'GET',
            suffix
        )


def get_client(params: dict) -> Client:
    return Client(
        'https://www.virustotal.com/api/v3/',
        verify=not params.get('insecure'),
        proxy=params.get('proxy'),
        headers={'x-apikey': params['api_key']}
    )


def bang_ip(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    ip = args['ip']
    raw_response = client.ip(ip)
    data = raw_response.get('data', {})['attributes']
    context = {
        'Address': ip,
        'ASN': data.get('asn'),
        'Geo': {'Country': data.get('country')},
        'Vendor': 'VirusTotal'
    }
    return CommandResults('IP', 'Address', context, raw_response=raw_response)


def bang_file(client, args):
    """
    1 API Call
    """
    file_hash = args['file']
    if get_hash_type(file_hash) not in ('sha256', 'sha1' or 'md5'):
        raw_response = client.file(file_hash)
    else:
        raise DemistoException(f'Hash {file_hash} is not of type sha256, sha1 or md5')


def main(params: dict, args: dict, command: str):
    client = get_client(params)
    demisto.debug(f'Command called {command}')
    if command == 'file':
        results = bang_file(client, args)
    elif command == 'ip':
        results = bang_ip(client, args)
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in '__main__':
    main(demisto.params(), demisto.args(), demisto.command())
