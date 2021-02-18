"""
An integration module for the Virus Total v3 API.
API Documentation:
    https://developers.virustotal.com/v3.0/reference
"""
import copy
from collections import defaultdict
from typing import Callable

from CommonServerPython import *
import demistomock as demisto

DBOT_SCORE = (Common.DBotScore.GOOD, Common.DBotScore.SUSPICIOUS, Common.DBotScore.BAD, Common.DBotScore.NONE)
INTEGRATION_NAME = "VirusTotal"
COMMAND_PREFIX = "vt"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"


class ScoreCalculator:
    """
    Calculating DBotScore of files, ip, etc.
    """
    logs: List[str]

    # General
    trusted_vendors_threshold: int
    trusted_vendors: List[str]

    # IP
    ip_threshold: int
    url_threshold: int

    # Domain
    domain_threshold: int
    domain_popularity_ranking: int

    # File
    file_threshold: int
    sigma_ids_threshold: int
    crowdsourced_yara_rules_enabled: bool
    crowdsourced_yara_rules_threshold: int

    def __init__(self, params: dict):
        self.trusted_vendors = argToList(params['preferredVendors'])
        self.trusted_vendors_threshold = int(params['preferredVendorsThreshold'])
        self.file_threshold = int(params['fileThreshold'])
        self.ip_threshold = int(params['ipThreshold'])
        self.url_threshold = int(params['urlThreshold'])
        self.domain_threshold = int(params['domainThreshold'])
        self.crowdsourced_yara_rules_enabled = argToBoolean(params['crowdsourced_yara_rules_enabled'])
        self.crowdsourced_yara_rules_threshold = int(params['yaraRulesThreshold'])
        self.sigma_ids_threshold = int(params['SigmaIDSThreshold'])
        self.domain_popularity_ranking = int(params['domain_popularity_ranking'])

    def get_logs(self) -> str:
        return '\n'.join(self.logs)

    def is_preferred_vendors_pass_malicious(self, analysis_results: dict) -> bool:
        recent = {key: analysis_results[key] for key in list(analysis_results.keys())[:20]}
        preferred_vendor_scores = {
            vendor: recent[vendor] for vendor in self.trusted_vendors if vendor in recent
        }
        malicious_trusted_vendors = [
            item for item in preferred_vendor_scores.values() if item.get('category') == 'malicious'
        ]
        if len(malicious_trusted_vendors) >= self.trusted_vendors_threshold:
            self.logs.append(
                f'{len(malicious_trusted_vendors)} trusted vendors found the hash malicious.\n'
                f'The trusted vendors threshold is {self.trusted_vendors_threshold}\n'
                f'Malicious check: {(len(malicious_trusted_vendors) >= self.trusted_vendors_threshold)=}'
            )
            return True
        else:
            self.logs.append(
                f'Those preferred vendors found the hash malicious: {malicious_trusted_vendors}.'
                f'They do not pass the threshold {self.trusted_vendors_threshold}'
            )
            return False

    def is_malicious_pass_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        total_malicious = analysis_stats['malicious']
        self.logs.append(
            f'{total_malicious} vendors found malicious.\n'
            f'The malicious threshold is {threshold}'
        )
        if total_malicious >= threshold:
            self.logs.append(f'Found as malicious: {total_malicious=} >= {threshold=}')
            return True
        self.logs.append(f'Not found malicious by threshold: {total_malicious=} >= {threshold=}')
        return False

    def file_score(self, given_hash: str, file_response: dict) -> DBOT_SCORE:
        self.logs = list()
        self.logs.append(f'Analysing file hash {given_hash}')
        data = file_response['data']
        analysis_results = data['attributes']['last_analysis_results']
        analysis_stats = data['attributes']['last_analysis_stats']

        # Trusted vendors
        if self.is_preferred_vendors_pass_malicious(analysis_results):
            return Common.DBotScore.BAD

        if self.is_malicious_pass_threshold(analysis_stats, self.file_threshold):
            return Common.DBotScore.BAD
        # Malicious by stats
        suscpicious_by_threshold = self.is_suspicious_by_threshold(analysis_stats, self.file_threshold)
        suspicious_by_rules = self.is_malicious_by_rules(file_response)
        if suscpicious_by_threshold and suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" has found malicious as the hash is suspicious both by threshold and rules '
                f'analysis.'
            )
            return Common.DBotScore.BAD
        elif suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" has found suspicious by rules analysis.'
            )
            return Common.DBotScore.SUSPICIOUS
        elif suscpicious_by_threshold:
            self.logs.append(
                f'Hash: "{given_hash}" has found suspicious by passing the threshold analysis.'
            )
            return Common.DBotScore.SUSPICIOUS
        self.logs.append(
            f'Hash: "{given_hash}" has found good'
        )
        return Common.DBotScore.GOOD  # Nothing caught

    def get_file_object(self, given_hash: str, file_response: dict) -> (dict, str):
        score = self.file_score(given_hash, file_response)
        logs = self.get_logs()
        demisto.debug(logs)
        dbot_entry = Common.DBotScore(
            given_hash,
            DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=score,
            malicious_description=logs
        ).to_context()
        return dbot_entry

    def ip_score(self, communicating_files: dict) -> DBOT_SCORE:
        pass

    def domain_score(self, domain: str, communicating_files: dict) -> dict:
        score: DBOT_SCORE
        # TODO: Calculate
        score = Common.DBotScore.GOOD
        return {
            'Indicator': domain,
            'type': DBotScoreType.DOMAIN,
            'Vendor': INTEGRATION_NAME,
            'Score': score
        }

    def url_score(self, url: str, communicating_files: dict) -> DBOT_SCORE:
        pass

    def is_suspicious_by_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        if analysis_stats['malicious'] >= threshold / 2:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats["malicious"] >= threshold / 2)=}'
            )
            return True
        elif analysis_stats['suspicious'] >= threshold:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats["suspicious"] >= threshold)=}'
            )
            return True
        return False

    def is_malicious_by_rules(self, file_response: dict) -> bool:
        data = file_response['data']
        if self.crowdsourced_yara_rules_enabled:
            self.logs.append(
                'Crowdsourced Yara Rules analyzing enabled'
            )
            if (total_yara_rules := len(
                    data.get('crowdsourced_yara_results', []))) >= self.crowdsourced_yara_rules_threshold:
                self.logs.append(
                    'Found malicious by finding more Crowdsourced Yara Rules than threshold\n'
                    f'{total_yara_rules=} >= {self.crowdsourced_yara_rules_threshold=}'
                )
                return True
        else:
            self.logs.append(
                'Crowdsourced Yara Rules analyzing is not enabled. Skipping'
            )
        if sigma_rules := data.get('sigma_analysis_stats'):
            self.logs.append(
                'Found sigma rules, analyzing.'
            )
            sigma_high, sigma_critical = sigma_rules.get('high', 0), sigma_rules.get('critical', 0)
            if (sigma_high + sigma_critical) >= self.sigma_ids_threshold:
                self.logs.append(
                    f'Found malicious, {(sigma_high + sigma_critical)=} >= {self.sigma_ids_threshold=}'
                )
                return True
            else:
                self.logs.append(
                    'Not found malicious by sigma'
                )
        else:
            self.logs.append(
                'Not found sigma analysis. Skipping'
            )
        if crowdsourced_ids_stats := data.get('crowdsourced_ids_stats'):
            self.logs.append(
                'Found crowdsourced IDS analysis, analyzing.'
            )
            ids_high, ids_critical = crowdsourced_ids_stats.get('high'), crowdsourced_ids_stats.get('critical')
            if (ids_high + ids_critical) >= self.sigma_ids_threshold:
                self.logs.append(
                    f'Found malicious, {((ids_high + ids_critical) >= self.sigma_ids_threshold)=}'
                )
                return True
            else:
                self.logs.append(
                    'Not found malicious by sigma'
                )
        else:
            self.logs.append(
                'Not found crowdsourced IDS analysis. Skipping'
            )
        return False

    def get_url_object(self, url: str, raw_response: dict):
        score = self.url_score(url, raw_response)


class Client(BaseClient):
    def __init__(self, params: dict):
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
            headers={'x-apikey': params['APIKey']}
        )
        self.score_calculator = ScoreCalculator(
            params
        )

    def ip(self, ip: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#ip-info
        """
        return self._http_request(
            'GET',
            f'ip_addresses/{ip}'
        )

    def file(self, file: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#file
        """
        return self._http_request(
            'GET',
            f'files/{file}'
        )

    def url(self, url: str):
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#url
        """
        return self._http_request(
            'GET',
            f'urls/{encode_url_to_base64(url)}'
        )

    def domain(self, domain: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#domain-info
        """
        return self._http_request(
            'GET',
            f'domains/{domain}'
        )

    def file_sandbox_report(self, file_hash: dict, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-relationships
        """
        return self._http_request(
            'GET',
            f'files/{file_hash}/behaviours',
            params={'limit': limit}
        )

    def passive_dns_data(self, ip: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#ip-relationships
        """
        return self._http_request(
            'GET',
            f'ip_addresses/{ip}/resolutions',
            params={'limit': limit}
        )

    def get_ip_comments(self, ip: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#ip-comments-get
        """
        return self._http_request(
            'GET',
            f'ip_addresses/{ip}/comments',
            params={'limit': limit}
        )

    def get_url_comments(self, url: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-comments-get

        """
        return self._http_request(
            'GET',
            f'urls/{encode_url_to_base64(url)}/comments',
            params={'limit': limit}
        )

    def get_hash_comments(self, file_hash: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-comments-get
        """
        return self._http_request(
            'GET',
            f'files/{file_hash}/comment',
            params={'limit': limit}
        )

    def get_domain_comments(self, domain: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#domains-comments-get
        """
        return self._http_request(
            'GET',
            f'domains/{domain}/comments',
            params={'limit': limit}
        )

    def get_comment_by_id(self, comment_id: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#get-comment
        """
        return self._http_request(
            'GET',
            f'comments/{comment_id}'
        )

    def add_comment_to_ip(self, ip: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#ip-comments-post
        """
        return self._http_request(
            'POST',
            f'ip_addresses/{ip}/comments',
            json_data={"type": "comment", "attributes": {"text": comment}}
        )

    def add_comment_to_url(self, url: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-comments-post
        """
        return self._http_request(
            'POST',
            f'urls/{encode_url_to_base64(url)}/comments',
            json_data={"type": "comment", "attributes": {"text": comment}}
        )

    def add_comment_to_domain(self, domain: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#domains-comments-post
        """
        return self._http_request(
            'POST',
            f'domain/{domain}/comments',
            json_data={"type": "comment", "attributes": {"text": comment}}
        )

    def add_comment_to_file(self, resource: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-comments-post
        """
        return self._http_request(
            'POST',
            f'files/{resource}/comments',
            json_data={"type": "comment", "attributes": {"text": comment}}
        )

    def file_rescan(self, file_hash: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-analyse
        """
        return self._http_request(
            'POST',
            f'/files/{file_hash}/analyse'
        )

    def file_scan(self, file_path: str, /, upload_url: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-scan
        """
        with open(file_path) as file:
            if upload_url:
                return self._http_request(
                    'POST',
                    full_url=upload_url,
                    files={'file': file}
                )
            else:
                return self._http_request(
                    'POST',
                    url_suffix='/files',
                    files={'file': file}
                )

    def get_upload_url(self) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-upload-url
        """
        return self._http_request(
            'GET',
            'files/upload_url'
        )

    def url_scan(self, url: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#urls
        """
        return self._http_request(
            'POST',
            'urls',
            data={'url': url}
        )

    def search(self, query: str):
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#search-1
        """
        return self._http_request(
            'GET',
            'search',
            params={'query': query}
        )

    def get_analysis(self, analysis_id: str) -> dict:
        return self._http_request(
            'GET',
            f'/analyses/{analysis_id}'
        )


# region Helper function
def get_file_context(entry_id: str) -> dict:
    """Gets a File object from context.

    Args:
        entry_id: The entry ID of the file

    Returns:
        File object contains Name, Hashes and more information
    """
    context = demisto.dt(demisto.context(), f'File(val.EntryID === "{entry_id}")')
    if not context:
        return {}
    if isinstance(context, list):
        return context[0]
    return context


def raise_if_ip_not_valid(ip: str):
    """Raises an error if ip is not valid

    Args:
        ip: ip address

    Raises:
        ValueError: If IP is not valid

    Examples:
        >>> raise_if_ip_not_valid('not ip at all')
        Traceback (most recent call last):
         ...
        ValueError: IP "not ip at all" is not valid
        >>> raise_if_ip_not_valid('8.8.8.8')
    """
    if not is_ip_valid(ip, accept_v6_ips=True):
        raise ValueError(f'IP "{ip}" is not valid')


def raise_if_hash_not_valid(file_hash: str):
    """Raises an error if file_hash is not valid

    Args:
        file_hash: file hash

    Raises:
        ValueError: if hash is not sha256, sha1, md5

    Examples:
        >>> raise_if_hash_not_valid('not a hash')
        Traceback (most recent call last):
         ...
        ValueError: Hash not a hash is not of type sha256, sha1 or md5
        >>> raise_if_hash_not_valid('7e641f6b9706d860baf09fe418b6cc87')
    """
    if get_hash_type(file_hash) not in ('sha256', 'sha1', 'md5'):
        raise ValueError(f'Hash {file_hash} is not of type sha256, sha1 or md5')


def encode_url_to_base64(url: str) -> str:
    """Gets a string (in this case, url but it can not be) and return it as base64 without padding ('=')

    Args:
         url: A string to encode

    Returns:
         Base64 encoded string with no padding

    Examples:
        >>> encode_url_to_base64('https://example.com')
        'aHR0cHM6Ly9leGFtcGxlLmNvbQ'
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def remove_links(data: List[dict]) -> list:
    """

    Args:
        data: List from raw response which may contain links.

    Returns:
        data without links key

    Examples:
        >>> remove_links([{'links': ['link', 'link']}])
        [{}]
    """
    data = copy.deepcopy(data)
    for i, item in enumerate(data):
        del item['links']
        data[i] = item
    return data


# endregion

def bang_ip(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    ip = args['ip']
    raise_if_ip_not_valid(ip)
    raw_response = client.ip(ip)
    # TODO: scores
    data = raw_response.get('data', {})['attributes']
    context = {
        'Address': ip,
        'ASN': data.get('asn'),
        'Geo': {'Country': data.get('country')},
        'Vendor': 'VirusTotal'
    }
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.IP',
        'id',
        context,
        raw_response=raw_response
    )


def bang_file(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['file']
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file(file_hash)
    data = raw_response['data']
    dbot_entry = client.score_calculator.get_file_object(file_hash, raw_response)
    data.update(dbot_entry)
    outputs = {
        f'{INTEGRATION_ENTRY_CONTEXT}.File(val.id && val.id === obj.id)': data,
        **dbot_entry
    }
    last_analysis_stats = data['attributes']["last_analysis_stats"]
    malicious = last_analysis_stats['malicious']
    total = sum(last_analysis_stats.values())
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Results of file hash {file_hash}',
            {
                **data,
                **data['attributes'],
                'positives': f'{malicious}/{total}'
            },
            headers=[
                'sha1', 'sha256', 'md5',
                'meaningful_name', 'type_extension', 'creation_date',
                'last_modification_date', 'reputation', 'positives',
                'links'
            ]
        ),
        outputs=outputs,
        raw_response=raw_response
    )


def bang_url(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    url = args['url']
    raw_response = client.url(
        url
    )
    data = raw_response['data']
    score = client.score_calculator.get_url_object(url, raw_response)
    url_standard = {
        'Data': url,
        'Category': data.get('attributes', {}).get('categories')
    }
    outputs = {
        f'{INTEGRATION_ENTRY_CONTEXT}.URL(val.id && val.id === obj.id)': data,
        Common.URL.CONTEXT_PATH: url_standard
    }
    return CommandResults(
        outputs=outputs,
        raw_response=raw_response
    )


def bang_domain(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    domain = args['domain']
    raw_response = client.domain(domain)
    data = raw_response['data']
    whois = defaultdict(lambda: None)
    for line in data['attributes']['whois'].splitlines():
        key, value = line.split(sep=':', maxsplit=1)
        if key in whois:
            if not isinstance(whois[key], list):
                value = whois[key]
                whois[key] = list()
                whois[key].append(value)
            whois[key].append(value)
        else:
            whois[key] = value
    domain_standard = {
        'Name': domain,
        'CreationDate': whois['Creation Date'],
        'UpdatedDate': whois['Updated Date'],
        'ExpirationDate': whois['Registry Expiry Date'],
        'NameServers': whois['Name Server'],
        'Admin': {
            'Name': whois['Admin Organization'],
            'Email': whois['Admin Email'],
            'Country': whois['Admin Country'],
        },
        'Registrant': {
            'Country': whois['Registrant Country'],
            'Email': whois['Registrant Email']
        },
        'WHOIS': {
            'CreationDate': whois['Creation Date'],
            'UpdatedDate': whois['Updated Date'],
            'ExpirationDate': whois['Registry Expiry Date'],
            'Registrar': {
                'Name': whois['Registrar'],
                'AbuseEmail': whois['Registrar Abuse Contact Email'],
                'AbusePhone': whois['Registrar Abuse Contact Phone'],
            },
            'Admin': {
                'Name': whois['Admin Organization'],
                'Email': whois['Admin Email']
            },
        }
    }
    context = {
        f'{INTEGRATION_ENTRY_CONTEXT}.Domain(val.id && val.id === obj.id) ': data,
        Common.Domain.CONTEXT_PATH: domain_standard
        # Common.DBotScore.CONTEXT_PATH: client.score_calculator.domain_score(domain)
    }

    # TODO: score
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Domain data of {domain}',
            {
                **data,
                **whois,
                **data['attributes']
            },
            headers=[
                'id', 'Registrant Country', 'last_modification_date',
                'last_analysis_stats', 'links'
            ],
            removeNull=True
        ),
        outputs=context,
        raw_response=raw_response
    )


def file_sandbox_report_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['file']
    limit = int(args['limit'])
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file_sandbox_report(file_hash, limit)
    data = raw_response['data']
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.SandboxReport'
        'id',
        readable_output=tableToMarkdown(
            f'Sandbox Reports for file hash: {file_hash}',
            [
                {
                    'id': item['id'],
                    **item['attributes'],
                    'link': item['links']['self']
                } for item in data
            ],
            headers=['analysis_date', 'last_modification_date', 'sandbox_name', 'link']
        ),
        outputs=data,
        raw_response=raw_response
    )


def ip_passive_dns_data(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    ip = args['ip']
    limit = int(args['limit'])
    raw_response = client.passive_dns_data(ip, limit)
    data = raw_response['data']
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.PassiveDNS',
        'id',
        readable_output=tableToMarkdown(
            f'Passive DNS data for IP {ip}',
            [
                {
                    'id': item['id'],
                    **item['attributes']
                } for item in data
            ],
            headers=['id', 'date', 'host_name', 'ip_address', 'resolver']
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_comments_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call

    BC Break - No NotBefore argument
    added limit
    """
    limit = int(args['limit'])
    resource = args['resource']
    resource_type = args['resource_type'].lower()
    # Will find if there's one and only one True in the list.
    if resource_type == 'ip':
        raise_if_ip_not_valid(resource)
        object_type = 'IP'
        raw_response = client.get_ip_comments(resource, limit)
    elif resource_type == 'url':
        object_type = 'URL'
        raw_response = client.get_url_comments(resource, limit)
    elif resource_type == 'hash':
        object_type = 'File'
        raise_if_hash_not_valid(resource)
        raw_response = client.get_hash_comments(resource, limit)
    elif resource_type == 'domain':
        object_type = 'Domain'
        raw_response = client.get_domain_comments(resource, limit)
    else:
        raise DemistoException(f'Could not find resource type of "{resource_type}"')
    data = raw_response['data']
    data = remove_links(data)
    context = {
        'id': resource,
        'comments': data
    }
    # TODO: human readable
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.{object_type}Comments',
        'id',
        readable_output=tableToMarkdown(
            '',
            data
        ),
        outputs=context,
        raw_response=raw_response
    )


def add_comments_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    resource = args['resource']
    resource_type = args['resource_type'].lower()
    comment = args['comment']
    if resource_type == 'ip':
        raise_if_ip_not_valid(resource)
        client.add_comment_to_ip(resource, comment)
    elif resource_type == 'url':
        client.add_comment_to_url(resource, comment)
    elif resource_type == 'domain':
        client.add_comment_to_domain(resource, comment)
    elif resource_type == 'hash':
        raise_if_hash_not_valid(resource)
        client.add_comment_to_file(resource, comment)
    else:
        raise DemistoException(f'Could not find resource type of "{resource_type}"')
    return CommandResults(
        readable_output=f'Comment has been added to {resource_type}: {resource}'
    )


def file_rescan_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['hash']
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file_rescan(file_hash)
    data = raw_response['data']
    data['hash'] = file_hash
    context = {
        'vtScanID': raw_response['data']['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            f'File "{file_hash}" resubmitted.',
            data
        ),
        outputs=context,
        raw_response=raw_response
    )


def file_scan(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    entry_id = args['entryID']
    upload_url = args.get('uploadURL')
    file_obj = demisto.getFilePath(entry_id)
    file_path = file_obj['path']
    raw_response = client.file_scan(file_path, upload_url=upload_url)
    data = raw_response['data']
    data.update(
        assign_params(
            **get_file_context(entry_id)
        )
    )

    context = {
        'vtScanID': data['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id == obj.id)': data
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            f'The file has been submitted {file_obj["name"]}',
            data,
            headers=['id', 'EntryID']
        ),
        outputs=context,
        raw_response=raw_response
    )


def get_upload_url(client: Client) -> CommandResults:
    """
    1 API Call
    """
    raw_response = client.get_upload_url()
    upload_url = raw_response['data']
    context = {
        'vtUploadURL': upload_url,  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.FileUploadURL': upload_url
    }
    return CommandResults(
        tableToMarkdown(
            'New upload url acquired!',
            {'upload_url': upload_url}
        ),
        outputs=context,
        raw_response=raw_response
    )


def scan_url_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    url = args['url']
    raw_response = client.url_scan(url)
    data = raw_response['data']
    data['url'] = url
    context = {
        'vtScanID': data['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            'New url submission:',
            data,
            headers=['id', 'url']
        ),
        outputs=context,
        raw_response=raw_response
    )


def search_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    query = args['query']
    raw_response = client.search(query)
    data = raw_response['data']
    data = remove_links(data)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.SearchResults',
        'id',
        readable_output=tableToMarkdown(
            f'Search result of query {query}',
            data
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_comments_by_id_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    comment_id = args['id']
    raw_response = client.get_comment_by_id(comment_id)
    data = raw_response['data']
    data = remove_links(data)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Comments',
        'id',
        readable_output=tableToMarkdown(
            f'Comment of ID {comment_id}',
            data
        ),
        outputs=data,
        raw_response=raw_response
    )


def check_module(client: Client) -> str:
    """
    1 API Call
    """
    client.get_ip_comments('8.8.8.8', 1)
    return 'ok'


def get_analysis_command(client: Client, args: dict) -> CommandResults:
    analysis_id = args['analysis_id']
    raw_response = client.get_analysis(analysis_id)
    data = raw_response['data']
    meta = raw_response['meta']
    if url_info := meta.get('url_info'):
        if client.score_calculator.url_score(data):
            pass

    if file_info := meta.get('file_info'):
        pass


def main(params: dict, args: dict, command: str):
    client = Client(params)
    demisto.debug(f'Command called {command}')
    if command == 'test-module':
        results = check_module(client)
    elif command == 'file':
        results = bang_file(client, args)
    elif command == 'ip':
        results = bang_ip(client, args)
    elif command == 'url':
        results = bang_url(client, args)
    elif command == 'domain':
        results = bang_domain(client, args)
    elif command == f'{COMMAND_PREFIX}-file-sandbox-report':
        results = file_sandbox_report_command(client, args)
    elif command == f'{COMMAND_PREFIX}-ip-passive-dns-data':
        results = ip_passive_dns_data(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-get':
        results = get_comments_command(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-add':
        results = add_comments_command(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-get-by-id':
        results = get_comments_by_id_command(client, args)
    elif command in (f'{COMMAND_PREFIX}-file-rescan', 'file-rescan'):
        results = file_rescan_command(client, args)
    elif command in (f'{COMMAND_PREFIX}-file-scan', f'file-scan'):
        results = file_scan(client, args)
    elif command == f'{COMMAND_PREFIX}-file-scan-upload-url':
        results = get_upload_url(client)
    elif command in (f'{COMMAND_PREFIX}-url-scan', 'url-scan'):
        results = scan_url_command(client, args)
    elif command == f'{COMMAND_PREFIX}-search':
        results = search_command(client, args)
    elif command == f'{COMMAND_PREFIX}-analysis-get':
        results = get_analysis_command(client, args)
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in ('builtins', '__builtin__'):
    try:
        main(demisto.params(), demisto.args(), demisto.command())
    except Exception as exc:
        return_error(exc)
