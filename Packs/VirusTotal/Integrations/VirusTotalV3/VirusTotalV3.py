import copy

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

        if self.is_malicious_pass_threshold(analysis_results, self.file_threshold):
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
    def __init__(self, params: dict):
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
            headers={'x-apikey': params['api_key']}
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
                    suffix='/files',
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
            json_data={'url': url}
        )


# region Helper function
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
    # TODO: scores
    score = client.score_calculator.file_score(file_hash, raw_response)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.File',
        'id',
        outputs=data,
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
    # TODO: scores
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.URL',
        'id',
        outputs=raw_response['data'],
        raw_response=raw_response
    )


def bang_domain(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    domain = args['domain']
    raw_response = client.domain(domain)
    # TODO: score
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Domain',
        'id',
        outputs=raw_response['data'],
        raw_response=raw_response
    )


def file_sandbox_report_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['hash']
    limit = int(args['limit'])
    if get_hash_type(file_hash) in ('sha256', 'sha1', 'md5'):
        raw_response = client.file_sandbox_report(file_hash, limit)
        return CommandResults(
            f'{INTEGRATION_ENTRY_CONTEXT}.SandboxReport'
            'id',
            readable_output=tableToMarkdown(
                f'Sandbox Reports for file hash: {file_hash}',
                raw_response['data'],
                headers=['analysis_date', 'last_modification_date', 'sandbox_name', 'links.self']
            ),
            outputs=raw_response['data'],
            raw_response=raw_response
        )
    else:
        raise DemistoException(f'Hash {file_hash} is not of type sha256, sha1 or md5')


def ip_passive_dns_data(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    ip = args['ip']
    limit = int(args['limit'])
    raw_response = client.passive_dns_data(ip, limit)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.PassiveDNS',
        'id',
        outputs=raw_response['data'],
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
        f'{INTEGRATION_ENTRY_CONTEXT}.{object_type}',
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
    context = {
        'vtScanID': raw_response['data']['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.FileSubmission(val.id && val.id === obj.id)': raw_response['data']
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            f'File "{file_hash}" resubmitted.',
            raw_response['data']
        ),
        outputs=context,
        raw_response=raw_response
    )


def file_scan(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    entry_id = args['entryID']
    upload_url = args['uploadURL']
    file_obj = demisto.getFilePath(entry_id)
    file_path = file_obj['path']
    raw_response = client.file_scan(file_path, upload_url=upload_url)
    data = raw_response['data']
    context = {
        'vtScanID': data['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.FileSubmission(val.id && val.id == obj.id)': data
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            f'The file has been submitted {file_obj["name"]}',
            data
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
    context = {
        'vtScanID': data['id'],  # BC Preservation
        f'{INTEGRATION_ENTRY_CONTEXT}.UrlSubmission(val.id && val.id === obj.id)': data
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            'New url submission:',
            data
        ),
        outputs=context,
        raw_response=raw_response
    )


def main(params: dict, args: dict, command: str):
    client = Client(params)
    results: CommandResults
    demisto.debug(f'Command called {command}')
    if command == 'file':
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
    elif command in (f'{COMMAND_PREFIX}-file-rescan', 'file-rescan'):
        results = file_rescan_command(client, args)
    elif command in (f'{COMMAND_PREFIX}-file-scan', f'file-scan'):
        results = file_scan(client, args)
    elif command == f'{COMMAND_PREFIX}-file-scan-upload-url':
        results = get_upload_url(client)
    elif command in (f'{COMMAND_PREFIX}-url-scan', 'url-scan'):
        results = scan_url_command(client, args)
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in ('__main__', '__builtin__)'):
    main(demisto.params(), demisto.args(), demisto.command())
