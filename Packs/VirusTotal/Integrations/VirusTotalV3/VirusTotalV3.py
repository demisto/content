"""
An integration module for the Virus Total v3 API.
API Documentation:
    https://developers.virustotal.com/v3.0/reference
"""
import copy
from collections import defaultdict
from typing import Callable

from CommonServerPython import *

INTEGRATION_NAME = "VirusTotal"
COMMAND_PREFIX = "vt"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"


class Client(BaseClient):
    """
    Attributes:
        is_premium: Shall use the premium api (mostly for reputation commands)
    """
    is_premium: bool

    def __init__(self, params: dict):
        self.is_premium = argToBoolean(params['is_premium_api'])
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
            headers={'x-apikey': params['APIKey']}
        )

    # region Reputation calls

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

    # endregion

    # region Comments call
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

    # endregion

    # region Scan calls
    def file_rescan(self, file_hash: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-analyse
        """
        return self._http_request(
            'POST',
            f'/files/{file_hash}/analyse'
        )

    def file_scan(self, file_path: str, /, upload_url: Optional[str]) -> dict:
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

    # endregion

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
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#analysis
        """
        return self._http_request(
            'GET',
            f'/analyses/{analysis_id}'
        )

    # region Premium commands
    def get_relationship(self, indicator: str, indicator_type: str, relationship: str) -> dict:
        """
        Args:
            indicator: a url encoded in base64 or domain.
            indicator_type: urls or domains
            relationship: a relationship to search for
        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-relationships
            https://developers.virustotal.com/v3.0/reference#domains-relationships
            https://developers.virustotal.com/v3.0/reference#ip-relationships
        """

        return self._http_request(
            'GET',
            urljoin(urljoin(indicator_type, indicator), relationship)
        )

    def get_domain_relationships(self, domain: str, relationship: str) -> dict:
        """
        Wrapper of get_relationship

        See Also:
                https://developers.virustotal.com/v3.0/reference#domains-relationships
        """
        return self.get_relationship(domain, 'domains', relationship)

    def get_domain_communicating_files(self, domain: str) -> dict:
        """
        Wrapper of get_domain_relationships

        See Also:
            https://developers.virustotal.com/v3.0/reference#domains-relationships
        """
        return self.get_domain_relationships(
            domain,
            'communicating_files'
        )

    def get_domain_downloaded_files(self, domain: str) -> dict:
        """
        Wrapper of get_domain_relationships

        See Also:
            https://developers.virustotal.com/v3.0/reference#domains-relationships
        """
        return self.get_domain_relationships(
            domain,
            'downloaded_files'
        )

    def get_domain_referrer_files(self, domain: str) -> dict:
        """
        Wrapper of get_domain_relationships

        See Also:
                https://developers.virustotal.com/v3.0/reference#domains-relationships
        """
        return self.get_domain_relationships(
            domain,
            'referrer_files'
        )

    def get_url_relationships(self, url: str, relationship: str) -> dict:
        """
        Wrapper of get_relationship

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_relationship(encode_url_to_base64(url), 'urls', relationship)

    def get_url_communicating_files(self, url: str) -> dict:
        """
        Wrapper of url_relationships

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_url_relationships(
            url,
            'communicating_files'
        )

    def get_url_downloaded_files(self, url: str) -> dict:
        """
        Wrapper of url_relationships

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_url_relationships(
            url,
            'downloaded_files'
        )

    def get_url_referrer_files(self, url: str) -> dict:
        """
        Wrapper of url_relationships

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_url_relationships(
            url,
            'referrer_files'
        )

    def get_ip_relationships(self, ip: str, relationship: str) -> dict:
        """
        Wrapper of get_relationship

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_relationship(ip, 'ip_addresses', relationship)

    def get_ip_communicating_files(self, ip: str) -> dict:
        """
        Wrapper of get_ip_relationships

        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_ip_relationships(
            ip,
            'communicating_files'
        )

    def get_ip_downloaded_files(self, ip: str) -> dict:
        """
        Wrapper of get_ip_relationships

        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_ip_relationships(
            ip,
            'downloaded_files'
        )

    def get_ip_referrer_files(self, ip: str) -> dict:
        """
        Wrapper of get_ip_relationships

        See Also:
                https://developers.virustotal.com/v3.0/reference#urls-relationships
        """
        return self.get_ip_relationships(
            ip,
            'referrer_files'
        )
    # endregion


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
    relationship_threshold: int

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
        self.relationship_threshold = int(params['relashionship_threshold'])
        self.logs = list()

    def get_logs(self) -> str:
        return '\n'.join(self.logs)

    def is_suspicious_by_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        if analysis_stats['malicious'] >= threshold / 2:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats["malicious"] >= threshold / 2)=}. '
            )
            return True
        elif analysis_stats['suspicious'] >= threshold:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats["suspicious"] >= threshold)=}. '
            )
            return True
        return False

    def is_good_by_popularity_ranks(self, popularity_ranks: dict) -> Optional[bool]:
        if popularity_ranks:
            self.logs.append(
                'Found popularity ranks. Analyzing. '
            )
            average = sum(rank['rank'] for rank in popularity_ranks.values()) / len(popularity_ranks)
            self.logs.append(
                f'The average of the ranks is {average} and the threshold is {self.domain_popularity_ranking}'
            )
            if average >= self.domain_popularity_ranking:
                self.logs.append('Indicator is good by popularity ranks.')
                return True
            else:
                self.logs.append('Indicator might not be good by it\'s popularity ranks')
                return False
        return None

    def is_suspicious_by_rules(self, file_response: dict) -> bool:
        data = file_response['data']
        if self.crowdsourced_yara_rules_enabled:
            self.logs.append(
                'Crowdsourced Yara Rules analyzing enabled. '
            )
            if (total_yara_rules := len(
                    data.get('crowdsourced_yara_results', []))) >= self.crowdsourced_yara_rules_threshold:
                self.logs.append(
                    'Found malicious by finding more Crowdsourced Yara Rules than threshold. \n'
                    f'{total_yara_rules=} >= {self.crowdsourced_yara_rules_threshold=}'
                )
                return True
        else:
            self.logs.append(
                'Crowdsourced Yara Rules analyzing is not enabled. Skipping. '
            )
        if sigma_rules := data.get('sigma_analysis_stats'):
            self.logs.append(
                'Found sigma rules, analyzing. '
            )
            sigma_high, sigma_critical = sigma_rules.get('high', 0), sigma_rules.get('critical', 0)
            if (sigma_high + sigma_critical) >= self.sigma_ids_threshold:
                self.logs.append(
                    f'Found malicious, {(sigma_high + sigma_critical)=} >= {self.sigma_ids_threshold=}. '
                )
                return True
            else:
                self.logs.append(
                    'Not found malicious by sigma. '
                )
        else:
            self.logs.append(
                'Not found sigma analysis. Skipping. '
            )
        if crowdsourced_ids_stats := data.get('crowdsourced_ids_stats'):
            self.logs.append(
                'Found crowdsourced IDS analysis, analyzing. '
            )
            ids_high, ids_critical = crowdsourced_ids_stats.get('high'), crowdsourced_ids_stats.get('critical')
            if (ids_high + ids_critical) >= self.sigma_ids_threshold:
                self.logs.append(
                    f'Found malicious, {((ids_high + ids_critical) >= self.sigma_ids_threshold)=}. '
                )
                return True
            else:
                self.logs.append(
                    'Not found malicious by sigma. '
                )
        else:
            self.logs.append(
                'Not found crowdsourced IDS analysis. Skipping. '
            )
        return False

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
                f'{len(malicious_trusted_vendors)} trusted vendors found the hash malicious. \n'
                f'The trusted vendors threshold is {self.trusted_vendors_threshold}. \n'
                f'Malicious check: {(len(malicious_trusted_vendors) >= self.trusted_vendors_threshold)=}. '
            )
            return True
        else:
            self.logs.append(
                f'Those preferred vendors found the hash malicious: {malicious_trusted_vendors}. '
                f'They do not pass the threshold {self.trusted_vendors_threshold}. '
            )
            return False

    def is_malicious_by_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        total_malicious = analysis_stats['malicious']
        self.logs.append(
            f'{total_malicious} vendors found malicious. \n'
            f'The malicious threshold is {threshold}. '
        )
        if total_malicious >= threshold:
            self.logs.append(f'Found as malicious: {total_malicious=} >= {threshold=}. ')
            return True
        self.logs.append(f'Not found malicious by threshold: {total_malicious=} >= {threshold=}. ')
        return False

    def score_by_threshold(self, analysis_stats: dict, threshold: int) -> int:
        if self.is_malicious_by_threshold(analysis_stats, threshold):
            return Common.DBotScore.BAD
        if self.is_suspicious_by_threshold(analysis_stats, threshold):
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.GOOD

    def score_by_results_and_stats(self, indicator: str, raw_response: dict, threshold: int) -> int:
        self.logs.append(f'Basic analyzing of "{indicator}"')
        data = raw_response['data']
        attributes = data['attributes']
        popularity_ranks = attributes.get('popularity_ranks')
        last_analysis_results = attributes['last_analysis_results']
        last_analysis_stats = attributes['last_analysis_stats']
        if self.is_good_by_popularity_ranks(popularity_ranks):
            return Common.DBotScore.GOOD
        if self.is_preferred_vendors_pass_malicious(last_analysis_results):
            return Common.DBotScore.BAD
        return self.score_by_threshold(last_analysis_stats, threshold)

    def file_score(self, given_hash: str, file_response: dict) -> int:
        self.logs.append(f'Analysing file hash {given_hash}. ')
        data = file_response['data']
        attributes = data['attributes']
        analysis_results = attributes['last_analysis_results']
        analysis_stats = attributes['last_analysis_stats']

        # Trusted vendors
        if self.is_preferred_vendors_pass_malicious(analysis_results):
            return Common.DBotScore.BAD

        score = self.score_by_threshold(analysis_stats, self.file_threshold)
        if score == Common.DBotScore.BAD:
            return Common.DBotScore.BAD

        suspicious_by_rules = self.is_suspicious_by_rules(file_response)
        if score == Common.DBotScore.SUSPICIOUS and suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" was found malicious as the hash is suspicious both by threshold and rules '
                f'analysis.'
            )
            return Common.DBotScore.BAD
        elif suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" was found suspicious by rules analysis.'
            )
            return Common.DBotScore.SUSPICIOUS
        elif score == Common.DBotScore.SUSPICIOUS:
            self.logs.append(
                f'Hash: "{given_hash}" was found suspicious by passing the threshold analysis.'
            )
            return Common.DBotScore.SUSPICIOUS
        self.logs.append(
            f'Hash: "{given_hash}" was found good'
        )
        return Common.DBotScore.GOOD  # Nothing caught

    def ip_score(self, ip: str, raw_response: dict) -> int:
        return self.score_by_results_and_stats(
            ip, raw_response, self.ip_threshold
        )

    def url_score(self, indicator: str, raw_response: dict) -> int:
        return self.score_by_results_and_stats(indicator, raw_response, self.url_threshold)

    def domain_score(self, indicator: str, raw_response: dict) -> int:
        return self.score_by_results_and_stats(indicator, raw_response, self.domain_threshold)

    # region Premium analysis
    def is_malicious_or_suspicious_by_relationship_files(self, relationship_files_response: dict) -> int:
        files = relationship_files_response['data'][:20]
        total_malicious = sum(
            self.file_score(file['sha256'], files) for file in files
        )
        if total_malicious >= self.url_threshold:
            self.logs.append(
                f'Found malicious by relationship files. {total_malicious=} >= {self.relationship_threshold}'
            )
            return Common.DBotScore.BAD
        if total_malicious >= self.url_threshold:
            self.logs.append(
                f'Found suspicious by relationship files. {total_malicious=} >= {self.relationship_threshold}'
            )
            return Common.DBotScore.SUSPICIOUS
        self.logs.append(
            f'Found safe by relationship files. {total_malicious=} >= {self.relationship_threshold}'
        )
        return Common.DBotScore.GOOD

    def analyze_premium_scores(
            self,
            indicator: str,
            base_score: int,
            relationship_functions: List[Callable[[str], dict]]
    ) -> int:
        """Analyzing with premium subscription.

        Args:
            indicator: The indicator to check
            base_score: DBotScore got by base check
            relationship_functions: function to get relationship from (found in client)

        Returns:
            DBOT Score:
            If one of the relationship files is Bad, returns Bad
            if one of the relationship files is suspicious and the base_score is suspicious, returns BAD
            If one of the relationship files is suspicious and base_score is not, returns Suspicious
            else return GOOD
        """
        is_suspicious = False
        for func in relationship_functions:
            self.logs.append(f'Analyzing by {func.__name__}')
            premium_score = self.is_malicious_or_suspicious_by_relationship_files(
                func(indicator)
            )
            if premium_score == Common.DBotScore.BAD:
                return premium_score
            if premium_score == Common.DBotScore.SUSPICIOUS and base_score == Common.DBotScore.SUSPICIOUS:
                self.logs.append('Found malicious!')
                return premium_score
            if premium_score == Common.DBotScore.SUSPICIOUS:
                self.logs.append('Found Suspicious entry, keep searching for malicious')
                is_suspicious = True
        if is_suspicious or base_score == Common.DBotScore.SUSPICIOUS:
            self.logs.append('Found Suspicious')
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.GOOD

    def analyze_premium_url_score(self, client: Client, url: str, base_score: int) -> int:
        """Analyzing premium subscription.

        Args:
            client: a client with relationship commands.
            url: the url to check
            base_score: the base score from basic analysis

        Returns:
            score calculated by relationship.

        """
        return self.analyze_premium_scores(
            url,
            base_score,
            [
                client.get_url_communicating_files,
                client.get_url_downloaded_files,
                client.get_url_referrer_files
            ]
        )

    def analyze_premium_domain_score(self, client: Client, domain: str, base_score: int) -> int:
        """Analyzing premium subscription.

        Args:
            client: a client with relationship commands.
            domain: the domain to check
            base_score: the base score from basic analysis

        Returns:
            score calculated by relationship.

        """
        return self.analyze_premium_scores(
            domain,
            base_score,
            [
                client.get_domain_communicating_files,
                client.get_url_downloaded_files,
                client.get_url_referrer_files
            ]
        )

    def analyze_premium_ip_score(self, client: Client, ip: str, base_score: int) -> int:
        """Analyzing premium subscription.

        Args:
            client: a client with relationship commands.
            ip: the ip to check
            base_score: the base score from basic analysis

        Returns:
            score calculated by relationship.

        """
        return self.analyze_premium_scores(
            ip,
            base_score,
            [
                client.get_ip_communicating_files,
                client.get_ip_downloaded_files,
                client.get_ip_referrer_files
            ]
        )
    # endregion


# region Helper functions
def build_url_output(client: Client, score_calculator: ScoreCalculator, url: str, raw_response: dict) -> CommandResults:
    data = raw_response['data']

    score = score_calculator.url_score(url, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_url_score(client, url, score)

    url_standard = {
        'Data': url,
        'Category': data.get('attributes', {}).get('categories')
    }
    logs = score_calculator.get_logs()
    if score == Common.DBotScore.BAD:
        url_standard['Malicious'] = {
            'Vendor': INTEGRATION_NAME,
            'Description': logs
        }
    demisto.debug(logs)
    outputs = {
        f'{INTEGRATION_ENTRY_CONTEXT}.URL(val.id && val.id === obj.id)': data,
        Common.URL.CONTEXT_PATH: url_standard
    }
    outputs.update(
        Common.DBotScore(
            url,
            DBotScoreType.URL,
            INTEGRATION_NAME,
            score
        ).to_context()
    )
    # creating readable output
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes['last_analysis_stats']
    malicious = last_analysis_stats['malicious']
    total = sum(last_analysis_stats.values())
    return CommandResults(
        readable_output=tableToMarkdown(
            f'URL data of "{url}"',
            {
                **data,
                **data.get('attributes', {}),
                'url': url,
                'positives': f'{malicious}/{total}',
                'last_modified': timestamp_to_datestring(attributes['last_modification_date'])
            },
            headers=[
                'url',
                'title',
                'last_modified',
                'has_content',
                'last_http_response_content_sha256',
                'positives',
                'reputation'
            ]
        ),
        outputs=outputs,
        raw_response=raw_response
    )


def build_file_output(score_calculator, file_hash, raw_response) -> CommandResults:
    data = raw_response['data']
    score = score_calculator.file_score(file_hash, raw_response)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    outputs = {
        f'{INTEGRATION_ENTRY_CONTEXT}.File(val.id && val.id === obj.id)': data,
        **Common.DBotScore(
            file_hash,
            DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=score,
            malicious_description=logs
        ).to_context()
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


def get_whois(whois_string: str) -> defaultdict:
    """Gets a WHOIS string and returns a parsed dict of the WHOIS String.

    Args:
        whois_string: whois from domain api call

    Returns:
        A parsed whois

    Examples:
        >>> get_whois('key1:value\\nkey2:value2')
        defaultdict({'key1': 'value', 'key2': 'value2'})
    """
    whois: defaultdict = defaultdict(lambda: None)
    for line in whois_string.splitlines():
        key, value = line.split(sep=':', maxsplit=1)
        if key in whois:
            if not isinstance(whois[key], list):
                value = whois[key]
                whois[key] = list()
                whois[key].append(value)
            whois[key].append(value)
        else:
            whois[key] = value
    return whois


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

# region Reputation commands
def bang_ip(client: Client, score_calculator: ScoreCalculator, args: dict) -> CommandResults:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    ip = args['ip']
    raise_if_ip_not_valid(ip)
    raw_response = client.ip(ip)
    score = score_calculator.ip_score(ip, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_ip_score(client, ip, score)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    data = raw_response['data']
    attributes = data['attributes']
    ip_standard = {
        'Address': ip,
        'ASN': attributes.get('asn'),
        'Geo': {'Country': data.get('country')},
        'Vendor': 'VirusTotal'
    }
    if score == Common.DBotScore.BAD:
        ip_standard['Malicious'] = {
            'Vendor': INTEGRATION_NAME,
            'Description': logs
        }
    outputs = {
        f'{INTEGRATION_ENTRY_CONTEXT}.IP(val.id && val.id === obj.id)': data,
        **Common.DBotScore(
            ip,
            DBotScoreType.IP,
            INTEGRATION_NAME,
            score
        ).to_context(),
        **ip_standard
    }
    last_analysis_stats = data['attributes']["last_analysis_stats"]
    malicious = last_analysis_stats['malicious']
    total = sum(last_analysis_stats.values())
    return CommandResults(
        readable_output=tableToMarkdown(
            'IP reputation:',
            {
                **data,
                **attributes,
                'last_modified': timestamp_to_datestring(attributes['last_modification_date']),
                'positives': f'{malicious}/{total}'
            },
            headers=['id', 'network', 'country', 'last_modified', 'reputation', 'positives']
        ),
        outputs=outputs,
        raw_response=raw_response
    )


def bang_file(client: Client, score_calculator: ScoreCalculator, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['file']
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file(file_hash)
    return build_file_output(score_calculator, file_hash, raw_response)


def bang_url(client: Client, score_calculator: ScoreCalculator, args: dict) -> CommandResults:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    url = args['url']
    raw_response = client.url(
        url
    )
    return build_url_output(client, score_calculator, url, raw_response)


def bang_domain(client: Client, score_calculator: ScoreCalculator, args: dict) -> CommandResults:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    domain = args['domain']
    raw_response = client.domain(domain)
    data = raw_response['data']
    attributes = data['attributes']
    whois = get_whois(attributes['whois'])
    domain_standard = assign_params(
        Name=domain,
        CreationDate=whois['Creation Date'],
        UpdatedDate=whois['Updated Date'],
        ExpirationDate=whois['Registry Expiry Date'],
        NameServers=whois['Name Server'],
        Admin=assign_params(
            Name=whois['Admin Organization'],
            Email=whois['Admin Email'],
            Country=whois['Admin Country'],
        ),
        Registrant=assign_params(
            Country=whois['Registrant Country'],
            Email=whois['Registrant Email']
        ),
        WHOIS=assign_params(
            CreationDate=whois['Creation Date'],
            UpdatedDate=whois['Updated Date'],
            ExpirationDate=whois['Registry Expiry Date'],
            Registrar=assign_params(
                Name=whois['Registrar'],
                AbuseEmail=whois['Registrar Abuse Contact Email'],
                AbusePhone=whois['Registrar Abuse Contact Phone'],
            ),
            Admin=assign_params(
                Name=whois['Admin Organization'],
                Email=whois['Admin Email']
            )
        )
    )
    score = score_calculator.domain_score(domain, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_domain_score(client, domain, score)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    if score == Common.DBotScore.BAD:
        domain_standard['Malicious'] = {
            'Vendor': INTEGRATION_NAME,
            'Description': logs
        }
    context = {
        f'{INTEGRATION_ENTRY_CONTEXT}.Domain(val.id && val.id === obj.id) ': data,
        Common.Domain.CONTEXT_PATH: domain_standard
    }
    context.update(
        Common.DBotScore(
            domain,
            DBotScoreType.DOMAIN,
            INTEGRATION_NAME,
            score,
            malicious_description=logs
        ).to_context()
    )

    attributes = data['attributes']
    return CommandResults(
        readable_output=tableToMarkdown(
            f'Domain data of {domain}',
            {
                'last_modified': timestamp_to_datestring(attributes['last_modification_date']),
                **data,
                **whois,
                **attributes
            },
            headers=[
                'id',
                'Registrant Country',
                'last_modified',
                'last_analysis_stats'
            ],
            removeNull=True
        ),
        outputs=context,
        raw_response=raw_response
    )


# endregion

# region Scan commands
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
    assert file_path, 'File path does not exists. it the entry id is right?'
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


# endregion

# region Comments commands
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


# endregion

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


def get_analysis_command(client: Client, args: dict) -> CommandResults:
    analysis_id = args['id']
    raw_response = client.get_analysis(analysis_id)
    attributes = raw_response['data']['attributes']
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Analysis',
        'id',
        readable_output=tableToMarkdown(
            'Analysis results:',
            {
                **attributes,
                'id': analysis_id

            },
            headers=['id', 'stats']
        ),
        outputs={
            **raw_response,
            'id': analysis_id
        },
        raw_response=raw_response
    )


def check_module(client: Client) -> str:
    """
    1 API Call
    """
    client.get_ip_comments('8.8.8.8', 1)
    return 'ok'


def main(params: dict, args: dict, command: str):
    results: Union[CommandResults, str, List[CommandResults]]
    client = Client(params)
    score_calculator = ScoreCalculator(params)
    demisto.debug(f'Command called {command}')
    if command == 'test-module':
        results = check_module(client)
    elif command == 'file':
        results = bang_file(client, score_calculator, args)
    elif command == 'ip':
        results = bang_ip(client, score_calculator, args)
    elif command == 'url':
        results = bang_url(client, score_calculator, args)
    elif command == 'domain':
        results = bang_domain(client, score_calculator, args)
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
    elif command in (f'{COMMAND_PREFIX}-file-scan', 'file-scan'):
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
