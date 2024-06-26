import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
An integration module for the Google Threat Intelligence API.
API Documentation:
    https://gtidocs.virustotal.com/reference
"""
from collections import defaultdict
from typing import cast

from dateparser import parse
import ipaddress

INTEGRATION_NAME = 'GoogleThreatIntelligence'
COMMAND_PREFIX = 'gti'
INTEGRATION_ENTRY_CONTEXT = INTEGRATION_NAME

INDICATOR_TYPE = {
    'ip': FeedIndicatorType.IP,
    'ip_address': FeedIndicatorType.IP,
    'domain': FeedIndicatorType.Domain,
    'file': FeedIndicatorType.File,
    'url': FeedIndicatorType.URL,
}

SEVERITY_LEVELS = {
    'SEVERITY_UNKNOWN': 'UNKNOWN',
    'SEVERITY_LOW': 'LOW',
    'SEVERITY_MEDIUM': 'MEDIUM',
    'SEVERITY_HIGH': 'HIGH',
}

VERDICTS = {
    'VERDICT_UNKNOWN': 'UNKNOWN',
    'VERDICT_UNDETECTED': 'UNDETECTED',
    'VERDICT_SUSPICIOUS': 'SUSPICIOUS',
    'VERDICT_MALICIOUS': 'MALICIOUS',
}


"""RELATIONSHIP TYPE"""
RELATIONSHIP_TYPE = {
    'file': {
        'carbonblack_children': EntityRelationship.Relationships.CREATES,
        'carbonblack_parents': EntityRelationship.Relationships.CREATED_BY,
        'compressed_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'contacted_domains': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'contacted_ips': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'contacted_urls': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'dropped_files': EntityRelationship.Relationships.DROPPED_BY,
        'email_attachments': EntityRelationship.Relationships.ATTACHES,
        'email_parents': EntityRelationship.Relationships.ATTACHMENT_OF,
        'embedded_domains': EntityRelationship.Relationships.EMBEDDED_IN,
        'embedded_ips': EntityRelationship.Relationships.EMBEDDED_IN,
        'embedded_urls': EntityRelationship.Relationships.EMBEDDED_IN,
        'execution_parents': EntityRelationship.Relationships.EXECUTED_BY,
        'itw_domains': EntityRelationship.Relationships.DOWNLOADS_FROM,
        'itw_ips': EntityRelationship.Relationships.DOWNLOADS_FROM,
        'overlay_children': EntityRelationship.Relationships.BUNDLES,
        'overlay_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'pcap_children': EntityRelationship.Relationships.BUNDLES,
        'pcap_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'pe_resource_children': EntityRelationship.Relationships.EXECUTED,
        'pe_resource_parents': EntityRelationship.Relationships.EXECUTED_BY,
        'similar_files': EntityRelationship.Relationships.SIMILAR_TO,
    },
    'domain': {
        'cname_records': EntityRelationship.Relationships.IS_ALSO,
        'caa_records': EntityRelationship.Relationships.RELATED_TO,
        'communicating_files': EntityRelationship.Relationships.DROPS,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'immediate_parent': EntityRelationship.Relationships.SUB_DOMAIN_OF,
        'mx_records': EntityRelationship.Relationships.RELATED_TO,
        'ns_records': EntityRelationship.Relationships.DROPS,
        'parent': EntityRelationship.Relationships.SUB_DOMAIN_OF,
        'referrer_files': EntityRelationship.Relationships.RELATED_TO,
        'resolutions': EntityRelationship.Relationships.RESOLVED_FROM,
        'siblings': EntityRelationship.Relationships.SUPRA_DOMAIN_OF,
        'soa_records': EntityRelationship.Relationships.IS_ALSO,
        'subdomains': EntityRelationship.Relationships.SUPRA_DOMAIN_OF,
        'urls': EntityRelationship.Relationships.HOSTS,
    },
    'ip': {
        'communicating_files': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'referrer_files': EntityRelationship.Relationships.RELATED_TO,
        'resolutions': EntityRelationship.Relationships.RESOLVES_TO,
        'urls': EntityRelationship.Relationships.RELATED_TO,
    },
    'url': {
        'contacted_domains': EntityRelationship.Relationships.RELATED_TO,
        'contacted_ips': EntityRelationship.Relationships.RELATED_TO,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'last_serving_ip_address': EntityRelationship.Relationships.RESOLVED_FROM,
        'network_location': EntityRelationship.Relationships.RESOLVED_FROM,
        'redirecting_urls': EntityRelationship.Relationships.DUPLICATE_OF,
        'redirects_to': EntityRelationship.Relationships.DUPLICATE_OF,
        'referrer_files': EntityRelationship.Relationships.EMBEDDED_IN,
        'referrer_urls': EntityRelationship.Relationships.RELATED_TO,
    },
}


class Client(BaseClient):
    """Client for Google Threat Intelligence API."""
    reliability: DBotScoreReliability

    def __init__(self, params: dict):
        self.reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(params['feedReliability'])

        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not argToBoolean(params.get('insecure')),
            proxy=argToBoolean(params.get('proxy')),
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexGTI',
            }
        )

    # region Reputation calls

    def ip(self, ip: str, relationships: str = '') -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/ip-info
        """
        return self._http_request(
            'GET',
            f'ip_addresses/{ip}?relationships={relationships}', ok_codes=(404, 429, 200)
        )

    def file(self, file: str, relationships: str = '') -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/file-info
        """
        return self._http_request(
            'GET',
            f'files/{file}?relationships={relationships}', ok_codes=(404, 429, 200)
        )

    # It is not a Reputation call
    def private_file(self, file: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/private-files-info
        """
        return self._http_request(
            'GET',
            f'private/files/{file}', ok_codes=(404, 429, 200)
        )

    def url(self, url: str, relationships: str = ''):
        """
        See Also:
            https://gtidocs.virustotal.com/reference/url-info
        """
        return self._http_request(
            'GET',
            f'urls/{encode_url_to_base64(url)}?relationships={relationships}',
            ok_codes=(404, 429, 200)
        )

    def domain(self, domain: str, relationships: str = '') -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/domain-info
        """
        return self._http_request(
            'GET',
            f'domains/{domain}?relationships={relationships}',
            ok_codes=(404, 429, 200)
        )

    # endregion

    # region Comments call
    def delete_comment(self, id_: str):
        """
        See Also:
            https://gtidocs.virustotal.com/reference/comment-id-delete
        """
        self._http_request(
            'DELETE',
            f'comments/{id_}',
            resp_type='response'
        )

    def get_ip_comments(self, ip: str, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/ip-comments-get
        """

        return self._http_request(
            'GET',
            f'ip_addresses/{ip}/comments',
            params={'limit': limit}
        )

    def get_url_comments(self, url: str, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/urls-comments-get

        """
        return self._http_request(
            'GET',
            f'urls/{encode_url_to_base64(url)}/comments',
            params={'limit': limit}
        )

    def get_hash_comments(self, file_hash: str, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-comments-get
        """
        return self._http_request(
            'GET',
            f'files/{file_hash}/comments',
            params={'limit': limit}
        )

    def get_domain_comments(self, domain: str, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/domains-comments-get
        """
        return self._http_request(
            'GET',
            f'domains/{domain}/comments',
            params={'limit': limit}
        )

    def get_comment_by_id(self, comment_id: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/get-comment
        """
        return self._http_request(
            'GET',
            f'comments/{comment_id}'
        )

    def add_comment(self, suffix: str, comment: str) -> dict:
        """Sending POST HTTP request to comment

        Args:
            suffix: suffix of the comment
            comment: the comment itself

        Returns:
            json of response
        """
        return self._http_request(
            'POST',
            suffix,
            json_data={'data': {'type': 'comment', 'attributes': {'text': comment}}}
        )

    def add_comment_to_ip(self, ip: str, comment: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/ip-comments-post
        """
        return self.add_comment(f'ip_addresses/{ip}/comments', comment)

    def add_comment_to_url(self, url: str, comment: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/urls-comments-post
        """
        return self.add_comment(f'urls/{encode_url_to_base64(url)}/comments', comment)

    def add_comment_to_domain(self, domain: str, comment: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/domains-comments-post
        """
        return self.add_comment(f'domains/{domain}/comments', comment)

    def add_comment_to_file(self, resource: str, comment: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-comments-post
        """
        return self.add_comment(f'files/{resource}/comments', comment)

    # endregion

    # region Scan calls
    def file_rescan(self, file_hash: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-analyse
        """
        return self._http_request(
            'POST',
            f'/files/{file_hash}/analyse'
        )

    def file_scan(self, file_path: str, /, upload_url: Optional[str]) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-analyse
        """
        response: requests.Response
        with open(file_path, 'rb') as file:
            if upload_url or os.stat(file_path).st_size / (1024 * 1024) >= 32:
                if not upload_url:
                    raw_response = self.get_upload_url()
                    upload_url = raw_response['data']
                response = self._http_request(
                    'POST',
                    full_url=upload_url,
                    files={'file': file},
                    resp_type='response'
                )
            else:
                response = self._http_request(
                    'POST',
                    url_suffix='/files',
                    files={'file': file},
                    resp_type='response'
                )
        demisto.debug(
            f'scan_file response:\n'
            f'{str(response.status_code)=}, {str(response.headers)=}, {str(response.content)}'
        )
        return response.json()

    def private_file_scan(self, file_path: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/post_files-1
        """
        response: requests.Response
        with open(file_path, 'rb') as file:
            if os.stat(file_path).st_size / (1024 * 1024) >= 32:
                raw_response = self.get_private_upload_url()
                upload_url = raw_response['data']
                response = self._http_request(
                    'POST',
                    full_url=upload_url,
                    files={'file': file},
                    resp_type='response'
                )
            else:
                response = self._http_request(
                    'POST',
                    url_suffix='/private/files',
                    files={'file': file},
                    resp_type='response'
                )
        demisto.debug(
            f'scan_file response:\n'
            f'{str(response.status_code)=}, {str(response.headers)=}, {str(response.content)}'
        )
        return response.json()

    def get_upload_url(self) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-upload-url
        """
        return self._http_request(
            'GET',
            'files/upload_url'
        )

    def get_private_upload_url(self) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/private-files-upload-url
        """
        return self._http_request(
            'GET',
            'private/files/upload_url'
        )

    def url_scan(self, url: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/urls-analyse
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
            https://gtidocs.virustotal.com/reference/files-relationships
        """
        return self._http_request(
            'GET',
            f'files/{file_hash}/behaviours',
            params={'limit': limit},
            ok_codes=(404, 429, 200)
        )

    def passive_dns_data(self, id: dict, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/ip-relationships
        """
        return self._http_request(
            'GET',
            f'{"ip_addresses" if id["type"] == "ip" else "domains"}/{id["value"]}/resolutions',
            params={'limit': limit}
        )

    def search(self, query: str, limit: int) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/intelligence-search
        """
        return self._http_request(
            'GET',
            'search',
            params={'query': query, 'limit': limit}
        )

    def get_analysis(self, analysis_id: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/analysis
        """
        return self._http_request(
            'GET',
            f'/analyses/{analysis_id}'
        )

    def get_private_analysis(self, analysis_id: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/private-analysis
        """
        return self._http_request(
            'GET',
            f'private/analyses/{analysis_id}'
        )

    def get_private_file_from_analysis(self, analysis_id: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/analysesidrelationship
        """
        return self._http_request(
            'GET',
            f'private/analyses/{analysis_id}/item?attributes=threat_severity,threat_verdict'
        )

    def get_file_sigma_analysis(self, file_hash: str) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/files-relationships
        """
        return self._http_request(
            'GET',
            f'files/{file_hash}/sigma_analysis',
        )


class ScoreCalculator:
    """
    Calculating DBotScore of files, ip, etc.
    """
    DEFAULT_SUSPICIOUS_THRESHOLD = 5
    DEFAULT_RELATIONSHIP_SUSPICIOUS_THRESHOLD = 2
    GTI_MALICIOUS_VERDICT = 'VERDICT_MALICIOUS'
    GTI_SUSPICIOUS_VERDICT = 'VERDICT_SUSPICIOUS'

    logs: List[str]

    # General
    trusted_vendors_threshold: int
    trusted_vendors: List[str]
    gti_malicious: bool
    gti_suspicious: bool

    # IP
    ip_threshold: dict[str, int]

    # URL
    url_threshold: dict[str, int]

    # Domain
    domain_threshold: dict[str, int]
    domain_popularity_ranking: int

    # File
    file_threshold: dict[str, int]
    sigma_ids_threshold: int
    crowdsourced_yara_rules_enabled: bool
    crowdsourced_yara_rules_threshold: int

    def __init__(self, params: dict):
        self.trusted_vendors = argToList(params['preferredVendors'])
        self.trusted_vendors_threshold = arg_to_number_must_int(
            params['preferredVendorsThreshold'],
            arg_name='Preferred Vendor Threshold',
            required=True
        )
        self.file_threshold = {
            'malicious': arg_to_number_must_int(
                params['fileThreshold'],
                arg_name='File Malicious Threshold',
                required=True),
            'suspicious': arg_to_number_must_int(
                params['fileSuspiciousThreshold'] or self.DEFAULT_SUSPICIOUS_THRESHOLD,
                arg_name='File Suspicious Threshold',
                required=True)
        }
        self.ip_threshold = {
            'malicious': arg_to_number_must_int(
                params['ipThreshold'],
                arg_name='IP Malicious Threshold',
                required=True),
            'suspicious': arg_to_number_must_int(
                params['ipSuspiciousThreshold'] or self.DEFAULT_SUSPICIOUS_THRESHOLD,
                arg_name='IP Suspicious Threshold',
                required=True)
        }
        self.url_threshold = {
            'malicious': arg_to_number_must_int(
                params['urlThreshold'],
                arg_name='URL Malicious Threshold',
                required=True),
            'suspicious': arg_to_number_must_int(
                params['urlSuspiciousThreshold'] or self.DEFAULT_SUSPICIOUS_THRESHOLD,
                arg_name='URL Suspicious Threshold',
                required=True)
        }
        self.domain_threshold = {
            'malicious': arg_to_number_must_int(
                params['domainThreshold'],
                arg_name='Domain Malicious Threshold',
                required=True),
            'suspicious': arg_to_number_must_int(
                params['domainSuspiciousThreshold'] or self.DEFAULT_SUSPICIOUS_THRESHOLD,
                arg_name='Domain Suspicious Threshold',
                required=True)
        }
        self.crowdsourced_yara_rules_enabled = argToBoolean(params['crowdsourced_yara_rules_enabled'])
        self.crowdsourced_yara_rules_threshold = arg_to_number_must_int(params['yaraRulesThreshold'])
        self.sigma_ids_threshold = arg_to_number_must_int(
            params['SigmaIDSThreshold'],
            arg_name='Sigma and Intrusion Detection Rules Threshold',
            required=True
        )
        self.domain_popularity_ranking = arg_to_number_must_int(
            params['domain_popularity_ranking'],
            arg_name='Domain Popularity Ranking Threshold',
            required=True
        )
        self.gti_malicious = argToBoolean(params.get('gti_malicious', False))
        self.gti_suspicious = argToBoolean(params.get('gti_suspicious', False))
        self.logs = []

    def get_logs(self) -> str:
        """Returns the log string
        """
        return '\n'.join(self.logs)

    def _is_by_threshold(self, analysis_stats: dict, threshold: int, suspicious: bool = False) -> bool:
        """Determines whatever the indicator malicious/suspicious by threshold.
        if number of malicious (+ suspicious) >= threshold -> Malicious (Suspicious)

        Args:
            analysis_stats: the analysis stats from the response.
            threshold: the threshold of the indicator type.
            suspicious: whether suspicious is also added.

        Returns:
            Whatever the indicator is malicious/suspicious by threshold.
        """
        total = analysis_stats.get('malicious', 0)
        if suspicious:
            total += analysis_stats.get('suspicious', 0)
        verdict = 'suspicious' if suspicious else 'malicious'
        self.logs.append(f'{total} vendors found {verdict}.\n'
                         f'The {verdict} threshold is {threshold}.')
        if total >= threshold:
            self.logs.append(f'Found as {verdict}: {total} >= {threshold}.')
            return True
        self.logs.append(f'Not found {verdict} by threshold: {total} < {threshold}.')
        return False

    def is_suspicious_by_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        """Determines whatever the indicator suspicious by threshold.
        if number of malicious + suspicious >= threshold -> Suspicious

        Args:
            analysis_stats: the analysis stats from the response
            threshold: the threshold of the indicator type.

        Returns:
            Whatever the indicator is suspicious by threshold.
        """
        return self._is_by_threshold(analysis_stats, threshold, suspicious=True)

    def is_good_by_popularity_ranks(self, popularity_ranks: dict) -> Optional[bool]:
        """Analyzing popularity ranks.
        if popularity ranks exist and average rank is < threshold -> Good
        Args:
            popularity_ranks: the popularity ranks object from response

        Returns:
            Whatever the indicator is good or not by popularity rank.
        """
        if popularity_ranks:
            self.logs.append('Found popularity ranks. Analyzing.')
            average = sum(rank.get('rank', 0) for rank in popularity_ranks.values()) / len(popularity_ranks)
            self.logs.append(
                f'The average of the ranks is {average} and the threshold is {self.domain_popularity_ranking}')
            if average <= self.domain_popularity_ranking:
                self.logs.append('Indicator is good by popularity ranks.')
                return True
            else:
                self.logs.append('Indicator might not be good by it\'s popularity ranks.')
                return False
        self.logs.append('Could not determine rank by popularity, No popularity ranks data.')
        return None

    def is_suspicious_by_rules(self, file_response: dict) -> bool:
        """Check if indicator is suspicious by rules analysis.

        crowdsourced_yara_results >= yara_rules_threshold ||
        sigma_analysis_stats.high + critical >= sigma_id_threshold ||
        crowdsourced_ids_stats.high + critical >= sigma_id_threshold -> suspicious

        Args:
            file_response: the file response

        Returns:
            Whatever the file is suspicious by rules analysis.
        """
        data = file_response.get('data', {})
        if self.crowdsourced_yara_rules_enabled:
            self.logs.append('Crowdsourced Yara Rules analyzing enabled.')
            if (total_yara_rules := len(
                    data.get('crowdsourced_yara_results', []))) >= self.crowdsourced_yara_rules_threshold:
                self.logs.append(
                    'Found malicious by finding more Crowdsourced Yara Rules than threshold. \n'
                    f'{total_yara_rules} >= {self.crowdsourced_yara_rules_threshold}')
                return True
            if sigma_rules := data.get('sigma_analysis_stats'):
                self.logs.append('Found sigma rules, analyzing.')
                sigma_high, sigma_critical = sigma_rules.get('high', 0), sigma_rules.get('critical', 0)
                if (sigma_high + sigma_critical) >= self.sigma_ids_threshold:
                    self.logs.append(
                        f'Found malicious, {sigma_high + sigma_critical} >= {self.sigma_ids_threshold}. ')
                    return True
                else:
                    self.logs.append('Not found malicious by sigma. ')
            else:
                self.logs.append('Not found sigma analysis. Skipping. ')
            if crowdsourced_ids_stats := data.get('crowdsourced_ids_stats'):
                self.logs.append('Found crowdsourced IDS analysis, analyzing. ')
                ids_high, ids_critical = crowdsourced_ids_stats.get('high'), crowdsourced_ids_stats.get('critical')
                if (ids_high + ids_critical) >= self.sigma_ids_threshold:
                    self.logs.append(
                        f'Found malicious, {(ids_high + ids_critical) >= self.sigma_ids_threshold}.')
                    return True
                else:
                    self.logs.append('Not found malicious by sigma.')
            else:
                self.logs.append('Not found crowdsourced IDS analysis. Skipping.')
        else:
            self.logs.append('Crowdsourced Yara Rules analyzing is not enabled. Skipping.')
        return False

    def is_preferred_vendors_pass_malicious(self, analysis_results: dict) -> bool:
        """Is the indicator counts as malicious by predefined malicious vendors.
        trusted_vendors.malicious >= trusted_vendors_threshold -> Malicious
        The function takes only the latest 20 results.

        Args:
            analysis_results: The results of the analysis.

        Returns:
            Whatever the indicator is malicious or not by preferred vendors.
        """
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
        """Determines whatever the indicator malicious by threshold.
        if number of malicious >= threshold -> Malicious

        Args:
            analysis_stats: the analysis stats from the response
            threshold: the threshold of the indicator type.

        Returns:
            Whatever the indicator is malicious by threshold.
        """
        return self._is_by_threshold(analysis_stats, threshold)

    def score_by_threshold(self, analysis_stats: dict, threshold: dict[str, int]) -> int:
        """Determines the DBOTSCORE of the indicator by threshold only.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        if self.is_malicious_by_threshold(analysis_stats, threshold['malicious']):
            return Common.DBotScore.BAD
        if self.is_suspicious_by_threshold(analysis_stats, threshold['suspicious']):
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.GOOD

    def score_by_results_and_stats(self, indicator: str, raw_response: dict, threshold: dict[str, int]) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The raw response from API.
            threshold: Threshold of the indicator.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        self.logs.append(f'Basic analyzing of "{indicator}"')
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})
        popularity_ranks = attributes.get('popularity_ranks')
        last_analysis_results = attributes.get('last_analysis_results')
        last_analysis_stats = attributes.get('last_analysis_stats')
        if self.is_good_by_popularity_ranks(popularity_ranks):
            return Common.DBotScore.GOOD
        if self.is_preferred_vendors_pass_malicious(last_analysis_results):
            return Common.DBotScore.BAD
        return self.score_by_threshold(last_analysis_stats, threshold)

    def is_malicious_by_gti(self, gti_assessment: dict) -> bool:
        """Determines if an IoC is malicious according to its GTI assessment."""
        if self.gti_malicious:
            return gti_assessment.get('verdict', {}).get('value') == self.GTI_MALICIOUS_VERDICT
        return False

    def is_suspicious_by_gti(self, gti_assessment: dict) -> bool:
        """Determines if an IoC is suspicious according to its GTI assessment."""
        if self.gti_suspicious:
            return gti_assessment.get('verdict', {}).get('value') == self.GTI_SUSPICIOUS_VERDICT
        return False

    def file_score(self, given_hash: str, raw_response: dict) -> int:
        """Analyzing file score.
        The next parameters are analyzed:
            Preferred vendors
            Score by threshold
            Score by rules analysis (YARA, IDS and Sigma, if presents)

        Args:
            given_hash: The hash we're analyzing
            raw_response: The response from the API

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        self.logs.append(f'Analysing file hash {given_hash}.')
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})
        analysis_results = attributes.get('last_analysis_results', {})
        analysis_stats = attributes.get('last_analysis_stats', {})

        # GTI assessment
        if self.is_malicious_by_gti(attributes.get('gti_assessment', {})):
            return Common.DBotScore.BAD

        # Trusted vendors
        if self.is_preferred_vendors_pass_malicious(analysis_results):
            return Common.DBotScore.BAD

        score = self.score_by_threshold(analysis_stats, self.file_threshold)
        if score == Common.DBotScore.BAD:
            return Common.DBotScore.BAD

        suspicious_by_rules = self.is_suspicious_by_rules(raw_response)
        if score == Common.DBotScore.SUSPICIOUS and suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" was found malicious as the '
                'hash is suspicious both by threshold and rules analysis.')
            return Common.DBotScore.BAD
        elif suspicious_by_rules:
            self.logs.append(
                f'Hash: "{given_hash}" was found suspicious by rules analysis.')
            return Common.DBotScore.SUSPICIOUS
        elif score == Common.DBotScore.SUSPICIOUS:
            self.logs.append(
                f'Hash: "{given_hash}" was found suspicious by passing the threshold analysis.')
            return Common.DBotScore.SUSPICIOUS
        elif self.is_suspicious_by_gti(attributes.get('gti_assessment', {})):
            self.logs.append(
                f'Hash: "{given_hash}" was found suspicious by gti assessment.')
            return Common.DBotScore.SUSPICIOUS
        self.logs.append(f'Hash: "{given_hash}" was found good.')
        return Common.DBotScore.GOOD  # Nothing caught

    def ip_score(self, indicator: str, raw_response: dict) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The response from the API

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})

        # GTI assessment
        if self.is_malicious_by_gti(attributes.get('gti_assessment', {})):
            return Common.DBotScore.BAD

        score = self.score_by_results_and_stats(indicator, raw_response, self.ip_threshold)
        if score == Common.DBotScore.GOOD and self.is_suspicious_by_gti(attributes.get('gti_assessment', {})):
            score = Common.DBotScore.SUSPICIOUS

        return score

    def url_score(self, indicator: str, raw_response: dict) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The raw response from API.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})

        # GTI assessment
        if self.is_malicious_by_gti(attributes.get('gti_assessment', {})):
            return Common.DBotScore.BAD

        score = self.score_by_results_and_stats(indicator, raw_response, self.url_threshold)
        if score == Common.DBotScore.GOOD and self.is_suspicious_by_gti(attributes.get('gti_assessment', {})):
            score = Common.DBotScore.SUSPICIOUS

        return score

    def domain_score(self, indicator: str, raw_response: dict) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The raw response from API.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})

        if self.is_malicious_by_gti(attributes.get('gti_assessment', {})):
            return Common.DBotScore.BAD

        score = self.score_by_results_and_stats(indicator, raw_response, self.domain_threshold)
        if score == Common.DBotScore.GOOD and self.is_suspicious_by_gti(attributes.get('gti_assessment', {})):
            score = Common.DBotScore.SUSPICIOUS

        return score
    # endregion


# region Helper functions


def create_relationships(entity_a: str, entity_a_type: str, relationships_response: dict, reliability):
    """
    Create a list of entityRelationship object from the api result
    entity_a: (str) - source of the relationship
    entity_a_type: (str) - type of the source of the relationship
    relationships_response: (dict) - the relationship response from the api
    reliability: The reliability of the source.

    Returns a list of EntityRelationship objects.
    """
    relationships_list: List[EntityRelationship] = []
    for relationship_type, relationship_type_raw in relationships_response.items():

        relationships_data = relationship_type_raw.get('data', [])
        if relationships_data:
            if isinstance(relationships_data, dict):
                relationships_data = [relationships_data]

            for relation in relationships_data:
                name = RELATIONSHIP_TYPE.get(entity_a_type.lower(), {}).get(relationship_type)
                entity_b = relation.get('id', '')
                entity_b_type = INDICATOR_TYPE.get(relation.get('type', '').lower())
                if entity_b and entity_b_type and name:
                    if entity_b_type == FeedIndicatorType.URL:
                        entity_b = dict_safe_get(relation, ['context_attributes', 'url'])
                    relationships_list.append(
                        EntityRelationship(entity_a=entity_a, entity_a_type=entity_a_type, name=name,
                                           entity_b=entity_b, entity_b_type=entity_b_type, source_reliability=reliability,
                                           brand=INTEGRATION_NAME))
                else:
                    demisto.info(
                        f"WARNING: Relationships will not be created to entity A {entity_a} with relationship name {name}")
    return relationships_list


def arg_to_number_must_int(arg: Any, arg_name: Optional[str] = None, required: bool = False):
    """Wrapper of arg_to_number that must return int
    For mypy fixes.
    """
    arg_num = arg_to_number(arg, arg_name, required)
    assert isinstance(arg_num, int)
    return arg_num


def epoch_to_timestamp(epoch: Union[int, str]) -> Optional[str]:
    """Converts epoch timestamp to a string.

    Args:
        epoch: Time to convert

    Returns:
        A formatted string if succeeded. if not, returns None.
    """
    try:
        return datetime.utcfromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%SZ")
    except (TypeError, OSError, ValueError):
        return None


def decrease_data_size(data: Union[dict, list]) -> Union[dict, list]:
    """ Minifying data size.

    Args:
        data: the data object from raw response

    Returns:
        the same data without:
            data['attributes']['last_analysis_results']
            data['attributes']['pe_info']
            data['attributes']['crowdsourced_ids_results']
            data['attributes']['autostart_locations']
            data['attributes']['sandbox_verdicts']
            data['attributes']['sigma_analysis_summary']
    """
    attributes_to_remove = [
        'last_analysis_results',
        'pe_info',
        'crowdsourced_ids_results',
        'autostart_locations',
        'sandbox_verdicts',
        'sigma_analysis_summary',
    ]
    if isinstance(data, list):
        data = [decrease_data_size(item) for item in data]
    else:
        for attribute in attributes_to_remove:
            data['attributes'].pop(attribute, None)
    return data


def _get_error_result(client: Client, ioc_id: str, ioc_type: str, message: str) -> CommandResults:
    dbot_type = ioc_type.upper()
    assert dbot_type in ('FILE', 'DOMAIN', 'IP', 'URL')
    common_type = dbot_type if dbot_type in ('IP', 'URL') else dbot_type.capitalize()
    desc = f'{common_type} "{ioc_id}" {message}'
    dbot = Common.DBotScore(ioc_id,
                            getattr(DBotScoreType, dbot_type),
                            INTEGRATION_NAME,
                            Common.DBotScore.NONE,
                            desc,
                            client.reliability)
    options: dict[str, Common.DBotScore | str] = {'dbot_score': dbot}
    if dbot_type == 'FILE':
        options[get_hash_type(ioc_id)] = ioc_id
    else:
        options[dbot_type.lower()] = ioc_id
    return CommandResults(indicator=getattr(Common, common_type)(**options), readable_output=desc)


def build_unknown_output(client: Client, ioc_id: str, ioc_type: str) -> CommandResults:
    return _get_error_result(client, ioc_id, ioc_type, 'was not found in GoogleThreatIntelligence.')


def build_quota_exceeded_output(client: Client, ioc_id: str, ioc_type: str) -> CommandResults:
    return _get_error_result(client, ioc_id, ioc_type, 'was not enriched. Quota was exceeded.')


def build_error_output(client: Client, ioc_id: str, ioc_type: str) -> CommandResults:
    return _get_error_result(client, ioc_id, ioc_type, 'could not be processed.')


def build_unknown_file_output(client: Client, file: str) -> CommandResults:
    return build_unknown_output(client, file, 'file')


def build_quota_exceeded_file_output(client: Client, file: str) -> CommandResults:
    return build_quota_exceeded_output(client, file, 'file')


def build_error_file_output(client: Client, file: str) -> CommandResults:
    return build_error_output(client, file, 'file')


def build_unknown_domain_output(client: Client, domain: str) -> CommandResults:
    return build_unknown_output(client, domain, 'domain')


def build_quota_exceeded_domain_output(client: Client, domain: str) -> CommandResults:
    return build_quota_exceeded_output(client, domain, 'domain')


def build_error_domain_output(client: Client, domain: str) -> CommandResults:
    return build_error_output(client, domain, 'domain')


def build_unknown_url_output(client: Client, url: str) -> CommandResults:
    return build_unknown_output(client, url, 'url')


def build_quota_exceeded_url_output(client: Client, url: str) -> CommandResults:
    return build_quota_exceeded_output(client, url, 'url')


def build_error_url_output(client: Client, url: str) -> CommandResults:
    return build_error_output(client, url, 'url')


def build_unknown_ip_output(client: Client, ip: str) -> CommandResults:
    return build_unknown_output(client, ip, 'ip')


def build_quota_exceeded_ip_output(client: Client, ip: str) -> CommandResults:
    return build_quota_exceeded_output(client, ip, 'ip')


def build_error_ip_output(client: Client, ip: str) -> CommandResults:
    return build_error_output(client, ip, 'ip')


def build_skipped_enrichment_ip_output(client: Client, ip: str) -> CommandResults:
    return _get_error_result(client, ip, 'ip',
                             'was not enriched. Reputation lookups have been disabled for private IP addresses.')


def _get_domain_indicator(client: Client, score_calculator: ScoreCalculator, domain: str, raw_response: dict):
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    detection_engines = sum(last_analysis_stats.values())
    positive_detections = last_analysis_stats.get('malicious', 0)
    whois = get_whois(attributes.get('whois', ''))

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=domain,
        entity_a_type=FeedIndicatorType.Domain,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    score = score_calculator.domain_score(domain, raw_response)

    logs = score_calculator.get_logs()
    demisto.debug(logs)

    return Common.Domain(
        domain=domain,
        name_servers=whois['Name Server'],
        creation_date=whois['Creation Date'],
        updated_date=whois['Updated Date'],
        expiration_date=whois['Registry Expiry Date'],
        admin_name=whois['Admin Organization'],
        admin_email=whois['Admin Email'],
        admin_country=whois['Admin Country'],
        registrant_email=whois['Registrant Email'],
        registrant_country=whois['Registrant Country'],
        registrar_name=whois['Registrar'],
        registrar_abuse_email=whois['Registrar Abuse Contact Email'],
        registrar_abuse_phone=whois['Registrar Abuse Contact Phone'],
        detection_engines=detection_engines,
        positive_detections=positive_detections,
        dbot_score=Common.DBotScore(
            domain,
            DBotScoreType.DOMAIN,
            INTEGRATION_NAME,
            score=score,
            malicious_description=logs,
            reliability=client.reliability
        ),
        relationships=relationships_list
    )


def _get_url_indicator(client: Client, score_calculator: ScoreCalculator, url: str, raw_response: dict):
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    detection_engines = sum(last_analysis_stats.values())
    positive_detections = last_analysis_stats.get('malicious', 0)

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=url,
        entity_a_type=FeedIndicatorType.URL,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    score = score_calculator.url_score(url, raw_response)

    logs = score_calculator.get_logs()
    demisto.debug(logs)

    return Common.URL(
        url,
        category=attributes.get('categories'),
        detection_engines=detection_engines,
        positive_detections=positive_detections,
        relationships=relationships_list,
        dbot_score=Common.DBotScore(
            url,
            DBotScoreType.URL,
            INTEGRATION_NAME,
            score=score,
            reliability=client.reliability,
            malicious_description=logs
        )
    )


def _get_ip_indicator(client: Client, score_calculator: ScoreCalculator, ip: str, raw_response: dict):
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    detection_engines = sum(last_analysis_stats.values())
    positive_engines = last_analysis_stats.get('malicious', 0)

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=ip,
        entity_a_type=FeedIndicatorType.IP,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    score = score_calculator.ip_score(ip, raw_response)

    logs = score_calculator.get_logs()
    demisto.debug(logs)

    return Common.IP(
        ip,
        asn=attributes.get('asn'),
        geo_country=attributes.get('country'),
        detection_engines=detection_engines,
        positive_engines=positive_engines,
        as_owner=attributes.get('as_owner'),
        relationships=relationships_list,
        dbot_score=Common.DBotScore(
            ip,
            DBotScoreType.IP,
            INTEGRATION_NAME,
            score=score,
            malicious_description=logs,
            reliability=client.reliability
        )
    )


def _get_file_indicator(client: Client, score_calculator: ScoreCalculator, file_hash: str, raw_response: dict):
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    exiftool = attributes.get('exiftool', {})
    signature_info = attributes.get('signature_info', {})

    score = score_calculator.file_score(file_hash, raw_response)

    logs = score_calculator.get_logs()
    demisto.debug(logs)

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=file_hash,
        entity_a_type=FeedIndicatorType.File,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    return Common.File(
        dbot_score=Common.DBotScore(
            file_hash,
            DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=score,
            malicious_description=logs,
            reliability=client.reliability
        ),
        name=exiftool.get('OriginalFileName'),
        size=attributes.get('size'),
        sha1=attributes.get('sha1'),
        sha256=attributes.get('sha256'),
        file_type=exiftool.get('MIMEType'),
        md5=attributes.get('md5'),
        ssdeep=attributes.get('ssdeep'),
        extension=exiftool.get('FileTypeExtension'),
        company=exiftool.get('CompanyName'),
        product_name=exiftool.get('ProductName'),
        tags=attributes.get('tags'),
        signature=Common.FileSignature(
            authentihash=attributes.get('authentihash'),
            copyright=signature_info.get('copyright'),
            file_version=signature_info.get('file version'),
            description=signature_info.get('description'),
            internal_name=signature_info.get('internal name'),
            original_name=signature_info.get('original name')
        ),
        relationships=relationships_list
    )


def build_domain_output(
        client: Client,
        score_calculator: ScoreCalculator,
        domain: str,
        raw_response: dict,
        extended_data: bool
) -> CommandResults:
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})

    last_analysis_stats = attributes.get('last_analysis_stats', {})
    positive_engines = last_analysis_stats.get('malicious', 0)
    detection_engines = sum(last_analysis_stats.values())

    whois = get_whois(attributes.get('whois', ''))

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=domain,
        entity_a_type=FeedIndicatorType.Domain,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    domain_indicator = _get_domain_indicator(client, score_calculator, domain, raw_response)

    if not extended_data:
        data = decrease_data_size(data)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.Domain',
        outputs_key_field='id',
        indicator=domain_indicator,
        readable_output=tableToMarkdown(
            f'Domain data of {domain}',
            {
                **data,
                **attributes,
                **whois,
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date')),
                'positives': f'{positive_engines}/{detection_engines}',
                'gti_threat_score': attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                'gti_severity': attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                'gti_verdict': attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
            },
            headers=[
                'id',
                'Registrant Country',
                'Registrar',
                'last_modified',
                'reputation',
                'positives',
                'gti_threat_score',
                'gti_severity',
                'gti_verdict',
            ],
            removeNull=True,
            headerTransform=string_to_table_header
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
    )


def build_url_output(
        client: Client,
        score_calculator: ScoreCalculator,
        url: str,
        raw_response: dict,
        extended_data: bool
) -> CommandResults:
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})

    last_analysis_stats = attributes.get('last_analysis_stats', {})
    positive_detections = last_analysis_stats.get('malicious', 0)
    detection_engines = sum(last_analysis_stats.values())

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=url,
        entity_a_type=FeedIndicatorType.URL,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    url_indicator = _get_url_indicator(client, score_calculator, url, raw_response)

    if not extended_data:
        data = decrease_data_size(data)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.URL',
        outputs_key_field='id',
        indicator=url_indicator,
        readable_output=tableToMarkdown(
            f'URL data of "{url}"',
            {
                **data,
                **attributes,
                'url': url,
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date')),
                'positives': f'{positive_detections}/{detection_engines}',
                'gti_threat_score': attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                'gti_severity': attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                'gti_verdict': attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
            },
            headers=[
                'url',
                'title',
                'has_content',
                'last_http_response_content_sha256',
                'last_modified',
                'reputation',
                'positives',
                'gti_threat_score',
                'gti_severity',
                'gti_verdict',
            ],
            removeNull=True,
            headerTransform=string_to_table_header
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
    )


def build_ip_output(
        client: Client,
        score_calculator: ScoreCalculator,
        ip: str,
        raw_response: dict,
        extended_data: bool
) -> CommandResults:
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})

    last_analysis_stats = attributes.get('last_analysis_stats', {})
    positive_engines = last_analysis_stats.get('malicious', 0)
    detection_engines = sum(last_analysis_stats.values())

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=ip,
        entity_a_type=FeedIndicatorType.IP,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    ip_indicator = _get_ip_indicator(client, score_calculator, ip, raw_response)

    if not extended_data:
        data = decrease_data_size(data)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.IP',
        outputs_key_field='id',
        indicator=ip_indicator,
        readable_output=tableToMarkdown(
            f'IP reputation of {ip}:',
            {
                **data,
                **attributes,
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date')),
                'positives': f'{positive_engines}/{detection_engines}',
                'gti_threat_score': attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                'gti_severity': attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                'gti_verdict': attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
            },
            headers=[
                'id',
                'network',
                'country',
                'as_owner',
                'last_modified',
                'reputation',
                'positives',
                'gti_threat_score',
                'gti_severity',
                'gti_verdict',
            ],
            headerTransform=string_to_table_header
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
    )


def build_file_output(
        client: Client,
        score_calculator: ScoreCalculator,
        file_hash: str,
        raw_response: dict,
        extended_data: bool
) -> CommandResults:
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})

    last_analysis_stats = attributes.get('last_analysis_stats', {})
    malicious = last_analysis_stats.get('malicious', 0)
    total = sum(last_analysis_stats.values())

    relationships_response = data.get('relationships', {})
    relationships_list = create_relationships(
        entity_a=file_hash,
        entity_a_type=FeedIndicatorType.File,
        relationships_response=relationships_response,
        reliability=client.reliability
    )

    file_indicator = _get_file_indicator(client, score_calculator, file_hash, raw_response)

    if not extended_data:
        data = decrease_data_size(data)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.File',
        outputs_key_field='id',
        indicator=file_indicator,
        readable_output=tableToMarkdown(
            f'Results of file hash {file_hash}',
            {
                **data,
                **attributes,
                'positives': f'{malicious}/{total}',
                'creation_date': epoch_to_timestamp(attributes.get('creation_date')),
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date', 0)),
                'gti_threat_score': attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                'gti_severity': attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                'gti_verdict': attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
            },
            headers=[
                'sha1',
                'sha256',
                'md5',
                'meaningful_name',
                'type_extension',
                'creation_date',
                'last_modified',
                'reputation',
                'positives',
                'gti_threat_score',
                'gti_severity',
                'gti_verdict',
            ],
            removeNull=True,
            headerTransform=string_to_table_header
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
    )


def build_private_file_output(file_hash: str, raw_response: dict) -> CommandResults:
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    threat_severity = attributes.get('threat_severity', {})
    threat_severity_level = threat_severity.get('threat_severity_level', '')
    threat_severity_data = threat_severity.get('threat_severity_data', {})
    popular_threat_category = threat_severity_data.get('popular_threat_category', '')
    threat_verdict = attributes.get('threat_verdict', '')
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.File',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'Results of file hash {file_hash}',
            {
                **attributes,
                'threat_severity_level': SEVERITY_LEVELS.get(threat_severity_level, threat_severity_level),
                'popular_threat_category': popular_threat_category,
                'threat_verdict': VERDICTS.get(threat_verdict, threat_verdict),
            },
            headers=[
                'sha1',
                'sha256',
                'md5',
                'meaningful_name',
                'type_extension',
                'threat_severity_level',
                'popular_threat_category',
                'threat_verdict',
            ],
            removeNull=True,
            headerTransform=string_to_table_header
        ),
        outputs=data,
        raw_response=raw_response,
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
        key: str
        value: str
        try:
            key, value = line.split(sep=':', maxsplit=1)
        except ValueError:
            demisto.debug(f'Could not unpack Whois string: {line}. Skipping')
            continue
        key = key.strip()
        value = value.strip()
        if key in whois:
            if not isinstance(whois[key], list):
                whois[key] = [whois[key]]
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
        ValueError: if hash is not of type SHA-256, SHA-1 or MD5

    Examples:
        >>> raise_if_hash_not_valid('not a hash')
        Traceback (most recent call last):
         ...
        ValueError: Hash "not a hash" is not of type SHA-256, SHA-1 or MD5
        >>> raise_if_hash_not_valid('7e641f6b9706d860baf09fe418b6cc87')
    """
    if get_hash_type(file_hash) not in ('sha256', 'sha1', 'md5'):
        raise ValueError(f'Hash "{file_hash}" is not of type SHA-256, SHA-1 or MD5')


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

# endregion

# region Reputation commands


def ip_command(client: Client, score_calculator: ScoreCalculator, args: dict,
               relationships: str, disable_private_ip_lookup: bool) -> List[CommandResults]:
    """
    1 API Call for regular
    """
    ips = argToList(args['ip'])
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()
    override_private_lookup = argToBoolean(args.get('override_private_lookup', False))

    for ip in ips:
        raise_if_ip_not_valid(ip)
        if disable_private_ip_lookup and ipaddress.ip_address(ip).is_private and not override_private_lookup:
            results.append(build_skipped_enrichment_ip_output(client, ip))
            execution_metrics.success += 1
            continue
        try:
            raw_response = client.ip(ip, relationships)
            if raw_response.get('error', {}).get('code') == "QuotaExceededError":
                execution_metrics.quota_error += 1
                results.append(build_quota_exceeded_ip_output(client, ip))
                continue
            if raw_response.get('error', {}).get('code') == 'NotFoundError':
                results.append(build_unknown_ip_output(client, ip))
                continue
        except Exception as exc:
            # If anything happens, just keep going
            demisto.debug(f'Could not process IP: "{ip}"\n {str(exc)}')
            execution_metrics.general_error += 1
            results.append(build_error_ip_output(client, ip))
            continue
        execution_metrics.success += 1
        results.append(
            build_ip_output(client, score_calculator, ip, raw_response, argToBoolean(args.get('extended_data', False))))
    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)
    return results


def file_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call
    """
    files = argToList(args['file'])
    extended_data = argToBoolean(args.get('extended_data', False))
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    for file in files:
        raise_if_hash_not_valid(file)
        try:
            raw_response = client.file(file, relationships)
            if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
                execution_metrics.quota_error += 1
                results.append(build_quota_exceeded_file_output(client, file))
                continue
            if raw_response.get('error', {}).get('code') == 'NotFoundError':
                results.append(build_unknown_file_output(client, file))
                continue
            results.append(build_file_output(client, score_calculator, file, raw_response, extended_data))
            execution_metrics.success += 1
        except Exception as exc:
            # If anything happens, just keep going
            demisto.debug(f'Could not process file: "{file}"\n {str(exc)}')
            execution_metrics.general_error += 1
            results.append(build_error_file_output(client, file))
            continue
    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)
    return results


def private_file_command(client: Client, args: dict) -> List[CommandResults]:
    """
    1 API Call
    """
    files = argToList(args['file'])
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    for file in files:
        raise_if_hash_not_valid(file)
        try:
            raw_response = client.private_file(file)
            if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
                execution_metrics.quota_error += 1
                results.append(build_quota_exceeded_file_output(client, file))
                continue
            if raw_response.get('error', {}).get('code') == 'NotFoundError':
                results.append(build_unknown_file_output(client, file))
                continue
            results.append(build_private_file_output(file, raw_response))
            execution_metrics.success += 1
        except Exception as exc:
            # If anything happens, just keep going
            demisto.debug(f'Could not process file: "{file}"\n {str(exc)}')
            execution_metrics.general_error += 1
            results.append(build_error_file_output(client, file))
            continue
    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)
    return results


def url_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call for regular
    """
    urls = argToList(args['url'])
    extended_data = argToBoolean(args.get('extended_data', False))
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()
    for url in urls:
        try:
            raw_response = client.url(url, relationships)
            if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
                execution_metrics.quota_error += 1
                results.append(build_quota_exceeded_url_output(client, url))
                continue
            if raw_response.get('error', {}).get('code') == 'NotFoundError':
                results.append(build_unknown_url_output(client, url))
                continue
        except Exception as exc:
            # If anything happens, just keep going
            demisto.debug(f'Could not process URL: "{url}".\n {str(exc)}')
            execution_metrics.general_error += 1
            results.append(build_error_url_output(client, url))
            continue
        execution_metrics.success += 1
        results.append(build_url_output(client, score_calculator, url, raw_response, extended_data))
    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)
    return results


def domain_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call for regular
    """
    execution_metrics = ExecutionMetrics()
    domains = argToList(args['domain'])
    results: List[CommandResults] = []
    for domain in domains:
        try:
            raw_response = client.domain(domain, relationships)
            if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
                execution_metrics.quota_error += 1
                results.append(build_quota_exceeded_domain_output(client, domain))
                continue
            if raw_response.get('error', {}).get('code') == 'NotFoundError':
                results.append(build_unknown_domain_output(client, domain))
                continue
        except Exception as exc:
            # If anything happens, just keep going
            demisto.debug(f'Could not process domain: "{domain}"\n {str(exc)}')
            execution_metrics.general_error += 1
            results.append(build_error_domain_output(client, domain))
            continue
        execution_metrics.success += 1
        result = build_domain_output(client, score_calculator, domain, raw_response,
                                     argToBoolean(args.get('extended_data', False)))
        results.append(result)
    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)

    return results


# endregion

# region Scan commands
def file_rescan_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['file']
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file_rescan(file_hash)
    data = raw_response['data']
    data['hash'] = file_hash
    context = {
        f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data,
        'vtScanID': data.get('id')  # BC preservation
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            f'File "{file_hash}" resubmitted.',
            data,
            removeNull=True,
            headerTransform=underscoreToCamelCase
        ),
        outputs=context,
        raw_response=raw_response
    )


def get_working_id(id_: str, entry_id: str) -> str:
    """Sometimes new scanned files ID will be only a number. Should connect them with base64(MD5:_id).
    Fixes bug in Google Threat Intelligence API.

    Args:
        entry_id: the entry id connected to the file
        id_: id given from the API

    Returns:
        A working ID that we can use in other commands.
    """
    if isinstance(id_, str) and id_.isnumeric() or isinstance(id_, int):
        demisto.debug(f'Got an integer id from file-scan. {id_=}, {entry_id=}\n')
        raise DemistoException(
            f'Got an int {id_=} as analysis report. This is a bug in Google Threat Intelligence API.\n'
            f'While Google Threat Intelligence team is fixing the problem, try to resend the file.'
        )
    return id_


def file_scan(client: Client, args: dict) -> List[CommandResults]:
    """
    1 API Call
    """
    return upload_file(client, args)


def private_file_scan(client: Client, args: dict) -> List[CommandResults]:
    """
    1 API Call
    """
    return upload_file(client, args, True)


def upload_file(client: Client, args: dict, private: bool = False) -> List[CommandResults]:
    """
    1 API Call
    """
    entry_ids = argToList(args['entryID'])
    upload_url = args.get('uploadURL')
    if len(entry_ids) > 1 and upload_url:
        raise DemistoException('You can supply only one entry ID with an upload URL.')
    results = []
    for entry_id in entry_ids:
        try:
            file_obj = demisto.getFilePath(entry_id)
            file_path = file_obj['path']
            if private:
                raw_response = client.private_file_scan(file_path)
            else:
                raw_response = client.file_scan(file_path, upload_url)
            data = raw_response.get('data', {})
            # add current file as identifiers
            data.update(get_file_context(entry_id))
            id_ = data.get('id')
            demisto.debug(f'Result from vt-scan-file {entry_id=} {id_=} {data.get("type")=}')
            id_ = get_working_id(id_, entry_id)
            data['id'] = id_
            context = {
                f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data,
                'vtScanID': id_  # BC preservation
            }
            results.append(CommandResults(
                readable_output=tableToMarkdown(
                    f'The file has been submitted "{file_obj["name"]}"',
                    data,
                    headers=['id', 'EntryID', 'MD5', 'SHA1', 'SHA256'],
                    removeNull=True
                ),
                outputs=context,
                raw_response=raw_response
            ))
        except Exception as exc:
            err = f'Could not process {entry_id=}.\n{str(exc)}'
            demisto.debug(err)
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': err
            })
    return results


def file_scan_and_get_analysis(client: Client, args: dict):
    """Calls to file-scan and gti-analysis-get."""
    interval = int(args.get('interval_in_seconds', 60))
    extended = argToBoolean(args.get('extended_data', False))

    if not args.get('id'):
        command_results = file_scan(client, args)
        command_result = command_results[0]
        outputs = command_result.outputs
        if not isinstance(outputs, dict):
            raise DemistoException('outputs is expected to be a dict')
        scheduled_command = ScheduledCommand(
            command=f'{COMMAND_PREFIX}-file-scan-and-analysis-get',
            next_run_in_seconds=interval,
            args={
                'entryID': args.get('entryID'),
                'id': outputs.get('vtScanID'),
                'interval_in_seconds': interval,
                'extended_data': extended,
            },
            timeout_in_seconds=6000,
        )
        command_result.scheduled_command = scheduled_command
        return command_result

    command_result = get_analysis_command(client, args)
    outputs = command_result.outputs
    if not isinstance(outputs, dict):
        raise DemistoException('outputs is expected to be a dict')
    if outputs.get('data', {}).get('attributes', {}).get('status') == 'completed':
        return command_result
    scheduled_command = ScheduledCommand(
        command=f'{COMMAND_PREFIX}-file-scan-and-analysis-get',
        next_run_in_seconds=interval,
        args={
            'entryID': args.get('entryID'),
            'id': outputs.get('id'),
            'interval_in_seconds': interval,
            'extended_data': extended,
        },
        timeout_in_seconds=6000,
    )
    return CommandResults(scheduled_command=scheduled_command)


def private_file_scan_and_get_analysis(client: Client, args: dict):
    """Calls to gti-privatescanning-file-scan and gti-privatescanning-analysis-get."""
    interval = int(args.get('interval_in_seconds', 60))
    extended = argToBoolean(args.get('extended_data', False))

    if not args.get('id'):
        command_results = private_file_scan(client, args)
        command_result = command_results[0]
        outputs = command_result.outputs
        if not isinstance(outputs, dict):
            raise DemistoException('outputs is expected to be a dict')
        scheduled_command = ScheduledCommand(
            command=f'{COMMAND_PREFIX}-private-file-scan-and-analysis-get',
            next_run_in_seconds=interval,
            args={
                'entryID': args.get('entryID'),
                'id': outputs.get('vtScanID'),
                'interval_in_seconds': interval,
                'extended_data': extended,
            },
            timeout_in_seconds=6000,
        )
        command_result.scheduled_command = scheduled_command
        return command_result

    command_result = private_get_analysis_command(client, args)
    outputs = command_result.outputs
    if not isinstance(outputs, dict):
        raise DemistoException('outputs is expected to be a dict')
    if outputs.get('data', {}).get('attributes', {}).get('status') == 'completed':
        return command_result
    scheduled_command = ScheduledCommand(
        command=f'{COMMAND_PREFIX}-private-file-scan-and-analysis-get',
        next_run_in_seconds=interval,
        args={
            'entryID': args.get('entryID'),
            'id': outputs.get('id'),
            'interval_in_seconds': interval,
            'extended_data': extended,
        },
        timeout_in_seconds=6000,
    )
    return CommandResults(scheduled_command=scheduled_command)


def url_scan_and_get_analysis(client: Client, args: dict):
    """Calls to url-scan and gti-analysis-get."""
    interval = int(args.get('interval_in_seconds', 60))
    extended = argToBoolean(args.get('extended_data', False))

    if not args.get('id'):
        command_result = scan_url_command(client, args)
        outputs = command_result.outputs
        if not isinstance(outputs, dict):
            raise DemistoException('outputs is expected to be a dict')
        scheduled_command = ScheduledCommand(
            command=f'{COMMAND_PREFIX}-url-scan-and-analysis-get',
            next_run_in_seconds=interval,
            args={
                'url': args.get('url'),
                'id': outputs.get('vtScanID'),
                'interval_in_seconds': interval,
                'extended_data': extended,
            },
            timeout_in_seconds=6000,
        )
        command_result.scheduled_command = scheduled_command
        return command_result

    command_result = get_analysis_command(client, args)
    outputs = command_result.outputs
    if not isinstance(outputs, dict):
        raise DemistoException('outputs is expected to be a dict')
    if outputs.get('data', {}).get('attributes', {}).get('status') == 'completed':
        return command_result
    scheduled_command = ScheduledCommand(
        command=f'{COMMAND_PREFIX}-url-scan-and-analysis-get',
        next_run_in_seconds=interval,
        args={
            'url': args.get('url'),
            'id': outputs.get('id'),
            'interval_in_seconds': interval,
            'extended_data': extended,
        },
        timeout_in_seconds=6000,
    )
    return CommandResults(scheduled_command=scheduled_command)


def get_upload_url(client: Client) -> CommandResults:
    """
    1 API Call
    """
    raw_response = client.get_upload_url()
    upload_url = raw_response['data']
    context = {
        f'{INTEGRATION_ENTRY_CONTEXT}.FileUploadURL': upload_url,
        'vtUploadURL': upload_url  # BC preservation
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            'New upload url acquired!',
            {'Upload url': upload_url}
        ),
        outputs=context,
        raw_response=raw_response
    )


def scan_url_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    url = args['url']
    raw_response: Dict[str, Any] = {}
    data: Dict[str, Any] = {}
    context: Dict[str, Any] = {}
    headers = ['id', 'url']

    try:
        raw_response = client.url_scan(url)
        data = raw_response['data']

        data['url'] = url
        context = {
            f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data,
            'vtScanID': data.get('id')  # BC preservation
        }
    except DemistoException as e:
        error = e.res.json().get('error')

        # Invalid url, probably due to an unknown TLD
        if error['code'] == 'InvalidArgumentError':
            data = {'url': url, 'id': '', 'error': error['message']}
            headers.append('error')
        else:
            raise e

    return CommandResults(
        readable_output=tableToMarkdown(
            'New url submission:',
            data,
            headers=headers
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
    limit = arg_to_number_must_int(
        args.get('limit'),
        arg_name='limit',
        required=True
    )
    resource = args['resource']
    if before := args.get('before'):
        before = parse(before)
        assert before is not None, f'Could not parse the before date "{before}"'
        before = before.replace(tzinfo=None)

    resource_type = args.get('resource_type')
    if not resource_type:
        try:
            raise_if_hash_not_valid(resource)
            resource_type = 'file'
        except ValueError:
            resource_type = 'url'
    resource_type = resource_type.lower()
    # Will find if there's one and only one True in the list.
    if resource_type == 'ip':
        raise_if_ip_not_valid(resource)
        raw_response = client.get_ip_comments(resource, limit)
    elif resource_type == 'url':
        raw_response = client.get_url_comments(resource, limit)
    elif resource_type in ('hash', 'file'):
        raise_if_hash_not_valid(resource)
        raw_response = client.get_hash_comments(resource, limit)
    elif resource_type == 'domain':
        raw_response = client.get_domain_comments(resource, limit)
    else:
        raise DemistoException(f'Could not find resource type of "{resource_type}"')

    data = raw_response.get('data', {})
    context = {
        'indicator': resource,
        'comments': data
    }
    comments = []
    for comment in data:
        attributes = comment.get('attributes', {})
        votes = attributes.get('votes', {})

        if date := parse(str(attributes.get('date'))):
            date = date.replace(tzinfo=None)

        if date and before and date > before:
            continue
        comments.append({
            'Date': epoch_to_timestamp(attributes.get('date')),
            'Text': attributes.get('text'),
            'Positive Votes': votes.get('positive'),
            'Abuse Votes': votes.get('abuse'),
            'Negative Votes': votes.get('negative')
        })

    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Comments',
        'id',
        readable_output=tableToMarkdown(
            f'Google Threat Intelligence comments of {resource_type}: "{resource}"',
            comments,
            headers=['Date', 'Text', 'Positive Votes', 'Abuse Votes', 'Negative Votes']
        ),
        outputs=context,
        raw_response=raw_response
    )


def add_comments_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    resource = args['resource']
    comment = args['comment']
    resource_type = args.get('resource_type')
    if not resource_type:
        try:
            raise_if_hash_not_valid(resource)
            resource_type = 'file'
        except ValueError:
            resource_type = 'url'
    resource_type = resource_type.lower()
    if resource_type == 'ip':
        raise_if_ip_not_valid(resource)
        raw_response = client.add_comment_to_ip(resource, comment)
    elif resource_type == 'url':
        raw_response = client.add_comment_to_url(resource, comment)
    elif resource_type == 'domain':
        raw_response = client.add_comment_to_domain(resource, comment)
    elif resource_type == 'file':
        raise_if_hash_not_valid(resource)
        raw_response = client.add_comment_to_file(resource, comment)
    else:
        raise DemistoException(f'Could not find resource type of "{resource_type}"')
    data = raw_response['data']
    attributes = data.get('attributes', {})
    votes = attributes.get('votes', {})
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Comments.comments',
        'id',
        readable_output=tableToMarkdown(
            'Comment has been added!',
            {
                'Date': epoch_to_timestamp(attributes.get('date')),
                'Text': attributes.get('text'),
                'Positive Votes': votes.get('positive'),
                'Abuse Votes': votes.get('abuse'),
                'Negative Votes': votes.get('negative')
            },
            headers=['Date', 'Text', 'Positive Votes', 'Abuse Votes', 'Negative Votes']
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
    attributes = data.get('attributes', {})
    votes = attributes.get('votes', {})
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Comments.comments',
        'id',
        readable_output=tableToMarkdown(
            f'Comment of ID {comment_id}',
            {
                'Date': epoch_to_timestamp(attributes.get('date')),
                'Text': attributes.get('text'),
                'Positive Votes': votes.get('positive'),
                'Abuse Votes': votes.get('abuse'),
                'Negative Votes': votes.get('negative')
            },
            headers=['Date', 'Text', 'Positive Votes', 'Abuse Votes', 'Negative Votes']
        ),
        outputs=data,
        raw_response=raw_response
    )


# endregion

def file_sandbox_report_command(client: Client, args: dict) -> List[CommandResults]:
    """
    1 API Call
    """
    execution_metrics = ExecutionMetrics()
    results: List[CommandResults] = []
    file_hash = args['file']
    limit = arg_to_number(
        args['limit'],
        'limit',
        required=True
    )
    assert isinstance(limit, int)  # mypy fix
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file_sandbox_report(file_hash, limit)
    if 'data' in raw_response:
        data = raw_response['data']
        execution_metrics.quota_error += 1
        results.append(
            CommandResults(
                f'{INTEGRATION_ENTRY_CONTEXT}.SandboxReport',
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
                    headers=['analysis_date', 'last_modification_date', 'sandbox_name', 'link'],
                    removeNull=True,
                    headerTransform=underscoreToCamelCase
                ),
                outputs=data,
                raw_response=raw_response
            )
        )
    elif raw_response.get('error', {}).get('code') == 'NotFoundError':
        results.append(build_unknown_file_output(client, file_hash))
    else:
        execution_metrics.quota_error += 1
        results.append(build_quota_exceeded_file_output(client, file_hash))

    if execution_metrics.is_supported():
        _metric_results = execution_metrics.metrics
        metric_results = cast(CommandResults, _metric_results)
        results.append(metric_results)

    return results


def passive_dns_data(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """

    id = {}
    if 'ip' in args:
        id['value'] = args['ip']
        id['type'] = 'ip'
        raise_if_ip_not_valid(id['value'])
    elif 'domain' in args:
        id['value'] = args['domain']
        id['type'] = 'domain'
    elif 'id' in args:
        id['value'] = args['id']
        if is_ip_valid(id['value']):
            id['type'] = 'ip'
        else:
            id['type'] = 'domain'
    else:
        return CommandResults(readable_output='No IP address or domain was given.')

    limit = arg_to_number_must_int(
        args['limit'],
        arg_name='limit',
        required=True
    )

    try:
        raw_response = client.passive_dns_data(id, limit)
    except Exception:
        return CommandResults(readable_output=f'{"IP" if id["type"] == "ip" else "Domain"} {id["value"]} was not found.')

    data = raw_response['data']
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.PassiveDNS',
        'id',
        readable_output=tableToMarkdown(
            f'Passive DNS data for {"IP" if id["type"] == "ip" else "domain"} {id["value"]}',
            [
                {
                    'id': item['id'],
                    **item['attributes']
                } for item in data
            ],
            headers=['id', 'date', 'host_name', 'ip_address', 'resolver'],
            removeNull=True,
            headerTransform=underscoreToCamelCase
        ),
        outputs=data,
        raw_response=raw_response
    )


def search_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    query = args['query']
    limit = arg_to_number_must_int(args.get('limit'), 'limit', required=True)
    raw_response = client.search(query, limit)
    data = raw_response.get('data', [])
    if not argToBoolean(args.get('extended_data', False)):
        data = decrease_data_size(data)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.SearchResults',
        'id',
        readable_output=tableToMarkdown(
            f'Search result of query {query}',
            [item.get('attributes') for item in data],
            removeNull=True,
            headerTransform=underscoreToCamelCase
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_analysis_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    analysis_id = args['id']
    raw_response = client.get_analysis(analysis_id)
    data = raw_response.get('data', {})
    if not argToBoolean(args.get('extended_data', False)):
        data = decrease_data_size(data)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Analysis',
        'id',
        readable_output=tableToMarkdown(
            'Analysis results:',
            {
                **data.get('attributes', {}),
                'id': analysis_id
            },
            headers=['id', 'stats', 'status'],
            headerTransform=underscoreToCamelCase
        ),
        outputs={
            **raw_response,
            'id': analysis_id
        },
        raw_response=raw_response
    )


def private_get_analysis_command(client: Client, args: dict) -> CommandResults:
    """
    1-2 API Call
    """
    analysis_id = args['id']
    raw_response = client.get_private_analysis(analysis_id)
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    stats = {
        'threat_severity_level': '',
        'popular_threat_category': '',
        'threat_verdict': '',
    }
    if attributes.get('status', '') == 'completed':
        file_response = client.get_private_file_from_analysis(analysis_id)
        file_attributes = file_response.get('data', {}).get('attributes', {})
        threat_severity = file_attributes.get('threat_severity', {})
        severity_level = threat_severity.get('threat_severity_level', '')
        stats['threat_severity_level'] = SEVERITY_LEVELS.get(severity_level, severity_level)
        threat_severity_data = threat_severity.get('threat_severity_data', {})
        stats['popular_threat_category'] = threat_severity_data.get('popular_threat_category', '')
        verdict = file_attributes.get('threat_verdict', '')
        stats['threat_verdict'] = VERDICTS.get(verdict, verdict)
    attributes.update(stats)
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Analysis',
        'id',
        readable_output=tableToMarkdown(
            'Analysis results:',
            {
                **attributes,
                'id': analysis_id
            },
            headers=['id', 'threat_severity_level', 'popular_threat_category', 'threat_verdict', 'status'],
            removeNull=True,
            headerTransform=string_to_table_header
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


def delete_comment(client: Client, args: dict) -> CommandResults:
    """Delete a comments"""
    id_ = args['id']
    client.delete_comment(id_)
    return CommandResults(readable_output=f'Comment {id_} has been deleted!')


def file_sigma_analysis_command(client: Client, args: dict) -> CommandResults:
    """Get last sigma analysis for a given file"""
    file_hash = args['file']
    only_stats = argToBoolean(args.get('only_stats', False))
    raw_response = client.file(file_hash)
    data = raw_response['data']

    if 'sigma_analysis_stats' not in data['attributes'] or 'sigma_analysis_results' not in data['attributes']:
        return CommandResults(readable_output=f'No Sigma analyses for file {file_hash} were found.')

    if only_stats:
        return CommandResults(
            f'{INTEGRATION_ENTRY_CONTEXT}.SigmaAnalysis',
            'id',
            readable_output=tableToMarkdown(
                f'Summary of the last Sigma analysis for file {file_hash}:',
                {
                    **data['attributes']['sigma_analysis_stats'],
                    '**TOTAL**': sum(data['attributes']['sigma_analysis_stats'].values())
                },
                headers=['critical', 'high', 'medium', 'low', '**TOTAL**'],
                removeNull=True,
                headerTransform=underscoreToCamelCase
            ),
            outputs=data,
            raw_response=data['attributes']['sigma_analysis_stats'],
        )
    else:
        return CommandResults(
            f'{INTEGRATION_ENTRY_CONTEXT}.SigmaAnalysis',
            'id',
            readable_output=tableToMarkdown(
                f'Matched rules for file {file_hash} in the last Sigma analysis:',
                data['attributes']['sigma_analysis_results'],
                headers=[
                    'rule_level', 'rule_description', 'rule_source',
                    'rule_title', 'rule_id', 'rule_author', 'match_context'
                ],
                removeNull=True,
                headerTransform=underscoreToCamelCase
            ),
            outputs=data,
            raw_response=data['attributes']['sigma_analysis_results'],
        )


def get_assessment_command(client: Client, score_calculator: ScoreCalculator, args: dict) -> CommandResults:
    """Get Google Threat Intelligence assessment for a given resource."""
    resource = args['resource']
    resource_type = args.get('resource_type', 'file').lower()
    # Will find if there's one and only one True in the list.
    if resource_type in ('hash', 'file'):
        raise_if_hash_not_valid(resource)
        raw_response = client.file(resource)
        if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
            return build_quota_exceeded_file_output(client, resource)
        if raw_response.get('error', {}).get('code') == 'NotFoundError':
            return build_unknown_file_output(client, resource)
        indicator = _get_file_indicator(client, score_calculator, resource, raw_response)
    elif resource_type == 'ip':
        raise_if_ip_not_valid(resource)
        raw_response = client.ip(resource)
        if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
            return build_quota_exceeded_ip_output(client, resource)
        if raw_response.get('error', {}).get('code') == 'NotFoundError':
            return build_unknown_ip_output(client, resource)
        indicator = _get_ip_indicator(client, score_calculator, resource, raw_response)
    elif resource_type == 'url':
        raw_response = client.url(resource)
        if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
            return build_quota_exceeded_url_output(client, resource)
        if raw_response.get('error', {}).get('code') == 'NotFoundError':
            return build_unknown_url_output(client, resource)
        indicator = _get_url_indicator(client, score_calculator, resource, raw_response)
    elif resource_type == 'domain':
        raw_response = client.domain(resource)
        if raw_response.get('error', {}).get('code') == 'QuotaExceededError':
            return build_quota_exceeded_domain_output(client, resource)
        if raw_response.get('error', {}).get('code') == 'NotFoundError':
            return build_unknown_domain_output(client, resource)
        indicator = _get_domain_indicator(client, score_calculator, resource, raw_response)
    else:
        raise DemistoException(f'Could not find resource type of "{resource_type}"')

    data = raw_response.get('data', {})
    data.pop('relationships', None)
    gti_assessment = data.get('attributes', {}).get('gti_assessment', {})

    if data:
        if gti_assessment:
            data['attributes'] = {'gti_assessment': gti_assessment}
        else:
            data.pop('attributes', None)

    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Assessment',
        'id',
        indicator=indicator,
        readable_output=tableToMarkdown(
            f'Google Threat Intelligence assessment of {resource_type}: "{resource}"',
            {
                'threat_score': gti_assessment.get('threat_score', {}).get('value'),
                'severity': gti_assessment.get('severity', {}).get('value'),
                'verdict': gti_assessment.get('verdict', {}).get('value'),
            },
            headers=[
                'threat_score',
                'severity',
                'verdict',
            ],
            headerTransform=string_to_table_header,
        ),
        outputs=data,
        raw_response=raw_response,
    )


def arg_to_relationships(arg):
    """Get an argument and return the relationship list."""
    return (','.join(argToList(arg))).replace('* ', '').replace(' ', '_')


def main(params: dict, args: dict, command: str):
    results: Union[CommandResults, str, List[CommandResults]]
    handle_proxy()
    client = Client(params)
    score_calculator = ScoreCalculator(params)

    ip_relationships = arg_to_relationships(params.get('ip_relationships'))
    url_relationships = arg_to_relationships(params.get('url_relationships'))
    domain_relationships = arg_to_relationships(params.get('domain_relationships'))
    file_relationships = arg_to_relationships(params.get('file_relationships'))

    disable_private_ip_lookup = argToBoolean(params.get('disable_private_ip_lookup', False))

    demisto.debug(f'Command called {command}')
    if command == 'test-module':
        results = check_module(client)
    elif command == 'file':
        results = file_command(client, score_calculator, args, file_relationships)
    elif command == 'ip':
        results = ip_command(client, score_calculator, args, ip_relationships, disable_private_ip_lookup)
    elif command == 'url':
        results = url_command(client, score_calculator, args, url_relationships)
    elif command == 'domain':
        results = domain_command(client, score_calculator, args, domain_relationships)
    elif command == f'{COMMAND_PREFIX}-file-sandbox-report':
        results = file_sandbox_report_command(client, args)
    elif command == f'{COMMAND_PREFIX}-passive-dns-data':
        results = passive_dns_data(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-get':
        results = get_comments_command(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-add':
        results = add_comments_command(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-get-by-id':
        results = get_comments_by_id_command(client, args)
    elif command == f'{COMMAND_PREFIX}-comments-delete':
        results = delete_comment(client, args)
    elif command == 'url-scan':
        results = scan_url_command(client, args)
    elif command == 'file-scan':
        results = file_scan(client, args)
    elif command == 'file-rescan':
        results = file_rescan_command(client, args)
    elif command == f'{COMMAND_PREFIX}-file-scan-upload-url':
        results = get_upload_url(client)
    elif command == f'{COMMAND_PREFIX}-search':
        results = search_command(client, args)
    elif command == f'{COMMAND_PREFIX}-analysis-get':
        results = get_analysis_command(client, args)
    elif command == f'{COMMAND_PREFIX}-file-sigma-analysis':
        results = file_sigma_analysis_command(client, args)
    elif command == f'{COMMAND_PREFIX}-privatescanning-file':
        results = private_file_command(client, args)
    elif command == f'{COMMAND_PREFIX}-privatescanning-file-scan':
        results = private_file_scan(client, args)
    elif command == f'{COMMAND_PREFIX}-privatescanning-analysis-get':
        results = private_get_analysis_command(client, args)
    elif command == f'{COMMAND_PREFIX}-assessment-get':
        results = get_assessment_command(client, score_calculator, args)
    elif command == f'{COMMAND_PREFIX}-file-scan-and-analysis-get':
        results = file_scan_and_get_analysis(client, args)
    elif command == f'{COMMAND_PREFIX}-private-file-scan-and-analysis-get':
        results = private_file_scan_and_get_analysis(client, args)
    elif command == f'{COMMAND_PREFIX}-url-scan-and-analysis-get':
        results = url_scan_and_get_analysis(client, args)
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in ('builtins', '__builtin__', '__main__'):
    try:
        main(demisto.params(), demisto.args(), demisto.command())
    except Exception as exception:
        return_error(exception)
