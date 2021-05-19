"""
An integration module for the Virus Total v3 API.
API Documentation:
    https://developers.virustotal.com/v3.0/reference
"""
from collections import defaultdict
from typing import Callable

from dateparser import parse

from CommonServerPython import *

INTEGRATION_NAME = "VirusTotal"
COMMAND_PREFIX = "vt"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"

INDICATOR_TYPE = {
    'ip': FeedIndicatorType.IP,
    'ip_address': FeedIndicatorType.IP,
    'domain': FeedIndicatorType.Domain,
    'file': FeedIndicatorType.File,
    'url': FeedIndicatorType.URL
}


""" RELATIONSHIP TYPE"""
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
    }, 'ip': {
        'communicating_files': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'referrer_files': EntityRelationship.Relationships.RELATED_TO,
        'resolutions': EntityRelationship.Relationships.RESOLVES_TO,
        'urls': EntityRelationship.Relationships.RELATED_TO,
    }, 'url': {
        'contacted_domains': EntityRelationship.Relationships.RELATED_TO,
        'contacted_ips': EntityRelationship.Relationships.RELATED_TO,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'last_serving_ip_address': EntityRelationship.Relationships.RESOLVED_FROM,
        'network_location': EntityRelationship.Relationships.RESOLVED_FROM,
        'redirecting_urls': EntityRelationship.Relationships.DUPLICATE_OF,
        'redirects_to': EntityRelationship.Relationships.DUPLICATE_OF,
        'referrer_files': EntityRelationship.Relationships.EMBEDDED_IN,
        'referrer_urls': EntityRelationship.Relationships.RELATED_TO,
    }
}


class Client(BaseClient):
    """
    Attributes:
        is_premium: Shall use the premium api (mostly for reputation commands)
    """
    is_premium: bool
    reliability: DBotScoreReliability

    def __init__(self, params: dict):
        self.is_premium = argToBoolean(params['is_premium_api'])
        self.reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(params['feedReliability'])
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not argToBoolean(params.get('insecure')),
            proxy=argToBoolean(params.get('proxy')),
            headers={'x-apikey': params['credentials']['password']}
        )

    # region Reputation calls

    def ip(self, ip: str, relationships: str = '') -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#ip-info
        """
        return self._http_request(
            'GET',
            f'ip_addresses/{ip}?relationships={relationships}'
        )

    def file(self, file: str, relationships: str = '') -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#file
        """
        return self._http_request(
            'GET',
            f'files/{file}?relationships={relationships}'
        )

    def url(self, url: str, relationships: str = ''):
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#url
        """
        return self._http_request(
            'GET',
            f'urls/{encode_url_to_base64(url)}?relationships={relationships}'
        )

    def domain(self, domain: str, relationships: str = '') -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#domain-info
        """
        return self._http_request(
            'GET',
            f'domains/{domain}?relationships={relationships}'
        )

    # endregion

    # region Comments call
    def delete_comment(self, id_: str):
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#comment-id-delete
        """
        self._http_request(
            'DELETE',
            f'comments/{id_}',
            resp_type='response'
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
            f'files/{file_hash}/comments',
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
            https://developers.virustotal.com/v3.0/reference#ip-comments-post
        """
        return self.add_comment(f'ip_addresses/{ip}/comments', comment)

    def add_comment_to_url(self, url: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#urls-comments-post
        """
        return self.add_comment(f'urls/{encode_url_to_base64(url)}/comments', comment)

    def add_comment_to_domain(self, domain: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#domains-comments-post
        """
        return self.add_comment(f'domains/{domain}/comments', comment)

    def add_comment_to_file(self, resource: str, comment: str) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#files-comments-post
        """
        return self.add_comment(f'files/{resource}/comments', comment)

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
        response: requests.Response
        with open(file_path, 'rb') as file:
            if upload_url:
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

    def search(self, query: str, limit: int) -> dict:
        """
        See Also:
            https://developers.virustotal.com/v3.0/reference#search-1
        """
        return self._http_request(
            'GET',
            'search',
            params={'query': query, 'limit': limit}
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
        trusted_vendors_threshold = arg_to_number_must_int(
            params['preferredVendorsThreshold'],
            arg_name='Preferred Vendor Threshold',
            required=True
        )
        assert isinstance(trusted_vendors_threshold, int)
        self.trusted_vendors_threshold = arg_to_number_must_int(
            params['preferredVendorsThreshold'],
            arg_name='Preferred Vendor Threshold',
            required=True
        )
        self.file_threshold = arg_to_number_must_int(
            params['fileThreshold'],
            arg_name='File Threshold',
            required=True
        )
        self.ip_threshold = arg_to_number_must_int(
            params['ipThreshold'],
            arg_name='IP Threshold',
            required=True
        )
        self.url_threshold = arg_to_number_must_int(
            params['urlThreshold'],
            arg_name='URL Threshold',
            required=True
        )
        self.domain_threshold = arg_to_number_must_int(
            params['domainThreshold'],
            arg_name='Domain Threshold',
            required=True
        )
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
        self.relationship_threshold = arg_to_number_must_int(
            params['relationship_threshold'],
            arg_name='Relationship Files Threshold',
            required=True
        )
        self.logs = list()

    def get_logs(self) -> str:
        """Returns the log string
        """
        return '\n'.join(self.logs)

    def is_suspicious_by_threshold(self, analysis_stats: dict, threshold: int) -> bool:
        """Determines whatever the indicator suspicious by threshold.
        if number of malicious >= threshold /2 ||
        number of suspicious >= threshold -> Suspicious

        Args:
            analysis_stats: the analysis stats from the response
            threshold: the threshold of the indicator type.

        Returns:
            Whatever the indicator is suspicious by threshold.
        """
        if analysis_stats.get('malicious', 0) >= threshold / 2:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats.get("malicious", 0) >= threshold / 2)=}. '
            )
            return True
        elif analysis_stats.get('suspicious', 0) >= threshold:
            self.logs.append(
                f'Found at least suspicious by {(analysis_stats.get("suspicious", 0) >= threshold)=}. '
            )
            return True
        return False

    def is_good_by_popularity_ranks(self, popularity_ranks: dict) -> Optional[bool]:
        """Analyzing popularity ranks.
        if popularity ranks exist and average rank is < threshold -> Good
        Args:
            popularity_ranks: the popularity ranks object from response

        Returns:
            Whatever the indicator is good or not by popularity rank.
        """
        if popularity_ranks:
            self.logs.append(
                'Found popularity ranks. Analyzing. '
            )
            average = sum(rank.get('rank', 0) for rank in popularity_ranks.values()) / len(popularity_ranks)
            self.logs.append(
                f'The average of the ranks is {average} and the threshold is {self.domain_popularity_ranking}'
            )
            if average >= self.domain_popularity_ranking:
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
        else:
            self.logs.append(
                'Crowdsourced Yara Rules analyzing is not enabled. Skipping. '
            )
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
        if number of malicious >= threshold -< Malicious

        Args:
            analysis_stats: the analysis stats from the response
            threshold: the threshold of the indicator type.

        Returns:
            Whatever the indicator is malicious by threshold.
        """
        total_malicious = analysis_stats.get('malicious', 0)
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
        """Determines the DBOTSCORE of the indicator by threshold only.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        if self.is_malicious_by_threshold(analysis_stats, threshold):
            return Common.DBotScore.BAD
        if self.is_suspicious_by_threshold(analysis_stats, threshold):
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.GOOD

    def score_by_results_and_stats(self, indicator: str, raw_response: dict, threshold: int) -> int:
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
        attributes = data['attributes']
        popularity_ranks = attributes.get('popularity_ranks')
        last_analysis_results = attributes['last_analysis_results']
        last_analysis_stats = attributes['last_analysis_stats']
        if self.is_good_by_popularity_ranks(popularity_ranks):
            return Common.DBotScore.GOOD
        if self.is_preferred_vendors_pass_malicious(last_analysis_results):
            return Common.DBotScore.BAD
        return self.score_by_threshold(last_analysis_stats, threshold)

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
        self.logs.append(f'Analysing file hash {given_hash}. ')
        data = raw_response.get('data', {})
        attributes = data.get('attributes', {})
        analysis_results = attributes.get('last_analysis_results', {})
        analysis_stats = attributes.get('last_analysis_stats', {})

        # Trusted vendors
        if self.is_preferred_vendors_pass_malicious(analysis_results):
            return Common.DBotScore.BAD

        score = self.score_by_threshold(analysis_stats, self.file_threshold)
        if score == Common.DBotScore.BAD:
            return Common.DBotScore.BAD

        suspicious_by_rules = self.is_suspicious_by_rules(raw_response)
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
        """Analyzing IP score.
        The next parameters are analyzed:
            Preferred vendors
            Score by threshold
            Score by rules analysis (YARA, IDS and Sigma, if presents)

        Args:
            ip: The hash we're analyzing
            raw_response: The response from the API

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        return self.score_by_results_and_stats(
            ip, raw_response, self.ip_threshold
        )

    def url_score(self, indicator: str, raw_response: dict) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The raw response from API.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        return self.score_by_results_and_stats(indicator, raw_response, self.url_threshold)

    def domain_score(self, indicator: str, raw_response: dict) -> int:
        """Determines indicator score by popularity preferred vendors and threshold.

        Args:
            indicator: The indicator we analyzing.
            raw_response: The raw response from API.

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        return self.score_by_results_and_stats(indicator, raw_response, self.domain_threshold)

    # region Premium analysis
    def is_malicious_or_suspicious_by_relationship_files(self, relationship_files_response: dict, lookback=20) -> int:
        """Checks maliciousness of indicator on relationship files. Look on the recent 20 results returned.
            if (number of relationship files that are malicious > threshold) -> Bad
            if (number of relationship files that are malicious > threshold / 2) -> suspicious
            else good
        Args:
            relationship_files_response: The raw_response of the relationship call
            lookback: analysing only the latest results. Defualt is 20

        Returns:
            DBotScore of the indicator. Can by Common.DBotScore.BAD, Common.DBotScore.SUSPICIOUS or
            Common.DBotScore.GOOD
        """
        files = relationship_files_response.get('data', [])[:lookback]  # lookback on recent 20 results. By design
        total_malicious = 0
        for file in files:
            if file_hash := file.get('sha256', file.get('sha1', file.get('md5', file.get('ssdeep')))):
                if self.file_score(file_hash, files) == Common.DBotScore.BAD:
                    total_malicious += 1

        if total_malicious >= self.url_threshold:
            self.logs.append(
                f'Found malicious by relationship files. {total_malicious=} >= {self.relationship_threshold}'
            )
            return Common.DBotScore.BAD
        if total_malicious >= self.url_threshold / 2:
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
        'last_analysis_results', 'pe_info', 'crowdsourced_ids_results', 'autostart_locations', 'sandbox_verdicts',
        'sigma_analysis_summary'
    ]
    if isinstance(data, list):
        data = [decrease_data_size(item) for item in data]
    else:
        for attribute in attributes_to_remove:
            try:
                del data['attributes'][attribute]
            except KeyError:
                pass
    return data


def build_domain_output(
        client: Client,
        score_calculator: ScoreCalculator,
        domain: str,
        raw_response: dict,
        extended_data: bool):
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    relationships_response = data.get('relationships', {})
    whois: defaultdict = get_whois(attributes.get('whois', ''))
    score = score_calculator.domain_score(domain, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_domain_score(client, domain, score)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    relationships_list = create_relationships(entity_a=domain, entity_a_type=FeedIndicatorType.Domain,
                                              relationships_response=relationships_response,
                                              reliability=client.reliability)
    domain_indicator = Common.Domain(
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
    if not extended_data:
        data = decrease_data_size(data)

    attributes = data.get('attributes', {})
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_ENTRY_CONTEXT}.Domain',
        outputs_key_field='id',
        indicator=domain_indicator,
        readable_output=tableToMarkdown(
            f'Domain data of {domain}',
            {
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date')),
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
            removeNull=True,
            headerTransform=underscoreToCamelCase
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
    score = score_calculator.url_score(url, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_url_score(client, url, score)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    # creating readable output
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    relationships_response = data.get('relationships', {})
    positive_detections = last_analysis_stats.get('malicious', 0)
    detection_engines = sum(last_analysis_stats.values())
    relationships_list = create_relationships(entity_a=url, entity_a_type=FeedIndicatorType.URL,
                                              relationships_response=relationships_response,
                                              reliability=client.reliability)
    url_indicator = Common.URL(
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
                **data.get('attributes', {}),
                'url': url,
                'positives': f'{positive_detections}/{detection_engines}',
                'last_modified': epoch_to_timestamp(attributes.get('last_modification_date'))
            },
            headers=[
                'url',
                'title',
                'last_modified',
                'has_content',
                'last_http_response_content_sha256',
                'positives',
                'reputation'
            ],
            removeNull=True,
            headerTransform=underscoreToCamelCase
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
    )


def build_ip_output(client: Client, score_calculator: ScoreCalculator, ip: str, raw_response: dict,
                    extended_data: bool) -> CommandResults:
    score = score_calculator.ip_score(ip, raw_response)
    if score != Common.DBotScore.BAD and client.is_premium:
        score = score_calculator.analyze_premium_ip_score(client, ip, score)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    data = raw_response.get('data', {})
    attributes = data.get('attributes', {})
    relationships_response = data.get('relationships', {})
    last_analysis_stats = attributes.get('last_analysis_stats')
    positive_engines = last_analysis_stats.get('malicious', 0)
    detection_engines = sum(last_analysis_stats.values())
    relationships_list = create_relationships(entity_a=ip, entity_a_type=FeedIndicatorType.IP,
                                              relationships_response=relationships_response,
                                              reliability=client.reliability)
    ip_indicator = Common.IP(
        ip,
        asn=attributes.get('asn'),
        geo_country=attributes.get('country'),
        detection_engines=detection_engines,
        positive_engines=positive_engines,
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
                'positives': f'{positive_engines}/{detection_engines}'
            },
            headers=['id', 'network', 'country', 'last_modified', 'reputation', 'positives'],
            headerTransform=underscoreToCamelCase
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
    attributes = data.get('attributes')
    relationships_response = data.get('relationships', {})
    score = score_calculator.file_score(file_hash, raw_response)
    logs = score_calculator.get_logs()
    demisto.debug(logs)
    signature_info = attributes.get('signature_info', {})
    exiftool = attributes.get('exiftool', {})
    relationships_list = create_relationships(entity_a=file_hash, entity_a_type=FeedIndicatorType.File,
                                              relationships_response=relationships_response,
                                              reliability=client.reliability)
    file_indicator = Common.File(
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
    if not extended_data:
        data = decrease_data_size(data)
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    malicious = last_analysis_stats.get('malicious', 0)
    total = sum(last_analysis_stats.values())
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
                'creation date': epoch_to_timestamp(attributes.get('creation_date')),
                'last modified': epoch_to_timestamp(attributes.get('last_modification_date', 0))
            },
            headers=[
                'sha1', 'sha256', 'md5',
                'meaningful_name', 'type_extension', 'creation date',
                'last modified', 'reputation', 'positives'
            ],
            removeNull=True,
            headerTransform=underscoreToCamelCase
        ),
        outputs=data,
        raw_response=raw_response,
        relationships=relationships_list
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
        key, value = line.split(sep=':', maxsplit=1)
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


def ip_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    ips = argToList(args['ip'])
    results: List[CommandResults] = list()
    for ip in ips:
        raise_if_ip_not_valid(ip)
        try:
            raw_response = client.ip(ip, relationships)
        except Exception as exception:
            # If anything happens, just keep going
            demisto.debug(f'Could not process IP: "{ip}"\n {str(exception)}')
            continue
        results.append(
            build_ip_output(client, score_calculator, ip, raw_response, argToBoolean(args.get('extended_data')))
        )
    return results


def file_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call
    """
    files = argToList(args['file'])
    extended_data = argToBoolean(args.get('extended_data'))
    results: List[CommandResults] = list()
    for file in files:
        raise_if_hash_not_valid(file)
        try:
            raw_response = client.file(file, relationships)
            results.append(build_file_output(client, score_calculator, file, raw_response, extended_data))
        except Exception as exc:
            # If anything happens, just keep going
            results.append(CommandResults(readable_output=f'Could not process file: "{file}"\n {str(exc)}'))

    return results


def url_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    urls = argToList(args['url'])
    extended_data = argToBoolean(args.get('extended_data'))
    results: List[CommandResults] = list()
    for url in urls:
        try:
            raw_response = client.url(
                url, relationships
            )
        except Exception as exception:
            # If anything happens, just keep going
            demisto.debug(f'Could not process URL: "{url}".\n {str(exception)}')
            continue
        results.append(build_url_output(client, score_calculator, url, raw_response, extended_data))
    return results


def domain_command(client: Client, score_calculator: ScoreCalculator, args: dict, relationships: str) -> List[CommandResults]:
    """
    1 API Call for regular
    1-4 API Calls for premium subscriptions
    """
    domains = argToList(args['domain'])
    results: List[CommandResults] = list()
    for domain in domains:
        try:
            raw_response = client.domain(domain, relationships)
        except Exception as exception:
            # If anything happens, just keep going
            demisto.debug(f'Could not process domain: "{domain}"\n {str(exception)}')
            continue
        results.append(
            build_domain_output(client, score_calculator, domain, raw_response, argToBoolean(args.get('extended_data')))
        )
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


def get_md5_by_entry_id(entry_id: str) -> str:
    """Gets an MD5 from context using entry ID"""
    md5 = demisto.dt(demisto.context(), f'File(val.EntryID === "{entry_id}").MD5')
    if not md5:
        raise DemistoException('Could not find MD5')
    return md5


def encode_to_base64(md5: str, id_: Union[str, int]) -> str:
    """Sometime the API returns the id as number only. Need to join the id with md5 in base64.

    Args:
        md5: The MD5 of the file sent to scan
        id_: The id returned from the file scan

    Returns:
        base64 encoded of md5:id_
    """
    return base64.b64encode(f'{md5}:{id_}'.encode('utf-8')).decode('utf-8')


def get_working_id(id_: str, entry_id: str) -> str:
    """Sometimes new scanned files ID will be only a number. Should connect them with base64(MD5:_id).
    Fixes bug in VirusTotal API.

    Args:
        entry_id: the entry id connected to the file
        id_: id given from the API

    Returns:
        A working ID that we can use in other commands.
    """
    if isinstance(id_, str) and id_.isnumeric() or (isinstance(id_, int)):
        demisto.debug(f'Got an integer id from file-scan. {id_=}, {entry_id=}\n')
        raise DemistoException(
            f'Got an int {id_=} as analysis report. This is a bug in VirusTotal v3 API.\n'
            f'While VirusTotal team is fixing the problem, try to resend the file.'
        )
    return id_


def file_scan(client: Client, args: dict) -> List[CommandResults]:
    """
    1 API Call
    """
    entry_ids = argToList(args['entryID'])
    upload_url = args.get('uploadURL')
    if len(entry_ids) > 1 and upload_url:
        raise DemistoException('You can supply only one entry ID with an upload URL.')
    results = list()
    for entry_id in entry_ids:
        try:
            file_obj = demisto.getFilePath(entry_id)
            file_path = file_obj['path']
            raw_response = client.file_scan(file_path, upload_url=upload_url)
            data = raw_response.get('data', {})
            # add current file as identifiers
            data.update(
                get_file_context(entry_id)
            )
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
    raw_response = client.url_scan(url)
    data = raw_response['data']
    data['url'] = url
    context = {
        f'{INTEGRATION_ENTRY_CONTEXT}.Submission(val.id && val.id === obj.id)': data,
        'vtScanID': data.get('id')  # BC preservation
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
    elif resource_type == 'hash':
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
            f'Virus Total comments of {resource_type}: "{resource}"',
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

def file_sandbox_report_command(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    file_hash = args['file']
    limit = arg_to_number(
        args['limit'],
        'limit',
        required=True
    )
    assert isinstance(limit, int)  # mypy fix
    raise_if_hash_not_valid(file_hash)
    raw_response = client.file_sandbox_report(file_hash, limit)
    data = raw_response['data']
    return CommandResults(
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


def passive_dns_data(client: Client, args: dict) -> CommandResults:
    """
    1 API Call
    """
    ip = args['ip']
    limit = arg_to_number_must_int(
        args['limit'],
        arg_name='limit',
        required=True
    )
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
    if not argToBoolean(args.get('extended_data')):
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


def main(params: dict, args: dict, command: str):
    results: Union[CommandResults, str, List[CommandResults]]
    handle_proxy()
    client = Client(params)
    score_calculator = ScoreCalculator(params)

    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(" ", "_")
    url_relationships = (','.join(argToList(params.get('url_relationships')))).replace('* ', '').replace(" ", "_")
    domain_relationships = (','.join(argToList(params.get('domain_relationships')))).replace('* ', '').replace(" ", "_")
    file_relationships = (','.join(argToList(params.get('file_relationships')))).replace('* ', '').replace(" ", "_")

    demisto.debug(f'Command called {command}')
    if command == 'test-module':
        results = check_module(client)
    elif command == 'file':
        results = file_command(client, score_calculator, args, file_relationships)
    elif command == 'ip':
        results = ip_command(client, score_calculator, args, ip_relationships)
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
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in ('builtins', '__builtin__', '__main__'):
    try:
        main(demisto.params(), demisto.args(), demisto.command())
    except Exception as exception:
        return_error(exception)
