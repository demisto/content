import ipaddress
from enum import Enum

import requests

import json
import urllib3
import traceback
from typing import Any
import ast
from urllib.parse import urlencode, urlparse

import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
urllib3.disable_warnings()

# pragma: no cover
""" CONSTANTS """


class ResourceType(Enum):
    IP4 = "ipv4"
    IP6 = "ipv6"
    DOMAIN = "domain"

    @classmethod
    def get_choices(cls):
        return [cls.IP4.value, cls.IP6.value, cls.DOMAIN.value]


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# API ENDPOINTS
THREAT_CHECK = "https://api.threatcheck.silentpush.com/v1/"
V1 = "api/v1/"
V2 = "api/v2/"
MERGE_API = V1 + "merge-api/explore/"
ENRICHMENT = MERGE_API + "enrich"
BULK_IP6_INFO = MERGE_API + "bulk/ip2asn/ipv6"
BULK_INFO = MERGE_API + "bulk/summary"
BULK_DOMAIN_INFO = BULK_INFO + "/domain"
BULK_IP4_INFO = BULK_INFO + "/ipv4"
FORWARD_PADNS = MERGE_API + "padns/lookup/query"
REVERSE_PADNS = MERGE_API + "padns/lookup/answer"
MULTI_CONDITIONAL_PADNS_LOOKUP = MERGE_API + "padns/lookup/both"
DENSITY = MERGE_API + "padns/lookup/density"
ASNS_DOMAIN = MERGE_API + "padns/lookup/domain/asns"
IP_DIVERSITY = MERGE_API + "padns/lookup/ipdiversity"
IP_DIVERSITY_PATTERNS = MERGE_API + "padns/search/ipdiversity"
NAMESERVER_REPUTATION = MERGE_API + "nsreputation/history/nameserver"
SUBNET_REPUTATION = MERGE_API + "ipreputation/history/subnet"
IPV4_REPUTATION = MERGE_API + "ipreputation/history/ipv4"
SEARCH_DOMAIN = MERGE_API + "domain/search"
SEARCH_SCAN = MERGE_API + "spql/search"
LIVE_SCAN_URL = V2 + "live-scan/scan-on-demand/query"
WHOIS = MERGE_API + "domain/whois"
DOMAIN_CERTIFICATE = MERGE_API + "domain/certificates"
ADD_FEED = V1 + "feeds/"
EXPORT_DATA = V1 + "export/"
JOB_STATUS = MERGE_API + "job/"

""" COMMANDS INPUTS """

FIRST_SEEN_INPUTS = [
    InputArgument(name="first_seen_after",
                  description="Filter results to include only records first seen after this date."),
    InputArgument(name="first_seen_before",
                  description="Filter results to include only records first seen before this date."),
]
LAST_SEEN_INPUTS = [
    InputArgument(name="last_seen_after",
                  description="Filter results to include only records last seen after this date."),
    InputArgument(name="last_seen_before",
                  description="Filter results to include only records last seen before this date."),
]
SEEN_INPUTS = FIRST_SEEN_INPUTS + LAST_SEEN_INPUTS
COMMON_INPUTS = [
    InputArgument(name="prefer", description="Preference for specific DNS servers or sources."),
    InputArgument(name="skip", description="Number of results to skip for pagination purposes."),
    InputArgument(name="limit", description="Maximum number of results to return."),
    InputArgument(name="with_metadata", description="Flag to include metadata in the DNS records."),
    InputArgument(name="max_wait", description="Maximum number of seconds to wait for results before timing out."),
]
COMMON_SEARCH_INPUTS = FIRST_SEEN_INPUTS + COMMON_INPUTS + [
    InputArgument(name="domain", description="Name or wildcard pattern of domain names to search for."),
    InputArgument(name="domain_regex",
                  description="A valid RE2 regex pattern to match domains. Overrides the domain argument."),
    InputArgument(name="nsname",
                  description="Name server name or wildcard pattern of the name server used by domains."),
    InputArgument(name="mxname",
                  description="mx server name or wildcard pattern of mx server used by domains, use mxname=self to find domains hosting their own mailservers."),
    InputArgument(name="first_seen_min",
                  description="only domains that have A records seen for the first time after the given date."),
    InputArgument(name="first_seen_max",
                  description="only domains that have A records seen for the first time before the given date."),
    InputArgument(name="first_seen_min_mode",
                  description="match mode for first_seen_min parameter, strict (default) - select A records that do not have any timestamps before first_seen_min, "
                              "any - select A records that have at least one timestamp after first_seen_min."),
    InputArgument(name="first_seen_max_mode",
                  description="match mode for first_seen_max parameter, strict (default) - select A records that do not have any timestamps after first_seen_max, "
                              "any - select A records that have at least one timestamp before first_seen_max."),
    InputArgument(name="last_seen_min",
                  description="only domains that have A records last seen more recently than the given date."),
    InputArgument(name="last_seen_max",
                  description="only domains that have A records last seen earlier than the given date."),
    InputArgument(name="last_seen_min_mode",
                  description="match mode for last_seen_min parameter, strict - select A records that do not have any timestamps before last_seen_min, "
                              "any (default) - select A records that have at least one timestamp after first_seen_min."),
    InputArgument(name="last_seen_max_mode",
                  description="match mode for last_seen_max parameter, strict (default) - select A records that do not have any timestamps after last_seen_max, "
                              "any - select A records that have at least one timestamp before last_seen_max."),
    InputArgument(name="asnum", description="Autonomous System (AS) number to filter domains."),
    InputArgument(name="asname",
                  description="Search for all AS numbers where the AS Name begins with the specified value."),
    InputArgument(name="network",
                  description="additional network and net mask, give option as 1.1.1.1/24, network parameter may be given multiple times and the search will be performed as an ‘or’ condition."),
    InputArgument(name="timeline",
                  description="include details of IPs, ASNs, first_seen and last_seen for each domain, 0 (default) = do not include, 1 = include timeline"),
    InputArgument(name="ip_diversity_all_min", description="Minimum IP diversity limit to filter domains."),
    InputArgument(name="registrar",
                  description="Name or partial name of the registrar used to register domains."),
    InputArgument(name="email",
                  description="email used to register domains - no wildcards, the given string is used in exact match - this is a slow search option and should only be used in combination with the domain match option."),
    InputArgument(name="nschange_from_ns",
                  description="domain has changed name server from nsname, exact match, wildcards and ‘self’ options supported."),
    InputArgument(name="nschange_to_ns",
                  description="domain has changed name server to nsname, exact match, wildcards and ‘self’ options supported."),
    InputArgument(name="nschange_date_after",
                  description="only domains with name server changes that occurred after the given date, if nschange_date_after is not given, the default is to find name server changes in the last 30 days, if nschange_date_before is not given."),
    InputArgument(name="nschange_date_before",
                  description="only domains with name server changes that occurred before the given date."),
    InputArgument(name="cert_date_min",
                  description="only domains that have had ssl certificates issued on or after the given date."),
    InputArgument(name="cert_date_max",
                  description="only domains that have had ssl certificates issued on or before the given date."),
    InputArgument(name="cert_issuer",
                  description="Filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported.", ),
    InputArgument(name="infratag",
                  description="search by infratag, infratag must include mx part, ns part, asname part, or registrar part, overrides mxname, nsname and registrar parameters, if infratag contains these parts, can be combined with all other parameters."),
    InputArgument(name="asn_diversity_min", description="Minimum ASN diversity limit to filter domains."),
    InputArgument(name="ip_diversity_all_min", description="minimum diversity limit, default = 1."),
    InputArgument(name="ip_diversity_groups_min", description="minimum diversity limit."),
    InputArgument(name="whois_date_after",
                  description="Filter domains with a WHOIS creation date after this date (YYYY-MM-DD)."),
]
NAMESERVER_REPUTATION_INPUTS = [
    InputArgument(name="nameserver", description="Nameserver name for which information needs to be retrieved.", required=True),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score."),
    InputArgument(name="limit", description="The maximum number of reputation history to retrieve."),
]
SUBNET_REPUTATION_INPUTS = [
    InputArgument(
        name="subnet",
        description="IPv4 subnet in the format IP/NETMASK for which reputation information needs to be retrieved, i.e.: 192.35.168.0/23",
        required=True
    ),
    InputArgument(name="explain", description="Show the detailed information used to calculate the reputation score."),
    InputArgument(name="limit", description="Maximum number of reputation history entries to retrieve."),
]
DOMAIN_INPUT = [
    InputArgument(
        name="domain",
        description="Domain name to search",
        required=True,
    )
]
ASNS_DOMAIN_INPUTS = DOMAIN_INPUT + [
    InputArgument(
        name="result_format",
        description="format of returned results: compact (default) = return ASN and AS Name only, full = return details of domain hosts in each ASN",
        required=False,
    )
]
DENSITY_LOOKUP_INPUTS = [
    InputArgument(name="qtype", description="Query type.", required=True),
    InputArgument(name="query", description="Value to query.", required=True),
    InputArgument(name="scope", description="Match level (optional)."),
]
IP_DIVERSITY_LOOKUP_INPUTS = [
    InputArgument(name="qtype", description="Query type.", required=True),
    InputArgument(name="query", description="Value to query.", required=True),
    InputArgument(name="window", description="use records with a last_seen more recently than days ago, default = 30"),
    InputArgument(name="asn", description="include asn diversity, 0 = do not include, 1 (default) = include asn diversity"),
    InputArgument(name="timeline",
                  description="include timeline of {ip, first_seen, last_seen} (+asn if asn=1), 0 (default) = do not include, 1 = include timeline"),
    InputArgument(name="verbose",
                  description="return ips, dates, timeline, (and asns if asn=1), 0 (default) = do not include, 1 = include all data"),
    InputArgument(name="scope",
                  description="exact or near match results by qtype, *scope=live is automatically set when timeline=1 or verbose=1. " +
                              "*for qtype = a: host - exact match (default when qtype=a), domain - match all hosts in this domain (domain extracted from {query}), " +
                              "subdomain - match all hosts at this subdomain level (i.e. *.{query}), live - calculate values from live data instead of pre-aggregated values - " +
                              "also switches to exact match only. *for qtype = aaaa, live - only this mode is supported for qtype=aaaa"
                  ),
]
SEARCH_DOMAIN_INPUTS = IP_DIVERSITY_PATTERNS_INPUTS = COMMON_SEARCH_INPUTS
LIST_DOMAIN_INPUTS = [
    InputArgument(name="domains", description="Comma-separated list of domains to query.", required=True),
]
LIST_IP_INPUTS = [
    InputArgument(name="ips", description="Comma-separated list of IPs to query.", required=True),
]
DOMAIN_CERTIFICATE_INPUTS = COMMON_INPUTS + [
    InputArgument(name="domain", description="The domain to query certificates for.", required=True),
    InputArgument(name="domain_regex", description="Regular expression to match domains."),
    InputArgument(name="certificate_issuer", description="Filter by certificate issuer."),
    InputArgument(name="date_min", description="Filter certificates issued on or after this date."),
    InputArgument(name="date_max", description="Filter certificates issued on or before this date."),
]
ENRICHMENT_INPUTS = [
    InputArgument(
        name="resource",
        description="Type of resource for which information needs to be retrieved {e.g. domain}.",
        required=True,
    ),
    InputArgument(
        name="value",
        description='Value corresponding to the selected "resource" for which information needs to be retrieved '
                    "{e.g. silentpush.com}.",
        required=True,
    ),
    InputArgument(name="explain", description="Include explanation of data calculations."),
    InputArgument(name="scan_data", description="Include scan data (IPv4 only)."),
]
IPV4_REPUTATION_INPUTS = [
    InputArgument(
        name="ipv4",
        description="IPv4 address for which information needs to be retrieved.",
        required=True,
    ),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score."),
    InputArgument(name="limit", description="The maximum number of reputation history to retrieve."),
]
PADNS_INPUTS = SEEN_INPUTS + COMMON_INPUTS + [
    InputArgument(name="qtype", description="DNS record type.", required=True),
    InputArgument(name="query", description="The DNS record name to lookup.", required=True),
    InputArgument(name="netmask", description="The netmask to filter the lookup results."),
    InputArgument(name="match", description="Type of match for the query (e.g., exact, partial)."),
    InputArgument(name="as_of", description="Date or time to get the DNS records as of a specific point in time."),
    InputArgument(name="sort", description="Sort the results by the specified field (e.g., date, score)."),
    InputArgument(name="output_format",
                  description="The format in which the results should be returned (e.g., JSON, XML)."),
]
FORWARD_REVERSE_PADNS_INPUTS = [
    InputArgument(name="subdomains", description="Flag to include subdomains in the lookup results."),
    InputArgument(name="regex", description="Regular expression to filter the DNS records."),
]
FORWARD_PADNS_INPUTS = REVERSE_PADNS_INPUTS = PADNS_INPUTS
FORWARD_PADNS_INPUTS += FORWARD_REVERSE_PADNS_INPUTS
REVERSE_PADNS_INPUTS += FORWARD_REVERSE_PADNS_INPUTS
MULTI_CONDITIONAL_PADNS_LOOKUP_INPUTS = PADNS_INPUTS + [
    InputArgument(name="answer", description="DNS record answer to lookup.",
                  required=True),
    InputArgument(name="name",
                  description="additional name to match qanswer, up to 5."),
    InputArgument(name="net",
                  description="find ptr4 or a records where ipv4 in or not in subnet defined by netmask. in (default) - find records in subnet, notin - find records not in subnet"),
    InputArgument(name="network",
                  description="additional network and net mask in the format 1.1.1.1/24, up to 5."),
    InputArgument(name="asnum",
                  description="Autonomous System (AS) number to filter domains."),
    InputArgument(name="asn",
                  description="include asn diversity, 0 = do not include, 1 (default) = include asn diversity"),
    InputArgument(name="asname",
                  description="Search for all AS numbers where the AS Name begins with the specified value."),
]
SEARCH_SCAN_INPUTS = [
    InputArgument(name="query", description="SPQL query string.", required=True),
    InputArgument(name="fields", description="Fields to return in the response."),
    InputArgument(name="sort", description="Sorting criteria for results."),
    InputArgument(name="skip", description="Number of records to skip in the response."),
    InputArgument(name="limit", description="Maximum number of results to return."),
    InputArgument(name="with_metadata", description="Whether to include metadata in the response."),
]
LIVE_SCAN_URL_INPUTS = [
    InputArgument(name="url", description="URL to scan.", required=True),
    InputArgument(name="platform", description="Platform to scan the URL on."),
    InputArgument(name="os", description="Operating system to scan the URL on."),
    InputArgument(name="browser", description="Browser to scan the URL on."),
    InputArgument(name="region", description="Region to scan the URL in."),
]
ADD_FEED_INPUTS = [
    InputArgument(name="name", description="Name of the feed.", required=True),
    InputArgument(name="type", description="Feed Type.", required=True),
    InputArgument(name="category", description="Feed Category.", required=False),
    InputArgument(name="vendor", description="Vendor.", required=False),
    InputArgument(name="feed_description", description="Detailed info about the feed.", required=False),
    InputArgument(name="tags", description="Tags that should be attached with the feed.", required=False),
]
ADD_FEED_TAGS_INPUTS = [
    InputArgument(
        name="feed_uuid",
        description="The feed uuid that is returned when creating it.",
    ),
    InputArgument(
        name="tags",
        description="Comma separated tags to be updated to the feed.",
    ),
]
ADD_INDICATORS_INPUTS = [
    InputArgument(name="feed_uuid", description="The feed uuid that is returned when creating it.", required=True),
    InputArgument(name="indicators", description="Indicators for the feed.", required=True),
]
ADD_INDICATOR_TAGS_INPUTS = [
    InputArgument(name="feed_uuid", description="The feed uuid that is returned when creating it.", required=True),
    InputArgument(name="indicator_name", description="The name of the indicator to tag.", required=True),
    InputArgument(name="tags", description="Tags to be added to the indicator.", required=True),
]
RUN_THREAT_CHECK_INPUTS = [
    InputArgument(name="data", description="The name of the data source to query.", required=True),
    InputArgument(name="query", description="The value to check for threats (e.g., IP or domain).", required=True),
    InputArgument(name="type", description="The type of the value being queried (e.g., ip, domain).", required=True),
    InputArgument(name="user_identifier", description="A unique identifier for the user making the request.", required=True),
]
GET_DATA_EXPORTS_INPUTS = [
    InputArgument(name="export_type", description="Which export type (iofa, organisation, etc)", required=True),
    InputArgument(name="file_name", description="The name of the file to be exported.", required=True),
    InputArgument(name="file_type", description="The file type (csv, json, txt, etc).", required=True),
]
JOB_STATUS_IMPUT = [
    InputArgument(name="job_id", description="The Job ID to retry", required=True)
]

""" COMMANDS OUTPUTS """
# 'des

NAMESERVER_REPUTATION_OUTPUTS = [
    OutputArgument(
        name="nameserver", output_type=int, description="The nameserver associated with the reputation history entry."
    ),
    OutputArgument(
        name="reputation_data.date",
        output_type=int,
        description="Date of the reputation history entry (in YYYYMMDD format).",
    ),
    OutputArgument(
        name="reputation_data.ns_server",
        output_type=str,
        description="Name of the nameserver associated with the reputation history entry.",
    ),
    OutputArgument(
        name="reputation_data.ns_server_reputation",
        output_type=int,
        description="Reputation score of the nameserver on the specified date.",
    ),
    OutputArgument(
        name="reputation_data.ns_server_reputation_explain.ns_server_domain_density",
        output_type=int,
        description="Number of domains associated with the nameserver.",
    ),
    OutputArgument(
        name="reputation_data.ns_server_reputation_explain.ns_server_domains_listed",
        output_type=int,
        description="Number of domains listed in reputation databases.",
    ),
]
SUBNET_REPUTATION_OUTPUTS = [
    OutputArgument(name="subnet", output_type=str, description="The subnet associated with the reputation history."),
    OutputArgument(name="reputation_history.date", output_type=int, description="The date of the subnet reputation record."),
    OutputArgument(
        name="reputation_history.subnet",
        output_type=str,
        description="The subnet associated with the reputation record.",
    ),
    OutputArgument(
        name="reputation_history.subnet_reputation", output_type=int, description="The reputation score of the subnet."
    ),
    OutputArgument(
        name="reputation_history.subnet_reputation_explain.ips_in_subnet",
        output_type=int,
        description="Total number of IPs in the subnet.",
    ),
    OutputArgument(
        name="reputation_history.subnet_reputation_explain.ips_num_active",
        output_type=int,
        description="Number of active IPs in the subnet.",
    ),
    OutputArgument(
        name="reputation_history.subnet_reputation_explain.ips_num_listed",
        output_type=int,
        description="Number of listed IPs in the subnet.",
    ),
]
ASNS_DOMAIN_OUTPUTS = [
    OutputArgument(name="domain", output_type=str, description="The domain name for which ASNs are retrieved."),
    OutputArgument(
        name="asns",
        output_type=dict,
        description="Dictionary of Autonomous System Numbers (ASNs) associated with the domain.",
    ),
]
DENSITY_LOOKUP_OUTPUTS = [
    OutputArgument(name="qtype", output_type=str, description="The following qtypes are supported: nssrv, mxsrv."),
    OutputArgument(
        name="query",
        output_type=str,
        description="The query value to lookup, which can be the name of an NS or MX server.",
    ),
    OutputArgument(name="records.density", output_type=int, description="The density value associated with the query result."),
    OutputArgument(name="records.nssrv", output_type=str, description="The name server (NS) for the query result."),
]
SEARCH_DOMAIN_OUTPUTS = IP_DIVERSITY_LOOKUP_OUTPUTS = IP_DIVERSITY_PATTERNS_OUTPUTS = [
    OutputArgument(
        name="asn_diversity",
        output_type=int,
        description="The diversity of Autonomous System Numbers (ASNs) associated with the domain.",
    ),
    OutputArgument(name="host", output_type=str, description="The domain name (host) associated with the record."),
    OutputArgument(
        name="ip_diversity_all",
        output_type=int,
        description="The total number of unique IPs associated with the domain.",
    ),
    OutputArgument(
        name="ip_diversity_groups",
        output_type=int,
        description="The number of unique IP groups associated with the domain.",
    ),
    OutputArgument(
        name="timeline",
        output_type=dict,
        description="timeline of {ip, first_seen, last_seen}.",
    ),
]
LIST_DOMAIN_OUTPUTS = [
    OutputArgument(name="host_flags", output_type=list, description="The domain name queried."),
    OutputArgument(name="domain_urls", output_type=dict, description="The last seen date of the domain in YYYYMMDD format."),
    OutputArgument(name="domaininfo", output_type=dict, description="The domain name used for the query."),
    OutputArgument(name="ns_reputation", output_type=dict,
                   description="The age of the domain in days based on WHOIS creation date."),
    OutputArgument(name="nschanges", output_type=dict, description="The first seen date of the domain in YYYYMMDD format."),
    OutputArgument(name="domain_string_frequency_probability", output_type=dict,
                   description="Indicates whether the domain is newly observed."),
    OutputArgument(name="is_private_suffix", output_type=bool,
                   description="The top-level domain (TLD) or zone of the queried domain."),
    OutputArgument(name="private_suffix_info", output_type=dict,
                   description="The registrar responsible for the domain registration."),
    OutputArgument(name="ip_diversity", output_type=dict, description="A risk score based on the domain's age."),
    OutputArgument(
        name="listing_score",
        output_type=int,
        description="The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format.",
    ),
    OutputArgument(name="listing_score_explain", output_type=dict, description="A risk score indicating how new the domain is."),
    OutputArgument(name="listing_score_feeds_explain", output_type=list, description="The age of the domain in days."),
    OutputArgument(name="sp_risk_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="sp_risk_score_explain", output_type=dict, description="The age of the domain in days."),
]
LIST_IP_OUTPUTS = [
    OutputArgument(name="ip", output_type=str, description="The domain name queried."),
    OutputArgument(name="asn", output_type=int, description="The last seen date of the domain in YYYYMMDD format."),
    OutputArgument(name="asname", output_type=str, description="The domain name used for the query."),
    OutputArgument(name="asn_allocation_date", output_type=int,
                   description="The age of the domain in days based on WHOIS creation date."),
    OutputArgument(name="asn_allocation_age", output_type=int,
                   description="The first seen date of the domain in YYYYMMDD format."),
    OutputArgument(name="asn_rank", output_type=int, description="Indicates whether the domain is newly observed."),
    OutputArgument(name="asn_rank_score", output_type=int,
                   description="The top-level domain (TLD) or zone of the queried domain."),
    OutputArgument(name="asn_reputation", output_type=int, description="The registrar responsible for the domain registration."),
    OutputArgument(name="asn_reputation_explain", output_type=dict, description="A risk score based on the domain's age."),
    OutputArgument(
        name="malscore",
        output_type=int,
        description="The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format.",
    ),
    OutputArgument(name="asn_takedown_reputation", output_type=int, description="A risk score indicating how new the domain is."),
    OutputArgument(name="asn_takedown_reputation_explain", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="asn_takedown_reputation_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="date", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="subnet", output_type=str, description="The age of the domain in days."),
    OutputArgument(name="subnet_allocation_date", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="subnet_allocation_age", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="subnet_reputation", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="subnet_reputation_explain", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="subnet_reputation_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="ip_reputation", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="ip_reputation_explain", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="ip_reputation_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="ip_location", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="ip_is_dsl_dynamic", output_type=bool, description="The age of the domain in days."),
    OutputArgument(name="ip_is_dsl_dynamic_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="ip_ptr", output_type=str, description="The age of the domain in days."),
    OutputArgument(name="benign_info", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="sinkhole_info", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="ip_is_tor_exit_node", output_type=bool, description="The age of the domain in days."),
    OutputArgument(name="ip_is_ipfs_node", output_type=bool, description="The age of the domain in days."),
    OutputArgument(name="ip_has_open_directory", output_type=bool, description="The age of the domain in days."),
    OutputArgument(name="ip_has_expired_certificate", output_type=bool, description="The age of the domain in days."),
    OutputArgument(name="ip_flags", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="density", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="listing_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="listing_score_explain", output_type=dict, description="The age of the domain in days."),
    OutputArgument(name="listing_score_feeds_explain", output_type=list, description="The age of the domain in days."),
    OutputArgument(name="sp_risk_score", output_type=int, description="The age of the domain in days."),
    OutputArgument(name="sp_risk_score_explain", output_type=dict, description="The age of the domain in days."),
]
DOMAIN_CERTIFICATE_OUTPUTS = [
    OutputArgument(name="domain", output_type=str, description="Queried domain."),
    OutputArgument(name="metadata", output_type=str, description="Metadata of the response."),
    OutputArgument(name="certificates.cert_index", output_type=int, description="Index of the certificate."),
    OutputArgument(name="certificates.chain", output_type=list, description="Certificate chain."),
    OutputArgument(name="certificates.date", output_type=int, description="Certificate issue date."),
    OutputArgument(name="certificates.domain", output_type=str, description="Primary domain of the certificate."),
    OutputArgument(name="certificates.domains", output_type=list, description="List of domains covered by the certificate."),
    OutputArgument(name="certificates.fingerprint", output_type=str, description="SHA-1 fingerprint of the certificate."),
    OutputArgument(name="certificates.fingerprint_md5", output_type=str, description="MD5 fingerprint of the certificate."),
    OutputArgument(name="certificates.fingerprint_sha1", output_type=str, description="SHA-1 fingerprint of the certificate."),
    OutputArgument(
        name="certificates.fingerprint_sha256", output_type=str, description="SHA-256 fingerprint of the certificate."
    ),
    OutputArgument(name="certificates.host", output_type=str, description="Host associated with the certificate."),
    OutputArgument(name="certificates.issuer", output_type=str, description="Issuer of the certificate."),
    OutputArgument(name="certificates.not_after", output_type=str, description="Expiration date of the certificate."),
    OutputArgument(name="certificates.not_before", output_type=str, description="Start date of the certificate validity."),
    OutputArgument(name="certificates.serial_dec", output_type=str, description="Decimal representation of the serial number."),
    OutputArgument(
        name="certificates.serial_hex", output_type=str, description="Hexadecimal representation of the serial number."
    ),
    OutputArgument(name="certificates.serial_number", output_type=str, description="Serial number of the certificate."),
    OutputArgument(name="certificates.source_name", output_type=str, description="Source log name of the certificate."),
    OutputArgument(name="certificates.source_url", output_type=str, description="URL of the certificate log source."),
    OutputArgument(name="certificates.subject", output_type=str, description="Subject details of the certificate."),
    OutputArgument(
        name="certificates.wildcard",
        output_type=int,
        description="Indicates if the certificate is a wildcard certificate.",
    ),
    OutputArgument(name="job_details.get", output_type=str, description="URL to get the data of the job or its status."),
    OutputArgument(name="job_details.job_id", output_type=str, description="ID of the job."),
    OutputArgument(name="job_details.status", output_type=str, description="Status of the job."),
]
ENRICHMENT_OUTPUTS = [
    OutputArgument(name="value", output_type=str, description="Queried value."),
    OutputArgument(
        name="domain_string_frequency_probability.avg_probability",
        output_type=float,
        description="Average probability score of the domain string.",
    ),
    OutputArgument(
        name="domain_string_frequency_probability.dga_probability_score",
        output_type=int,
        description="Probability score indicating likelihood of being a DGA domain.",
    ),
    OutputArgument(name="domain_string_frequency_probability.domain", output_type=str, description="Domain name analyzed."),
    OutputArgument(
        name="domain_string_frequency_probability.domain_string_freq_probabilities",
        output_type=list,
        description="List of frequency probabilities for different domain string components.",
    ),
    OutputArgument(name="domain_string_frequency_probability.query", output_type=str, description="Domain name queried."),
    OutputArgument(name="domain_urls.results_summary.alexa_rank", output_type=int, description="Alexa rank of the domain."),
    OutputArgument(
        name="domain_urls.results_summary.alexa_top10k",
        output_type=bool,
        description="Indicates if the domain is in the Alexa top 10k.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.alexa_top10k_score",
        output_type=int,
        description="Score indicating domain's Alexa top 10k ranking.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.dynamic_domain_score",
        output_type=int,
        description="Score indicating likelihood of domain being dynamically generated.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.is_dynamic_domain",
        output_type=bool,
        description="Indicates if the domain is dynamic.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.is_url_shortener",
        output_type=bool,
        description="Indicates if the domain is a known URL shortener.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.results",
        output_type=int,
        description="Number of results found for the domain.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.url_shortner_score", output_type=int, description="Score of the shortned URL."
    ),
    OutputArgument(name="domaininfo.domain", output_type=str, description="Domain name analyzed."),
    OutputArgument(name="domaininfo.error", output_type=str, description="Error message if no data is available for the domain."),
    OutputArgument(name="domaininfo.zone", output_type=str, description="TLD zone of the domain."),
    OutputArgument(name="domaininfo.registrar", output_type=str, description="registrar of the domain."),
    OutputArgument(name="domaininfo.whois_age", output_type=str, description="The age of the domain based on WHOIS records."),
    OutputArgument(name="domaininfo.whois_created_date", output_type=str, description="The created date on WHOIS records."),
    OutputArgument(name="domaininfo.query", output_type=str, description="The domain name that was queried in the system."),
    OutputArgument(
        name="domaininfo.last_seen",
        output_type=int,
        description="The first recorded observation of the domain in the database.",
    ),
    OutputArgument(
        name="domaininfo.first_seen",
        output_type=int,
        description="The last recorded observation of the domain in the database.",
    ),
    OutputArgument(name="domaininfo.is_new", output_type=bool, description='Indicates whether the domain is considered "new.".'),
    OutputArgument(
        name="domaininfo.is_new_score",
        output_type=int,
        description='A scoring metric indicating how "new" the domain is.',
    ),
    OutputArgument(name="domaininfo.age", output_type=int, description="Represents the age of the domain in days."),
    OutputArgument(
        name="domaininfo.age_score",
        output_type=int,
        description="A scoring metric indicating the trustworthiness of the domain based on its age.",
    ),
    OutputArgument(
        name="ip_diversity.asn_diversity",
        output_type=str,
        description="Number of different ASNs associated with the domain.",
    ),
    OutputArgument(
        name="ip_diversity.ip_diversity_all",
        output_type=str,
        description="Total number of unique IPs observed for the domain.",
    ),
    OutputArgument(name="ip_diversity.host", output_type=str, description="The hostname being analyzed."),
    OutputArgument(
        name="ip_diversity.ip_diversity_groups",
        output_type=str,
        description="The number of distinct IP groups (e.g., IPs belonging to different ranges or providers).",
    ),
    OutputArgument(
        name="ns_reputation.is_expired",
        output_type=bool,
        description="Indicates if the domain`s nameserver is expired.",
    ),
    OutputArgument(
        name="ns_reputation.is_parked",
        output_type=bool,
        description=" The domain is not parked (a parked domain is one without active content).",
    ),
    OutputArgument(
        name="ns_reputation.is_sinkholed",
        output_type=bool,
        description="The domain is not sinkholed (not forcibly redirected to a security researcher`s trap).",
    ),
    OutputArgument(
        name="ns_reputation.ns_reputation_max", output_type=int, description="Maximum reputation score for nameservers."
    ),
    OutputArgument(
        name="ns_reputation.ns_reputation_score",
        output_type=int,
        description="Reputation score of the domain`s nameservers.",
    ),
    OutputArgument(name="ns_reputation.ns_srv_reputation.domain", output_type=str, description="The nameservers of domain."),
    OutputArgument(name="ns_reputation.ns_srv_reputation.ns_server", output_type=str, description="Provided nameserver."),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_domain_density",
        output_type=int,
        description="Number of domains sharing this NS.",
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_domains_listed",
        output_type=int,
        description="Number of listed domains using this NS.",
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_reputation",
        output_type=int,
        description="Reputation score for this NS.",
    ),
    OutputArgument(
        name="scan_data.certificates.domain",
        output_type=str,
        description="Domain for which the SSL certificate was issued.",
    ),
    OutputArgument(
        name="scan_data.certificates.domains",
        output_type=list,
        description="Other Domains for which the SSL certificate was issued.",
    ),
    OutputArgument(
        name="scan_data.certificates.issuer_organization",
        output_type=str,
        description="Issuer organization of the SSL certificate.",
    ),
    OutputArgument(
        name="scan_data.certificates.fingerprint_sha1",
        output_type=str,
        description="A unique identifier for the certificate.",
    ),
    OutputArgument(
        name="scan_data.certificates.hostname",
        output_type=str,
        description="The hostname associated with the certificate.",
    ),
    OutputArgument(
        name="scan_data.certificates.ip",
        output_type=str,
        description="The IP address of the server using this certificate.",
    ),
    OutputArgument(
        name="scan_data.certificates.is_expired",
        output_type=str,
        description="Indicates whether the certificate has expired.",
    ),
    OutputArgument(
        name="scan_data.certificates.issuer_common_name",
        output_type=str,
        description="he Common Name (CN) of the Certificate Authority (CA) that issued this certificate.",
    ),
    OutputArgument(name="scan_data.certificates.not_after", output_type=str, description="Expiry date of the certificate."),
    OutputArgument(
        name="scan_data.certificates.not_before", output_type=str, description="Start date of the certificate validity."
    ),
    OutputArgument(
        name="scan_data.certificates.scan_date",
        output_type=str,
        description="The date when this certificate data was last scanned.",
    ),
    OutputArgument(name="scan_data.headers.response", output_type=str, description="HTTP response code for the domain scan."),
    OutputArgument(name="scan_data.headers.hostname", output_type=str, description="The hostname that sent this response."),
    OutputArgument(name="scan_data.headers.ip", output_type=str, description="The IP address responding to the request."),
    OutputArgument(name="scan_data.headers.scan_date", output_type=str, description="The date when the headers were scanned."),
    OutputArgument(name="scan_data.headers.headers.cache-control", output_type=str, description="HTTP cache-control."),
    OutputArgument(
        name='scan_data.headers.headers.content-length"',
        output_type=str,
        description="Content length of the HTTP response.",
    ),
    OutputArgument(name="scan_data.headers.headers.date", output_type=str, description="The date/time of the response."),
    OutputArgument(
        name="scan_data.headers.headers.expires", output_type=str, description="Indicates an already expired response."
    ),
    OutputArgument(
        name="scan_data.headers.headers.server",
        output_type=str,
        description="The web server handling the request (Cloudflare proxy).",
    ),
    OutputArgument(name="scan_data.html.hostname", output_type=str, description="HTTP response code for the domain scan."),
    OutputArgument(name="scan_data.html.html_body_murmur3", output_type=str, description="hash of the page content."),
    OutputArgument(
        name="scan_data.html.html_body_ssdeep",
        output_type=str,
        description="SSDEEP hash (used for fuzzy matching similar HTML content).",
    ),
    OutputArgument(
        name="scan_data.html.html_title",
        output_type=str,
        description="The page title (suggests a Cloudflare challenge page, likely due to bot protection).",
    ),
    OutputArgument(name="scan_data.html.ip", output_type=str, description="The IP address responding to the request."),
    OutputArgument(name="scan_data.html.scan_date", output_type=str, description="The date when the headers were scanned."),
    OutputArgument(name="scan_data.favicon.favicon2_md5", output_type=str, description="MD5 hash of a secondary favicon."),
    OutputArgument(name="scan_data.favicon.favicon2_mmh3", output_type=str, description="Murmur3 hash of a secondary favicon."),
    OutputArgument(
        name="scan_data.favicon.favicon2_path", output_type=str, description="The file path of the secondary favicon."
    ),
    OutputArgument(name="scan_data.favicon.favicon_md5", output_type=str, description="MD5 hash of the primary favicon."),
    OutputArgument(name="scan_data.favicon.favicon_mmh3", output_type=str, description="Murmur3 hash of the primary favicon."),
    OutputArgument(name="scan_data.favicon.hostname", output_type=str, description="The hostname where this favicon was found."),
    OutputArgument(name="scan_data.favicon.ip", output_type=str, description="The IP address associated with the favicon."),
    OutputArgument(name="scan_data.favicon.scan_date", output_type=str, description="Date when this favicon was last scanned."),
    OutputArgument(name="scan_data.jarm.hostname", output_type=str, description="The hostname where this jarm was found."),
    OutputArgument(name="scan_data.jarm.ip", output_type=str, description="The IP address responding to the request."),
    OutputArgument(
        name="scan_data.jarm.jarm_hash",
        output_type=str,
        description="Unique identifier for the TLS configuration of the server.",
    ),
    OutputArgument(name="scan_data.jarm.scan_date", output_type=str, description="Date when this jarm was last scanned."),
    OutputArgument(name="sp_risk_score", output_type=int, description="Overall risk score for the domain."),
    OutputArgument(
        name="sp_risk_score_explain.sp_risk_score_decider",
        output_type=str,
        description="Factor that determined the final risk score.",
    ),
    OutputArgument(name="ip2asn.asn", output_type=int, description="Autonomous System Number (ASN) associated with the IP."),
    OutputArgument(name="ip2asn.asn_allocation_age", output_type=int, description="Age of ASN allocation in days."),
    OutputArgument(name="ip2asn.asn_allocation_date", output_type=int, description="Date of ASN allocation."),
    OutputArgument(name="ip2asn.asn_rank", output_type=int, description="Rank of the ASN."),
    OutputArgument(name="ip2asn.asn_rank_score", output_type=int, description="Rank score of the ASN."),
    OutputArgument(name="ip2asn.asn_reputation", output_type=int, description="Reputation score of the ASN."),
    OutputArgument(
        name="ip2asn.asn_reputation_explain.ips_in_asn", output_type=int, description="Total number of IPs in the ASN."
    ),
    OutputArgument(
        name="ip2asn.asn_reputation_explain.ips_num_active",
        output_type=int,
        description="Number of active IPs in the ASN.",
    ),
    OutputArgument(
        name="ip2asn.asn_reputation_explain.ips_num_listed",
        output_type=int,
        description="Number of listed IPs in the ASN.",
    ),
    OutputArgument(name="ip2asn.asn_reputation_score", output_type=int, description="Reputation score of the ASN."),
    OutputArgument(name="ip2asn.asn_takedown_reputation", output_type=int, description="Takedown reputation score of the ASN."),
    OutputArgument(
        name="ip2asn.asn_takedown_reputation_explain.ips_in_asn",
        output_type=int,
        description="Total number of IPs in the ASN with takedown reputation.",
    ),
    OutputArgument(
        name="ip2asn.asn_takedown_reputation_explain.ips_num_listed",
        output_type=int,
        description="Number of listed IPs in the ASN with takedown reputation.",
    ),
    OutputArgument(
        name="ip2asn.asn_takedown_reputation_explain.items_num_listed",
        output_type=int,
        description="Number of flagged items in the ASN with takedown reputation.",
    ),
    OutputArgument(
        name="ip2asn.asn_takedown_reputation_explain.listings_max_age",
        output_type=int,
        description="Maximum age of listings for the ASN with takedown reputation.",
    ),
    OutputArgument(
        name="ip2asn.asn_takedown_reputation_score",
        output_type=int,
        description="Takedown reputation score of the ASN.",
    ),
    OutputArgument(name="ip2asn.asname", output_type=str, description="Name of the Autonomous System (AS)."),
    OutputArgument(
        name="ip2asn.benign_info.actor",
        output_type=str,
        description="This field is usually used to indicate a known organization or individual associated with the IP.",
    ),
    OutputArgument(
        name="ip2asn.benign_info.known_benign",
        output_type=bool,
        description="Indicates whether this IP/ASN is explicitly known to be safe "
                    "(e.g., a reputable cloud provider or public service).",
    ),
    OutputArgument(
        name="ip2asn.benign_info.tags",
        output_type=list,
        description='Contains descriptive tags if the IP/ASN has a known role (e.g., "Google Bot", "Cloudflare Proxy").',
    ),
    OutputArgument(name="ip2asn.date", output_type=int, description="Date of the scan data (YYYYMMDD format)."),
    OutputArgument(name="ip2asn.density", output_type=int, description="The density value associated with the IP."),
    OutputArgument(name="ip2asn.ip", output_type=str, description="IP address associated with the ASN."),
    OutputArgument(
        name="ip2asn.ip_has_expired_certificate",
        output_type=bool,
        description="Indicates whether the IP has an expired SSL/TLS certificate.",
    ),
    OutputArgument(
        name="ip2asn.ip_has_open_directory",
        output_type=bool,
        description="Indicates whether the IP hosts an open directory listing.",
    ),
    OutputArgument(name="ip2asn.ip_is_dsl_dynamic", output_type=bool, description="the IP is from a dynamic DSL pool."),
    OutputArgument(
        name="ip2asn.ip_is_dsl_dynamic_score",
        output_type=int,
        description="A score indicating how likely this IP is dynamic.",
    ),
    OutputArgument(
        name="ip2asn.ip_is_ipfs_node",
        output_type=bool,
        description="the InterPlanetary File System (IPFS), a decentralized file storage system.",
    ),
    OutputArgument(
        name="ip2asn.ip_is_tor_exit_node",
        output_type=bool,
        description="Tor exit node (used for anonymous internet browsing).",
    ),
    OutputArgument(
        name="ip2asn.ip_location.continent_code",
        output_type=str,
        description="abbreviation for the continent where the IP is located.",
    ),
    OutputArgument(name="ip2asn.ip_location.continent_name", output_type=str, description="The full name of the continent."),
    OutputArgument(
        name="ip2asn.ip_location.country_code",
        output_type=str,
        description="The ISO 3166-1 alpha-2 country code representing the country.",
    ),
    OutputArgument(
        name="ip2asn.ip_location.country_is_in_european_union",
        output_type=bool,
        description="A Boolean value (true/false) indicating if the country is part of the European Union (EU).",
    ),
    OutputArgument(
        name="ip2asn.ip_location.country_name",
        output_type=str,
        description="The full name of the country where the IP is registered.",
    ),
    OutputArgument(name="ip2asn.ip_ptr", output_type=str, description="The reverse DNS (PTR) record for the IP."),
    OutputArgument(
        name="ip2asn.listing_score",
        output_type=int,
        description="Measures how frequently the IP appears in threat intelligence or blacklist databases.",
    ),
    OutputArgument(
        name="ip2asn.listing_score_explain",
        output_type=dict,
        description="A breakdown of why the listing score is assigned.",
    ),
    OutputArgument(name="ip2asn.malscore", output_type=int, description="Malicious activity score for the IP."),
    OutputArgument(
        name="ip2asn.scan_data.certificates.hostname",
        output_type=str,
        description="Hostname associated with the SSL certificate.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.domain",
        output_type=str,
        description="Domain for which the SSL certificate was issued.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.fingerprint_sha1",
        output_type=str,
        description="SHA-1 fingerprint of the SSL certificate.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.issuer_common_name",
        output_type=str,
        description="Common name of the certificate issuer.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.issuer_organization",
        output_type=str,
        description="Organization that issued the SSL certificate.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.not_before",
        output_type=str,
        description="Start date of SSL certificate validity.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.not_after",
        output_type=str,
        description="Expiration date of SSL certificate validity.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.domains",
        output_type=list,
        description="Other domains for which the SSL certificate was issued.",
    ),
    OutputArgument(name="ip2asn.scan_data.certificates.is_expired", output_type=bool, description="Is certificate expired."),
    OutputArgument(name="ip2asn.scan_data.certificates.scan_date", output_type=str, description="Scan date of the certificate."),
    OutputArgument(name="ip2asn.scan_data.favicon.favicon2_md5", output_type=str, description="MD5 hash of the second favicon."),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon2_mmh3",
        output_type=int,
        description="MurmurHash3 value of the second favicon.",
    ),
    OutputArgument(name="ip2asn.scan_data.favicon.favicon_md5", output_type=str, description="MD5 hash of the favicon."),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon_mmh3", output_type=int, description="MurmurHash3 value of the favicon."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon2_path", output_type=str, description="Path to the second favicon file."
    ),
    OutputArgument(name="ip2asn.scan_data.favicon.scan_date", output_type=str, description="Scan date of favicon file."),
    OutputArgument(name="ip2asn.scan_data.headers.response", output_type=str, description="HTTP response code from the scan."),
    OutputArgument(
        name="ip2asn.scan_data.headers.scan_date",
        output_type=str,
        description="The date and time when the scan was performed.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.headers.server",
        output_type=str,
        description="Server header from the HTTP response.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.headers.content-type",
        output_type=str,
        description="Content-Type header from the HTTP response.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.headers.content-length",
        output_type=str,
        description="Content-Length header from the HTTP response.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.headers.cache-control",
        output_type=str,
        description="Cache-control header from the HTTP response.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.headers.date", output_type=str, description="Date header from the HTTP response."
    ),
    OutputArgument(name="ip2asn.scan_data.html.html_title", output_type=str, description="Title of the scanned HTML page."),
    OutputArgument(
        name="ip2asn.scan_data.html.html_body_murmur3",
        output_type=str,
        description="MurmurHash3 of the HTML body content.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.html.html_body_ssdeep",
        output_type=str,
        description="SSDEEP fuzzy hash of the HTML body content.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.html.scan_date",
        output_type=str,
        description="The date and time when the scan was performed.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.jarm.scan_date",
        output_type=str,
        description="The date and time when the scan was performed.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.jarm.jarm_hash", output_type=str, description="JARM fingerprint hash for TLS analysis."
    ),
    OutputArgument(name="ip2asn.sp_risk_score", output_type=int, description="Security risk score for the IP."),
    OutputArgument(
        name="ip2asn.sp_risk_score_explain.sp_risk_score_decider",
        output_type=str,
        description="Factor that determined the final risk score.",
    ),
    OutputArgument(name="ip2asn.subnet", output_type=str, description="Subnet associated with the IP."),
    OutputArgument(
        name="ip2asn.sinkhole_info.known_sinkhole_ip",
        output_type=bool,
        description="Indicates whether the IP is part of a sinkhole (a controlled system that captures malicious traffic).",
    ),
    OutputArgument(
        name="ip2asn.sinkhole_info.tags",
        output_type=list,
        description="If the IP were a known sinkhole, this field would contain tags describing its purpose.",
    ),
    OutputArgument(
        name="ip2asn.subnet_allocation_age",
        output_type=int,
        description="Represents the age (in days) since the subnet was allocated.",
    ),
    OutputArgument(
        name="ip2asn.subnet_allocation_date",
        output_type=int,
        description="The date when the subnet was assigned to an organization or ISP.",
    ),
    OutputArgument(
        name="ip2asn.subnet_reputation",
        output_type=int,
        description="A measure of how frequently IPs from this subnet appear in threat intelligence databases.",
    ),
    OutputArgument(
        name="ip2asn.subnet_reputation_explain",
        output_type=dict,
        description="A breakdown of why the subnet received its reputation score.",
    ),
    OutputArgument(
        name="ip2asn.subnet_reputation_score",
        output_type=int,
        description="A numerical risk score (typically 0-100, with higher values indicating higher risk).",
    ),
]
IPV4_REPUTATION_OUTPUTS = [
    OutputArgument(name="date", output_type=int, description="Date when the reputation information was retrieved."),
    OutputArgument(name="ip", output_type=str, description="IPv4 address for which the reputation is calculated."),
    OutputArgument(name="reputation_score", output_type=int, description="Reputation score for the given IP address."),
    OutputArgument(
        name="ip_reputation_explain.ip_density",
        output_type=int,
        description="The number of domain names or services associated with this IP. "
                    "A higher value may indicate shared hosting or potential abuse.",
    ),
    OutputArgument(
        name="ip_reputation_explain.names_num_listed",
        output_type=int,
        description="The number of domain names linked to this IP that are flagged or listed in security threat databases.",
    ),
]
PADNS_OUTPUTS = [
    OutputArgument(name="qname", output_type=str, description="The DNS record name that was looked up."),
    OutputArgument(name="qtype", output_type=str, description="The DNS record type queried (e.g., NS)."),
    OutputArgument(name="records.answer", output_type=str, description="The answer (e.g., name server) for the DNS record."),
    OutputArgument(name="records.count", output_type=int, description="The number of occurrences for this DNS record."),
    OutputArgument(name="records.first_seen", output_type=str, description="The timestamp when this DNS record was first seen."),
    OutputArgument(name="records.last_seen", output_type=str, description="The timestamp when this DNS record was last seen."),
    OutputArgument(name="records.nshash", output_type=str, description="Unique hash for the DNS record."),
    OutputArgument(name="records.query", output_type=str, description="The DNS record query name (e.g., silentpush.com)."),
    OutputArgument(name="records.ttl", output_type=int, description="Time to live (TTL) value for the DNS record."),
    OutputArgument(name="records.type", output_type=str, description="The type of the DNS record (e.g., NS)."),
]
WHOIS_OUTPUTS = [
    OutputArgument(name="whois.registrar", output_type=str,
                   description="Name or partial name of the registrar used to register domains."),
    OutputArgument(name="whois.name", output_type=str, description="The registrant name"),
    OutputArgument(name="whois.whois_server", output_type=str, description="The server queried"),
    OutputArgument(name="whois.org", output_type=str, description="Organization"),
    OutputArgument(name="whois.address", output_type=str, description="Address"),
    OutputArgument(name="whois.city", output_type=int, description="City"),
    OutputArgument(name="whois.country", output_type=str, description="Country"),
    OutputArgument(name="whois.created", output_type=str, description="Date created"),
    OutputArgument(name="whois.date", output_type=str, description="Date"),
    OutputArgument(name="whois.domain", output_type=str, description="Domain"),
    OutputArgument(name="whois.emails", output_type=int, description="Emails"),
    OutputArgument(name="whois.expires", output_type=str, description="Expires"),
    OutputArgument(name="whois.nameservers", output_type=str, description="Nameservers"),
    OutputArgument(name="whois.state", output_type=str, description="State"),
    OutputArgument(name="whois.updated", output_type=str, description="Date updated"),
    OutputArgument(name="whois.zipcode", output_type=str, description="Zip code"),
]
FORWARD_PADNS_OUTPUTS = PADNS_OUTPUTS
REVERSE_PADNS_OUTPUTS = PADNS_OUTPUTS
SEARCH_SCAN_OUTPUTS = [
    OutputArgument(name="HHV", output_type=str, description="Unique identifier for the scan data entry."),
    OutputArgument(name="adtech", output_type=dict, description="Adtech information for the scan data entry."),
    OutputArgument(name="adtech.ads_txt", output_type=bool, description="Indicates if ads.txt is used."),
    OutputArgument(name="adtech.app_ads_txt", output_type=bool, description="Indicates if app_ads.txt is used."),
    OutputArgument(name="adtech.sellers_json", output_type=bool, description="Indicates if sellers.json is used."),
    OutputArgument(name="body_analysis", output_type=dict, description="Body analysis for the scan data entry."),
    OutputArgument(name="body_analysis.body_sha256", output_type=str, description="SHA256 hash of the body."),
    OutputArgument(name="body_analysis.language", output_type=list, description="Languages detected in the body."),
    OutputArgument(name="body_analysis.ICP_license", output_type=str, description="ICP License information."),
    OutputArgument(name="body_analysis.SHV", output_type=str, description="Server Hash Verification value."),
    OutputArgument(name="body_analysis.adsense", output_type=list, description="List of AdSense data."),
    OutputArgument(name="body_analysis.footer_sha256", output_type=str, description="SHA-256 hash of the footer content."),
    OutputArgument(name="body_analysis.google-GA4", output_type=list, description="List of Google GA4 identifiers."),
    OutputArgument(
        name="body_analysis.google-UA", output_type=list, description="List of Google Universal Analytics identifiers."
    ),
    OutputArgument(name="body_analysis.google-adstag", output_type=list, description="List of Google adstag identifiers."),
    OutputArgument(name="body_analysis.header_sha256", output_type=list, description="SHA-256 hash of the header content."),
    OutputArgument(
        name="body_analysis.js_sha256",
        output_type=list,
        description="List of JavaScript files with SHA-256 hash values.",
    ),
    OutputArgument(
        name="body_analysis.js_ssdeep",
        output_type=list,
        description="List of JavaScript files with SSDEEP hash values.",
    ),
    OutputArgument(name="body_analysis.onion", output_type=list, description="List of Onion URLs detected."),
    OutputArgument(name="body_analysis.telegram", output_type=list, description="List of Telegram-related information."),
    OutputArgument(name="datahash", output_type=str, description="Hash of the data."),
    OutputArgument(name="datasource", output_type=str, description="Source of the scan data."),
    OutputArgument(name="domain", output_type=str, description="Domain associated with the scan data."),
    OutputArgument(name="geoip", output_type=dict, description="GeoIP information related to the scan."),
    OutputArgument(name="geoip.city_name", output_type=str, description="City where the scan data was retrieved."),
    OutputArgument(name="geoip.country_name", output_type=str, description="Country name from GeoIP information."),
    OutputArgument(name="geoip.location", output_type=dict, description="Geo-location coordinates."),
    OutputArgument(name="geoip.location.lat", output_type=float, description="Latitude from GeoIP location."),
    OutputArgument(name="geoip.location.lon", output_type=float, description="Longitude from GeoIP location."),
    OutputArgument(name="header", output_type=dict, description="HTTP header information for the scan."),
    OutputArgument(name="header.content-length", output_type=str, description="Content length from HTTP response header."),
    OutputArgument(name="header.location", output_type=str, description="Location from HTTP response header."),
    OutputArgument(name="header.connection", output_type=str, description="Connection type used, e.g., keep-alive."),
    OutputArgument(
        name="header.server", output_type=str, description="Server software used to serve the content, e.g., openresty."
    ),
    OutputArgument(name="hostname", output_type=str, description="Hostname associated with the scan data."),
    OutputArgument(name="html_body_sha256", output_type=str, description="SHA256 hash of the HTML body."),
    OutputArgument(name="htmltitle", output_type=str, description="Title of the HTML page scanned."),
    OutputArgument(name="ip", output_type=str, description="IP address associated with the scan."),
    OutputArgument(name="jarm", output_type=str, description="JARM hash value."),
    OutputArgument(name="mobile_enabled", output_type=bool, description="Indicates if the page is mobile-enabled."),
    OutputArgument(name="origin_domain", output_type=str, description="Origin domain associated with the scan."),
    OutputArgument(name="origin_geoip", output_type=dict, description="GeoIP information of the origin domain."),
    OutputArgument(
        name="origin_geoip.city_name", output_type=str, description="City of the origin domain from GeoIP information."
    ),
    OutputArgument(name="origin_hostname", output_type=str, description="Origin hostname associated with the scan data."),
    OutputArgument(name="origin_ip", output_type=str, description="Origin IP address of the scan."),
    OutputArgument(name="origin_jarm", output_type=str, description="JARM hash value of the origin domain."),
    OutputArgument(name="origin_ssl", output_type=dict, description="SSL certificate information for the origin domain."),
    OutputArgument(name="origin_ssl.SHA256", output_type=str, description="SHA256 of the SSL certificate."),
    OutputArgument(name="origin_ssl.subject", output_type=dict, description="Subject of the SSL certificate."),
    OutputArgument(name="origin_ssl.subject.common_name", output_type=str, description="Common name in the SSL certificate."),
    OutputArgument(name="port", output_type=int, description="Port used during the scan."),
    OutputArgument(name="redirect", output_type=bool, description="Indicates if a redirect occurred during the scan."),
    OutputArgument(name="redirect_count", output_type=int, description="Count of redirects encountered."),
    OutputArgument(name="redirect_list", output_type=list, description="List of redirect URLs encountered during the scan."),
    OutputArgument(name="response", output_type=int, description="HTTP response code received during the scan."),
    OutputArgument(name="scan_date", output_type=str, description="Timestamp of the scan date."),
    OutputArgument(name="scheme", output_type=str, description="URL scheme used in the scan."),
    OutputArgument(name="ssl", output_type=dict, description="SSL certificate details for the scan."),
    OutputArgument(name="ssl.SHA256", output_type=str, description="SHA256 of the SSL certificate."),
    OutputArgument(name="ssl.subject", output_type=dict, description="Subject of the SSL certificate."),
    OutputArgument(name="ssl.subject.common_name", output_type=str, description="Common name in the SSL certificate."),
    OutputArgument(name="subdomain", output_type=str, description="Subdomain associated with the scan data."),
    OutputArgument(name="tld", output_type=str, description="Top-level domain (TLD) of the scanned URL."),
    OutputArgument(name="url", output_type=str, description="The URL scanned."),
]
LIVE_SCAN_URL_OUTPUTS = [
    OutputArgument(name="HHV", output_type=str, description="Unique identifier for HHV."),
    OutputArgument(name="adtech.ads_txt", output_type=bool, description="Indicates if ads_txt is present."),
    OutputArgument(name="adtech.app_ads_txt", output_type=bool, description="Indicates if app_ads_txt is present."),
    OutputArgument(name="adtech.sellers_json", output_type=bool, description="Indicates if sellers_json is present."),
    OutputArgument(name="datahash", output_type=str, description="Hash value of the data."),
    OutputArgument(name="domain", output_type=str, description="The domain name."),
    OutputArgument(name="favicon2_avg", output_type=str, description="Hash value for favicon2 average."),
    OutputArgument(name="favicon2_md5", output_type=str, description="MD5 hash for favicon2."),
    OutputArgument(name="favicon2_murmur3", output_type=int, description="Murmur3 hash for favicon2."),
    OutputArgument(name="favicon2_path", output_type=str, description="Path to favicon2 image."),
    OutputArgument(name="favicon_avg", output_type=str, description="Hash value for favicon average."),
    OutputArgument(name="favicon_md5", output_type=str, description="MD5 hash for favicon."),
    OutputArgument(name="favicon_murmur3", output_type=str, description="Murmur3 hash for favicon."),
    OutputArgument(name="favicon_path", output_type=str, description="Path to favicon image."),
    OutputArgument(name="favicon_urls", output_type=list, description="List of favicon URLs."),
    OutputArgument(name="header.cache-control", output_type=str, description="Cache control header value."),
    OutputArgument(name="header.content-encoding", output_type=str, description="Content encoding header value."),
    OutputArgument(name="header.content-type", output_type=str, description="Content type header value."),
    OutputArgument(name="header.server", output_type=str, description="Server header value."),
    OutputArgument(name="header.x-powered-by", output_type=str, description="X-Powered-By header value."),
    OutputArgument(name="hostname", output_type=str, description="The hostname of the server."),
    OutputArgument(name="html_body_length", output_type=int, description="Length of the HTML body."),
    OutputArgument(name="html_body_murmur3", output_type=int, description="Murmur3 hash for the HTML body."),
    OutputArgument(name="html_body_sha256", output_type=str, description="SHA256 hash for the HTML body."),
    OutputArgument(name="html_body_similarity", output_type=int, description="Similarity score of the HTML body."),
    OutputArgument(name="html_body_ssdeep", output_type=str, description="ssdeep hash for the HTML body."),
    OutputArgument(name="htmltitle", output_type=str, description="The HTML title of the page."),
    OutputArgument(name="ip", output_type=str, description="IP address associated with the domain."),
    OutputArgument(name="jarm", output_type=str, description="JARM (TLS fingerprint) value."),
    OutputArgument(name="mobile_enabled", output_type=bool, description="Indicates if the mobile version is enabled."),
    OutputArgument(name="opendirectory", output_type=bool, description="Indicates if open directory is enabled."),
    OutputArgument(name="origin_domain", output_type=str, description="Origin domain of the server."),
    OutputArgument(name="origin_hostname", output_type=str, description="Origin hostname of the server."),
    OutputArgument(name="origin_ip", output_type=str, description="Origin IP address of the server."),
    OutputArgument(name="origin_jarm", output_type=str, description="JARM (TLS fingerprint) value for the origin."),
    OutputArgument(name="origin_path", output_type=str, description="Origin path for the URL."),
    OutputArgument(name="origin_port", output_type=int, description="Port used for the origin server."),
    OutputArgument(name="origin_ssl.CHV", output_type=str, description="SSL Certificate Chain Value (CHV)."),
    OutputArgument(name="origin_ssl.SHA1", output_type=str, description="SHA1 hash of the SSL certificate."),
    OutputArgument(name="origin_ssl.SHA256", output_type=str, description="SHA256 hash of the SSL certificate."),
    OutputArgument(
        name="origin_ssl.authority_key_id", output_type=str, description="Authority Key Identifier for SSL certificate."
    ),
    OutputArgument(name="origin_ssl.expired", output_type=bool, description="Indicates if the SSL certificate is expired."),
    OutputArgument(name="origin_ssl.issuer.common_name", output_type=str, description="Issuer common name for SSL certificate."),
    OutputArgument(name="origin_ssl.issuer.country", output_type=str, description="Issuer country for SSL certificate."),
    OutputArgument(
        name="origin_ssl.issuer.organization", output_type=str, description="Issuer organization for SSL certificate."
    ),
    OutputArgument(name="origin_ssl.not_after", output_type=str, description="Expiration date of the SSL certificate."),
    OutputArgument(name="origin_ssl.not_before", output_type=str, description="Start date of the SSL certificate validity."),
    OutputArgument(
        name="origin_ssl.sans",
        output_type=list,
        description="List of Subject Alternative Names (SANs) for the SSL certificate.",
    ),
    OutputArgument(name="origin_ssl.sans_count", output_type=int, description="Count of SANs for the SSL certificate."),
    OutputArgument(name="origin_ssl.serial_number", output_type=str, description="Serial number of the SSL certificate."),
    OutputArgument(name="origin_ssl.sigalg", output_type=str, description="Signature algorithm used for the SSL certificate."),
    OutputArgument(
        name="origin_ssl.subject.common_name",
        output_type=str,
        description="Subject common name for the SSL certificate.",
    ),
    OutputArgument(name="origin_ssl.subject_key_id", output_type=str, description="Subject Key Identifier for SSL certificate."),
    OutputArgument(name="origin_ssl.valid", output_type=bool, description="Indicates if the SSL certificate is valid."),
    OutputArgument(name="origin_ssl.wildcard", output_type=bool, description="Indicates if the SSL certificate is a wildcard."),
    OutputArgument(name="origin_subdomain", output_type=str, description="Subdomain of the origin."),
    OutputArgument(name="origin_tld", output_type=str, description="Top-level domain of the origin."),
    OutputArgument(name="origin_url", output_type=str, description="Complete URL of the origin."),
    OutputArgument(name="path", output_type=str, description="Path for the URL."),
    OutputArgument(name="port", output_type=int, description="Port for the URL."),
    OutputArgument(name="proxy_enabled", output_type=bool, description="Indicates if the proxy is enabled."),
    OutputArgument(name="redirect", output_type=bool, description="Indicates if a redirect occurs."),
    OutputArgument(name="redirect_count", output_type=int, description="Count of redirects."),
    OutputArgument(name="redirect_list", output_type=list, description="List of redirect URLs."),
    OutputArgument(name="resolves_to", output_type=list, description="List of IPs the domain resolves to."),
    OutputArgument(name="response", output_type=int, description="HTTP response code."),
    OutputArgument(name="scheme", output_type=str, description="URL scheme (e.g., https)."),
    OutputArgument(name="screenshot", output_type=str, description="URL for the domain screenshot."),
    OutputArgument(name="ssl.CHV", output_type=str, description="SSL Certificate Chain Value (CHV)."),
    OutputArgument(name="ssl.SHA1", output_type=str, description="SHA1 hash of the SSL certificate."),
    OutputArgument(name="ssl.SHA256", output_type=str, description="SHA256 hash of the SSL certificate."),
    OutputArgument(name="ssl.authority_key_id", output_type=str, description="Authority Key Identifier for SSL certificate."),
    OutputArgument(name="ssl.expired", output_type=bool, description="Indicates if the SSL certificate is expired."),
    OutputArgument(name="ssl.issuer.common_name", output_type=str, description="Issuer common name for SSL certificate."),
    OutputArgument(name="ssl.issuer.country", output_type=str, description="Issuer country for SSL certificate."),
    OutputArgument(name="ssl.issuer.organization", output_type=str, description="Issuer organization for SSL certificate."),
    OutputArgument(name="ssl.not_after", output_type=str, description="Expiration date of the SSL certificate."),
    OutputArgument(name="ssl.not_before", output_type=str, description="Start date of the SSL certificate validity."),
    OutputArgument(
        name="ssl.sans",
        output_type=list,
        description="List of Subject Alternative Names (SANs) for the SSL certificate.",
    ),
    OutputArgument(name="ssl.sans_count", output_type=int, description="Count of SANs for the SSL certificate."),
    OutputArgument(name="ssl.serial_number", output_type=str, description="Serial number of the SSL certificate."),
    OutputArgument(name="ssl.sigalg", output_type=str, description="Signature algorithm used for the SSL certificate."),
    OutputArgument(name="ssl.subject.common_name", output_type=str, description="Subject common name for the SSL certificate."),
    OutputArgument(name="ssl.subject_key_id", output_type=str, description="Subject Key Identifier for SSL certificate."),
    OutputArgument(name="ssl.valid", output_type=bool, description="Indicates if the SSL certificate is valid."),
    OutputArgument(name="ssl.wildcard", output_type=bool, description="Indicates if the SSL certificate is a wildcard."),
    OutputArgument(name="body_analysis.SHV", output_type=str, description="Unique identifier for body analysis."),
    OutputArgument(name="body_analysis.body_sha256", output_type=str, description="SHA-256 hash of the body content."),
    OutputArgument(name="body_analysis.google-GA4", output_type=list, description="List of Google GA4 tracking IDs."),
    OutputArgument(
        name="body_analysis.google-UA", output_type=list, description="List of Google Universal Analytics tracking IDs."
    ),
    OutputArgument(name="body_analysis.google-adstag", output_type=list, description="List of Google Adstag tracking IDs."),
    OutputArgument(name="body_analysis.js_sha256", output_type=list, description="List of SHA-256 hashes of JavaScript files."),
    OutputArgument(
        name="body_analysis.js_ssdeep", output_type=list, description="List of ssdeep fuzzy hashes of JavaScript files."
    ),
]
ADD_FEED_OUTPUTS = [
    OutputArgument(name="name", output_type=str, description="The name of the feed."),
    OutputArgument(name="type", output_type=str, description="The type of the feed."),
    OutputArgument(name="vendor", output_type=str, description="The vendor of the feed."),
    OutputArgument(name="feed_description", output_type=str, description="A description of the feed."),
    OutputArgument(name="category", output_type=str, description="The category of the feed."),
    OutputArgument(name="tags", output_type=list, description="Tags associated with the feed."),
]
ADD_FEED_TAGS_OUTPUTS = [
    OutputArgument(name="created_or_updated", description="List of tags that have been created or updated to the feed.")
]
ADD_INDICATORS_OUTPUTS = [
    OutputArgument(
        name="created_or_updated",
        output_type=list,
        description="List of indicator names that were created or updated in the feed.",
    ),
    OutputArgument(
        name="invalid_indicators",
        output_type=list,
        description="List of indicators that were considered invalid and not added to the feed.",
    ),
]
ADD_INDICATOR_TAGS_OUTPUTS = [
    OutputArgument(name="uuid", output_type=str, description="The UUID of the indicator."),
    OutputArgument(name="name", output_type=str, description="The name of the indicator."),
    OutputArgument(name="tags", output_type=str, description="The tags assigned to the indicator."),
]
RUN_THREAT_CHECK_OUTPUTS = [
    OutputArgument(name="is_listed", output_type=bool, description="Indicates whether the queried value is listed as a threat."),
    OutputArgument(name="listed_txt", output_type=str, description="Textual description of the listing status."),
    OutputArgument(name="query", output_type=str, description="The original value that was checked."),
]

metadata_collector = YMLMetadataCollector(
    integration_name="SilentPush_v2",
    description=(
        "The Silent Push Platform uses first-party data and a proprietary scanning engine to enrich global DNS data with risk "
        "and reputation scoring, giving security teams the ability to join the dots across the entire IPv4 and IPv6 range, "
        "and identify adversary infrastructure before an attack is launched. The content pack integrates with the Silent Push "
        "system to gain insights into domain/IP information, reputations, enrichment, and infratag-related details. "
        "It also provides functionality to live-scan URLs and take screenshots of them. Additionally, "
        "it allows fetching future attack feeds from the Silent Push system."
    ),
    display="SilentPush",
    category="Data Enrichment & Threat Intelligence",
    docker_image="demisto/xsoar-tools:1.0.0.8457987",
    is_fetch=False,
    long_running=False,
    long_running_port=False,
    is_runonce=False,
    integration_subtype="python3",
    integration_type="python",
    fromversion="5.0.0",
    conf=[
        ConfKey(name="url", display="Base URL", required=True, default_value="https://api.silentpush.com"),
        ConfKey(
            name="credentials",
            display="API Key",
            required=False,
            key_type=ParameterTypes.AUTH,
        ),
        ConfKey(
            name="insecure",
            display="Trust any certificate (not secure)",
            required=False,
            key_type=ParameterTypes.BOOLEAN,
        ),
        ConfKey(name="proxy", display="Use system proxy settings", required=False, key_type=ParameterTypes.BOOLEAN),
    ],
)
# end pragma: no cover

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the SilentPush API.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initializes the client with the necessary parameters.

        :param base_url (str): The base URL for the SilentPush API.
        :param api_key (str): The API key for authentication.
        :param verify (bool): Flag to determine whether to verify SSL certificates (default True).
        :param proxy (bool): Flag to determine whether to use a proxy (default False).
        """
        full_base_url = base_url.rstrip("/")
        super().__init__(full_base_url, verify, proxy)
        self.base_url = full_base_url
        self.verify = verify
        self.proxies = handle_proxy() if proxy else None
        self._headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "Cortex/2.0 (PaloAlto XSOAR Integration)"
        }

    def _http_request(
        self, method: str,
        url_suffix: str = "",
        params: dict = None,
        data: dict = None,
        url: str = None,
        force_json: bool = True,
        **kwargs
    ) -> Any:
        """
        Perform an HTTP request to the SilentPush API.

        :param method (str): The HTTP method to use (e.g., 'GET', 'POST').
        :param url_suffix (str): The endpoint suffix to append to the base URL.
        :param params (dict, optional): Query parameters to include in the request.
        :param data (dict, optional): JSON data to send in the request body.

        :return: Any: Parsed JSON response from the API.

        :raises DemistoException: If the response is not JSON or if the request fails.
        """
        full_url = url if url else f"{self.base_url.rstrip('/')}/{url_suffix.lstrip('/')}"
        try:
            response = requests.request(
                method=method,
                url=full_url,
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data,
                proxies=self.proxies,
            )
        except requests.exceptions.RequestException as e:
            raise DemistoException(f"Connection error: {str(e)}")
        if not response.ok:
            raise DemistoException(f"HTTP {response.status_code} Error: {response.text}", res=response)
        try:
            return response.json() if force_json else response
        except ValueError:
            raise DemistoException("Failed to parse JSON response.", res=response)

    def lookup(self, url_path: str, args: dict, both: bool = False) -> tuple[dict, str] | str:
        """
        Command function to perform a PADNS lookup on the SilentPush API.

        :param client (Client): SilentPush API client.
        :param args (dict): Command arguments containing 'qtype' and 'query', and optionally 'scope'.
        :param both (bool): if it's a multi conditional lookup, which matches both query and answer

        :return: CommandResults: Formatted results of the density lookup, including either the density records or an error message.
        """
        qtype = args.get("qtype")
        query = args.get("query")
        if not qtype or not query:
            raise DemistoException("Both 'qtype' and 'query' are required parameters.")
        url_suffix = f"{url_path}/{qtype}/{query}"
        url_suffix += ('/' + args.get("answer")) if both else ""
        raw_response = self._http_request(method="GET", url_suffix=url_suffix, params=args)
        if raw_response.get("error"):
            raise DemistoException(f"API Error: {raw_response.get('error')}")
        records = raw_response.get("response", {}).get("records", [])
        readable_output = (
            f"No records found for {qtype} {query}"
            if not records
            else tableToMarkdown(f"Lookup Results for {qtype} {query}", records, removeNull=True)
        )
        return raw_response, readable_output

    def get_bulk_info(self, payload, url_suffix):
        if len(list(payload.values())[0]) > 100:
            raise ValueError("Maximum of 100 values can be submitted in a single request.")
        raw_response = self._http_request(method="POST", url_suffix=url_suffix, data=payload)
        response = raw_response.get("response", []) or []
        markdown = "# Information Results\n"
        markdown += self.get_markdown(response)
        return response, markdown

    def get_reputation(self, url_suffix: str, args: dict, request_field: str, response_field: str):
        reputation_query = args.get(request_field)
        if not reputation_query:
            raise ValueError("a query for reputation is required.")
        url_suffix = f"{url_suffix}/{reputation_query}"
        params = {"explain": args.get("explain"), "limit": args.get("limit")}
        remove_nulls_from_dictionary(params)
        response = self._http_request(method="GET", url_suffix=url_suffix, params=params)
        reputation_data = response.get("response", {}).get(response_field, [])
        if reputation_data and all(isinstance(item, dict) for item in reputation_data):
            all_headers = set()
            for item in reputation_data:
                all_headers.update(item.keys())
            readable_output = tableToMarkdown(
                f"{request_field.capitalize()} Reputation for {reputation_query}",
                reputation_data,
                headers=sorted(all_headers),
                removeNull=True
            )
        else:
            readable_output = f"No valid reputation history found for {request_field}: {reputation_query}"
        return readable_output, reputation_data

    def get_response_schema(self, response):
        """
        Try to figure out the JSON schema from the response
        """
        import jsonschema
        from jsonschema.exceptions import ValidationError, SchemaError

        schemas = {
            "common": {  # [{"x": "x", "y": "y"}, {"z": "z", "w": "w"}]
                "type": "array",
                "items": {
                    "type": "object",
                }
            },
            "dict_list_dict": {  # {"w": [{"x": "x", "y": "y"}, {"z": "z", "w": "w"}]}
                "$schema": "https://json-schema.org",
                "type": "object",
                "patternProperties": {
                    "^[a-z].*$": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                },
                'additionalProperties': False  # Forces strict rejection of unmapped patterns
            },
            "dict_dict": {  # {'x': {'y':'y'}, 'y': {'z': 'z'}}
                "$schema": "https://json-schema.org",
                "type": "object",
                "patternProperties": {
                    "^[a-z].*$": {"type": "object"},
                },
                'additionalProperties': False  # Forces strict rejection of unmapped patterns
            },
        }
        for name, schema in schemas.items():
            try:
                jsonschema.validate(instance=response, schema=schema)
                return name, schema
            except (ValidationError, SchemaError):
                pass
        return "common", schemas.get("common")

    def get_markdown(self, response):
        """
        Generates a markdown from the response schema
        """
        schema, _ = self.get_response_schema(response)
        markdown = ""
        try:
            if schema == "dict_dict":
                for k, v in response.items():
                    markdown += tableToMarkdown(k, v, headers=v.keys(), is_auto_json_transform=True)
            elif schema == "dict_list_dict":
                for k, v in response.items():
                    markdown += tableToMarkdown(k, v, headers=v[0].keys(), is_auto_json_transform=True)
            else:
                for v in response:
                    markdown += tableToMarkdown('', v, headers=v.keys())
        except AttributeError:
            pass
        return markdown

    def response_has_job(self, response: dict) -> dict | bool:
        try:
            has_job = any([
                response.get("job_status", False),
                response.get("response", {}).get("job_status", False),
            ])
        except AttributeError:
            return False
        if has_job:
            job_details = response.get("response", {}).get("job_status", {})
            if not job_details:
                job_details = response.get("job_status", {})
            return job_details
        return False

    def format_job_command_response(self, job_details, response):
        readable_output = tableToMarkdown(
            f"# This task is taking longer, please try again later or use the 'retry job' command\n",
            job_details,
            removeNull=True
        )
        return CommandResults(
            outputs_prefix="SilentPush.Job",
            outputs_key_field="job_id",
            outputs=job_details,
            readable_output=readable_output,
            raw_response=response,
        )

    def format_certificate_info(self, cert: dict[str, Any]) -> dict[str, str]:
        """
        Formats certificate information into a structured dictionary.

        :param cert (Dict[str, Any]): Certificate details from the API response.

        :return: Dict[str, str]: Formatted certificate details.
        """
        subject = ast.literal_eval(cert.get("subject", {}))
        return {
            "Issuer": cert.get("issuer", "N/A"),
            "Issued On": cert.get("not_before", "N/A"),
            "Expires On": cert.get("not_after", "N/A"),
            "Common Name": subject.get("CN", "N/A"),
            "Subject Alternative Names": ", ".join(cert.get("domains", [])),
            "Serial Number": cert.get("serial_number", "N/A"),
            "Fingerprint SHA256": cert.get("fingerprint_sha256", "N/A"),
        }

    def validate_ip(self, resource: str, value: str) -> None:
        """
        Validate the IP address based on the resource type.

        Args:
            client (Client): The client object to interact with the enrichment service.
            resource (str): The resource type (ipv4 or ipv6).
            value (str): The IP address to validate.

        Raises:
            DemistoException: If the IP address is invalid for the given resource type.
        """
        is_valid_ip = self.validate_ip_address(value, allow_ipv6=(resource == "ipv6"))
        if not is_valid_ip:
            raise DemistoException(f"Invalid {resource.upper()} address: {value}")

    def validate_url_scan_parameters(self, platform: str, os: str, browser: str, region: str) -> str:
        """Validate the platform, os, browser, and region values."""
        valid_platforms = ["Desktop", "Mobile", "Crawler"]
        valid_os = ["Windows", "Linux", "MacOS", "iOS", "Android"]
        valid_browsers = ["Firefox", "Chrome", "Edge", "Safari"]
        valid_regions = ["US", "EU", "AS", "TOR"]
        errors = []
        if platform and platform not in valid_platforms:
            errors.append(f"Invalid platform. Must be one of: {', '.join(valid_platforms)}")
        if os and os not in valid_os:
            errors.append(f"Invalid OS. Must be one of: {', '.join(valid_os)}")
        if browser and browser not in valid_browsers:
            errors.append(f"Invalid browser. Must be one of: {', '.join(valid_browsers)}")
        if region and region not in valid_regions:
            errors.append(f"Invalid region. Must be one of: {', '.join(valid_regions)}")
        return "\n".join(errors)

    def fetch_bulk_info(self, values: list[str], resource: ResourceType = ResourceType.DOMAIN) -> dict[str, Any]:
        """
        Fetch basic domain information for a list of domains, IP4 or IP6.

        :ref: https://help.silentpush.com/docs/bulk-enrich-indicatora

        :param values (list[str]): List of domains to fetch.
        :param resource (ResourceType): Resource type to fetch.
        """
        payload = {"domains": values} if resource == ResourceType.DOMAIN else {"ips": values}
        url = BULK_INFO + f"/{resource.value}"
        if resource.value == "ipv6":
            url = BULK_IP6_INFO
        response = self._http_request(method="POST", url_suffix=url, data=payload)
        return response.get("response", [])

    def validate_ip_address(self, ip: str, allow_ipv6: bool = True) -> bool:
        """
        Validate an IP address.

        :param self: The instance of the class.
        :param ip (str): IP address to validate.
        :param allow_ipv6 (bool, optional): Whether to allow IPv6 addresses. Defaults to True.

        :return: bool: True if valid IP address, False otherwise.
        """
        try:
            ip = ip.strip()
            ip_obj = ipaddress.ip_address(ip)
            return not (not allow_ipv6 and ip_obj.version == 6)
        except ValueError:
            return False

    def get_enrichment_data(
        self,
        value: str,
        explain: bool | None = False,
        scan_data: bool | None = False,
        resource: ResourceType = ResourceType.DOMAIN
    ) -> dict:
        """
        Retrieve enrichment data for a specific resource.

        :param resource (str): Type of resource (e.g., 'ip', 'domain').
        :param value (str): The specific value to enrich.
        :param explain (bool, optional): Whether to include detailed explanations. Defaults to False.
        :param scan_data (bool, optional): Whether to include scan data. Defaults to False.

        :return: dict: Enrichment data for the specified resource.
        """
        endpoint = f"{ENRICHMENT}/{resource.value}/{value}"
        query_params = {"explain": explain if explain else 0, "scan_data": scan_data if scan_data else 0}
        response = self._http_request(method="GET", url_suffix=endpoint, params=query_params)
        if resource in [ResourceType.IP4, ResourceType.IP6]:
            ip2asn_data = response.get("response", {}).get("ip2asn", [])
            return ip2asn_data[0] if isinstance(ip2asn_data, list) and ip2asn_data else {}
        return response.get("response", {})

    def search_scan_data(self, query: str, args: dict) -> dict[str, Any]:
        """
        Search the Silent Push scan data repositories.

        :ref: https://help.silentpush.com/docs/spql-api

        :param query (str): Query in SPQL syntax to scan data (mandatory)
        :param params (dict): Optional parameters to filter scan data
        :return: Dict[str, Any]: Search results from scan data repositories

        raises: DemistoException: If query is not provided or API call fails
        """
        if not query:
            raise DemistoException("Query parameter is required for search scan data.")
        params = {
            "limit": args.get("limit"),
            "skip": args.get("skip"),
            "with_metadata": args.get("with_metadata"),
        }
        remove_nulls_from_dictionary(params)
        payload = {
            "query": query,
            "fields": argToList(args.get("fields")),
            "sort": argToList(args.get("sort")),
        }
        return self._http_request(method="POST", url_suffix=SEARCH_SCAN, data=payload, params=params)

    def live_url_scan(
        self,
        url: str,
        platform: str | None = None,
        os: str | None = None,
        browser: str | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        """
        Perform a live scan of a URL to get hosting metadata.

        :param url (str): The URL to scan.
        :param platform (str, optional): Device to perform scan with (Desktop, Mobile, Crawler).
        :param os (str, optional): OS to perform scan with (Windows, Linux, MacOS, iOS, Android).
        :param browser (str, optional): Browser to perform scan with (Firefox, Chrome, Edge, Safari).
        :param region (str, optional): Region from where scan should be performed (US, EU, AS, TOR).

        :return: Dict[str, Any]: The scan results including hosting metadata.
        """
        params = {"url": url, "platform": platform, "os": os, "browser": browser, "region": region}
        remove_nulls_from_dictionary(params)
        return self._http_request(method="GET", url_suffix=LIVE_SCAN_URL, params=params)

    def add_feed(self, args: dict) -> dict[str, Any]:
        """
        Add new feed on SilentPush.

        :ref: https://help.silentpush.com/docs/view-the-customer-feed-api-endpoints#feed-management

        :param args: Payload for filtering and pagination.

        :return: Dict[str, Any]: Response containing feed information.
        """
        payload = {
            "name": args.get("name"),
            "type": args.get("type"),
            "vendor": args.get("vendor"),
            "feed_description": args.get("feed_description"),
            "category": args.get("category"),
            "tags": argToList(args.get("tags")),
        }
        remove_nulls_from_dictionary(payload)
        response = self._http_request(method="POST", url_suffix=ADD_FEED, data=payload)
        if isinstance(response, dict) and response.get("errors"):
            return {"error": f"Failed to add new feed: {response['errors']}"}
        return response

    def add_feed_tags(self, args: dict) -> dict[str, Any]:
        """
        Add new feed on SilentPush.

        :ref: https://help.silentpush.com/docs/view-the-customer-feed-api-endpoints#tag-management

        :param args: Payload for filtering and pagination.

        :return: Dict[str, Any]: Response containing feed tags information.
        """
        feed_uuid = args.get("feed_uuid")
        url = f"{ADD_FEED}" + f"{feed_uuid}" + "/tags/"
        tags = argToList(args.get("tags"))
        payload = {"tags": tags}
        remove_nulls_from_dictionary(payload)
        response = self._http_request(method="POST", url_suffix=url, data=payload)
        if isinstance(response, dict) and response.get("errors"):
            return {"error": f"Failed to add feed tags: {response['errors']}"}
        return response

    def add_indicators(self, args: dict) -> dict[str, Any]:
        """
        Add new indicator on SilentPush.

        :ref: https://help.silentpush.com/docs/view-the-customer-feed-api-endpoints#list-indicators

        :param args: Payload for filtering and pagination.

        :return: Dict[str, Any]: Response containing indicators information.
        """
        feed_uuid = args.get("feed_uuid")
        url = f"{ADD_FEED}" + f"{feed_uuid}" + "/indicators/"
        indicators = argToList(args.get("indicators"))
        payload = {"indicators": indicators}
        remove_nulls_from_dictionary(payload)
        response = self._http_request(method="POST", url_suffix=url, data=payload)
        if isinstance(response, dict) and response.get("errors"):
            return {"error": f"Failed to add new indicators: {response['errors']}"}
        return response

    def add_indicators_tags(self, args: dict) -> dict[str, Any]:
        """
        Add new indicator tags on SilentPush.

        :ref: https://help.silentpush.com/docs/view-the-customer-feed-api-endpoints#manage-indicator-tags

        :param args: Payload for tags.

        :return: Dict[str, Any]: Response containing indicator tags information.
        """
        feed_uuid = args.get("feed_uuid")
        indicator_name = args.get("indicator_name")
        url = f"{ADD_FEED}{feed_uuid}/indicators/{indicator_name}/update-tags/"
        tags = argToList(args.get("tags"))
        payload = {"tags": tags}
        remove_nulls_from_dictionary(payload)
        response = self._http_request(method="PUT", url_suffix=url, data=payload)
        if isinstance(response, dict) and response.get("errors"):
            return {"error": f"Failed to add indicator tags: {response['errors']}"}
        return response

    def run_threat_check(self, args: dict) -> dict[str, Any]:
        """
        Fetch threat checks on SilentPush.

        :ref: https://help.silentpush.com/docs/threat-check-api-endpoints

        :param args: Params for threat checks.

        :return: Dict[str, Any]: Response containing threat check information.
        """
        params = {
            "t": args.get("type"),
            "d": args.get("data"),
            "u": args.get("user_identifier"),
            "q": args.get("query")
        }
        remove_nulls_from_dictionary(params)
        response = self._http_request(method="GET", url=THREAT_CHECK, params=params)
        if isinstance(response, dict) and response.get("errors"):
            return {"error": f"Failed to run threat check: {response['errors']}"}
        return response

    def get_data_exports(self, file_name: str, export_type: str = "iofa", file_type: str = "json") -> requests.Response:
        """
        Exports data on SilentPush.

        :ref: https://help.silentpush.com/docs/data-automations

        :param feed_url: Feed url for exporting data.

        :return: Dict[str, Any]: Response containing feed information.
        """
        url_suffix = f"{EXPORT_DATA}{export_type}-exports/{file_name}.{file_type}"
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            force_json=False,
        )
        return response


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: SilentPush client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        resp = client._http_request("GET", V1 + "me")
        if resp.get("status_code") != 200:
            return f"Connection failed :- {resp.get('errors')}"
        return "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise e


def jobify(command):
    def wrapper(client: Client, args: dict):
        command_result = command(client, args)
        has_job = client.response_has_job(command_result.raw_response)
        if has_job is not False:
            return client.format_job_command_response(
                has_job, command_result.raw_response
            )
        return command_result

    return wrapper


@metadata_collector.command(
    command_name="silentpush-get-nameserver-reputation",
    inputs_list=NAMESERVER_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.NameserverReputation",
    outputs_list=NAMESERVER_REPUTATION_OUTPUTS,
    description="This command retrieves historical reputation data for a specified nameserver,"
                "including reputation scores and optional detailed calculation information.",
)
@jobify
def get_nameserver_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving nameserver reputation.

    :param client (Client): The API client instance.
    :param args (dict): Command arguments.

    :return: CommandResults: The command results containing nameserver reputation data.
    """
    readable_output, reputation_data = client.get_reputation(
        url_suffix=NAMESERVER_REPUTATION,
        args=args,
        request_field="nameserver",
        response_field="ns_server_reputation_history",
    )
    return CommandResults(
        outputs_prefix="SilentPush.NameserverReputation",
        outputs_key_field="ns_server",
        outputs={"nameserver": args.get("nameserver"), "reputation_data": reputation_data},
        readable_output=readable_output,
        raw_response=reputation_data,
    )


@metadata_collector.command(
    command_name="silentpush-get-subnet-reputation",
    inputs_list=SUBNET_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.SubnetReputation",
    outputs_list=SUBNET_REPUTATION_OUTPUTS,
    description="This command retrieves the reputation history for a specific subnet.",
)
@jobify
def get_subnet_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the reputation history of a given subnet.

    :ref: https://help.silentpush.com/docs/subnet-reputation-history

    :param client (Client): The API client instance.
    :param args (dict): Command arguments containing:
            - subnet (str): The subnet to query.
            - explain (bool, optional): Whether to include an explanation.
            - limit (int, optional): Limit the number of reputation records.

    :return: CommandResults: The command result containing the subnet reputation data.
    """
    readable_output, reputation_data = client.get_reputation(
        url_suffix=SUBNET_REPUTATION,
        args=args,
        request_field="subnet",
        response_field="subnet_reputation_history",
    )
    return CommandResults(
        outputs_prefix="SilentPush.SubnetReputation",
        outputs_key_field="subnet",
        outputs={"subnet": args.get("subnet"), "reputation_history": reputation_data},
        readable_output=readable_output,
        raw_response=reputation_data,
    )


@metadata_collector.command(
    command_name="silentpush-get-ipv4-reputation",
    inputs_list=IPV4_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.IPv4Reputation",
    outputs_list=IPV4_REPUTATION_OUTPUTS,
    description="This command retrieves the reputation information for an IPv4.",
)
@jobify
def get_ipv4_reputation_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the reputation data for a given IPv4 address from the client.

    :param client (Client): The client to interact with the reputation service.
    :param args (Dict[str, Any]): Arguments passed to the command, including the IPv4 address, explain flag, and limit.

    :return: CommandResults: The results of the command including the IPv4 reputation data.
    """
    readable_output, reputation_data = client.get_reputation(
        url_suffix=IPV4_REPUTATION,
        args=args,
        request_field="ipv4",
        response_field="ip_reputation_history",
    )
    return CommandResults(
        outputs_prefix="SilentPush.IPv4Reputation",
        outputs_key_field="ip",
        outputs={"IPv4": args.get("ipv4"), "reputation_history": reputation_data},
        readable_output=readable_output,
        raw_response=reputation_data,
    )


@metadata_collector.command(
    command_name="silentpush-get-asns-for-domain",
    inputs_list=ASNS_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.DomainASNs",
    outputs_list=ASNS_DOMAIN_OUTPUTS,
    description="This command retrieves Autonomous System Numbers (ASNs) associated with a domain.",
)
@jobify
def get_asns_for_domain_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves Autonomous System Numbers (ASNs) for the specified domain.

    :param client (Client): The client object used to interact with the service.
    :param args (dict): Arguments passed to the command, including the domain.

    :return: CommandResults: The results containing ASNs for the domain or an error message.
    """
    domain = args.get("domain")
    if not domain:
        raise DemistoException("Domain is a required parameter.")
    url_suffix = f"{ASNS_DOMAIN}/{domain}"
    raw_response = client._http_request(method="GET", url_suffix=url_suffix)
    records = raw_response.get("response", {}).get("records", [])
    if not records or "domain_asns" not in records[0]:
        readable_output = f"No ASNs found for domain: {domain}"
        asns = []
    else:
        domain_asns = records[0]["domain_asns"]
        asns = [{"ASN": asn, "Description": description} for asn, description in domain_asns.items()]
        readable_output = tableToMarkdown(f"ASNs for Domain: {domain}", asns, headers=["ASN", "Description"])
    return CommandResults(
        outputs_prefix="SilentPush.DomainASNs",
        outputs_key_field="domain",
        outputs={"domain": domain, "asns": asns},
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-forward-padns-lookup",
    inputs_list=FORWARD_PADNS_INPUTS,
    outputs_prefix="SilentPush.PADNSLookup",
    outputs_list=FORWARD_PADNS_OUTPUTS,
    description="This command performs a forward PADNS lookup using various filtering parameters.",
)
@jobify
def forward_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform a forward PADNS lookup.

    :ref: https://help.silentpush.com/docs/forward-padns-lookup

    :param client (Client): The SilentPush API client.
    :param args (dict): The command arguments containing lookup parameters.

    :return: CommandResults: The formatted results of the PADNS lookup or an error message if something goes wrong.
    """
    raw_response, readable_output = client.lookup(url_path=FORWARD_PADNS, args=args)
    return CommandResults(
        outputs_prefix="SilentPush.PADNSLookup",
        outputs_key_field="qname",
        outputs={
            "qtype": args.get("qtype"),
            "query": args.get("query"),
            "records": raw_response.get("response", {}).get("records", [])
        },
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-reverse-padns-lookup",
    inputs_list=REVERSE_PADNS_INPUTS,
    outputs_prefix="SilentPush.ReversePADNSLookup",
    outputs_list=REVERSE_PADNS_OUTPUTS,
    description="This command retrieve reverse Passive DNS data for specific DNS record types.",
)
@jobify
def reverse_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform reverse PADNS lookup.

    :ref: https://help.silentpush.com/docs/reverse-padns-lookup

    :param client (Client): SilentPush API client.
    :param args (dict): Command arguments.

    :return: CommandResults: Formatted results of the reverse PADNS lookup.
    """

    raw_response, readable_output = client.lookup(url_path=REVERSE_PADNS, args=args)
    return CommandResults(
        outputs_prefix="SilentPush.ReversePADNSLookup",
        outputs_key_field="qname",
        outputs={
            "qtype": args.get("qtype"),
            "query": args.get("query"),
            "records": raw_response.get("response", {}).get("records", [])
        },
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-multi-conditional-padns-lookup",
    inputs_list=MULTI_CONDITIONAL_PADNS_LOOKUP_INPUTS,
    outputs_prefix="SilentPush.MultiConditionalPADNSLookup",
    outputs_list=PADNS_OUTPUTS,
    description="This command searches passive DNS data for records matching both query and answer.",
)
@jobify
def multi_conditional_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform reverse PADNS lookup.

    :ref: https://help.silentpush.com/docs/multi-condition-padns-lookup

    :param client (Client): SilentPush API client.
    :param args (dict): Command arguments.

    :return: CommandResults: Formatted results of the reverse PADNS lookup.
    """

    raw_response, readable_output = client.lookup(
        url_path=MULTI_CONDITIONAL_PADNS_LOOKUP, args=args, both=True
    )
    return CommandResults(
        outputs_prefix="SilentPush.MultiConditionalPADNSLookup",
        outputs_key_field="qname",
        outputs={
            "qtype": args.get("qtype"),
            "query": args.get("query"),
            "records": raw_response.get("response", {}).get("records", [])
        },
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-density-lookup",
    inputs_list=DENSITY_LOOKUP_INPUTS,
    outputs_prefix="SilentPush.DensityLookup",
    outputs_list=DENSITY_LOOKUP_OUTPUTS,
    description="This command queries granular DNS/IP parameters (e.g., NS servers, MX servers, IPaddresses, ASNs) for density "
                "information.",
)
@jobify
def density_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform a density lookup on the SilentPush API.

    :ref: https://help.silentpush.com/docs/density-lookup

    :param client (Client): SilentPush API client.
    :param args (dict): Command arguments containing 'qtype' and 'query', and optionally 'scope'.

    :return: CommandResults: Formatted results of the density lookup, including either the density records or an error message.
    """
    raw_response, readable_output = client.lookup(url_path=DENSITY, args=args)
    return CommandResults(
        outputs_prefix="SilentPush.Lookup",
        outputs_key_field="query",
        outputs={
            "qtype": args.get("qtype"),
            "query": args.get("query"),
            "records": raw_response.get("response", {}).get("records", [])
        },
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-ip-diversity-lookup",
    inputs_list=IP_DIVERSITY_LOOKUP_INPUTS,
    outputs_prefix="SilentPush.IPdiversityLookup",
    outputs_list=IP_DIVERSITY_LOOKUP_OUTPUTS,
    description="Get IP diversity (number of IP addresses pointed to over time) for the query to qtype.",
)
@jobify
def ip_diversity_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform a IP diversity lookup on the SilentPush API.

    :param client (Client): SilentPush API client.
    :param args (dict): Command arguments containing 'qtype' and 'query', and optionally 'scope'.

    :return: CommandResults: Formatted results of the density lookup, including either the density records or an error message.
    """
    raw_response, readable_output = client.lookup(url_path=IP_DIVERSITY, args=args)
    return CommandResults(
        outputs_prefix="SilentPush.Lookup",
        outputs_key_field="query",
        outputs=raw_response.get("response", {}).get("records", []),
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-ip-diversity-patterns",
    inputs_list=IP_DIVERSITY_PATTERNS_INPUTS,
    outputs_prefix="SilentPush.IPDiversityPatterns",
    outputs_list=IP_DIVERSITY_PATTERNS_OUTPUTS,
    description="Search for IP Diversity patterns, with optional name server and domain name pattern matching.",
)
@jobify
def ip_diversity_patterns_command(client: Client, args: dict) -> CommandResults:
    """
    Command to Search for IP Diversity patterns, with optional name server and domain name pattern matching.

    :ref: https://help.silentpush.com/docs/domain-search

    :param client (Client): The client instance to interact with the external service.
    :param args (dict): Arguments containing filter parameters for domain search.

    :return: CommandResults: The results of the ip diversity pattern search, including readable output and raw response.
    """
    minimum_parameters_keys = [
        "asn_diversity",
        "asn_diversity_min",
        "asn_diversity_max",
        "ip_diversity_all",
        "ip_diversity_all_min",
        "ip_diversity_all_max",
        "ip_diversity_groups",
        "ip_diversity_groups_min",
        "ip_diversity_groups_max",
    ]
    minimum_parameters = [
        args.get(key) for key in minimum_parameters_keys
    ]
    if not any(minimum_parameters):
        raise DemistoException(f"At least one of {minimum_parameters_keys} is required.")
    remove_nulls_from_dictionary(args)
    raw_response = client._http_request("GET", IP_DIVERSITY_PATTERNS, params=args)
    records = raw_response.get("response", {}).get("records", [])
    readable_output = tableToMarkdown("IP Diversity Patterns Results", records)
    return CommandResults(
        outputs_prefix="SilentPush.Domain",
        outputs_key_field="host",
        outputs=records,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-search-domains",
    inputs_list=SEARCH_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.IPDiversityPatterns",
    outputs_list=SEARCH_DOMAIN_OUTPUTS,
    description="This command search for domains with optional filters.",
)
@jobify
def search_domains_command(client: Client, args: dict) -> CommandResults:
    """
    Command to search for domains based on various filter parameters.

    :ref: https://help.silentpush.com/docs/domain-search

    :param client (Client): The client instance to interact with the external service.
    :param args (dict): Arguments containing filter parameters for domain search.

    :return: CommandResults: The results of the domain search, including readable output and raw response.
    """
    remove_nulls_from_dictionary(args)
    raw_response = client._http_request("GET", SEARCH_DOMAIN, params=args)
    records = raw_response.get("response", {}).get("records", [])
    if not records:
        readable_output = "No domains found."
    else:
        readable_output = tableToMarkdown("Domain Search Results", records)
    #     is_auto_json_transform=argToBoolean(args.get("timeline"))
    return CommandResults(
        outputs_prefix="SilentPush.Domain",
        outputs_key_field="domain",
        outputs=records,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-bulk-enrich",
    inputs_list=ENRICHMENT_INPUTS,
    outputs_prefix="SilentPush.Bulk.Enrich",
    outputs_list=ENRICHMENT_OUTPUTS,
    description="This command enriches IPs or Domains in a bulk",
)
@jobify
def bulk_enrich_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle bulk-enrich command execution.

    :ref: https://help.silentpush.com/docs/bulk-enrich-indicatora

    :param client (Client): The client object for making API calls
    :param args (Dict[str, Any]): Command arguments

    :return: CommandResults: Results for XSOAR
    """
    resource = ResourceType(args.get("resource"))
    values = argToList(args.get("value"))
    if len(values) > 100:
        raise ValueError("Maximum of 100 IoCs can be submitted in a single request.")
    response = client.fetch_bulk_info(values, resource)
    if resource == ResourceType.DOMAIN:
        markdown = "# Domain Information Results\n"
    else:
        markdown = "# IP Information Results\n"
    markdown += client.get_markdown(response)
    return CommandResults(
        outputs_prefix="SilentPush.Bulk.Enrich",
        outputs_key_field=resource.value,
        outputs=response,
        readable_output=markdown,
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-list-domain-information",
    inputs_list=LIST_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.Domain",
    outputs_list=LIST_DOMAIN_OUTPUTS,
    description="This command get domain information along with Silent Push risk score "
                "and live whois information for multiple domains.",
)
@jobify
def list_domain_information_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle the list-domain-information command execution.

    :ref: https://help.silentpush.com/docs/bulk-enrich-indicatora

    :param client (Client): The client object for making API calls
    :param args (Dict[str, Any]): Command arguments

    :return: CommandResults: Results for XSOAR
    """
    response, markdown = client.get_bulk_info(
        payload={"domains": argToList(args.get("domains"))},
        url_suffix=BULK_DOMAIN_INFO
    )
    return CommandResults(
        outputs_prefix="SilentPush.Domain",
        outputs_key_field="domain",
        outputs=response,
        readable_output=markdown,
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-list-ip4-information",
    inputs_list=LIST_IP_INPUTS,
    outputs_prefix="SilentPush.IP4",
    outputs_list=LIST_IP_OUTPUTS,
    description="This command get IP4 information along with Silent Push risk score "
)
@jobify
def list_ip4_information_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle the list-ip4-information command execution.

    :ref: https://help.silentpush.com/docs/bulk-enrich-indicatora

    :param client (Client): The client object for making API calls
    :param args (Dict[str, Any]): Command arguments

    :return: CommandResults: Results for XSOAR
    """
    response, markdown = client.get_bulk_info(
        payload={"ips": argToList(args.get("ips"))},
        url_suffix=BULK_IP4_INFO
    )
    return CommandResults(
        outputs_prefix="SilentPush.IP4",
        outputs_key_field="ip",
        outputs=response,
        readable_output=markdown,
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-list-ip6-information",
    inputs_list=LIST_IP_INPUTS,
    outputs_prefix="SilentPush.IP6",
    outputs_list=LIST_IP_OUTPUTS,
    description="This command get IP6 information along with Silent Push risk score "
)
@jobify
def list_ip6_information_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle the list-ip6-information command execution.

    :ref: https://help.silentpush.com/docs/bulk-enrich-indicatora

    :param client (Client): The client object for making API calls
    :param args (Dict[str, Any]): Command arguments

    :return: CommandResults: Results for XSOAR
    """
    response, markdown = client.get_bulk_info(
        payload={"ips": argToList(args.get("ips"))},
        url_suffix=BULK_IP6_INFO
    )
    return CommandResults(
        outputs_prefix="SilentPush.IP6",
        outputs_key_field="ip",
        outputs=response,
        readable_output=markdown,
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-whois",
    inputs_list=DOMAIN_INPUT,
    outputs_prefix="SilentPush.whois",
    outputs_list=WHOIS_OUTPUTS,
    description="This command get Whois information"
)
@jobify
def whois_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle the whois command execution.

    :ref: https://help.silentpush.com/docs/whois-information

    :param client (Client): The client object for making API calls
    :param args (Dict[str, Any]): Command arguments

    :return: CommandResults: Results for XSOAR
    """
    raw_response = client._http_request(method="GET", url_suffix=f"{WHOIS}/{args.get('domain')}")
    response = raw_response.get("response", {}).get("whois", [{}])[0]
    headers = list(response.keys())
    readable_output = tableToMarkdown(f"Whois Results for {args.get('domain')}", [response], headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix="SilentPush.Whois",
        outputs_key_field="whois",
        outputs={"whois": response},
        readable_output=readable_output,
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-get-domain-certificates",
    inputs_list=DOMAIN_CERTIFICATE_INPUTS,
    outputs_prefix="SilentPush.Certificate",
    outputs_list=DOMAIN_CERTIFICATE_OUTPUTS,
    description="This command get certificate data collected from domain scanning.",
)
@jobify
def get_domain_certificates_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves SSL/TLS certificates for a given domain.

    :ref: https://help.silentpush.com/docs/domain-certificates

    :param client (Client): The API client to interact with SilentPush.
    :param args (Dict[str, Any]): Command arguments including:
            - domain (str, required): The domain name to search for certificates.
            - domain_regex (str, optional): RE2 regex pattern to match domains.
            - certificate_issuer (str, optional): Filter certificates by issuer.
            - date_min (str, optional): Minimum issuance date (YYYY-MM-DD).
            - date_max (str, optional): Maximum issuance date (YYYY-MM-DD).
            - prefer (str, optional): Preference parameter for API filtering.
            - max_wait (int, optional): Maximum time to wait for results.
            - with_metadata (bool, optional): Whether to include metadata.
            - skip (int, optional): Number of records to skip.
            - limit (int, optional): Maximum number of results to return.

    :return: CommandResults: The results containing the retrieved certificates.
    """
    domain = args.get("domain")
    if not domain:
        raise DemistoException("The 'domain' parameter is required.")
    params = {
        "domain_regex": args.get("domain_regex"),
        "cert_issuer": args.get("certificate_issuer"),
        "date_min": args.get("date_min"),
        "date_max": args.get("date_max"),
        "prefer": args.get("prefer"),
        "max_wait": arg_to_number(args.get("max_wait")),
        "with_metadata": argToBoolean(str(args.get("with_metadata"))) if "with_metadata" in args else None,
        "skip": arg_to_number(args.get("skip")),
        "limit": arg_to_number(args.get("limit")),
    }
    remove_nulls_from_dictionary(params)
    raw_response = client._http_request(method="GET", url_suffix=f"{DOMAIN_CERTIFICATE}/{domain}/?max_wait=2", params=params)
    certificates = raw_response.get("response", {}).get("domain_certificates", [])
    metadata = raw_response.get("response", {}).get("metadata", {})
    markdown = [f"# SSL/TLS Certificate Information for Domain: {domain}\n"]
    for cert in certificates:
        cert_info = client.format_certificate_info(cert)
        markdown.append(tableToMarkdown("Certificate Information", [cert_info]))
    return CommandResults(
        outputs_prefix="SilentPush.Certificate",
        outputs_key_field="domain",
        outputs={"domain": domain, "certificates": certificates, "metadata": metadata},
        readable_output="\n".join(markdown),
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-get-enrichment-data",
    inputs_list=ENRICHMENT_INPUTS,
    outputs_prefix="SilentPush.Enrichment",
    outputs_list=ENRICHMENT_OUTPUTS,
    description="This command retrieves comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).",
)
@jobify
def get_enrichment_data_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve enrichment data for a specific resource and value.

    :param client (Client): The client object to interact with the enrichment service.
    :param args (dict): Arguments containing the resource type, value, explain flag, and scan_data flag.

    :return: CommandResults: The results of the enrichment data retrieval, including readable output and raw response.
    """
    resource = args.get("resource", "").lower()
    value = args.get("value")
    explain = argToBoolean(str(args.get("explain", False)))
    scan_data = argToBoolean(str(args.get("scan_data", False)))
    if not resource or not value:
        raise ValueError("Both 'resource' and 'value' arguments are required.")
    if resource not in ResourceType.get_choices():
        raise ValueError(f"Invalid input: {resource}. Allowed values are {ResourceType.get_choices()}")
    if resource in ["ipv4", "ipv6"]:
        client.validate_ip(resource, value)
    enrichment_data = client.get_enrichment_data(
        resource=ResourceType(resource), value=value, explain=explain, scan_data=scan_data
    )
    readable_output = tableToMarkdown(f"Enrichment Data for {value}", enrichment_data, removeNull=True,
                                      is_auto_json_transform=True)
    return CommandResults(
        outputs_prefix="SilentPush.Enrichment",
        outputs_key_field="value",
        outputs={"value": value, **enrichment_data},
        readable_output=readable_output,
        raw_response=enrichment_data,
    )


@metadata_collector.command(
    command_name="silentpush-search-scan-data",
    inputs_list=SEARCH_SCAN_INPUTS,
    outputs_prefix="SilentPush.ScanData",
    outputs_list=SEARCH_SCAN_OUTPUTS,
    description="This command search Silent Push scan data repositories using SPQL queries.",
)
@jobify
def search_scan_data_command(client: Client, args: dict) -> CommandResults:
    """
    Search scan data command handler.

    :param client (Client): SilentPush API client
    :param args (dict): Command arguments:
            - query (str): Required. SPQL syntax query

    :return: CommandResults: Command results with formatted output
    """
    query = args.get("query")
    if not query:
        raise ValueError("Query parameter is required")
    raw_response = client.search_scan_data(query, args)
    scan_data = raw_response.get("response", {}).get("records", [])
    if not scan_data:
        return CommandResults(readable_output="No scan data records found", outputs_prefix="SilentPush.ScanData", outputs=None)
    readable_output = tableToMarkdown("Raw Scan Data Results", scan_data, removeNull=True)
    outputs = {"records": scan_data, "query": query}
    remove_nulls_from_dictionary(outputs)
    return CommandResults(
        outputs_prefix="SilentPush.ScanData",
        outputs_key_field="domain",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-live-url-scan",
    inputs_list=LIVE_SCAN_URL_INPUTS,
    outputs_prefix="SilentPush.URLScan",
    outputs_list=LIVE_SCAN_URL_OUTPUTS,
    description="This command scan a URL to retrieve hosting metadata.",
)
@jobify
def live_url_scan_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for live URL scan command.

    :param client (Client): The SilentPush API client
    :param args (dict): Command arguments

    :return: CommandResults: Results of the URL scan
    """
    url = args.get("url")
    if not url:
        raise DemistoException("URL is a required parameter")
    platform = args.get("platform", "")
    os = args.get("os", "")
    browser = args.get("browser", "")
    region = args.get("region", "")
    validation_errors = client.validate_url_scan_parameters(platform, os, browser, region)
    if validation_errors:
        raise DemistoException(validation_errors)
    raw_response = client.live_url_scan(url, platform, os, browser, region)
    readable_output = client.get_markdown(raw_response)
    return CommandResults(
        outputs_prefix="SilentPush.URLScan",
        outputs_key_field="url",
        outputs={"url": url, "scan_results": raw_response},
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-add-feed",
    inputs_list=ADD_FEED_INPUTS,
    outputs_prefix="SilentPush.Feed",
    outputs_list=ADD_FEED_OUTPUTS,
    description="This command add the new feed",
)
def add_feed_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler for adding new feeds.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, Any]): Command arguments, must include 'name' and 'type' key.

    :return: CommandResults: JSON response of added feed.
    """
    result = client.add_feed(args)
    feed_name = result.get("name")
    feed_type = result.get("type")
    return CommandResults(
        outputs_prefix="SilentPush.Feed",
        outputs_key_field="name",
        outputs=result,
        readable_output=f"SilentPush feed: {feed_name} of type: {feed_type} was added successfully.",
        raw_response=result,
    )


@metadata_collector.command(
    command_name="silentpush-add-feed-tags",
    inputs_list=ADD_FEED_TAGS_INPUTS,
    outputs_prefix="SilentPush.AddFeedTags",
    outputs_list=ADD_INDICATORS_OUTPUTS,
    description="This command add indicators to the feed",
)
def add_feed_tags_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler for adding new feed tags.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, Any]): Command arguments, must include 'feed_uuid' key.

    :return: CommandResults: JSON response of added tags.
    """
    result = client.add_feed_tags(args).get("created_or_updated")
    uuid = args.get("feed_uuid")
    tags = args.get("tags")
    return CommandResults(
        outputs_prefix="SilentPush.AddFeedTags",
        outputs_key_field="feed_uuid",
        outputs=result,
        readable_output=f"feed with uuid: {uuid} was updated with tags: {tags}",
        raw_response=result,
    )


@metadata_collector.command(
    command_name="silentpush-add-indicators",
    inputs_list=ADD_INDICATORS_INPUTS,
    outputs_prefix="SilentPush.AddIndicators",
    outputs_list=ADD_INDICATORS_OUTPUTS,
    description="This command add indicators to the feed",
)
def add_indicators_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler for add new indicators.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, Any]): Command arguments, must include 'feed_uuid' and 'indicators key.

    :return: CommandResults: JSON response of added indicators.
    """
    result = client.add_indicators(args).get("created_or_updated")
    indicators = args.get("indicators")
    feed_uuid = args.get("feed_uuid")
    return CommandResults(
        outputs_prefix="SilentPush.AddIndicators",
        outputs_key_field="feed_uuid",
        outputs=result,
        readable_output=f"Indicators: '{indicators}' were added successfully to SilentPush feed: '{feed_uuid}'.",
        raw_response=result,
    )


@metadata_collector.command(
    command_name="silentpush-add-indicator-tags",
    inputs_list=ADD_INDICATOR_TAGS_INPUTS,
    outputs_prefix="SilentPush.AddIndicatorTags",
    outputs_list=ADD_INDICATOR_TAGS_OUTPUTS,
    description="This command updates tags to the indicators",
)
def add_indicators_tags_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler for add new indicator tags.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, Any]): Command arguments, must include 'feed_uuid' and 'indicator_name key.

    :return: CommandResults: JSON response of added indicator tags.
    """
    result = client.add_indicators_tags(args)
    tags = args.get("tags")
    indicator_name = args.get("indicator_name")
    return CommandResults(
        outputs_prefix="SilentPush.AddIndicatorTags",
        outputs_key_field="feed_uuid",
        outputs=result,
        readable_output=f"Indicator Tags: '{tags}' added to indicator '{indicator_name}' successfully",
        raw_response=result,
    )


@metadata_collector.command(
    command_name="silentpush-run-threat-check",
    inputs_list=RUN_THREAT_CHECK_INPUTS,
    outputs_prefix="SilentPush.RunThreatCheck",
    outputs_list=RUN_THREAT_CHECK_OUTPUTS,
    description="This command runs the threat check on the specified ",
)
def run_threat_check_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler to fetch threat checks.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, Any]): Command arguments, must include 'feed_uuid' key.

    :return: CommandResults: JSON response of threat check.
    """
    result = client.run_threat_check(args)
    ip = result.get("query")
    return CommandResults(
        outputs_prefix="SilentPush.RunThreatCheck",
        outputs_key_field="query",
        outputs=result,
        readable_output=f"Threat check for query '{ip}' completed successfully",
        raw_response=result,
    )


@metadata_collector.command(
    command_name="silentpush-get-data-exports",
    inputs_list=GET_DATA_EXPORTS_INPUTS,
    outputs_prefix="SilentPush.GetDataExports",
    outputs_list=[],
    file_output=True,
    description="This command runs the threat check on the specified ",
)
def get_data_exports_command(client: Client, args: dict[str, str]) -> dict[str, Any]:
    """
    Command handler to export data.

    :param client (Client): SilentPush API client instance.
    :param args (Dict[str, str]): Command arguments, must include 'feed_uuid' key.

    :return: CommandResults: JSON response of threat check.
    """
    file_name = args.get("file_name")
    export_type = args.get("export_type")
    file_type = args.get("file_type")
    response = client.get_data_exports(file_name, export_type, file_type)
    if response.status_code != 200:
        raise Exception(f"Failed to download file: {response.status_code} {response.text}")
    file_entry = fileResult(file_name, response.content, file_type=EntryType.ENTRY_INFO_FILE)
    return file_entry


@metadata_collector.command(
    command_name="silentpush-retry-job",
    inputs_list=JOB_STATUS_IMPUT,
    outputs_prefix="SilentPush.RetryJob",
    outputs_list=[],
    description="This command retry another command which returned a Job ID",
)
def retry_job_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    raw_response = client._http_request(method="GET", url_suffix=f"{JOB_STATUS}/{args.get('job_id')}")
    response = raw_response.get("response")
    markdown = f"# Job Results for {args.get('job_id')}\n"
    markdown += client.get_markdown(response)
    return CommandResults(
        outputs_prefix="SilentPush.RetryJob",
        outputs_key_field="job_id",
        outputs=response,
        readable_output=markdown,
        raw_response=response,
    )


commands_map = {  # maps demisto commands to their specific functions
    "test-module": test_module,
    "silentpush-get-nameserver-reputation": get_nameserver_reputation_command,
    "silentpush-get-subnet-reputation": get_subnet_reputation_command,
    "silentpush-get-ipv4-reputation": get_ipv4_reputation_command,
    "silentpush-forward-padns-lookup": forward_padns_lookup_command,
    "silentpush-reverse-padns-lookup": reverse_padns_lookup_command,
    "silentpush-multi-conditional-padns-lookup": multi_conditional_padns_lookup_command,
    "silentpush-density-lookup": density_lookup_command,
    "silentpush-ip-diversity-lookup": ip_diversity_lookup_command,
    "silentpush-get-enrichment-data": get_enrichment_data_command,
    "silentpush-bulk-enrich": bulk_enrich_command,
    "silentpush-list-domain-information": list_domain_information_command,
    "silentpush-list-ip4-information": list_ip4_information_command,
    "silentpush-list-ip6-information": list_ip6_information_command,
    "silentpush-search-domains": search_domains_command,
    "silentpush-get-asns-for-domain": get_asns_for_domain_command,
    "silentpush-get-domain-certificates": get_domain_certificates_command,
    "silentpush-search-scan-data": search_scan_data_command,
    "silentpush-live-url-scan": live_url_scan_command,
    "silentpush-add-feed": add_feed_command,
    "silentpush-add-feed-tags": add_feed_tags_command,
    "silentpush-add-indicators": add_indicators_command,
    "silentpush-add-indicator-tags": add_indicators_tags_command,
    "silentpush-run-threat-check": run_threat_check_command,
    "silentpush-get-data-exports": get_data_exports_command,
    "silentpush-whois": whois_command,
    "silentpush-retry-job": retry_job_command,
    "silentpush-ip-diversity-patterns": ip_diversity_patterns_command,
}

""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions"""
    try:
        params = demisto.params()
        api_key = params.get("credentials", {}).get("password")
        base_url = params.get("url", "https://api.silentpush.com")
        verify_ssl = not params.get("insecure", False)
        proxy = params.get("proxy", False)
        client = Client(base_url=base_url, api_key=api_key, verify=verify_ssl, proxy=proxy)
        command = commands_map[demisto.command()]
        results = command(client, demisto.args())
        return_results(results)
    except (IndexError, KeyError,):
        return_error(f"command '{demisto.command()}' not found")
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
