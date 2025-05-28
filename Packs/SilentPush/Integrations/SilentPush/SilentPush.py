import ipaddress
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

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RESOURCE = {"ipv4", "ipv6", "domain"}

# API ENDPOINTS
JOB_STATUS = "explore/job"
NAMESERVER_REPUTATION = "explore/nsreputation/history/nameserver"
SUBNET_REPUTATION = "explore/ipreputation/history/subnet"
ASNS_DOMAIN = "explore/padns/lookup/domain/asns"
DENSITY_LOOKUP = "explore/padns/lookup/density"
SEARCH_DOMAIN = "explore/domain/search"
DOMAIN_INFRATAGS = "explore/bulk/domain/infratags"
DOMAIN_INFO = "explore/bulk/domaininfo"
RISK_SCORE = "explore/bulk/domain/riskscore"
WHOIS = "explore/domain/whois"
DOMAIN_CERTIFICATE = "explore/domain/certificates"
ENRICHMENT = "explore/enrich"
LIST_IP = "explore/bulk/ip2asn"
ASN_REPUTATION = "explore/ipreputation/history/asn"
ASN_TAKEDOWN_REPUTATION = "explore/takedownreputation/history/asn"
IPV4_REPUTATION = "explore/ipreputation/history/ipv4"
FORWARD_PADNS = "explore/padns/lookup/query"
REVERSE_PADNS = "explore/padns/lookup/answer"
SEARCH_SCAN = "explore/scandata/search/raw"
LIVE_SCAN_URL = "explore/tools/scanondemand"
FUTURE_ATTACK_INDICATOR = "/api/v2/iocs/threat-ranking"
SCREENSHOT_URL = "explore/tools/screenshotondemand"

""" COMMANDS INPUTS """

JOB_STATUS_INPUTS = [  # pragma: no cover
    InputArgument(
        name="job_id",  # option 1
        description="ID of the job returned by Silent Push actions.",
        required=True,
    ),
    InputArgument(name="max_wait", description="Number of seconds to wait for results (0-25 seconds)."),
    InputArgument(name="status_only", description="Return job status, even if job is complete."),
    InputArgument(
        name="force_metadata_on",
        description="Always return query metadata, even if original request did not include metadata.",
    ),
    InputArgument(
        name="force_metadata_off",
        description="Never return query metadata, even if original request did include metadata.",
    ),
]
NAMESERVER_REPUTATION_INPUTS = [
    InputArgument(
        name="nameserver", description="Nameserver name for which information needs to be retrieved", required=True
    ),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score"),
    InputArgument(name="limit", description="The maximum number of reputation history to retrieve"),
]
SUBNET_REPUTATION_INPUTS = [
    InputArgument(
        name="subnet", description="IPv4 subnet for which reputation information needs to be retrieved.", required=True
    ),
    InputArgument(name="explain", description="Show the detailed information used to calculate the reputation score."),
    InputArgument(name="limit", description="Maximum number of reputation history entries to retrieve."),
]
ASNS_DOMAIN_INPUTS = [
    InputArgument(
        name="domain",  # option 1
        description="Domain name to search ASNs for. Retrieves ASNs associated with a records for the specified domain "
        "and its subdomains in the last 30 days.",
        required=True,
    )
]
DENSITY_LOOKUP_INPUTS = [
    InputArgument(name="qtype", description="Query type.", required=True),
    InputArgument(name="query", description="Value to query.", required=True),
    InputArgument(name="scope", description="Match level (optional)."),
]
SEARCH_DOMAIN_INPUTS = [
    InputArgument(name="domain", description="Name or wildcard pattern of domain names to search for."),
    InputArgument(
        name="domain_regex", description="A valid RE2 regex pattern to match domains. Overrides the domain argument."
    ),
    InputArgument(
        name="name_server", description="Name server name or wildcard pattern of the name server used by domains."
    ),
    InputArgument(name="asnum", description="Autonomous System (AS) number to filter domains."),
    InputArgument(
        name="asname", description="Search for all AS numbers where the AS Name begins with the specified value."
    ),
    InputArgument(name="min_ip_diversity", description="Minimum IP diversity limit to filter domains."),
    InputArgument(name="registrar", description="Name or partial name of the registrar used to register domains."),
    InputArgument(name="min_asn_diversity", description="Minimum ASN diversity limit to filter domains."),
    InputArgument(
        name="certificate_issuer",
        description="Filter domains that had SSL certificates issued by the specified certificate issuer. Wildcards supported.",
    ),
    InputArgument(
        name="whois_date_after", description="Filter domains with a WHOIS creation date after this date (YYYY-MM-DD)."
    ),
    InputArgument(name="skip", description="Number of results to skip in the search query."),
    InputArgument(name="limit", description="Number of results to return. Defaults to the SilentPush API's behavior."),
]
DOMAIN_INFRATAGS_INPUTS = [
    InputArgument(name="domains", description="Comma-separated list of domains.", required=True),
    InputArgument(name="cluster", description="Whether to cluster the results."),
    InputArgument(name="mode", description='Mode for lookup (live/padns). Defaults to "live".', default="live"),
    InputArgument(
        name="match", description='Handling of self-hosted infrastructure. Defaults to "self".', default="self"
    ),
    InputArgument(
        name="as_of",
        description="Build infratags from padns data where the as_of timestamp equivalent is between the first_seen "
        "and the last_seen timestamp - automatically sets mode to padns. Example :- date: yyyy-mm-dd (2021-07-09) - "
        "fixed date, epoch: number (1625834953) - fixed time in epoch format, sec: negative number (-172800) - "
        "relative time <sec> seconds ago",
        default="self",
    ),
]
LIST_DOMAIN_INPUTS = [
    InputArgument(name="domains", description="Comma-separated list of domains to query.", required=True),
    InputArgument(name="fetch_risk_score", description="Whether to fetch risk scores for the domains.", required=False),
    InputArgument(
        name="fetch_whois_info", description="Whether to fetch WHOIS information for the domains.", required=False
    ),
]
DOMAIN_CERTIFICATE_INPUTS = [
    InputArgument(name="domain", description="The domain to query certificates for.", required=True),
    InputArgument(name="domain_regex", description="Regular expression to match domains."),
    InputArgument(name="certificate_issuer", description="Filter by certificate issuer."),
    InputArgument(name="date_min", description="Filter certificates issued on or after this date."),
    InputArgument(name="date_max", description="Filter certificates issued on or before this date."),
    InputArgument(
        name="prefer",
        description="Prefer to wait for results for longer running queries or to return job_id immediately "
        "(Defaults to Silent Push API behaviour).",
    ),
    InputArgument(
        name="max_wait",
        description="Number of seconds to wait for results before returning a job_id, with a range from 0 to 25 seconds.",
    ),
    InputArgument(
        name="with_metadata",
        description="Includes a metadata object in the response, containing returned results, total results, and job_id.",
    ),
    InputArgument(name="skip", description="Number of results to skip."),
    InputArgument(name="limit", description="Number of results to return."),
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
LIST_IP_INPUTS = [InputArgument(name="ips", description="Comma-separated list of IP addresses.", required=True)]
ASN_REPUTATION_INPUTS = [
    InputArgument(name="asn", description="The ASN to lookup.", required=True),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score."),
    InputArgument(name="limit", description="The maximum number of reputation history records to retrieve."),
]
ASN_TAKEDOWN_REPUTATION_INPUTS = [
    InputArgument(name="asn", description="The ASN to lookup.", required=True),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score."),
    InputArgument(name="limit", description="The maximum number of reputation history records to retrieve."),
]
IPV4_REPUTATION_INPUTS = [
    InputArgument(
        name="ipv4",  # option 1
        description="IPv4 address for which information needs to be retrieved",
        required=True,
    ),
    InputArgument(name="explain", description="Show the information used to calculate the reputation score"),
    InputArgument(name="limit", description="The maximum number of reputation history to retrieve"),
]
FORWARD_PADNS_INPUTS = [
    InputArgument(name="qtype", description="DNS record type", required=True),
    InputArgument(name="qname", description="The DNS record name to lookup", required=True),
    InputArgument(name="netmask", description="The netmask to filter the lookup results."),
    InputArgument(name="subdomains", description="Flag to include subdomains in the lookup results."),
    InputArgument(name="regex", description="Regular expression to filter the DNS records."),
    InputArgument(name="match", description="Type of match for the query (e.g., exact, partial)."),
    InputArgument(
        name="first_seen_after", description="Filter results to include only records first seen after this date."
    ),
    InputArgument(
        name="first_seen_before", description="Filter results to include only records first seen before this date."
    ),
    InputArgument(
        name="last_seen_after", description="Filter results to include only records last seen after this date."
    ),
    InputArgument(
        name="last_seen_before", description="Filter results to include only records last seen before this date."
    ),
    InputArgument(name="as_of", description="Date or time to get the DNS records as of a specific point in time."),
    InputArgument(name="sort", description="Sort the results by the specified field (e.g., date, score)."),
    InputArgument(
        name="output_format", description="The format in which the results should be returned (e.g., JSON, XML)."
    ),
    InputArgument(name="prefer", description="Preference for specific DNS servers or sources."),
    InputArgument(name="with_metadata", description="Flag to include metadata in the DNS records."),
    InputArgument(name="max_wait", description="Maximum number of seconds to wait for results before timing out."),
    InputArgument(name="skip", description="Number of results to skip for pagination purposes."),
    InputArgument(name="limit", description="Maximum number of results to return."),
]
REVERSE_PADNS_INPUTS = [
    InputArgument(name="qtype", description="Type of DNS record.", required=True),
    InputArgument(name="qname", description="The DNS record name to lookup.", required=True),
    InputArgument(name="netmask", description="The netmask for the lookup."),
    InputArgument(name="subdomains", description="Whether to include subdomains in the lookup."),
    InputArgument(name="regex", description="Regular expression to filter the DNS records."),
    InputArgument(name="first_seen_after", description="Filter for records first seen after a specific date/time."),
    InputArgument(name="first_seen_before", description="Filter for records first seen before a specific date/time."),
    InputArgument(name="last_seen_after", description="Filter for records last seen after a specific date/time."),
    InputArgument(name="last_seen_before", description="Filter for records last seen before a specific date/time."),
    InputArgument(name="as_of", description="Specify a date/time for the PADNS lookup."),
    InputArgument(name="sort", description="Sort the results by specified criteria."),
    InputArgument(name="output_format", description="Format for the output (e.g., JSON, XML)."),
    InputArgument(name="prefer", description="Preference for certain record types during the lookup."),
    InputArgument(name="with_metadata", description="Include metadata in the results."),
    InputArgument(name="max_wait", description="Maximum wait time in seconds for the lookup results."),
    InputArgument(name="skip", description="Number of results to skip in pagination."),
    InputArgument(name="limit", description="Limit the number of results returned."),
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
FUTURE_ATTACK_INDICATOR_INPUTS = [
    InputArgument(name="feed_uuid", description="Unique ID for the feed.", required=True),
    InputArgument(name="page_no", description="The page number to fetch results from."),
    InputArgument(name="page_size", description="The number of indicators to fetch per page."),
]
SCREENSHOT_URL_INPUTS = [
    InputArgument(
        name="url",  # option 1
        description="URL for the screenshot.",
        required=True,
    )
]

""" COMMANDS OUTPUTS """

JOB_STATUS_OUTPUTS = [
    OutputArgument(name="get", output_type=str, description="URL to retrieve the job status."),
    OutputArgument(name="job_id", output_type=str, description="Unique identifier for the job."),
    OutputArgument(name="status", output_type=str, description="Current status of the job."),
]
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
    OutputArgument(
        name="reputation_history.date", output_type=int, description="The date of the subnet reputation record."
    ),
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
    OutputArgument(
        name="records.density", output_type=int, description="The density value associated with the query result."
    ),
    OutputArgument(name="records.nssrv", output_type=str, description="The name server (NS) for the query result."),
]
SEARCH_DOMAIN_OUTPUTS = [
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
]
DOMAIN_INFRATAGS_OUTPUTS = [
    OutputArgument(name="infratags.domain", output_type=str, description="The domain associated with the infratag."),
    OutputArgument(name="infratags.mode", output_type=str, description="The mode associated with the domain infratag."),
    OutputArgument(name="infratags.tag", output_type=str, description="The tag associated with the domain infratag."),
    OutputArgument(
        name="tag_clusters.25.domains",
        output_type=list,
        description="List of domains in the tag cluster with score 25.",
    ),
    OutputArgument(
        name="tag_clusters.25.match",
        output_type=str,
        description="The match string associated with the domains in the tag cluster with score 25.",
    ),
    OutputArgument(
        name="tag_clusters.50.domains",
        output_type=list,
        description="List of domains in the tag cluster with score 50.",
    ),
    OutputArgument(
        name="tag_clusters.50.match",
        output_type=str,
        description="The match string associated with the domains in the tag cluster with score 50.",
    ),
    OutputArgument(
        name="tag_clusters.75.domains",
        output_type=list,
        description="List of domains in the tag cluster with score 75.",
    ),
    OutputArgument(
        name="tag_clusters.75.match",
        output_type=str,
        description="The match string associated with the domains in the tag cluster with score 75.",
    ),
    OutputArgument(
        name="tag_clusters.100.domains",
        output_type=list,
        description="List of domains in the tag cluster with score 100.",
    ),
    OutputArgument(
        name="tag_clusters.100.match",
        output_type=str,
        description="The match string associated with the domains in the tag cluster with score 100.",
    ),
]
LIST_DOMAIN_OUTPUTS = [
    OutputArgument(name="domain", output_type=str, description="The domain name queried."),
    OutputArgument(
        name="last_seen", output_type=int, description="The last seen date of the domain in YYYYMMDD format."
    ),
    OutputArgument(name="query", output_type=str, description="The domain name used for the query."),
    OutputArgument(
        name="whois_age", output_type=int, description="The age of the domain in days based on WHOIS creation date."
    ),
    OutputArgument(
        name="first_seen", output_type=int, description="The first seen date of the domain in YYYYMMDD format."
    ),
    OutputArgument(name="is_new", output_type=bool, description="Indicates whether the domain is newly observed."),
    OutputArgument(
        name="zone", output_type=str, description="The top-level domain (TLD) or zone of the queried domain."
    ),
    OutputArgument(
        name="registrar", output_type=str, description="The registrar responsible for the domain registration."
    ),
    OutputArgument(name="age_score", output_type=int, description="A risk score based on the domain's age."),
    OutputArgument(
        name="whois_created_date",
        output_type=str,
        description="The WHOIS creation date of the domain in YYYY-MM-DD HH:MM:SS format.",
    ),
    OutputArgument(name="is_new_score", output_type=int, description="A risk score indicating how new the domain is."),
    OutputArgument(name="age", output_type=int, description="The age of the domain in days."),
]
DOMAIN_CERTIFICATE_OUTPUTS = [
    OutputArgument(name="domain", output_type=str, description="Queried domain."),
    OutputArgument(name="metadata", output_type=str, description="Metadata of the response"),
    OutputArgument(name="certificates.cert_index", output_type=int, description="Index of the certificate."),
    OutputArgument(name="certificates.chain", output_type=list, description="Certificate chain."),
    OutputArgument(name="certificates.date", output_type=int, description="Certificate issue date."),
    OutputArgument(name="certificates.domain", output_type=str, description="Primary domain of the certificate."),
    OutputArgument(
        name="certificates.domains", output_type=list, description="List of domains covered by the certificate."
    ),
    OutputArgument(
        name="certificates.fingerprint", output_type=str, description="SHA-1 fingerprint of the certificate."
    ),
    OutputArgument(
        name="certificates.fingerprint_md5", output_type=str, description="MD5 fingerprint of the certificate."
    ),
    OutputArgument(
        name="certificates.fingerprint_sha1", output_type=str, description="SHA-1 fingerprint of the certificate."
    ),
    OutputArgument(
        name="certificates.fingerprint_sha256", output_type=str, description="SHA-256 fingerprint of the certificate."
    ),
    OutputArgument(name="certificates.host", output_type=str, description="Host associated with the certificate."),
    OutputArgument(name="certificates.issuer", output_type=str, description="Issuer of the certificate."),
    OutputArgument(name="certificates.not_after", output_type=str, description="Expiration date of the certificate."),
    OutputArgument(
        name="certificates.not_before", output_type=str, description="Start date of the certificate validity."
    ),
    OutputArgument(
        name="certificates.serial_dec", output_type=str, description="Decimal representation of the serial number."
    ),
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
    OutputArgument(
        name="job_details.get", output_type=str, description="URL to get the data of the job or its status."
    ),
    OutputArgument(name="job_details.job_id", output_type=str, description="ID of the job."),
    OutputArgument(name="job_details.status", output_type=str, description="Status of the job."),
]
ENRICHMENT_OUTPUTS = [
    OutputArgument(name="value", output_type=str, description="Queried value"),
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
    OutputArgument(
        name="domain_string_frequency_probability.domain", output_type=str, description="Domain name analyzed."
    ),
    OutputArgument(
        name="domain_string_frequency_probability.domain_string_freq_probabilities",
        output_type=list,
        description="List of frequency probabilities for different domain string components.",
    ),
    OutputArgument(
        name="domain_string_frequency_probability.query", output_type=str, description="Domain name queried."
    ),
    OutputArgument(
        name="domain_urls.results_summary.alexa_rank", output_type=int, description="Alexa rank of the domain."
    ),
    OutputArgument(
        name="domain_urls.results_summary.alexa_top10k",
        output_type=bool,
        description="Indicates if the domain is in the Alexa top 10k.",
    ),
    OutputArgument(
        name="domain_urls.results_summary.alexa_top10k_score",
        output_type=int,
        description={repr("Score indicating domain's Alexa top 10k ranking.")},
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
        name="domain_urls.results_summary.url_shortner_score", output_type=int, description="Score of the shortned URL"
    ),
    OutputArgument(name="domaininfo.domain", output_type=str, description="Domain name analyzed."),
    OutputArgument(
        name="domaininfo.error", output_type=str, description="Error message if no data is available for the domain."
    ),
    OutputArgument(name="domaininfo.zone", output_type=str, description="TLD zone of the domain."),
    OutputArgument(name="domaininfo.registrar", output_type=str, description="registrar of the domain."),
    OutputArgument(
        name="domaininfo.whois_age", output_type=str, description="The age of the domain based on WHOIS records."
    ),
    OutputArgument(
        name="domaininfo.whois_created_date", output_type=str, description="The created date on WHOIS records."
    ),
    OutputArgument(
        name="domaininfo.query", output_type=str, description="The domain name that was queried in the system."
    ),
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
    OutputArgument(
        name="domaininfo.is_new", output_type=bool, description='Indicates whether the domain is considered "new.".'
    ),
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
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.domain", output_type=str, description="The nameservers of domain."
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server", output_type=str, description="Provided nameserver."
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_domain_density",
        output_type=int,
        description="Number of domains sharing this NS",
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_domains_listed",
        output_type=int,
        description="Number of listed domains using this NS.",
    ),
    OutputArgument(
        name="ns_reputation.ns_srv_reputation.ns_server_reputation",
        output_type=int,
        description="Reputation score for this NS",
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
    OutputArgument(
        name="scan_data.certificates.not_after", output_type=str, description="Expiry date of the certificate."
    ),
    OutputArgument(
        name="scan_data.certificates.not_before", output_type=str, description="Start date of the certificate validity."
    ),
    OutputArgument(
        name="scan_data.certificates.scan_date",
        output_type=str,
        description="The date when this certificate data was last scanned.",
    ),
    OutputArgument(
        name="scan_data.headers.response", output_type=str, description="HTTP response code for the domain scan."
    ),
    OutputArgument(
        name="scan_data.headers.hostname", output_type=str, description="The hostname that sent this response."
    ),
    OutputArgument(
        name="scan_data.headers.ip", output_type=str, description="The IP address responding to the request."
    ),
    OutputArgument(
        name="scan_data.headers.scan_date", output_type=str, description="The date when the headers were scanned."
    ),
    OutputArgument(name="scan_data.headers.headers.cache-control", output_type=str, description="HTTP cache-control"),
    OutputArgument(
        name='scan_data.headers.headers.content-length"',
        output_type=str,
        description="Content lenght of the HTTP response.",
    ),
    OutputArgument(
        name="scan_data.headers.headers.date", output_type=str, description="The date/time of the response."
    ),
    OutputArgument(
        name="scan_data.headers.headers.expires", output_type=str, description="Indicates an already expired response."
    ),
    OutputArgument(
        name="scan_data.headers.headers.server",
        output_type=str,
        description="The web server handling the request (Cloudflare proxy).",
    ),
    OutputArgument(
        name="scan_data.html.hostname", output_type=str, description="HTTP response code for the domain scan."
    ),
    OutputArgument(name="scan_data.html.html_body_murmur3", output_type=str, description="hash of the page content"),
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
    OutputArgument(
        name="scan_data.html.scan_date", output_type=str, description="The date when the headers were scanned."
    ),
    OutputArgument(
        name="scan_data.favicon.favicon2_md5", output_type=str, description="MD5 hash of a secondary favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.favicon2_mmh3", output_type=str, description="Murmur3 hash of a secondary favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.favicon2_path", output_type=str, description="The file path of the secondary favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.favicon_md5", output_type=str, description="MD5 hash of the primary favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.favicon_mmh3", output_type=str, description="Murmur3 hash of the primary favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.hostname", output_type=str, description="The hostname where this favicon was found."
    ),
    OutputArgument(
        name="scan_data.favicon.ip", output_type=str, description="The IP address associated with the favicon."
    ),
    OutputArgument(
        name="scan_data.favicon.scan_date", output_type=str, description="Date when this favicon was last scanned."
    ),
    OutputArgument(
        name="scan_data.jarm.hostname", output_type=str, description="The hostname where this jarm was found."
    ),
    OutputArgument(name="scan_data.jarm.ip", output_type=str, description="The IP address responding to the request."),
    OutputArgument(
        name="scan_data.jarm.jarm_hash",
        output_type=str,
        description="Unique identifier for the TLS configuration of the server.",
    ),
    OutputArgument(
        name="scan_data.jarm.scan_date", output_type=str, description="Date when this jarm was last scanned."
    ),
    OutputArgument(name="sp_risk_score", output_type=int, description="Overall risk score for the domain."),
    OutputArgument(
        name="sp_risk_score_explain.sp_risk_score_decider",
        output_type=str,
        description="Factor that determined the final risk score.",
    ),
    OutputArgument(
        name="ip2asn.asn", output_type=int, description="Autonomous System Number (ASN) associated with the IP."
    ),
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
    OutputArgument(
        name="ip2asn.asn_takedown_reputation", output_type=int, description="Takedown reputation score of the ASN."
    ),
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
        "(e.g., a reputable cloud provider or public service)",
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
    OutputArgument(
        name="ip2asn.ip_location.continent_name", output_type=str, description="The full name of the continent."
    ),
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
    OutputArgument(
        name="ip2asn.scan_data.certificates.is_expired", output_type=bool, description="Is certificate expired."
    ),
    OutputArgument(
        name="ip2asn.scan_data.certificates.scan_date", output_type=str, description="Scan date of the certificate."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon2_md5", output_type=str, description="MD5 hash of the second favicon."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon2_mmh3",
        output_type=int,
        description="MurmurHash3 value of the second favicon.",
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon_md5", output_type=str, description="MD5 hash of the favicon."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon_mmh3", output_type=int, description="MurmurHash3 value of the favicon."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.favicon2_path", output_type=str, description="Path to the second favicon file."
    ),
    OutputArgument(
        name="ip2asn.scan_data.favicon.scan_date", output_type=str, description="Scan date of favicon file."
    ),
    OutputArgument(
        name="ip2asn.scan_data.headers.response", output_type=str, description="HTTP response code from the scan."
    ),
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
    OutputArgument(
        name="ip2asn.scan_data.html.html_title", output_type=str, description="Title of the scanned HTML page."
    ),
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
LIST_IP_OUTPUTS = [
    OutputArgument(name="ip_is_dsl_dynamic", output_type=bool, description="Indicates if the IP is a DSL dynamic IP."),
    OutputArgument(
        name="ip_has_expired_certificate",
        output_type=bool,
        description="Indicates if the IP has an expired certificate.",
    ),
    OutputArgument(name="subnet_allocation_age", output_type=str, description="Age of the subnet allocation."),
    OutputArgument(name="asn_rank_score", output_type=int, description="Rank score of the ASN."),
    OutputArgument(name="asn_allocation_age", output_type=int, description="Age of the ASN allocation in days."),
    OutputArgument(name="sp_risk_score", output_type=int, description="Risk score of the service provider (SP)."),
    OutputArgument(
        name="asn_takedown_reputation_explain.ips_active",
        output_type=int,
        description="Number of active IPs in the ASN takedown reputation.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.ips_in_asn",
        output_type=int,
        description="Total number of IPs in the ASN.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.ips_num_listed",
        output_type=int,
        description="Number of IPs listed in the ASN takedown reputation.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.items_num_listed",
        output_type=int,
        description="Number of items listed in the ASN takedown reputation.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.lifetime_avg",
        output_type=int,
        description="Average lifetime of items in the ASN takedown reputation.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.lifetime_max",
        output_type=int,
        description="Maximum lifetime of items in the ASN takedown reputation.",
    ),
    OutputArgument(
        name="asn_takedown_reputation_explain.lifetime_total",
        output_type=int,
        description="Total lifetime of items in the ASN takedown reputation.",
    ),
    OutputArgument(name="ip_reputation_score", output_type=int, description="Reputation score of the IP."),
    OutputArgument(
        name="listing_score_feeds_explain", output_type=str, description="Explanation of the listing score feeds."
    ),
    OutputArgument(name="ip", output_type=str, description="The IP address being evaluated."),
    OutputArgument(name="density", output_type=int, description="Density score of the IP."),
    OutputArgument(name="benign_info.actor", output_type=str, description="Actor associated with the benign info."),
    OutputArgument(
        name="benign_info.known_benign", output_type=bool, description="Indicates if the IP is known benign."
    ),
    OutputArgument(name="benign_info.tags", output_type=str, description="Tags associated with the benign info."),
    OutputArgument(name="ip_reputation_explain", output_type=str, description="Explanation of the IP reputation."),
    OutputArgument(name="asn_allocation_date", output_type=int, description="The ASN allocation date."),
    OutputArgument(name="subnet_allocation_date", output_type=str, description="The subnet allocation date."),
    OutputArgument(name="asn_takedown_reputation", output_type=int, description="Reputation score of ASN takedown."),
    OutputArgument(
        name="ip_location.continent_code", output_type=str, description="Continent code of the IP location."
    ),
    OutputArgument(
        name="ip_location.continent_name", output_type=str, description="Continent name of the IP location."
    ),
    OutputArgument(name="ip_location.country_code", output_type=str, description="Country code of the IP location."),
    OutputArgument(
        name="ip_location.country_is_in_european_union",
        output_type=bool,
        description="Indicates if the country is in the European Union.",
    ),
    OutputArgument(name="ip_location.country_name", output_type=str, description="Country name of the IP location."),
    OutputArgument(name="date", output_type=int, description="Date associated with the IP data."),
    OutputArgument(name="subnet_reputation_score", output_type=int, description="Reputation score of the subnet."),
    OutputArgument(name="asn_rank", output_type=int, description="Rank of the ASN."),
    OutputArgument(name="listing_score_explain", output_type=str, description="Explanation of the listing score."),
    OutputArgument(name="asn_reputation_score", output_type=int, description="Reputation score of the ASN."),
    OutputArgument(name="ip_is_ipfs_node", output_type=bool, description="Indicates if the IP is an IPFS node."),
    OutputArgument(name="ip_reputation", output_type=int, description="Reputation score of the IP."),
    OutputArgument(
        name="subnet_reputation_explain", output_type=str, description="Explanation of the subnet reputation."
    ),
    OutputArgument(
        name="ip_is_dsl_dynamic_score", output_type=int, description="Score indicating if the IP is a DSL dynamic IP."
    ),
    OutputArgument(name="asn_reputation_explain", output_type=str, description="Explanation of the ASN reputation."),
    OutputArgument(
        name="ip_has_open_directory", output_type=bool, description="Indicates if the IP has an open directory."
    ),
    OutputArgument(name="ip_ptr", output_type=str, description="Pointer (PTR) record for the IP."),
    OutputArgument(name="listing_score", output_type=int, description="Listing score of the IP."),
    OutputArgument(name="malscore", output_type=int, description="Malware score associated with the IP."),
    OutputArgument(
        name="sinkhole_info.known_sinkhole_ip",
        output_type=bool,
        description="Indicates if the IP is a known sinkhole IP.",
    ),
    OutputArgument(
        name="sinkhole_info.tags", output_type=str, description="Tags associated with the sinkhole information."
    ),
    OutputArgument(name="subnet_reputation", output_type=int, description="Reputation score of the subnet."),
    OutputArgument(name="asn_reputation", output_type=int, description="Reputation score of the ASN."),
    OutputArgument(name="asn", output_type=int, description="Autonomous System Number (ASN) of the IP."),
    OutputArgument(
        name="sp_risk_score_explain.sp_risk_score_decider",
        output_type=str,
        description="Decider for the service provider risk score.",
    ),
    OutputArgument(name="asname", output_type=str, description="Name of the ASN."),
    OutputArgument(name="subnet", output_type=str, description="The subnet the IP belongs to."),
    OutputArgument(name="ip_is_tor_exit_node", output_type=bool, description="Indicates if the IP is a TOR exit node."),
    OutputArgument(
        name="asn_takedown_reputation_score", output_type=int, description="Reputation score of ASN takedown."
    ),
    OutputArgument(
        name="ip_flags.is_proxy", output_type=bool, description="Indicates if the IP is a proxy (True/False)."
    ),
    OutputArgument(
        name="ip_flags.is_sinkhole", output_type=bool, description="Indicates if the IP is a sinkhole (True/False)."
    ),
    OutputArgument(name="ip_flags.is_vpn", output_type=bool, description="Indicates if the IP is a VPN (True/False)."),
    OutputArgument(
        name="ip_flags.proxy_tags", output_type=list, description="List of proxy-related tags or null if not a proxy."
    ),
    OutputArgument(
        name="ip_flags.vpn_tags", output_type=list, description="List of VPN-related tags or null if not a VPN."
    ),
]
ASN_REPUTATION_OUTPUTS = [
    OutputArgument(
        name="asn",
        output_type=int,
        description="Autonomous System Number (ASN) associated with the reputation history.",
    ),
    OutputArgument(
        name="asn_reputation", output_type=int, description="Reputation score of the ASN at a given point in time."
    ),
    OutputArgument(
        name="asn_reputation_explain.ips_in_asn", output_type=int, description="Total number of IPs within the ASN."
    ),
    OutputArgument(
        name="asn_reputation_explain.ips_num_active",
        output_type=int,
        description="Number of actively used IPs in the ASN.",
    ),
    OutputArgument(
        name="asn_reputation_explain.ips_num_listed",
        output_type=int,
        description="Number of IPs in the ASN that are listed as malicious.",
    ),
    OutputArgument(name="asname", output_type=str, description="Name of the ASN provider or organization."),
    OutputArgument(
        name="date", output_type=int, description="Date of the recorded reputation history in YYYYMMDD format."
    ),
]
ASN_TAKEDOWN_REPUTATION_OUTPUTS = [
    OutputArgument(
        name="takedown_reputation.asname", output_type=str, description="The name of the Autonomous System (AS)."
    ),
    OutputArgument(name="takedown_reputation.asn", output_type=str, description="The Autonomous System Number (ASN)."),
    OutputArgument(
        name="takedown_reputation.allocation_age", output_type=int, description="The age of the ASN allocation in days."
    ),
    OutputArgument(
        name="takedown_reputation.allocation_date",
        output_type=int,
        description="The date when the ASN was allocated (YYYYMMDD).",
    ),
    OutputArgument(
        name="takedown_reputation.asn_takedown_reputation",
        output_type=int,
        description="The takedown reputation score for the ASN.",
    ),
    OutputArgument(
        name="takedown_reputation.asn_takedown_reputation_explain.ips_in_asn",
        output_type=int,
        description="The total number of IP addresses associated with the ASN.",
    ),
    OutputArgument(
        name="takedown_reputation.asn_takedown_reputation_explain.ips_num_listed",
        output_type=int,
        description="The number of IP addresses within the ASN that are flagged or listed in security threat databases.",
    ),
    OutputArgument(
        name="takedown_reputation.asn_takedown_reputation_explain.items_num_listed",
        output_type=int,
        description="The total number of security-related listings associated with the ASN, including IP addresses and domains.",
    ),
    OutputArgument(
        name="takedown_reputation.asn_takedown_reputation_explain.listings_max_age",
        output_type=int,
        description="The maximum age (in hours) of the listings, indicating how recent the flagged IPs/domains are.",
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
FORWARD_PADNS_OUTPUTS = [
    OutputArgument(name="qname", output_type=str, description="The DNS record name that was looked up."),
    OutputArgument(name="qtype", output_type=str, description="The DNS record type queried (e.g., NS)."),
    OutputArgument(
        name="records.answer", output_type=str, description="The answer (e.g., name server) for the DNS record."
    ),
    OutputArgument(name="records.count", output_type=int, description="The number of occurrences for this DNS record."),
    OutputArgument(
        name="records.first_seen", output_type=str, description="The timestamp when this DNS record was first seen."
    ),
    OutputArgument(
        name="records.last_seen", output_type=str, description="The timestamp when this DNS record was last seen."
    ),
    OutputArgument(name="records.nshash", output_type=str, description="Unique hash for the DNS record."),
    OutputArgument(
        name="records.query", output_type=str, description="The DNS record query name (e.g., silentpush.com)."
    ),
    OutputArgument(name="records.ttl", output_type=int, description="Time to live (TTL) value for the DNS record."),
    OutputArgument(name="records.type", output_type=str, description="The type of the DNS record (e.g., NS)."),
]
REVERSE_PADNS_OUTPUTS = [
    OutputArgument(name="qname", output_type=str, description="The DNS record name looked up."),
    OutputArgument(name="qtype", output_type=str, description="The type of the DNS record."),
    OutputArgument(name="records.answer", output_type=str, description="The answer for the DNS query."),
    OutputArgument(name="records.count", output_type=int, description="The number of occurrences of the DNS record."),
    OutputArgument(
        name="records.first_seen", output_type=str, description="Timestamp of when the record was first seen."
    ),
    OutputArgument(
        name="records.last_seen", output_type=str, description="Timestamp of the most recent occurrence of the record."
    ),
    OutputArgument(name="records.nshash", output_type=str, description="The hash of the NS record."),
    OutputArgument(name="records.query", output_type=str, description="The DNS query associated with the record."),
    OutputArgument(name="records.ttl", output_type=int, description="Time-to-live (TTL) of the DNS record."),
    OutputArgument(name="records.type", output_type=str, description="The type of DNS record (e.g., NS)."),
]
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
    OutputArgument(
        name="body_analysis.footer_sha256", output_type=str, description="SHA-256 hash of the footer content."
    ),
    OutputArgument(name="body_analysis.google-GA4", output_type=list, description="List of Google GA4 identifiers."),
    OutputArgument(
        name="body_analysis.google-UA", output_type=list, description="List of Google Universal Analytics identifiers."
    ),
    OutputArgument(
        name="body_analysis.google-adstag", output_type=list, description="List of Google adstag identifiers."
    ),
    OutputArgument(
        name="body_analysis.header_sha256", output_type=list, description="SHA-256 hash of the header content."
    ),
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
    OutputArgument(
        name="body_analysis.telegram", output_type=list, description="List of Telegram-related information."
    ),
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
    OutputArgument(
        name="header.content-length", output_type=str, description="Content length from HTTP response header."
    ),
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
    OutputArgument(
        name="origin_hostname", output_type=str, description="Origin hostname associated with the scan data."
    ),
    OutputArgument(name="origin_ip", output_type=str, description="Origin IP address of the scan."),
    OutputArgument(name="origin_jarm", output_type=str, description="JARM hash value of the origin domain."),
    OutputArgument(
        name="origin_ssl", output_type=dict, description="SSL certificate information for the origin domain."
    ),
    OutputArgument(name="origin_ssl.SHA256", output_type=str, description="SHA256 of the SSL certificate."),
    OutputArgument(name="origin_ssl.subject", output_type=dict, description="Subject of the SSL certificate."),
    OutputArgument(
        name="origin_ssl.subject.common_name", output_type=str, description="Common name in the SSL certificate."
    ),
    OutputArgument(name="port", output_type=int, description="Port used during the scan."),
    OutputArgument(name="redirect", output_type=bool, description="Indicates if a redirect occurred during the scan."),
    OutputArgument(name="redirect_count", output_type=int, description="Count of redirects encountered."),
    OutputArgument(
        name="redirect_list", output_type=list, description="List of redirect URLs encountered during the scan."
    ),
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
    OutputArgument(
        name="origin_ssl.expired", output_type=bool, description="Indicates if the SSL certificate is expired."
    ),
    OutputArgument(
        name="origin_ssl.issuer.common_name", output_type=str, description="Issuer common name for SSL certificate."
    ),
    OutputArgument(
        name="origin_ssl.issuer.country", output_type=str, description="Issuer country for SSL certificate."
    ),
    OutputArgument(
        name="origin_ssl.issuer.organization", output_type=str, description="Issuer organization for SSL certificate."
    ),
    OutputArgument(name="origin_ssl.not_after", output_type=str, description="Expiration date of the SSL certificate."),
    OutputArgument(
        name="origin_ssl.not_before", output_type=str, description="Start date of the SSL certificate validity."
    ),
    OutputArgument(
        name="origin_ssl.sans",
        output_type=list,
        description="List of Subject Alternative Names (SANs) for the SSL certificate.",
    ),
    OutputArgument(name="origin_ssl.sans_count", output_type=int, description="Count of SANs for the SSL certificate."),
    OutputArgument(
        name="origin_ssl.serial_number", output_type=str, description="Serial number of the SSL certificate."
    ),
    OutputArgument(
        name="origin_ssl.sigalg", output_type=str, description="Signature algorithm used for the SSL certificate."
    ),
    OutputArgument(
        name="origin_ssl.subject.common_name",
        output_type=str,
        description="Subject common name for the SSL certificate.",
    ),
    OutputArgument(
        name="origin_ssl.subject_key_id", output_type=str, description="Subject Key Identifier for SSL certificate."
    ),
    OutputArgument(name="origin_ssl.valid", output_type=bool, description="Indicates if the SSL certificate is valid."),
    OutputArgument(
        name="origin_ssl.wildcard", output_type=bool, description="Indicates if the SSL certificate is a wildcard."
    ),
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
    OutputArgument(
        name="ssl.authority_key_id", output_type=str, description="Authority Key Identifier for SSL certificate."
    ),
    OutputArgument(name="ssl.expired", output_type=bool, description="Indicates if the SSL certificate is expired."),
    OutputArgument(
        name="ssl.issuer.common_name", output_type=str, description="Issuer common name for SSL certificate."
    ),
    OutputArgument(name="ssl.issuer.country", output_type=str, description="Issuer country for SSL certificate."),
    OutputArgument(
        name="ssl.issuer.organization", output_type=str, description="Issuer organization for SSL certificate."
    ),
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
    OutputArgument(
        name="ssl.subject.common_name", output_type=str, description="Subject common name for the SSL certificate."
    ),
    OutputArgument(
        name="ssl.subject_key_id", output_type=str, description="Subject Key Identifier for SSL certificate."
    ),
    OutputArgument(name="ssl.valid", output_type=bool, description="Indicates if the SSL certificate is valid."),
    OutputArgument(
        name="ssl.wildcard", output_type=bool, description="Indicates if the SSL certificate is a wildcard."
    ),
    OutputArgument(name="body_analysis.SHV", output_type=str, description="Unique identifier for body analysis."),
    OutputArgument(name="body_analysis.body_sha256", output_type=str, description="SHA-256 hash of the body content."),
    OutputArgument(name="body_analysis.google-GA4", output_type=list, description="List of Google GA4 tracking IDs."),
    OutputArgument(
        name="body_analysis.google-UA", output_type=list, description="List of Google Universal Analytics tracking IDs."
    ),
    OutputArgument(
        name="body_analysis.google-adstag", output_type=list, description="List of Google Adstag tracking IDs."
    ),
    OutputArgument(
        name="body_analysis.js_sha256", output_type=list, description="List of SHA-256 hashes of JavaScript files."
    ),
    OutputArgument(
        name="body_analysis.js_ssdeep", output_type=list, description="List of ssdeep fuzzy hashes of JavaScript files."
    ),
]
FUTURE_ATTACK_INDICATOR_OUTPUTS = [
    OutputArgument(name="feed_uuid", output_type=str, description="Unique identifier for the feed."),
    OutputArgument(name="page_no", output_type=int, description="Current page number for pagination."),
    OutputArgument(name="page_size", output_type=int, description="Number of items to be retrieved per page."),
    OutputArgument(
        name="indicators.total_ioc",
        output_type=int,
        description="Total number of Indicators of Compromise (IOCs) associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.total", output_type=int, description="Total occurrences of the indicator across all sources."
    ),
    OutputArgument(
        name="indicators.total_source_score",
        output_type=int,
        description="Cumulative score assigned to the indicator by all sources.",
    ),
    OutputArgument(
        name="indicators.name",
        output_type=str,
        description="Name associated with the indicator, such as a domain name.",
    ),
    OutputArgument(
        name="indicators.total_custom",
        output_type=int,
        description="Total number of custom indicators for the specific entry.",
    ),
    OutputArgument(
        name="indicators.source_name", output_type=str, description="Name of the source providing the indicator."
    ),
    OutputArgument(
        name="indicators.first_seen_on",
        output_type=str,
        description="Date and time when the indicator was first observed.",
    ),
    OutputArgument(
        name="indicators.last_seen_on",
        output_type=str,
        description="Date and time when the indicator was last observed.",
    ),
    OutputArgument(
        name="indicators.type", output_type=str, description="Type of the indicator (e.g., domain, IP address, URL)."
    ),
    OutputArgument(name="indicators.uuid", output_type=str, description="Unique identifier assigned to the indicator."),
    OutputArgument(
        name="indicators.ioc_template",
        output_type=str,
        description="Template type describing the indicator (e.g., domain template).",
    ),
    OutputArgument(
        name="indicators.ioc_uuid",
        output_type=str,
        description="Unique identifier for the IOC related to the indicator.",
    ),
    OutputArgument(
        name="indicators.source_vendor_name",
        output_type=str,
        description="Name of the vendor providing the indicator source (e.g., Silent Push).",
    ),
    OutputArgument(
        name="indicators.source_uuid", output_type=str, description="Unique identifier for the source of the indicator."
    ),
    OutputArgument(
        name="indicators.total_ioc",
        output_type=int,
        description="Total count of Indicators of Compromise associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.collected_tags", output_type=list, description="Tags associated with the indicator."
    ),
    OutputArgument(
        name="indicators.listing_score",
        output_type=int,
        description="Score assigned by the source indicating the severity or importance of the indicator.",
    ),
    OutputArgument(
        name="indicators.sp_risk_score",
        output_type=int,
        description="Risk score calculated by the source for the indicator, reflecting its potential threat level.",
    ),
    OutputArgument(
        name="indicators.ip_is_tor_exit_node",
        output_type=bool,
        description="Indicates whether the IP address is a known TOR exit node.",
    ),
    OutputArgument(
        name="indicators.ip_is_dsl_dynamic",
        output_type=bool,
        description="Indicates whether the IP address is a DSL dynamic IP.",
    ),
    OutputArgument(
        name="indicators.ip_reputation_score",
        output_type=int,
        description="Reputation score assigned to the IP address based on its history and activities.",
    ),
    OutputArgument(
        name="indicators.known_sinkhole_ip",
        output_type=str,
        description="Indicates if the IP address is associated with a known sinkhole.",
    ),
    OutputArgument(
        name="indicators.known_benign",
        output_type=int,
        description="Indicates whether the indicator is known to be benign or harmless.",
    ),
    OutputArgument(
        name="indicators.asn_rank_score",
        output_type=int,
        description="Score indicating the reputation rank of the ASN.",
    ),
    OutputArgument(
        name="indicators.asn_reputation_score",
        output_type=int,
        description="Reputation score assigned to the ASN based on its activities.",
    ),
    OutputArgument(
        name="indicators.ip_is_dsl_dynamic_score",
        output_type=int,
        description="Score indicating the likelihood of the IP being a DSL dynamic IP.",
    ),
    OutputArgument(
        name="indicators.subnet_reputation_score",
        output_type=int,
        description="Reputation score assigned to a subnet based on its history and activities.",
    ),
    OutputArgument(
        name="indicators.asn_takedown_reputation_score",
        output_type=int,
        description="Reputation score of the ASN considering takedown activities or abuse reports.",
    ),
    OutputArgument(
        name="indicators.asn",
        output_type=int,
        description="Autonomous System Number (ASN) associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.density",
        output_type=int,
        description="Indicator density score based on traffic or other relevant factors.",
    ),
    OutputArgument(
        name="indicators.asn_rank",
        output_type=int,
        description="Rank of the ASN indicating its reputation or trustworthiness.",
    ),
    OutputArgument(
        name="indicators.malscore",
        output_type=int,
        description="Maliciousness score assigned to the indicator based on threat analysis.",
    ),
    OutputArgument(
        name="indicators.asn_reputation", output_type=int, description="Reputation score associated with the ASN."
    ),
    OutputArgument(
        name="indicators.subnet_reputation", output_type=int, description="Reputation score associated with the subnet."
    ),
    OutputArgument(
        name="indicators.asn_allocation_age", output_type=int, description="Age of the ASN allocation in days."
    ),
    OutputArgument(
        name="indicators.subnet_allocation_age", output_type=int, description="Age of the subnet allocation in days."
    ),
    OutputArgument(
        name="indicators.asn_takedown_reputation",
        output_type=int,
        description="Reputation score of the ASN considering takedown reports or abuse.",
    ),
    OutputArgument(name="indicators.ipv4", output_type=str, description="IPv4 address associated with the indicator."),
    OutputArgument(
        name="indicators.asname",
        output_type=str,
        description="Autonomous System Name (ASName) associated with the ASN.",
    ),
    OutputArgument(
        name="indicators.ip_ptr",
        output_type=str,
        description="PTR (reverse DNS) record associated with the IP address.",
    ),
    OutputArgument(name="indicators.subnet", output_type=str, description="Subnet associated with the indicator."),
    OutputArgument(
        name="indicators.country_code",
        output_type=int,
        description="Country code associated with the indicator (e.g., US, CA).",
    ),
    OutputArgument(
        name="indicators.continent_code",
        output_type=int,
        description="Continent code associated with the indicator (e.g., NA, EU).",
    ),
    OutputArgument(
        name="indicators.it_exists",
        output_type=bool,
        description="Indicates if the indicator currently exists in the dataset.",
    ),
    OutputArgument(
        name="indicators.is_new", output_type=bool, description="Indicates if the indicator is newly detected."
    ),
    OutputArgument(
        name="indicators.is_alexa_top10k",
        output_type=bool,
        description="Indicates if the domain is part of the Alexa Top 10K list.",
    ),
    OutputArgument(
        name="indicators.is_dynamic_domain",
        output_type=bool,
        description="Indicates if the domain is classified as dynamic.",
    ),
    OutputArgument(
        name="indicators.is_url_shortener",
        output_type=bool,
        description="Indicates if the URL is associated with a URL shortener service.",
    ),
    OutputArgument(
        name="indicators.is_parked", output_type=bool, description="Indicates if the domain is a parked domain."
    ),
    OutputArgument(
        name="indicators.is_expired", output_type=bool, description="Indicates if the domain registration has expired."
    ),
    OutputArgument(
        name="indicators.is_sinkholed",
        output_type=bool,
        description="Indicates if the domain is associated with a sinkhole operation.",
    ),
    OutputArgument(
        name="indicators.ns_entropy_score",
        output_type=int,
        description="Entropy score of the nameserver, indicating randomness or irregularity.",
    ),
    OutputArgument(
        name="indicators.age_score",
        output_type=int,
        description="Score indicating the age of the domain, with higher scores for older domains.",
    ),
    OutputArgument(
        name="indicators.is_new_score",
        output_type=bool,
        description="Score indicating the likelihood of the domain being newly registered.",
    ),
    OutputArgument(
        name="indicators.ns_avg_ttl_score",
        output_type=int,
        description="Score representing the average TTL of the nameservers.",
    ),
    OutputArgument(
        name="indicators.ns_reputation_max", output_type=int, description="Maximum reputation score of the nameservers."
    ),
    OutputArgument(
        name="indicators.ns_reputation_score",
        output_type=int,
        description="Overall reputation score of the nameservers.",
    ),
    OutputArgument(
        name="indicators.avg_probability_score",
        output_type=int,
        description="Average probability score indicating the likelihood of malicious activity.",
    ),
    OutputArgument(
        name="indicators.alexa_top10k_score",
        output_type=int,
        description="Score indicating the rank within the Alexa Top 10K list.",
    ),
    OutputArgument(
        name="indicators.url_shortener_score",
        output_type=int,
        description="Score indicating the likelihood of the URL being a URL shortener.",
    ),
    OutputArgument(
        name="indicators.dynamic_domain_score",
        output_type=int,
        description="Score indicating the likelihood of the domain being dynamic.",
    ),
    OutputArgument(
        name="indicators.ns_entropy",
        output_type=int,
        description="Entropy value of the nameserver, indicating randomness or irregularity.",
    ),
    OutputArgument(name="indicators.age", output_type=int, description="Age of the domain in days."),
    OutputArgument(
        name="indicators.whois_age", output_type=int, description="Age of the domain based on the WHOIS creation date."
    ),
    OutputArgument(
        name="indicators.alexa_rank",
        output_type=int,
        description="Alexa rank of the domain, indicating its popularity.",
    ),
    OutputArgument(
        name="indicators.asn_diversity",
        output_type=int,
        description="Diversity score of the ASN, indicating the variety of ASNs associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.ip_diversity_all",
        output_type=int,
        description="Count of all unique IP addresses associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.ip_diversity_groups",
        output_type=int,
        description="Count of unique IP address groups associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.avg_probability",
        output_type=float,
        description="Average probability indicating the likelihood of malicious activity.",
    ),
    OutputArgument(
        name="indicators.whois_created_date",
        output_type=str,
        description="Creation date of the domain from WHOIS records.",
    ),
    OutputArgument(name="indicators.domain", output_type=str, description="Domain name associated with the indicator."),
    OutputArgument(
        name="indicators.subdomain",
        output_type=str,
        description="Subdomain associated with the indicator, if applicable.",
    ),
    OutputArgument(name="indicators.host", output_type=str, description="Host associated with the indicator."),
    OutputArgument(
        name="indicators.nameservers_tags",
        output_type=str,
        description="Tags related to the nameservers associated with the indicator.",
    ),
    OutputArgument(
        name="indicators.source_false_positive_ratio",
        output_type=int,
        description="Ratio of false positives reported by the source.",
    ),
    OutputArgument(
        name="indicators.source_true_positive_ratio",
        output_type=int,
        description="Ratio of true positives reported by the source.",
    ),
    OutputArgument(
        name="indicators.source_last_updated_score",
        output_type=int,
        description="Score indicating the last update time of the source.",
    ),
    OutputArgument(
        name="indicators.source_frequency_score",
        output_type=int,
        description="Score representing the frequency of updates from the source.",
    ),
    OutputArgument(
        name="indicators.source_accuracy_score",
        output_type=int,
        description="Score indicating the accuracy of the source reporting.",
    ),
    OutputArgument(
        name="indicators.source_geographic_spread_score",
        output_type=int,
        description="Score indicating the geographic spread of the indicator.",
    ),
    OutputArgument(
        name="indicators.source_custom_score",
        output_type=int,
        description="Custom score provided by the source for the indicator.",
    ),
    OutputArgument(
        name="indicators.source_score",
        output_type=int,
        description="Overall score assigned by the source to the indicator.",
    ),
    OutputArgument(
        name="indicators.source_frequency",
        output_type=int,
        description="Frequency of the indicator appearance in the source data.",
    ),
    OutputArgument(
        name="indicators.source_geographic_spread_explain",
        output_type=dict,
        description="Explanation of the geographic spread of the indicator as provided by the source.",
    ),
]
SCREENSHOT_URL_OUTPUTS = [
    OutputArgument(name="file_id", output_type=str, description="Unique identifier for the generated screenshot file."),
    OutputArgument(name="file_name", output_type=str, description="Name of the screenshot file."),
    OutputArgument(name="screenshot_url", output_type=str, description="URL to access the generated screenshot."),
    OutputArgument(name="status", output_type=str, description="Status of the screenshot generation process."),
    OutputArgument(name="status_code", output_type=int, description="HTTP status code of the response."),
    OutputArgument(name="url", output_type=str, description="The URL that was used to generate the screenshot."),
]


metadata_collector = YMLMetadataCollector(
    integration_name="SilentPush",
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
    docker_image="demisto/python3:3.11.10.116949",
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

    This Client implements API calls and does not contain any XSOAR logic.
    It should only perform requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initializes the client with the necessary parameters.
        Args:
            base_url (str): The base URL for the SilentPush API.
            api_key (str): The API key for authentication.
            verify (bool): Flag to determine whether to verify SSL certificates (default True).
            proxy (bool): Flag to determine whether to use a proxy (default False).
        """
        full_base_url = base_url.rstrip("/") + "/api/v1/merge-api/"
        super().__init__(full_base_url, verify, proxy)

        self.base_url = full_base_url
        self.verify = verify
        self.proxies = handle_proxy() if proxy else None  # ✅ Add this line

        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    def _http_request(  # type: ignore[override]
        self, method: str, url_suffix: str = "", params: dict = None, data: dict = None, url: str = None, **kwargs
    ) -> Any:
        """
        Perform an HTTP request to the SilentPush API.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST').
            url_suffix (str): The endpoint suffix to append to the base URL.
            params (dict, optional): Query parameters to include in the request.
            data (dict, optional): JSON data to send in the request body.

        Returns:
            Any: Parsed JSON response from the API.

        Raises:
            DemistoException: If the response is not JSON or if the request fails.
        """
        # Properly build the full URL using override if provided
        full_url = url if url else f"{self.base_url.rstrip('/')}/{url_suffix.lstrip('/')}"

        try:
            response = requests.request(
                method=method,
                url=full_url,  # <<< this must be full_url, not something else
                headers=self._headers,
                verify=self.verify,
                params=params,
                json=data,
                proxies=self.proxies,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise DemistoException(f"Request error: {str(e)}")

    def get_job_status(self, job_id: str, params: dict) -> dict[str, Any]:
        """
        Retrieve the status of a specific job.

        Args:
            job_id (str): The unique identifier of the job to check.
            params (dict, optional): Optional parameters to include in the request (max_wait, etc.).

        Returns:
            Dict[str, Any]: Job status information.

        Raises:
            ValueError: If max_wait is invalid.
        """
        url_suffix = f"{JOB_STATUS}/{job_id}"
        max_wait = arg_to_number(params.get("max_wait", 20))  # type ignore

        if max_wait is not None and not (0 <= max_wait <= 25):
            raise ValueError("max_wait must be an integer between 0 and 25")

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_nameserver_reputation(self, nameserver: str, explain: bool = False, limit: int = None):
        """
        Retrieve historical reputation data for the specified nameserver.

        Args:
            nameserver (str): The nameserver for which the reputation data is to be fetched.
            explain (bool): Whether to include detailed calculation explanations.
            limit (int): Maximum number of reputation entries to return.

        Returns:
            list: A list of reputation entries (each being a dict) for the given nameserver.
        """
        url_suffix = f"{NAMESERVER_REPUTATION}/{nameserver}"

        params = {"explain": int(bool(explain)), "limit": limit}

        remove_nulls_from_dictionary(params)

        response = self._http_request(method="GET", url_suffix=url_suffix, params=params)

        if isinstance(response, str):
            try:
                response = json.loads(response)
            except Exception as e:
                raise ValueError(f"Unable to parse JSON from response: {e}")

        return response.get("response", {}).get("ns_server_reputation_history", [])

    def get_subnet_reputation(self, subnet: str, explain: bool = False, limit: int | None = None) -> dict[str, Any]:
        """
        Retrieve reputation history for a specific subnet.

        Args:
            subnet (str): The subnet to query.
            explain (bool, optional): Whether to include detailed explanations. Defaults to False.
            limit (int, optional): Maximum number of results to return. Defaults to None.

        Returns:
            Dict[str, Any]: Subnet reputation history information.
        """
        url_suffix = f"{SUBNET_REPUTATION}/{subnet}"

        params = {"explain": str(explain).lower() if explain else None, "limit": limit}
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_asns_for_domain(self, domain: str) -> dict[str, Any]:
        """
        Retrieve Autonomous System Numbers (ASNs) associated with the specified domain.

        Args:
            domain (str): The domain to retrieve ASNs for.

        Returns:
            Dict[str, Any]: A dictionary containing the ASN information for the domain.
        """
        url_suffix = f"{ASNS_DOMAIN}/{domain}"

        # Send the request and return the response directly
        return self._http_request(method="GET", url_suffix=url_suffix)

    def density_lookup(self, qtype: str, query: str, **kwargs) -> dict[str, Any]:
        """
        Perform a density lookup based on various query types and optional parameters.

        Args:
            qtype (str): Query type to perform the lookup. Options include: nssrv, mxsrv, nshash, mxhash, ipv4, ipv6, asn, chv.
            query (str): The value to look up.
            **kwargs: Optional parameters (e.g., filters) for scoping the lookup.

        Returns:
            Dict[str, Any]: The results of the density lookup, containing relevant information based on the query.
        """
        url_suffix = f"{DENSITY_LOOKUP}/{qtype}/{query}"

        params = kwargs
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def search_domains(
        self,
        query: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        risk_score_min: int | None = None,
        risk_score_max: int | None = None,
        limit: int | None = 100,
        domain_regex: str | None = None,
        name_server: str | None = None,
        asnum: int | None = None,
        asname: str | None = None,
        min_ip_diversity: int | None = None,
        registrar: str | None = None,
        min_asn_diversity: int | None = None,
        certificate_issuer: str | None = None,
        whois_date_after: str | None = None,
        skip: int | None = None,
    ) -> dict:
        """
        Search for domains based on various filtering criteria.

        Args:
            query (str): Domain search query.
            start_date (str, optional): Start date for domain search (YYYY-MM-DD).
            end_date (str, optional): End date for domain search (YYYY-MM-DD).
            risk_score_min (int, optional): Minimum risk score filter.
            risk_score_max (int, optional): Maximum risk score filter.
            limit (int): Maximum number of results to return (defaults to 100).
            domain_regex (str, optional): Regular expression to filter domains.
            name_server (str, optional): Name server filter.
            asnum (int, optional): Autonomous System Number (ASN) filter.
            asname (str, optional): ASN Name filter.
            min_ip_diversity (int, optional): Minimum IP diversity filter.
            registrar (str, optional): Domain registrar filter.
            min_asn_diversity (int, optional): Minimum ASN diversity filter.
            certificate_issuer (str, optional): Filter domains by certificate issuer.
            whois_date_after (str, optional): Filter domains based on WHOIS date (YYYY-MM-DD).
            skip (int, optional): Number of results to skip.

        Returns:
            dict: Search results matching the specified criteria.
        """
        url_suffix = SEARCH_DOMAIN

        # Prepare parameters and filter out None values using remove_nulls_from_dictionary function
        params = {
            "domain": query,
            "start_date": start_date,
            "end_date": end_date,
            "risk_score_min": risk_score_min,
            "risk_score_max": risk_score_max,
            "limit": limit,
            "domain_regex": domain_regex,
            "name_server": name_server,
            "asnum": asnum,
            "asname": asname,
            "min_ip_diversity": min_ip_diversity,
            "registrar": registrar,
            "asn_diversity_min": min_asn_diversity,
            "cert_issuer": certificate_issuer,
            "whois_date_after": whois_date_after,
            "skip": skip,
        }
        remove_nulls_from_dictionary(params)

        # Make the request with the filtered parameters
        return self._http_request("GET", url_suffix, params=params)

    def list_domain_infratags(
        self,
        domains: list,
        cluster: bool = False,
        mode: str = "live",
        match: str = "self",
        as_of: str | None = None,
        origin_uid: str | None = None,
    ) -> dict:
        """
        Retrieve infrastructure tags for specified domains, supporting both GET and POST methods.

        Args:
            domains (list): List of domains to fetch infrastructure tags for.
            cluster (bool): Whether to include cluster information (default: False).
            mode (str): Tag retrieval mode (default: 'live').
            match (str): Matching criteria (default: 'self').
            as_of (Optional[str]): Specific timestamp for tag retrieval.
            origin_uid (Optional[str]): Unique identifier for the API user.

        Returns:
            dict: API response containing infratags and optional tag clusters.
        """
        url_suffix = DOMAIN_INFRATAGS

        payload = {
            "domains": domains,
            "mode": mode,
            "match": match,
            "clusters": int(cluster),
            "as_of": as_of,
            "origin_uid": origin_uid,
        }
        remove_nulls_from_dictionary(payload)

        return self._http_request(method="POST", url_suffix=url_suffix, data=payload)

    def fetch_bulk_domain_info(self, domains: list[str]) -> dict[str, Any]:
        """Fetch basic domain information for a list of domains."""
        response = self._http_request(method="POST", url_suffix=DOMAIN_INFO, data={"domains": domains})
        domain_info_list = response.get("response", {}).get("domaininfo", [])
        return {item["domain"]: item for item in domain_info_list}

    def fetch_risk_scores(self, domains: list[str]) -> dict[str, Any]:
        """Fetch risk scores for a list of domains."""
        response = self._http_request(method="POST", url_suffix=RISK_SCORE, data={"domains": domains})
        risk_score_list = response.get("response", [])
        return {item["domain"]: item for item in risk_score_list}

    def fetch_whois_info(self, domain: str) -> dict[str, Any]:
        """Fetch WHOIS information for a single domain."""
        try:
            response = self._http_request(method="GET", url_suffix=f"{WHOIS}/{domain}")
            whois_data = response.get("response", {}).get("whois", [{}])[0]

            return {
                "Registrant Name": whois_data.get("name", "N/A"),
                "Registrant Organization": whois_data.get("org", "N/A"),
                "Registrant Address": (
                    ", ".join(whois_data.get("address", []))
                    if isinstance(whois_data.get("address"), list)
                    else whois_data.get("address", "N/A")
                ),
                "Registrant City": whois_data.get("city", "N/A"),
                "Registrant State": whois_data.get("state", "N/A"),
                "Registrant Country": whois_data.get("country", "N/A"),
                "Registrant Zipcode": whois_data.get("zipcode", "N/A"),
                "Creation Date": whois_data.get("created", "N/A"),
                "Updated Date": whois_data.get("updated", "N/A"),
                "Expiration Date": whois_data.get("expires", "N/A"),
                "Registrar": whois_data.get("registrar", "N/A"),
                "WHOIS Server": whois_data.get("whois_server", "N/A"),
                "Nameservers": ", ".join(whois_data.get("nameservers", [])),
                "Emails": ", ".join(whois_data.get("emails", [])),
            }
        except Exception as e:
            return {"error": str(e)}

    def list_domain_information(
        self, domains: list[str], fetch_risk_score: bool | None = False, fetch_whois_info: bool | None = False
    ) -> dict[str, Any]:
        """
        Retrieve domain information along with optional risk scores and WHOIS data.

        Args:
            domains (List[str]): List of domains to get information for.
            fetch_risk_score (bool, optional): Whether to fetch risk scores. Defaults to False.
            fetch_whois_info (bool, optional): Whether to fetch WHOIS information. Defaults to False.

        Returns:
            Dict[str, Any]: Dictionary containing domain information with optional risk scores and WHOIS data.

        Raises:
            ValueError: If more than 100 domains are provided.
        """
        if len(domains) > 100:
            raise ValueError("Maximum of 100 domains can be submitted in a single request.")

        domain_info_dict = self.fetch_bulk_domain_info(domains)

        risk_score_dict = self.fetch_risk_scores(domains) if fetch_risk_score else {}

        whois_info_dict = {domain: self.fetch_whois_info(domain) for domain in domains} if fetch_whois_info else {}

        results = []
        for domain in domains:
            domain_info = {
                "domain": domain,
                **domain_info_dict.get(domain, {}),
            }

            if fetch_risk_score:
                risk_data = risk_score_dict.get(domain, {})
                domain_info.update(
                    {
                        "risk_score": risk_data.get("sp_risk_score", "N/A"),
                        "risk_score_explanation": risk_data.get("sp_risk_score_explain", "N/A"),
                    }
                )

            if fetch_whois_info:
                domain_info["whois_info"] = whois_info_dict.get(domain, {})  # type: ignore

            results.append(domain_info)

        return {"domains": results}

    def get_domain_certificates(self, domain: str, **kwargs) -> dict[str, Any]:
        """
        Retrieve SSL certificate details associated with a given domain.

        Args:
            domain (str): The domain for which SSL certificate details are retrieved.
            **kwargs: Optional query parameters for filtering the results.

        Returns:
            Dict[str, Any]: SSL certificate details for the specified domain.
        """
        url_suffix = f"{DOMAIN_CERTIFICATE}/{domain}"
        params = kwargs
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def parse_subject(self, subject: Any) -> dict[str, Any]:
        """
        Parse the subject of a certificate or domain record.

        Args:
            subject (Any): The subject to parse, which can be a dictionary, string, or other type.

        Returns:
            Dict[str, Any]: A dictionary representation of the subject,
            with a fallback to {'CN': subject} or {'CN': 'N/A'} if parsing fails.
        """
        if isinstance(subject, dict):
            return subject
        if isinstance(subject, str):
            parsed_subject = json.loads(subject.replace("'", '"')) if subject else {"CN": "N/A"}
            return parsed_subject if isinstance(parsed_subject, dict) else {"CN": subject}
        return {"CN": "N/A"}

    def validate_ip_address(self, ip: str, allow_ipv6: bool = True) -> bool:
        """
        Validate an IP address.

        Args:
            self: The instance of the class.
            ip (str): IP address to validate.
            allow_ipv6 (bool, optional): Whether to allow IPv6 addresses. Defaults to True.

        Returns:
            bool: True if valid IP address, False otherwise.
        """
        try:
            ip = ip.strip()
            ip_obj = ipaddress.ip_address(ip)

            return not (not allow_ipv6 and ip_obj.version == 6)
        except ValueError:
            return False

    def get_enrichment_data(
        self, resource: str, value: str, explain: bool | None = False, scan_data: bool | None = False
    ) -> dict:
        """
        Retrieve enrichment data for a specific resource.

        Args:
            resource (str): Type of resource (e.g., 'ip', 'domain').
            value (str): The specific value to enrich.
            explain (bool, optional): Whether to include detailed explanations. Defaults to False.
            scan_data (bool, optional): Whether to include scan data. Defaults to False.

        Returns:
            dict: Enrichment data for the specified resource.
        """
        endpoint = f"{ENRICHMENT}/{resource}/{value}"

        query_params = {"explain": int(explain) if explain else 0, "scan_data": int(scan_data) if scan_data else 0}
        response = self._http_request(method="GET", url_suffix=endpoint, params=query_params)
        # Handle the response based on resource type
        if resource in ["ip", "ipv4", "ipv6"]:
            ip2asn_data = response.get("response", {}).get("ip2asn", [])
            return ip2asn_data[0] if isinstance(ip2asn_data, list) and ip2asn_data else {}
        return response.get("response", {})

    def validate_ips(self, ips: list[str]) -> None:
        """Validates the number of IPs in the list."""
        if len(ips) > 100:
            raise DemistoException("Maximum of 100 IPs can be submitted in a single request.")

    def list_ip_information(self, ips: list[str], resource: str) -> dict:
        """
        Retrieve information for multiple IP addresses.

        Args:
            ips (List[str]): List of IPv4 or IPv6 addresses to fetch information for.
            resource (str): The resource type ('ipv4' or 'ipv6').

        Returns:
            Dict: API response containing IP information.
        """
        self.validate_ips(ips)

        ip_data = {"ips": ips}
        url_suffix = f"{LIST_IP}/{resource}"

        return self._http_request("POST", url_suffix, data=ip_data)

    def get_asn_reputation(self, asn: int, limit: int | None = None, explain: bool = False) -> dict[str, Any]:
        """
        Retrieve reputation history for a specific Autonomous System Number (ASN).

        Args:
            asn (int): The Autonomous System Number to query.
            limit (int, optional): Maximum number of results to return. Defaults to None.
            explain (bool, optional): Whether to include explanation for reputation score. Defaults to False.

        Returns:
            Dict[str, Any]: ASN reputation history information.
        """
        params = {"explain": int(bool(explain)), "limit": limit}

        return self._http_request(method="GET", url_suffix=f"{ASN_REPUTATION}/{asn}", params=params)

    def get_asn_takedown_reputation(self, asn: str, explain: int = 0, limit: int = None) -> dict[str, Any]:
        """
        Retrieve takedown reputation for a specific Autonomous System Number (ASN).

        Args:
            asn (str): The ASN number to query.
            limit (Optional[int]): Maximum results to return (default is None).
            explain (bool): Whether to include an explanation for the reputation score (default is False).

        Returns:
            Dict[str, Any]: Takedown reputation information for the specified ASN.
                            Returns an empty dictionary if no takedown reputation is found.

        Raises:
            ValueError: If ASN is not provided.
            DemistoException: If the API call fails.
        """
        if not asn:
            raise ValueError("ASN is required.")

        url_suffix = f"{ASN_TAKEDOWN_REPUTATION}/{asn}"
        query_params = assign_params(explain=int(bool(explain)), limit=limit)

        raw_response = self._http_request(method="GET", url_suffix=url_suffix, params=query_params)
        return raw_response.get("response", {})

    def get_ipv4_reputation(self, ipv4: str, explain: bool = True, limit: int = None) -> dict:
        """
        Retrieve historical reputation data for the specified IPv4 address.

        Args:
            ipv4 (str): The IPv4 address to check.
            explain (bool): Whether to include explanation details.
            limit (int): Maximum number of history entries to return.

        Returns:
            dict: Dictionary containing 'ip_reputation_history' key with list of entries.
        """
        url_suffix = f"{IPV4_REPUTATION}/{ipv4}"

        params = {"explain": int(bool(explain)), "limit": limit}

        remove_nulls_from_dictionary(params)

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

        if isinstance(response, str):
            try:
                response = json.loads(response)
            except Exception as e:
                raise ValueError(f"Unable to parse JSON from response: {e}")

        data = response.get("response", {}).get("ip_reputation_history", [])

        if isinstance(data, dict) and "error" in data:
            if explain:
                return self.get_ipv4_reputation(ipv4, explain=False, limit=limit)
            raise ValueError(f"API Error: {data['error']}")

        return {"ip_reputation_history": data if isinstance(data, list) else []}

    def forward_padns_lookup(self, qtype: str, qname: str, **kwargs) -> dict[str, Any]:
        """
        Perform a forward PADNS lookup using various filtering parameters.

        Args:
            qtype (str): Type of DNS record.
            qname (str): The DNS record name to lookup.
            **kwargs: Optional parameters for filtering and pagination.

        Returns:
            Dict[str, Any]: PADNS lookup results.
        """
        url_suffix = f"{FORWARD_PADNS}/{qtype}/{qname}"

        params = kwargs
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def reverse_padns_lookup(self, qtype: str, qname: str, **kwargs) -> dict[str, Any]:
        """
        Perform a reverse PADNS lookup using various filtering parameters.

        Args:
            qtype (str): Type of DNS record.
            qname (str): The DNS record name to lookup.
            **kwargs: Optional parameters for filtering and pagination.

        Returns:
            Dict[str, Any]: Reverse PADNS lookup results.
        """
        url_suffix = f"{REVERSE_PADNS}/{qtype}/{qname}"

        return self._http_request(method="GET", url_suffix=url_suffix, params=kwargs)

    def search_scan_data(self, query: str, params: dict) -> dict[str, Any]:
        """
        Search the Silent Push scan data repositories.

        Args:
            query (str): Query in SPQL syntax to scan data (mandatory)
            params (dict): Optional parameters to filter scan data
        Returns:
            Dict[str, Any]: Search results from scan data repositories

        Raises:
            DemistoException: If query is not provided or API call fails
        """
        if not query:
            raise DemistoException("Query parameter is required for search scan data.")

        params = {
            "limit": params.get("limit"),
            "fields": params.get("fields"),
            "sort": params.get("sort"),
            "skip": params.get("skip"),
            "with_metadata": params.get("with_metadata"),
        }
        remove_nulls_from_dictionary(params)
        url_suffix = SEARCH_SCAN

        payload = {"query": query}

        return self._http_request(method="POST", url_suffix=url_suffix, data=payload, params=params)

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

        Args:
            url (str): The URL to scan.
            platform (str, optional): Device to perform scan with (Desktop, Mobile, Crawler).
            os (str, optional): OS to perform scan with (Windows, Linux, MacOS, iOS, Android).
            browser (str, optional): Browser to perform scan with (Firefox, Chrome, Edge, Safari).
            region (str, optional): Region from where scan should be performed (US, EU, AS, TOR).

        Returns:
            Dict[str, Any]: The scan results including hosting metadata.
        """
        url_suffix = LIVE_SCAN_URL

        params = {"url": url, "platform": platform, "os": os, "browser": browser, "region": region}
        remove_nulls_from_dictionary(params)

        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_future_attack_indicators(self, feed_uuid: str, page_no: int = 1, page_size: int = 10000) -> dict[str, Any]:
        """
        Retrieve indicators of future attack feed from SilentPush.

        Args:
            feed_uuid (str): Feed unique identifier to fetch records for.
            page_no (int, optional): Page number for pagination. Defaults to 1.
            page_size (int, optional): Number of records per page. Defaults to 10000.

        Returns:
            Dict[str, Any]: Response containing future attack indicators.
        """

        params = {"source_uuids": feed_uuid, "page": page_no, "limit": page_size}

        query_string = urlencode(params)
        url = self._base_url.replace("/api/v1/merge-api", "") + f"/api/v2/iocs/threat-ranking/?{query_string}"

        return self._http_request(method="GET", url=url)

    def screenshot_url(self, url: str) -> dict[str, Any]:
        """
        Generate a screenshot for a given URL and store it in the vault using GET request.

        Args:
            url (str): The URL to capture a screenshot of

        Returns:
            Dict[str, Any]: Response containing screenshot information and vault details
        """
        endpoint = SCREENSHOT_URL
        params = {"url": url}
        remove_nulls_from_dictionary(params)

        response = self._http_request(method="GET", url_suffix=endpoint, params=params)
        if response.get("error"):
            return {"error": f"Failed to get screenshot: {response['error']}"}

        screenshot_data = response.get("response", {}).get("screenshot", {})
        if not screenshot_data:
            return {"error": "No screenshot data returned from API"}

        screenshot_url = screenshot_data.get("message")
        if not screenshot_url:
            return {"error": "No screenshot URL returned"}

        return {"status_code": screenshot_data.get("response", 200), "screenshot_url": screenshot_url}


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
        resp = client.search_domains("job_id", "max_wait", "result_type")
        if resp.get("status_code") != 200:
            return f"Connection failed :- {resp.get('errors')}"
        return "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise e


@metadata_collector.command(
    command_name="silentpush-get-job-status",
    inputs_list=JOB_STATUS_INPUTS,
    outputs_prefix="SilentPush.JobStatus",
    outputs_list=JOB_STATUS_OUTPUTS,
    description="This command retrieve status of running job or results from completed job.",
)
def get_job_status_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the status of a job based on the provided job ID and other optional parameters.

    Args:
        client (Client): The client instance that interacts with the service to fetch job status.
        args (dict): A dictionary of arguments, which should include:
            - 'job_id' (str): The unique identifier of the job for which status is being retrieved.
            - 'max_wait' (Optional[int]): The maximum wait time in seconds (default is None).

    Returns:
        CommandResults: The command results containing:
            - 'outputs_prefix' (str): The prefix for the output context.
            - 'outputs_key_field' (str): The field used as the key in the outputs.
            - 'outputs' (dict): A dictionary with job ID and job status information.
            - 'readable_output' (str): A formatted string that represents the job status in a human-readable format.
            - 'raw_response' (dict): The raw response received from the service.

    Raises:
        DemistoException: If the 'job_id' parameter is missing or if no job status is found for the given job ID.
    """
    job_id = args.get("job_id")

    params = {
        "max_wait": arg_to_number(args.get("max_wait")),
        "status_only": argToBoolean(args.get("status_only", False)),
        "force_metadata_on": argToBoolean(args.get("force_metadata_on", False)),
        "force_metadata_off": argToBoolean(args.get("force_metadata_off", False)),
    }

    if not job_id:
        raise DemistoException("job_id is a required parameter")

    raw_response = client.get_job_status(job_id, params)
    job_status = raw_response.get("response", {})

    if not job_status:
        raise DemistoException(f"No job status found for Job ID: {job_id}")

    readable_output = tableToMarkdown(
        f"Job Status for Job ID: {job_id}", [job_status], headers=list(job_status.keys()), removeNull=True
    )
    return CommandResults(
        outputs_prefix="SilentPush.JobStatus",
        outputs_key_field="job_id",
        outputs=job_status,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-get-nameserver-reputation",
    inputs_list=NAMESERVER_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.NameserverReputation",
    outputs_list=NAMESERVER_REPUTATION_OUTPUTS,
    description="This command retrieves historical reputation data for a specified nameserver,"
    "including reputation scores and optional detailed calculation information.",
)
def get_nameserver_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving nameserver reputation.

    Args:
        client (Client): The API client instance.
        args (dict): Command arguments.

    Returns:
        CommandResults: The command results containing nameserver reputation data.
    """
    nameserver = args.get("nameserver")
    explain = argToBoolean(args.get("explain", "false"))
    limit = arg_to_number(args.get("limit"))

    if not nameserver:
        raise ValueError("Nameserver is required.")

    reputation_data = client.get_nameserver_reputation(nameserver, explain, limit)

    if not isinstance(reputation_data, list):
        demisto.error(f"Expected list, got: {type(reputation_data)}")
        reputation_data = []

    for item in reputation_data:
        date_val = item.get("date")
        if isinstance(date_val, int):
            try:
                parsed_date = datetime.strptime(str(date_val), "%Y%m%d").date()
                item["date"] = parsed_date.isoformat()
            except ValueError as e:
                demisto.error(f"Failed to parse date {date_val}: {e}")

    if reputation_data and all(isinstance(item, dict) for item in reputation_data):
        all_headers = set()
        for item in reputation_data:
            all_headers.update(item.keys())

        readable_output = tableToMarkdown(
            f"Nameserver Reputation for {nameserver}", reputation_data, headers=sorted(all_headers), removeNull=True
        )
    else:
        readable_output = f"No valid reputation history found for nameserver: {nameserver}"
        reputation_data = []

    return CommandResults(
        outputs_prefix="SilentPush.NameserverReputation",
        outputs_key_field="ns_server",
        outputs={"nameserver": nameserver, "reputation_data": reputation_data},
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
def get_subnet_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the reputation history of a given subnet.

    Args:
        client (Client): The API client instance.
        args (dict): Command arguments containing:
            - subnet (str): The subnet to query.
            - explain (bool, optional): Whether to include an explanation.
            - limit (int, optional): Limit the number of reputation records.

    Returns:
        CommandResults: The command result containing the subnet reputation data.
    """
    subnet = args.get("subnet")
    if not subnet:
        raise DemistoException("Subnet is a required parameter.")

    explain = argToBoolean(args.get("explain", False))
    limit = arg_to_number(args.get("limit"))

    raw_response = client.get_subnet_reputation(subnet, explain, limit)
    subnet_reputation = raw_response.get("response", {}).get("subnet_reputation_history", [])

    readable_output = (
        f"No reputation history found for subnet: {subnet}"
        if not subnet_reputation
        else tableToMarkdown(f"Subnet Reputation for {subnet}", subnet_reputation, removeNull=True)
    )

    return CommandResults(
        outputs_prefix="SilentPush.SubnetReputation",
        outputs_key_field="subnet",
        outputs={"subnet": subnet, "reputation_history": subnet_reputation},
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-get-asns-for-domain",
    inputs_list=ASNS_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.DomainASNs",
    outputs_list=ASNS_DOMAIN_OUTPUTS,
    description="This command retrieves Autonomous System Numbers (ASNs) associated with a domain.",
)
def get_asns_for_domain_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves Autonomous System Numbers (ASNs) for the specified domain.

    Args:
        client (Client): The client object used to interact with the service.
        args (dict): Arguments passed to the command, including the domain.

    Returns:
        CommandResults: The results containing ASNs for the domain or an error message.
    """
    domain = args.get("domain")

    if not domain:
        raise DemistoException("Domain is a required parameter.")

    raw_response = client.get_asns_for_domain(domain)
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
    command_name="silentpush-density-lookup",
    inputs_list=DENSITY_LOOKUP_INPUTS,
    outputs_prefix="SilentPush.DensityLookup",
    outputs_list=DENSITY_LOOKUP_OUTPUTS,
    description="This command queries granular DNS/IP parameters (e.g., NS servers, MX servers, IPaddresses, ASNs) for density "
    "information.",
)
def density_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform a density lookup on the SilentPush API.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments containing 'qtype' and 'query', and optionally 'scope'.

    Returns:
        CommandResults: Formatted results of the density lookup, including either the density records or an error message.
    """
    qtype = args.get("qtype")
    query = args.get("query")

    if not qtype or not query:
        raise DemistoException("Both 'qtype' and 'query' are required parameters.")

    scope = args.get("scope")

    raw_response = client.density_lookup(qtype=qtype, query=query, scope=scope)

    # Check for API error in the response
    if raw_response.get("error"):
        raise DemistoException(f"API Error: {raw_response.get('error')}")

    records = raw_response.get("response", {}).get("records", [])

    readable_output = (
        f"No density records found for {qtype} {query}"
        if not records
        else tableToMarkdown(f"Density Lookup Results for {qtype} {query}", records, removeNull=True)
    )

    return CommandResults(
        outputs_prefix="SilentPush.$Lookup",
        outputs_key_field="query",
        outputs={"qtype": qtype, "query": query, "records": records},
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-search-domains",
    inputs_list=SEARCH_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.Domain",
    outputs_list=SEARCH_DOMAIN_OUTPUTS,
    description="This command search for domains with optional filters.",
)
def search_domains_command(client: Client, args: dict) -> CommandResults:
    """
    Command to search for domains based on various filter parameters.

    Args:
        client (Client): The client instance to interact with the external service.
        args (dict): Arguments containing filter parameters for domain search.

    Returns:
        CommandResults: The results of the domain search, including readable output and raw response.
    """
    # Extract arguments
    query = args.get("domain")
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    risk_score_min = arg_to_number(args.get("risk_score_min"))
    risk_score_max = arg_to_number(args.get("risk_score_max"))
    limit = arg_to_number(args.get("limit", 100))
    domain_regex = args.get("domain_regex")
    name_server = args.get("name_server")
    asnum = arg_to_number(args.get("asnum"))
    asname = args.get("asname")
    min_ip_diversity = arg_to_number(args.get("min_ip_diversity"))
    registrar = args.get("registrar")
    min_asn_diversity = arg_to_number(args.get("min_asn_diversity"))
    certificate_issuer = args.get("certificate_issuer")
    whois_date_after = args.get("whois_date_after")
    skip = arg_to_number(args.get("skip"))

    # Call the client method to search domains
    raw_response = client.search_domains(
        query=query,
        start_date=start_date,
        end_date=end_date,
        risk_score_min=risk_score_min,
        risk_score_max=risk_score_max,
        limit=limit,
        domain_regex=domain_regex,
        name_server=name_server,
        asnum=asnum,
        asname=asname,
        min_ip_diversity=min_ip_diversity,
        registrar=registrar,
        min_asn_diversity=min_asn_diversity,
        certificate_issuer=certificate_issuer,
        whois_date_after=whois_date_after,
        skip=skip,
    )

    records = raw_response.get("response", {}).get("records", [])

    if not records:
        return CommandResults(
            readable_output="No domains found.",
            raw_response=raw_response,
            outputs_prefix="SilentPush.Domain",
            outputs_key_field="domain",
            outputs=records,
        )

    readable_output = tableToMarkdown("Domain Search Results", records)

    return CommandResults(
        outputs_prefix="SilentPush.Domain",
        outputs_key_field="domain",
        outputs=records,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def format_tag_clusters(tag_clusters: list) -> str:
    """
    Helper function to format the tag clusters output.

    Args:
        tag_clusters (list): List of domain tag clusters.

    Returns:
        str: Formatted table output for tag clusters.
    """
    if not tag_clusters:
        return "\n\n**No tag cluster data returned by the API.**"

    cluster_details = [
        {"Cluster Level": key, "Details": value} for cluster in tag_clusters for key, value in cluster.items()
    ]
    return tableToMarkdown("Domain Tag Clusters", cluster_details)


@metadata_collector.command(
    command_name="silentpush-list-domain-infratags",
    inputs_list=DOMAIN_INFRATAGS_INPUTS,
    outputs_prefix="SilentPush.InfraTags",
    outputs_list=DOMAIN_INFRATAGS_OUTPUTS,
    description="This command get infratags for multiple domains with optional clustering.",
)
def list_domain_infratags_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to retrieve domain infratags with optional cluster details.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the infratags lookup.
    """
    domains = argToList(args.get("domains", ""))
    cluster = argToBoolean(args.get("cluster", False))
    mode = args.get("mode", "live").lower()
    match = args.get("match", "self")
    as_of = args.get("as_of")
    origin_uid = args.get("origin_uid")
    use_get = argToBoolean(args.get("use_get", False))

    if not domains and not use_get:
        raise ValueError('"domains" argument is required when using POST.')

    raw_response = client.list_domain_infratags(
        domains, cluster, mode=mode, match=match, as_of=as_of, origin_uid=origin_uid
    )

    response_mode = raw_response.get("response", {}).get("mode", "").lower()
    if response_mode and response_mode != mode:
        raise ValueError(f"Expected mode '{mode}' but got '{response_mode}'")

    infratags = raw_response.get("response", {}).get("infratags", [])
    tag_clusters = raw_response.get("response", {}).get("tag_clusters", [])

    readable_output = tableToMarkdown("Domain Infratags", infratags)

    if cluster:
        readable_output += format_tag_clusters(tag_clusters)

    return CommandResults(
        outputs_prefix="SilentPush.InfraTags",
        outputs_key_field="domain",
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-list-domain-information",
    inputs_list=LIST_DOMAIN_INPUTS,
    outputs_prefix="SilentPush.Domain",
    outputs_list=LIST_DOMAIN_OUTPUTS,
    description="This command get domain information along with Silent Push risk score "
    "and live whois information for multiple domains.",
)
def list_domain_information_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Handle the list-domain-information command execution.

    Args:
        client (Client): The client object for making API calls
        args (Dict[str, Any]): Command arguments

    Returns:
        CommandResults: Results for XSOAR
    """
    domains, fetch_risk_score, fetch_whois_info = parse_arguments(args)
    response = client.list_domain_information(domains, fetch_risk_score, fetch_whois_info)
    markdown = format_domain_information(response, fetch_risk_score, fetch_whois_info)

    return CommandResults(
        outputs_prefix="SilentPush.Domain",
        outputs_key_field="domain",
        outputs=response.get("domains", []),
        readable_output=markdown,
        raw_response=response,
    )


def parse_arguments(args: dict[str, Any]) -> tuple[list[str], bool, bool]:
    """
    Parse and validate command arguments.

    Args:
        args (Dict[str, Any]): Command arguments

    Returns:
        Tuple[List[str], bool, bool]: Parsed domains, risk score flag, and WHOIS flag
    """
    domains_arg = args.get("domains", "")
    if not domains_arg:
        raise DemistoException("No domains provided")

    domains = argToList(domains_arg)
    fetch_risk_score = argToBoolean(args.get("fetch_risk_score", False))
    fetch_whois_info = argToBoolean(args.get("fetch_whois_info", False))

    return domains, fetch_risk_score, fetch_whois_info


def format_domain_information(response: dict[str, Any], fetch_risk_score: bool, fetch_whois_info: bool) -> str:
    """
    Format the response data into markdown format.

    Args:
        response (Dict[str, Any]): API response data
        fetch_risk_score (bool): Whether to include risk score data
        fetch_whois_info (bool): Whether to include WHOIS data

    Returns:
        str: Markdown-formatted response
    """
    markdown = ["# Domain Information Results\n"]

    for domain_data in response.get("domains", []):
        domain = domain_data.get("domain", "N/A")
        markdown.append(f"## Domain: {domain}")
        markdown.append(tableToMarkdown("Domain Information", [domain_data]))

        if fetch_risk_score:
            risk_info = {
                "Risk Score": domain_data.get("risk_score", "N/A"),
                "Risk Score Explanation": domain_data.get("risk_score_explanation", "N/A"),
            }
            markdown.append(tableToMarkdown("Risk Assessment", [risk_info]))

        if fetch_whois_info:
            whois_info = domain_data.get("whois_info", {})
            if whois_info and isinstance(whois_info, dict):
                if "error" in whois_info:
                    markdown.append(f'WHOIS Error: {whois_info["error"]}')
                else:
                    markdown.append(tableToMarkdown("WHOIS Information", [whois_info]))

        markdown.append("\n---\n")

    return "\n".join(markdown)


@metadata_collector.command(
    command_name="silentpush-get-domain-certificates",
    inputs_list=DOMAIN_CERTIFICATE_INPUTS,
    outputs_prefix="SilentPush.Certificate",
    outputs_list=DOMAIN_CERTIFICATE_OUTPUTS,
    description="This command get certificate data collected from domain scanning.",
)
def get_domain_certificates_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves SSL/TLS certificates for a given domain.

    Args:
        client (Client): The API client to interact with SilentPush.
        args (Dict[str, Any]): Command arguments including:
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

    Returns:
        CommandResults: The results containing the retrieved certificates.
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
        "with_metadata": argToBoolean(args.get("with_metadata")) if "with_metadata" in args else None,
        "skip": arg_to_number(args.get("skip")),
        "limit": arg_to_number(args.get("limit")),
    }
    remove_nulls_from_dictionary(params)

    raw_response = client.get_domain_certificates(domain, **(params or {}))

    if raw_response.get("response", {}).get("job_status", {}):
        job_details = raw_response.get("response", {}).get("job_status", {})
        readable_output = tableToMarkdown(f"# Job status for Domain: {domain}\n", job_details, removeNull=True)
        return CommandResults(
            outputs_prefix="SilentPush.Certificate",
            outputs_key_field="domain",
            outputs={"domain": domain, "job_details": job_details},
            readable_output=readable_output,
            raw_response=raw_response,
        )

    certificates = raw_response.get("response", {}).get("domain_certificates", [])
    metadata = raw_response.get("response", {}).get("metadata", {})

    if not certificates:
        return CommandResults(
            readable_output=f"No certificates found for domain: {domain}",
            outputs_prefix="SilentPush.Certificate",
            outputs_key_field="domain",
            outputs={"domain": domain, "certificates": [], "metadata": metadata},
            raw_response=raw_response,
        )

    markdown = [f"# SSL/TLS Certificate Information for Domain: {domain}\n"]
    for cert in certificates:
        cert_info = format_certificate_info(cert)
        markdown.append(tableToMarkdown("Certificate Information", [cert_info]))

    return CommandResults(
        outputs_prefix="SilentPush.Certificate",
        outputs_key_field="domain",
        outputs={"domain": domain, "certificates": certificates, "metadata": metadata},
        readable_output="\n".join(markdown),
        raw_response=raw_response,
    )


def format_certificate_info(cert: dict[str, Any]) -> dict[str, str]:
    """
    Formats certificate information into a structured dictionary.

    Args:
        cert (Dict[str, Any]): Certificate details from the API response.

    Returns:
        Dict[str, str]: Formatted certificate details.
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


@metadata_collector.command(
    command_name="silentpush-get-enrichment-data",
    inputs_list=ENRICHMENT_INPUTS,
    outputs_prefix="SilentPush.Enrichment",
    outputs_list=ENRICHMENT_OUTPUTS,
    description="This command retrieves comprehensive enrichment information for a given resource (domain, IPv4, or IPv6).",
)
def get_enrichment_data_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve enrichment data for a specific resource and value.

    Args:
        client (Client): The client object to interact with the enrichment service.
        args (dict): Arguments containing the resource type, value, explain flag, and scan_data flag.

    Returns:
        CommandResults: The results of the enrichment data retrieval, including readable output and raw response.
    """
    resource = args.get("resource", "").lower()
    value = args.get("value")
    explain = argToBoolean(args.get("explain", False))
    scan_data = argToBoolean(args.get("scan_data", False))

    if not resource or not value:
        raise ValueError("Both 'resource' and 'value' arguments are required.")

    if resource not in RESOURCE:
        raise ValueError(f"Invalid input: {resource}. Allowed values are {RESOURCE}")

    if resource in ["ipv4", "ipv6"]:
        validate_ip(client, resource, value)

    # Retrieve enrichment data
    enrichment_data = client.get_enrichment_data(resource, value, explain, scan_data)

    # Return results based on data availability
    if not enrichment_data:
        return CommandResults(
            readable_output=f"No enrichment data found for resource: {value}",
            outputs_prefix="SilentPush.Enrichment",
            outputs_key_field="value",
            outputs={"value": value, **enrichment_data},
            raw_response=enrichment_data,
        )

    readable_output = tableToMarkdown(f"Enrichment Data for {value}", enrichment_data, removeNull=True)

    return CommandResults(
        outputs_prefix="SilentPush.Enrichment",
        outputs_key_field="value",
        outputs={"value": value, **enrichment_data},
        readable_output=readable_output,
        raw_response=enrichment_data,
    )


def validate_ip(client: Client, resource: str, value: str) -> None:
    """
    Validate the IP address based on the resource type.

    Args:
        client (Client): The client object to interact with the enrichment service.
        resource (str): The resource type (ipv4 or ipv6).
        value (str): The IP address to validate.

    Raises:
        DemistoException: If the IP address is invalid for the given resource type.
    """
    is_valid_ip = client.validate_ip_address(value, allow_ipv6=(resource == "ipv6"))
    if not is_valid_ip:
        raise DemistoException(f"Invalid {resource.upper()} address: {value}")


@metadata_collector.command(
    command_name="silentpush-list-ip-information",
    inputs_list=LIST_IP_INPUTS,
    outputs_prefix="SilentPush.IPInformation",
    outputs_list=LIST_IP_OUTPUTS,
    description="This command get IP information for multiple IPv4s and IPv6s.",
)
def list_ip_information_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Command to list IP information for a given set of IP addresses, categorized by IPv4 and IPv6.

    Args:
        client (Client): The client instance to interact with the IP data.
        args (Dict[str, Any]): Dictionary of command arguments.

    Returns:
        CommandResults: Command results containing the IP information.
    """
    ips = argToList(args.get("ips", ""))

    if not ips:
        return CommandResults(
            readable_output="The 'ips' parameter is required.",
            outputs_prefix="SilentPush.IPInformation",
            outputs_key_field="ip",
            outputs=[],
            raw_response={"ips": ips},
        )

    ipv4_addresses, ipv6_addresses = validate_ips(ips, client)

    results = []
    if ipv4_addresses:
        results.extend(gather_ip_information(client, ipv4_addresses, resource="ipv4"))

    if ipv6_addresses:
        results.extend(gather_ip_information(client, ipv6_addresses, resource="ipv6"))

    if not results:
        return CommandResults(
            readable_output=f"No information found for IPs: {', '.join(ips)}",
            outputs_prefix="SilentPush.IPInformation",
            outputs_key_field="ip",
            outputs=[],
            raw_response={"ips": ips, "results": results},
        )

    readable_output = tableToMarkdown(
        "Comprehensive IP Information",
        results,
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix="SilentPush.IPInformation",
        outputs_key_field="ip",
        outputs=results,
        readable_output=readable_output,
        raw_response={"ips": ips, "results": results},
    )


def validate_ips(ips: list, client: Client) -> tuple:
    """
    Validates and categorizes the IPs into IPv4 and IPv6 addresses.

    Args:
        ips (list): List of IPs to validate.
        client (Client): The client instance to use for validation.

    Returns:
        tuple: A tuple containing two lists: (ipv4_addresses, ipv6_addresses)
    """
    ipv4_addresses = []
    ipv6_addresses = []

    for ip in ips:
        if client.validate_ip_address(ip, allow_ipv6=False):  # IPv4
            ipv4_addresses.append(ip)
        elif client.validate_ip_address(ip, allow_ipv6=True):  # IPv6
            ipv6_addresses.append(ip)

    return ipv4_addresses, ipv6_addresses


def gather_ip_information(client: Client, ip_addresses: list, resource: str) -> list:
    """
    Gathers IP information for a given list of IP addresses.

    Args:
        client (Client): The client instance to query IP information.
        ip_addresses (list): The list of IPs to gather information for.
        resource (str): The resource type ('ipv4' or 'ipv6').

    Returns:
        list: A list of IP to ASN information.
    """
    ip_info = client.list_ip_information(ip_addresses, resource=resource)
    return ip_info.get("response", {}).get("ip2asn", [])


@metadata_collector.command(
    command_name="silentpush-get-asn-reputation",
    inputs_list=ASN_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.ASNReputation",
    outputs_list=ASN_REPUTATION_OUTPUTS,
    description="This command retrieve the reputation information for an IPv4.",
)
def get_asn_reputation_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for retrieving ASN reputation data.

    Args:
        client (Client): The API client instance
        args (dict): Command arguments containing:
            - asn: ASN number
            - limit (optional): Maximum results to return
            - explain (optional): Whether to include explanation

    Returns:
        CommandResults: Formatted command results for XSOAR
    """
    asn = args.get("asn")
    if not asn:
        raise ValueError("ASN is required.")
    try:
        asn = int(asn)
    except ValueError:
        raise ValueError("Invalid ASN number")
    limit = arg_to_number(args.get("limit"))
    explain = argToBoolean(args.get("explain", "false"))

    if not asn:
        raise ValueError("ASN is required.")

    raw_response = client.get_asn_reputation(asn, limit, explain)
    asn_reputation = extract_and_sort_asn_reputation(raw_response)

    if not asn_reputation:
        return CommandResults(
            readable_output=f"No reputation data found for ASN {asn}.",
            outputs_prefix="SilentPush.ASNReputation",
            outputs_key_field="asn",
            outputs=[],
            raw_response=raw_response,
        )

    data_for_table = prepare_asn_reputation_table(asn_reputation, explain)
    readable_output = tableToMarkdown(f"ASN Reputation for {asn}", data_for_table, headers=get_table_headers(explain))

    return CommandResults(
        outputs_prefix="SilentPush.ASNReputation",
        outputs_key_field="asn",
        outputs=asn_reputation,
        readable_output=readable_output,
        raw_response=raw_response,
    )


def extract_and_sort_asn_reputation(raw_response: dict) -> list:
    """
    Extract ASN reputation data and sort by date.

    Args:
        raw_response (dict): Raw response data from API.

    Returns:
        list: Sorted ASN reputation data.
    """
    response_data = raw_response.get("response", {})

    if not isinstance(response_data, dict):
        response_data = {"asn_reputation": response_data}

    asn_reputation = response_data.get("asn_reputation") or response_data.get("asn_reputation_history", [])

    if isinstance(asn_reputation, dict):
        asn_reputation = [asn_reputation]
    elif not isinstance(asn_reputation, list):
        asn_reputation = []

    return sorted(asn_reputation, key=lambda x: x.get("date", ""), reverse=True)


def generate_no_reputation_response(asn: str, raw_response: dict) -> CommandResults:
    """
    Generate a response when no ASN reputation data is found.

    Args:
        asn (str): The ASN for which data was searched.
        raw_response (dict): Raw response data from the API.

    Returns:
        CommandResults: The no data response.
    """
    return CommandResults(
        readable_output=f"No reputation data found for ASN {asn}.",
        outputs_prefix="SilentPush.ASNReputation",
        outputs_key_field="asn",
        outputs=[],
        raw_response=raw_response,
    )


def prepare_asn_reputation_table(asn_reputation: list, explain: bool) -> list:
    """
    Prepare the data for the ASN reputation table.

    Args:
        asn_reputation (list): List of ASN reputation entries.
        explain (bool): Whether to include explanations in the table.

    Returns:
        list: Data formatted for the table.
    """
    data_for_table = []
    for entry in asn_reputation:
        row = {
            "ASN": entry.get("asn"),
            "Reputation": entry.get("asn_reputation"),
            "ASName": entry.get("asname"),
            "Date": entry.get("date"),
        }
        if explain and entry.get("asn_reputation_explain"):
            row["Explanation"] = entry.get("asn_reputation_explain")
        data_for_table.append(row)
    return data_for_table


def get_table_headers(explain: bool) -> list:
    """
    Get the table headers based on the explain flag.

    Args:
        explain (bool): Whether to include explanations in the table.

    Returns:
        list: List of table headers.
    """
    headers = ["ASN", "Reputation", "ASName", "Date"]
    if explain:
        headers.append("Explanation")
    return headers


@metadata_collector.command(
    command_name="silentpush-get-asn-takedown-reputation",
    inputs_list=ASN_TAKEDOWN_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.ASNTakedownReputation",
    outputs_list=ASN_TAKEDOWN_REPUTATION_OUTPUTS,
    description="This command retrieve the takedown reputation information for an Autonomous System Number (ASN).",
)
def get_asn_takedown_reputation_command(client, args):
    """
    Command handler for retrieving ASN takedown reputation.

    Args:
        client (Client): The API client instance to interact with the external service.
        args (dict): Command arguments, containing:
            - 'asn' (str): The ASN (Autonomous System Number).
            - 'limit' (int, optional): Limit for the number of results.
            - 'explain' (bool, optional): Flag to request explanation of the reputation.

    Returns:
        CommandResults: Command results formatted for XSOAR, containing the ASN takedown reputation data.

    Raises:
        ValueError: If 'asn' is not provided or 'limit' is not a valid integer.
        DemistoException: If an error occurs while retrieving the data from the API.
    """
    asn = args.get("asn")
    if not asn:
        raise ValueError("ASN is a required parameter.")

    try:
        explain = argToBoolean(args.get("explain", False))
        limit = arg_to_number(args.get("limit"))
    except Exception as e:
        raise ValueError(f"Invalid argument: {e}")

    try:
        response = client.get_asn_takedown_reputation(asn, explain, limit)
    except Exception as e:
        raise DemistoException(f"API call failed: {str(e)}")

    takedown_history = response.get("takedown_reputation_history")

    if not takedown_history:
        return CommandResults(
            readable_output=f"No takedown reputation history found for ASN: {asn}",
            outputs_prefix="SilentPush.ASNTakedownReputation",
            outputs_key_field="asn",
            outputs={"asn": asn, "history": []},
            raw_response=response,
        )

    for entry in takedown_history:
        if isinstance(entry.get("date"), int):
            try:
                entry["date"] = datetime.strptime(str(entry["date"]), "%Y%m%d").date().isoformat()
            except ValueError:
                demisto.debug(f"Failed to format date: {entry.get('date')}")

    readable_output = tableToMarkdown(f"Takedown Reputation for ASN {asn}", takedown_history, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SilentPush.ASNTakedownReputation",
        outputs_key_field="asn",
        outputs={"asn": asn, "history": takedown_history},
        raw_response=response,
    )


@metadata_collector.command(
    command_name="silentpush-get-ipv4-reputation",
    inputs_list=IPV4_REPUTATION_INPUTS,
    outputs_prefix="SilentPush.IPv4Reputation",
    outputs_list=IPV4_REPUTATION_OUTPUTS,
    description="This command retrieves the reputation information for an IPv4.",
)
def get_ipv4_reputation_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the reputation data for a given IPv4 address from the client.

    Args:
        client (Client): The client to interact with the reputation service.
        args (Dict[str, Any]): Arguments passed to the command, including the IPv4 address, explain flag, and limit.

    Returns:
        CommandResults: The results of the command including the IPv4 reputation data.
    """
    ipv4 = args.get("ipv4")
    if not ipv4:
        raise DemistoException("IPv4 address is required")

    validate_ip(client, "ipv4", ipv4)

    explain = argToBoolean(args.get("explain", "false"))
    limit = arg_to_number(args.get("limit"))

    raw_response = client.get_ipv4_reputation(ipv4, explain, limit)

    history = raw_response.get("response", {}).get("ip_reputation_history")
    if not history:
        history = raw_response.get("ip_reputation_history")

    if not isinstance(history, list) or not history:
        return CommandResults(
            readable_output=f"No reputation data found for IPv4: {ipv4}",
            outputs_prefix="SilentPush.IPv4Reputation",
            outputs_key_field="ip",
            outputs={"ip": ipv4},
            raw_response=raw_response,
        )

    for entry in history:
        entry["ip"] = entry.get("ipv4", ipv4)

    readable_output = tableToMarkdown(
        f"IPv4 Reputation History for {ipv4}", history, headers=["date", "ip", "ip_reputation"]
    )

    return CommandResults(
        outputs_prefix="SilentPush.IPv4Reputation",
        outputs_key_field="ip",
        outputs={"ip": ipv4, "reputation_history": history},
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
def forward_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform a forward PADNS lookup.

    Args:
        client (Client): The SilentPush API client.
        args (dict): The command arguments containing lookup parameters.

    Returns:
        CommandResults: The formatted results of the PADNS lookup or an error message if something goes wrong.
    """
    qtype = args.get("qtype")
    qname = args.get("qname")

    if not qtype or not qname:
        raise DemistoException("Both 'qtype' and 'qname' are required parameters.")

    netmask = args.get("netmask")
    subdomains = argToBoolean(args.get("subdomains")) if "subdomains" in args else None
    regex = args.get("regex")
    match = args.get("match")
    first_seen_after = args.get("first_seen_after")
    first_seen_before = args.get("first_seen_before")
    last_seen_after = args.get("last_seen_after")
    last_seen_before = args.get("last_seen_before")
    as_of = args.get("as_of")
    sort = args.get("sort")
    output_format = args.get("output_format")
    prefer = args.get("prefer")
    with_metadata = argToBoolean(args.get("with_metadata")) if "with_metadata" in args else None
    max_wait = arg_to_number(args.get("max_wait"))
    skip = arg_to_number(args.get("skip"))
    limit = arg_to_number(args.get("limit"))

    raw_response = client.forward_padns_lookup(
        qtype=qtype,
        qname=qname,
        netmask=netmask,
        subdomains=subdomains,
        regex=regex,
        match=match,
        first_seen_after=first_seen_after,
        first_seen_before=first_seen_before,
        last_seen_after=last_seen_after,
        last_seen_before=last_seen_before,
        as_of=as_of,
        sort=sort,
        output_format=output_format,
        prefer=prefer,
        with_metadata=with_metadata,
        max_wait=max_wait,
        skip=skip,
        limit=limit,
    )

    # Check for API error in the response
    if raw_response.get("error"):
        raise DemistoException(f"API Error: {raw_response.get('error')}")

    records = raw_response.get("response", {}).get("records", [])

    if not records:
        readable_output = f"No records found for {qtype} {qname}"
    else:
        readable_output = tableToMarkdown(f"PADNS Lookup Results for {qtype} {qname}", records, removeNull=True)

    return CommandResults(
        outputs_prefix="SilentPush.PADNSLookup",
        outputs_key_field="qname",
        outputs={"qtype": qtype, "qname": qname, "records": records},
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
def reverse_padns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Command function to perform reverse PADNS lookup.

    Args:
        client (Client): SilentPush API client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Formatted results of the reverse PADNS lookup.
    """
    qtype = args.get("qtype")
    qname = args.get("qname")

    if not qtype or not qname:
        raise DemistoException("Both 'qtype' and 'qname' are required parameters.")

    filtered_args = {key: value for key, value in args.items() if key not in ("qtype", "qname")}
    remove_nulls_from_dictionary(filtered_args)

    raw_response = client.reverse_padns_lookup(qtype=qtype, qname=qname, **(filtered_args or {}))

    if raw_response.get("error"):
        raise DemistoException(f"API Error: {raw_response.get('error')}")

    records = raw_response.get("response", {}).get("records", [])
    if not records:
        readable_output = f"No records found for {qtype} {qname}"
    else:
        readable_output = tableToMarkdown(f"Reverse PADNS Lookup Results for {qtype} {qname}", records, removeNull=True)

    return CommandResults(
        outputs_prefix="SilentPush.ReversePADNSLookup",
        outputs_key_field="qname",
        outputs={"qtype": qtype, "qname": qname, "records": records},
        readable_output=readable_output,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-search-scan-data",
    inputs_list=SEARCH_SCAN_INPUTS,
    outputs_prefix="SilentPush.ScanData",
    outputs_list=SEARCH_SCAN_OUTPUTS,
    description="This command search Silent Push scan data repositories using SPQL queries.",
)
def search_scan_data_command(client: Client, args: dict) -> CommandResults:
    """
    Search scan data command handler.

    Args:
        client (Client): SilentPush API client
        args (dict): Command arguments:
            - query (str): Required. SPQL syntax query

    Returns:
        CommandResults: Command results with formatted output
    """
    query = args.get("query")
    if not query:
        raise ValueError("Query parameter is required")

    params = args
    raw_response = client.search_scan_data(query, params)

    scan_data = raw_response.get("response", {}).get("scandata_raw", [])

    if not scan_data:
        return CommandResults(
            readable_output="No scan data records found", outputs_prefix="SilentPush.ScanData", outputs=None
        )

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
def live_url_scan_command(client: Client, args: dict) -> CommandResults:
    """
    Command handler for live URL scan command.

    Args:
        client (Client): The SilentPush API client
        args (dict): Command arguments

    Returns:
        CommandResults: Results of the URL scan
    """
    url = args.get("url")
    if not url:
        raise DemistoException("URL is a required parameter")

    platform = args.get("platform", "")
    os = args.get("os", "")
    browser = args.get("browser", "")
    region = args.get("region", "")

    # Validate platform, os, browser, and region
    validation_errors = validate_parameters(platform, os, browser, region)
    if validation_errors:
        raise DemistoException(validation_errors)

    # Call the client to get the scan results
    raw_response = client.live_url_scan(url, platform, os, browser, region)
    scan_results = raw_response.get("response", {}).get("scan", {})

    # Generate the readable output
    readable_output, scan_results = format_scan_results(scan_results, url)

    return CommandResults(
        outputs_prefix="SilentPush.URLScan",
        outputs_key_field="url",
        outputs={"url": url, "scan_results": scan_results},
        readable_output=readable_output,
        raw_response=raw_response,
    )


def validate_parameters(platform: str, os: str, browser: str, region: str) -> str:
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


def format_scan_results(scan_results: dict, url: str) -> tuple:
    """Format the scan results for the output."""
    if not isinstance(scan_results, dict):
        readable_output = f"Unexpected response format for URL scan. Response: {scan_results}"
        return readable_output, scan_results

    if not scan_results:
        readable_output = f"No scan results found for URL: {url}"
        return readable_output, scan_results

    headers = list(scan_results.keys())
    readable_output = tableToMarkdown(f"URL Scan Results for {url}", [scan_results], headers=headers, removeNull=True)
    return readable_output, scan_results


@metadata_collector.command(
    command_name="silentpush-get-future-attack-indicators",
    inputs_list=FUTURE_ATTACK_INDICATOR_INPUTS,
    outputs_prefix="SilentPush.FutureAttackIndicators",
    outputs_list=FUTURE_ATTACK_INDICATOR_OUTPUTS,
    description="This command fetch indicators of potential future attacks using a feed UUID.",
)
def get_future_attack_indicators_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Command handler for retrieving indicators of future attack feed.

    Args:
        client (Client): SilentPush API client instance.
        args (dict): Command arguments, should include 'feed_uuid' and may include 'page_no', and 'page_size'.

    Returns:
        CommandResults: Results for XSOAR containing future attack indicators or error message.

    Raises:
        ValueError: If required parameters are missing.
    """
    feed_uuid = args.get("feed_uuid")
    page_no = int(args.get("page_no", 1))
    page_size = int(args.get("page_size", 10000))

    if not feed_uuid:
        raise ValueError("feed_uuid is a required parameter")

    raw_response = client.get_future_attack_indicators(feed_uuid, page_no, page_size)

    # Handle list or dict gracefully
    if isinstance(raw_response, list):
        indicators = raw_response
    else:
        indicators = raw_response.get("indicators", [])

    return CommandResults(
        readable_output=tableToMarkdown("SilentPush Future Attack Indicators", indicators),
        outputs_prefix="SilentPush.FutureAttackIndicators",
        outputs_key_field="feed_uuid",  # replace with appropriate key like "uuid" if needed
        outputs=indicators,
        raw_response=raw_response,
    )


@metadata_collector.command(
    command_name="silentpush-screenshot-url",
    inputs_list=SCREENSHOT_URL_INPUTS,
    outputs_prefix="SilentPush.Screenshot",
    outputs_list=SCREENSHOT_URL_OUTPUTS,
    description="This commandGenerate screenshot of a URL.",
)
def screenshot_url_command(client: Client, args: dict[str, Any]) -> CommandResults | dict:
    """
    Command handler for taking URL screenshots.

    Args:
        client (Client): SilentPush API client instance.
        args (Dict[str, Any]): Command arguments, must include 'url' key.

    Returns:
        CommandResults: Results including screenshot data and vault info.
    """
    url = args.get("url")
    if not url:
        raise ValueError("URL is required")

    result = client.screenshot_url(url)
    if result.get("error"):
        raise Exception(result.get("error"))

    if not result.get("screenshot_url"):
        raise ValueError("screenshot_url is missing from API response.")

    screenshot_url = result["screenshot_url"]
    parsed_url = urlparse(screenshot_url)

    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError(f"Invalid screenshot URL format: {screenshot_url}")

    server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    url_suffix = parsed_url.path
    if parsed_url.query:
        url_suffix += f"?{parsed_url.query}"

    image_response = generic_http_request(
        method="GET", server_url=server_url, url_suffix=url_suffix, resp_type="response"
    )

    if not image_response or image_response.status_code != 200:
        return {
            "error": f"Failed to download screenshot image: HTTP {getattr(image_response, 'status_code', 'No response')}"
        }

    filename = f"{urlparse(url).netloc}_screenshot.jpg"

    readable_output = (
        f"### Screenshot captured for {url}\n"
        f"- Status: Success\n"
        f"- Screenshot URL: {result['screenshot_url']}\n"
        f"- File Name: {filename}"
    )

    result_data = {
        "url": url,
        "status": "success",
        "status_code": result.get("status_code"),
        "screenshot_url": result["screenshot_url"],
        "file_name": filename,
    }
    remove_nulls_from_dictionary(result_data)

    return_results(fileResult(filename, image_response.content))

    return CommandResults(
        outputs_prefix="SilentPush.Screenshot",
        outputs_key_field="url",
        outputs=result_data,
        readable_output=readable_output,
        raw_response=result,
    )


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

        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "silentpush-get-job-status":
            return_results(get_job_status_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-nameserver-reputation":
            return_results(get_nameserver_reputation_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-subnet-reputation":
            return_results(get_subnet_reputation_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-asns-for-domain":
            return_results(get_asns_for_domain_command(client, demisto.args()))

        elif demisto.command() == "silentpush-density-lookup":
            return_results(density_lookup_command(client, demisto.args()))

        elif demisto.command() == "silentpush-search-domains":
            return_results(search_domains_command(client, demisto.args()))

        elif demisto.command() == "silentpush-list-domain-infratags":
            return_results(list_domain_infratags_command(client, demisto.args()))

        elif demisto.command() == "silentpush-list-domain-information":
            return_results(list_domain_information_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-domain-certificates":
            return_results(get_domain_certificates_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-enrichment-data":
            return_results(get_enrichment_data_command(client, demisto.args()))

        elif demisto.command() == "silentpush-list-ip-information":
            return_results(list_ip_information_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-asn-reputation":
            return_results(get_asn_reputation_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-asn-takedown-reputation":
            return_results(get_asn_takedown_reputation_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-ipv4-reputation":
            return_results(get_ipv4_reputation_command(client, demisto.args()))

        elif demisto.command() == "silentpush-forward-padns-lookup":
            return_results(forward_padns_lookup_command(client, demisto.args()))

        elif demisto.command() == "silentpush-reverse-padns-lookup":
            return_results(reverse_padns_lookup_command(client, demisto.args()))

        elif demisto.command() == "silentpush-search-scan-data":
            return_results(search_scan_data_command(client, demisto.args()))

        elif demisto.command() == "silentpush-live-url-scan":
            return_results(live_url_scan_command(client, demisto.args()))

        elif demisto.command() == "silentpush-get-future-attack-indicators":
            return_results(get_future_attack_indicators_command(client, demisto.args()))

        elif demisto.command() == "silentpush-screenshot-url":
            return_results(screenshot_url_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
