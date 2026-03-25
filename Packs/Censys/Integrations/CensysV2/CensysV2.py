from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, base_url: str, api_token: str, org_id: str | None = None, verify: bool = True, proxy: bool = False):
        """
        Initialize the Censys Client.

        Args:
            base_url: The base URL for the Censys API
            api_token: The API token for authentication
            org_id: Organization ID for multi-org accounts
            verify: Whether to verify SSL certificates
            proxy: Whether to use proxy settings
        """
        # Build headers for v3 API
        headers = {"Authorization": f"Bearer {api_token}", "X-Organization-ID": org_id}
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def censys_view_request(self, index: str, query: str) -> dict:
        asset_type = "host" if index == "ipv4" else "certificate"
        demisto.debug(f"censys_view_request: index={index}, query={query}, asset_type={asset_type}")
        result = self._http_request("GET", f"/v3/global/asset/{asset_type}/{query}")
        return result

    def censys_search_request(
        self, query: str, page_size: int | None = None, fields: list | None = None, page_token: str | None = None
    ) -> dict:
        """
        Execute a single search query request.

        Args:
            query: The search query string
            page_size: Number of results per page
            fields: List of fields to return
            page_token: Token for pagination (to get next page)

        Returns:
            API response dictionary
        """
        url_suffix = "/v3/global/search/query"
        data = assign_params(query=query, page_size=page_size, fields=fields, page_token=page_token)
        demisto.debug(f"censys_search_request: query={query}, page_size={page_size}, page_token={page_token}")
        return self._http_request("POST", url_suffix, json_data=data)


""" HELPER FUNCTIONS """


def censys_search_with_pagination(
    client: Client, query: str, page_size: int | None = None, fields: list | None = None, limit: int | None = None
) -> dict:
    """
    Execute a search query with automatic pagination.

    This function handles pagination automatically by fetching multiple pages
    until either all results are retrieved or the limit is reached.

    Args:
        client: The Censys client instance
        query: The search query string
        page_size: Number of results per page (default: 50, max: 100)
        fields: List of fields to return
        limit: Maximum total number of results to return across all pages

    Returns:
        Dictionary with 'result' containing all hits and metadata:
        {
            "result": {
                "hits": [...],  # All collected hits
                "total_hits": int,  # Total available results
                "next_page_token": str,  # Token for next page (if any)
                "previous_page_token": str,  # Token for previous page (if any)
                "query_duration_millis": int  # Query duration
            }
        }
    """
    # Determine initial page size
    if page_size is None:
        page_size = 100
    if limit and limit < page_size:
        page_size = limit

    all_hits = []
    page_token = None
    total_fetched = 0
    total_hits = None
    last_result = {}

    # Pagination loop
    demisto.debug(f"censys_search_with_pagination: starting pagination for query={query}, limit={limit}")
    while True:
        # Make API request for current page
        response = client.censys_search_request(query, page_size, fields, page_token)
        result = response.get("result", {})
        hits = result.get("hits", [])

        # Store metadata from first response
        if total_hits is None:
            total_hits = result.get("total_hits")

        # Keep last result for metadata
        last_result = result

        # If no hits, break
        if not hits:
            break

        # Add hits to collection
        all_hits.extend(hits)
        total_fetched += len(hits)

        # Check for next page token (it's directly in result, not in links)
        next_page_token = result.get("next_page_token")

        # Stop if no more pages or reached limit
        if not next_page_token or (limit and total_fetched >= limit):
            break

        # Update for next iteration
        page_token = next_page_token

        # Adjust page_size if approaching limit
        if limit:
            remaining = limit - total_fetched
            if remaining < page_size:
                page_size = remaining

    demisto.debug(f"censys_search_with_pagination: finished pagination. total_fetched={total_fetched}, total_hits={total_hits}")

    # Trim to exact limit if specified
    if limit and len(all_hits) > limit:
        all_hits = all_hits[:limit]

    # Return response in same format as single request
    return {
        "result": {
            "hits": all_hits,
            "total_hits": total_hits,
            "next_page_token": last_result.get("next_page_token"),
            "previous_page_token": last_result.get("previous_page_token"),
            "query_duration_millis": last_result.get("query_duration_millis"),
        }
    }


def handle_exceptions(e: Exception, results: list[CommandResults], execution_metrics: ExecutionMetrics, item: str):
    demisto.debug(f"handle_exceptions: item={item}, error={str(e)}")
    status_code = 0
    message = str(e)

    if isinstance(e, DemistoException) and e.res is not None:
        status_code = e.res.status_code
        message = e.message

    if status_code == 403 and "quota" in message:
        # Handle quota exceeded error
        execution_metrics.quota_error += 1
        results.append(CommandResults(readable_output=f"Quota exceeded. Error: {message}"))
        return True

    elif status_code == 429:
        # Handle rate limits error
        execution_metrics.general_error += 1
        results.append(CommandResults(readable_output=f"Too many requests. Error: {message}"))
        return True

    elif status_code == 403 and "specific fields" in message:
        # Handle non-premium access error
        raise DemistoException(
            "Your user does not have permission for premium features. "
            "Please ensure that you deselect the 'Labels premium feature available' option "
            f"for non-premium access. Error: {message}"
        )

    elif status_code == 401 or status_code == 403:
        # Handle unauthorized access error
        raise e

    else:
        # Handle general error
        execution_metrics.general_error += 1
        error_msg = f"An error occurred for item: {item}. Error: {message}"
        results.append(CommandResults(readable_output=error_msg))
        return False


def get_dbot_score(params: dict, result_labels: list):
    malicious_labels = set(argToList(params.get("malicious_labels", [])))
    suspicious_labels = set(argToList(params.get("suspicious_labels", [])))
    malicious_threshold = arg_to_number(params.get("malicious_labels_threshold")) or 0
    suspicious_threshold = arg_to_number(params.get("suspicious_labels_threshold")) or 0
    num_malicious = len(malicious_labels.intersection(result_labels))
    if num_malicious >= malicious_threshold and num_malicious > 0:
        matched_labels = sorted(malicious_labels.intersection(result_labels))
        description = f"Matched malicious labels: {', '.join(matched_labels)}"
        return Common.DBotScore.BAD, description

    num_suspicious = len(suspicious_labels.intersection(result_labels))
    if num_suspicious >= suspicious_threshold and num_suspicious > 0:
        matched_labels = sorted(suspicious_labels.intersection(result_labels))
        description = f"Matched suspicious labels: {', '.join(matched_labels)}"
        return Common.DBotScore.SUSPICIOUS, description

    return Common.DBotScore.NONE, None


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    # Check if the user has selected malicious or suspicious labels without premium access
    if not params.get("premium_access") and (params.get("malicious_labels") or params.get("suspicious_labels")):
        raise DemistoException(
            "The 'Determine IP score by label' feature only works for Censys paid subscribers (v3 API). "
            "If you have paid access select the 'Determine IP score by label' option "
            "to utilize this functionality, or deselect labels"
        )

    fields = ["labels"] if params.get("premium_access") else None

    try:
        # Build query for test IP
        query = 'host.ip="8.8.8.8"'
        censys_search_with_pagination(client, query, fields=fields, limit=1)
        return "ok"
    except DemistoException as e:
        if e.res is not None:
            if e.res.status_code == 401:
                raise DemistoException(
                    "401 Unauthorized: Access credentials are invalid. "
                    "Please verify your 'API Token' in the integration configuration."
                )
            if e.res.status_code == 403:
                # Handle permission error for non-premium users attempting to access premium features
                if "specific fields" in e.message:
                    raise DemistoException(
                        "Your user does not have permission for premium features (v3 API). "
                        "Please ensure that you deselect the 'Determine IP score by label' option "
                        "for non-premium access."
                    )
                # Handle organization authorization error
                raise DemistoException(
                    "403 Forbidden: The provided Organization ID is incorrect or the user is not authorized to access it. "
                    "Please verify your 'Organization ID' in the integration configuration."
                )
            # Handle organization ID format error
            if e.res.status_code == 422:
                raise DemistoException(
                    "422 Unprocessable Entity: The provided Organization ID is malformed. " "Please ensure it is a valid UUID."
                )
        raise e


def censys_view_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns host information for the specified IP address or structured certificate data for the specified SHA-256
    """
    index = args.get("index", "")
    query = args.get("query", "")
    demisto.debug(f"censys_view_command: index={index}, query={query}")
    res = client.censys_view_request(index, query)
    resource = demisto.get(res, "result.resource", {})
    if index == "ipv4":
        city = demisto.get(resource, "location.city")
        province = demisto.get(resource, "location.province")
        postal = demisto.get(resource, "location.postal_code")
        country_code = demisto.get(resource, "location.country_code")
        country = demisto.get(resource, "location.country")

        description = ", ".join([str(x) for x in [city, province, postal, country_code] if x])
        lat = demisto.get(resource, "location.coordinates.latitude")
        lon = demisto.get(resource, "location.coordinates.longitude")

        params = demisto.params()
        labels = list({label.get("value") for label in resource.get("labels", [])})
        score, malicious_description = get_dbot_score(params, labels)
        dbot_score = Common.DBotScore(
            indicator=query,
            indicator_type=DBotScoreType.IP,
            integration_name="Censys",
            score=score,
            malicious_description=malicious_description,
            reliability=params.get("integration_reliability"),
        )
        indicator = Common.IP(
            ip=query,
            dbot_score=dbot_score,
            asn=demisto.get(resource, "autonomous_system.asn"),
            geo_latitude=str(lat) if lat else None,
            geo_longitude=str(lon) if lon else None,
            geo_description=description or None,
            geo_country=country,
            as_owner=demisto.get(resource, "autonomous_system.name"),
        )

        hr_content = {
            "Network": resource.get("autonomous_system", {}).get("name"),
            "Routing": resource.get("autonomous_system", {}).get("bgp_prefix"),
            "ASN": resource.get("autonomous_system", {}).get("asn"),
            "Protocols": ", ".join(
                [f"{service.get('port')}/{service.get('protocol')}" for service in resource.get("services", [])]
            ),
            "Whois Last Updated": demisto.get(resource, "whois.network.updated"),
        }
        human_readable = tableToMarkdown(f"Information for IP {query}", hr_content, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.View",
            outputs_key_field="ip",
            outputs=resource,
            indicator=indicator,
            raw_response=res,
        )
    else:
        hr_content = {
            "Added At": resource.get("added_at"),
            "Modified At": resource.get("modified_at"),
            "Browser Trust": [
                f"{name}: {'Valid' if val.get('ever_valid') else 'Invalid'}"
                for name, val in resource.get("validation", {}).items()
            ],
            "SHA 256": resource.get("fingerprint_sha256"),
            "Validated At": resource.get("validated_at"),
        }
        human_readable = tableToMarkdown("Information for certificate", hr_content, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.View",
            outputs_key_field="fingerprint_sha256",
            outputs=resource,
            raw_response=res,
        )


def censys_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns previews of hosts matching a specified search query or a list of certificates that match the given query.
    """
    index = args.get("index")
    query = args.get("query", "")
    demisto.debug(f"censys_search_command: index={index}, query={query}")
    page_size: int = arg_to_number(args.get("page_size", 50))  # type: ignore[assignment]
    limit = arg_to_number(args.get("limit", 50))
    hr_contents = []

    if index == "ipv4":
        # Use pagination helper to fetch all results up to limit
        res = censys_search_with_pagination(client, query, page_size=page_size, limit=limit)
        hits = res.get("result", {}).get("hits", [])

        # Extract results
        results = []
        for hit in hits:
            # Extract resource for human readable output
            resource = demisto.get(hit, "host_v1.resource", {})
            results.append(resource)

            hr_contents.append(
                {
                    "IP": resource.get("ip"),
                    "Services": ", ".join(
                        [f"{service.get('port')}/{service.get('protocol')}" for service in resource.get("services", [])]
                    ),
                    "Country code": demisto.get(resource, "location.country_code"),
                    "ASN": demisto.get(resource, "autonomous_system.asn"),
                    "Description": demisto.get(resource, "autonomous_system.description"),
                    "Name": demisto.get(resource, "autonomous_system.name"),
                }
            )
        human_readable = tableToMarkdown(f'Search results for query "{query}"', hr_contents, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.Search",
            outputs_key_field="ip",
            outputs=results,
            raw_response=res,
        )
    else:
        response = search_certs_command(client, args, query, limit, page_size)
        return response


def search_certs_command(client: Client, args: dict[str, Any], query: str, limit: Optional[int], page_size: int | None = None):
    # Default fields to request (using new API field names with cert prefix)
    fields = [
        "cert.fingerprint_sha256",
        "cert.parsed.subject_dn",
        "cert.parsed.issuer_dn",
        "cert.parsed.issuer.organization",
        "cert.parsed.validity_period.not_before",
        "cert.parsed.validity_period.not_after",
        "cert.names",
    ]

    # Add user-requested fields
    search_fields = argToList(args.get("fields"))
    if search_fields:
        fields.extend(search_fields)

    # Use pagination helper to fetch all results up to limit
    res = censys_search_with_pagination(client, query, page_size=page_size, fields=fields, limit=limit)
    raw_response = res.get("result", {})
    hits = raw_response.get("hits", [])

    if not hits or not isinstance(hits, list):
        error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
        raise ValueError(error_msg)

    # Extract results
    results = []
    hr_contents = []

    for hit in hits:
        # Extract the certificate data
        resource = demisto.get(hit, "certificate_v1.resource", {})
        results.append(resource)

        # Extract data for human readable output
        parsed = resource.get("parsed", {})

        hr_contents.append(
            {
                "Issuer DN": demisto.get(parsed, "issuer_dn"),
                "Subject DN": demisto.get(parsed, "subject_dn"),
                "Validity not before": demisto.get(parsed, "validity_period.not_before"),
                "Validity not after": demisto.get(parsed, "validity_period.not_after"),
                "SHA256": resource.get("fingerprint_sha256"),
                "Names": resource.get("names"),
                "Issuer": demisto.get(parsed, "issuer.organization"),
            }
        )

    human_readable = tableToMarkdown(f'Search results for query "{query}"', hr_contents, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Censys.Search",
        outputs_key_field="fingerprint_sha256",
        outputs=results,
        raw_response=res,
    )


def ip_command(client: Client, args: dict, params: dict):
    fields = (
        [
            "host.labels.value",
            "host.ip",
            "host.autonomous_system.asn",
            "host.autonomous_system.name",
            "host.autonomous_system.bgp_prefix",
            "host.autonomous_system.country_code",
            "host.autonomous_system.description",
            "host.location.country_code",
            "host.location.timezone",
            "host.location.province",
            "host.location.postal_code",
            "host.location.coordinates.latitude",
            "host.location.coordinates.longitude",
            "host.location.city",
            "host.location.continent",
            "host.location.country",
            "host.services.protocol",
            "host.services.port",
            "host.services.transport_protocol",
            "host.services.extended_service_name",
            "host.services.cert",
            "host.whois.network.updated",
            "host.dns.reverse_dns.names",
            "host.operating_system.source",
            "host.operating_system.part",
            "host.operating_system.version",
        ]
        if params.get("premium_access")
        else None
    )

    ips: list = argToList(args.get("ip"))
    demisto.debug(f"ip_command: processing IPs {ips}")
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    try:
        # Build query for all IPs
        query = " or ".join([f'host.ip="{ip_addr}"' for ip_addr in ips])

        # Send all IPs in a single API call with pagination
        raw_response = censys_search_with_pagination(client, query, fields=fields)
        hits = raw_response.get("result", {}).get("hits")
        if hits is None or not isinstance(hits, list):
            error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
            raise ValueError(error_msg)

        # Track which IPs were found
        found_ips = set()

        # Process each hit from the response
        for hit in hits:
            # Extract resource from host_v1 wrapper
            resource = demisto.get(hit, "host_v1.resource", {})
            ip = resource.get("ip")
            found_ips.add(ip)
            labels = list({label.get("value") for label in resource.get("labels", [])})
            score, malicious_description = get_dbot_score(params, labels)
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name="Censys",
                score=score,
                malicious_description=malicious_description,
                reliability=params.get("integration_reliability"),
            )
            content = {
                "ip": ip,
                "asn": demisto.get(resource, "autonomous_system.asn"),
                "updated_date": demisto.get(resource, "whois.network.updated"),
                "geo_latitude": demisto.get(resource, "location.coordinates.latitude"),
                "geo_longitude": demisto.get(resource, "location.coordinates.longitude"),
                "geo_country": demisto.get(resource, "location.country"),
                "port": ", ".join([str(service.get("port")) for service in resource.get("services", [])]),
            }
            indicator = Common.IP(dbot_score=dbot_score, **content)

            hr_content = {
                **content,
                "labels": ", ".join(labels),
                "score": dbot_score.score,
            }

            results.append(
                CommandResults(
                    outputs_prefix="Censys.IP",
                    outputs_key_field="ip",
                    readable_output=tableToMarkdown(
                        f"censys results for IP: {ip}",
                        hr_content,
                        headerTransform=string_to_table_header,
                        removeNull=True,
                    ),
                    outputs=resource,
                    raw_response=raw_response,
                    indicator=indicator,
                )
            )
            execution_metrics.success += 1

        # Report IPs that were not found
        for ip in ips:
            if ip not in found_ips:
                demisto.debug(f"ip_command: IP {ip} not found in search results")
                results.append(CommandResults(readable_output=f"No results found for IP: {ip}"))

    except Exception as e:
        # Handle exceptions for the entire batch
        handle_exceptions(e, results, execution_metrics, ", ".join(ips))

    if execution_metrics.metrics:
        demisto.debug(f"ip_command: adding execution metrics: {execution_metrics.metrics}")
        results.append(execution_metrics.metrics)

    demisto.debug(f"ip_command: returning {len(results)} results. Types: {[type(r) for r in results]}")
    return results


def domain_command(client: Client, args: dict, params: dict):
    domains: list = argToList(args.get("domain"))
    demisto.debug(f"domain_command: processing domains {domains}")
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    try:
        # Build query for all domains
        query = " or ".join([f'host.dns.names="{dom}"' for dom in domains])

        # Send all domains in a single API call with pagination
        raw_response = censys_search_with_pagination(client, query)
        response = raw_response.get("result", {})
        hits = response.get("hits")
        if hits is None or not isinstance(hits, list):
            error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {response}"
            raise ValueError(error_msg)

        # Track which domains were found
        found_domains = set()

        # Group hits by domain (based on dns.names field)
        domain_hits: dict[str, list] = {domain: [] for domain in domains}
        for hit in hits:
            resource = demisto.get(hit, "host_v1.resource", {})
            dns_names = demisto.get(resource, "dns.names", [])
            # Match this hit to the requested domain(s)
            for domain in domains:
                if domain in dns_names:
                    domain_hits[domain].append(hit)
                    found_domains.add(domain)

        # Create results for each domain
        for domain in domains:
            hits_for_domain = domain_hits.get(domain, [])

            if not hits_for_domain:
                # No results for this domain
                demisto.debug(f"domain_command: domain {domain} not found in search results")
                results.append(CommandResults(readable_output=f"No results found for domain: {domain}"))
                continue

            # Extract resources from host_v1 wrapper
            resources = []
            for hit in hits_for_domain:
                resource = demisto.get(hit, "host_v1.resource", {})
                resources.append(resource)

            relationships = [
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=domain,
                    entity_a_type="Domain",
                    entity_b=demisto.get(hit, "host_v1.resource.ip"),
                    entity_b_type="IP",
                    reverse_name=EntityRelationship.Relationships.RELATED_TO,
                    brand="Censys",
                )
                for hit in hits_for_domain
            ]
            # Collect all labels from all hits for this domain
            all_labels = []
            for res in resources:
                all_labels.extend([label.get("value") for label in res.get("labels", [])])
            all_labels = list(set(all_labels))

            score, malicious_description = get_dbot_score(params, all_labels)
            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name="Censys",
                score=score,
                malicious_description=malicious_description,
                reliability=params.get("integration_reliability"),
            )
            indicator = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

            results.append(
                CommandResults(
                    outputs_prefix="Censys.Domain",
                    outputs_key_field="Domain",
                    readable_output=tableToMarkdown(
                        f"Censys results for Domain: {domain}",
                        {
                            "domain": domain,
                            "labels": ", ".join(all_labels),
                            "score": dbot_score.score,
                        },
                        headerTransform=string_to_table_header,
                        removeNull=True,
                    ),
                    outputs=resources,
                    raw_response=raw_response,
                    indicator=indicator,
                    relationships=relationships,
                )
            )
            execution_metrics.success += 1

    except Exception as e:
        # Handle exceptions for the entire batch
        handle_exceptions(e, results, execution_metrics, ", ".join(domains))

    if execution_metrics.metrics:
        demisto.debug(f"domain_command: adding execution metrics: {execution_metrics.metrics}")
        results.append(execution_metrics.metrics)

    demisto.debug(f"domain_command: returning {len(results)} results. Types: {[type(r) for r in results]}")
    return results


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    api_token = params.get("api_token", {}).get("password")
    org_id = params.get("organization_id")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    base_url = params.get("server_url") or "https://api.platform.censys.io"

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        args = demisto.args()
        client = Client(base_url=base_url, api_token=api_token, org_id=org_id, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, params))

        elif command == "cen-view":
            return_results(censys_view_command(client, args))
        elif command == "cen-search":
            return_results(censys_search_command(client, args))
        elif command == "ip":
            return_results(ip_command(client, args, params))
        elif command == "domain":
            return_results(domain_command(client, args, params))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
