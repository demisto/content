"""
The script accepts indicators and creates relevant queries in Panw products
"""

from CommonServerPython import *


def generate_ip_queries(ips: list):
    ips = [ip for ip in ips if is_ip_valid(ip)]
    if not ips:
        return {}

    queries = {}
    # Cortex traps IP
    ip_fields = ["endPointHeader.agentIp='{}'".format(ip) for ip in ips]
    query_cortex_traps_ip = " OR ".join(ip_fields)
    queries["CortexTrapsIP"] = (
        f"SELECT * from tms.threat where "  # guardrails-disable-line
        f"{query_cortex_traps_ip}"
    )

    # Cortex Analytics IP
    ip_fields = ["endPointHeader.agentIp='{}'".format(ip) for ip in ips]
    query_cortex_analytics_ip = " OR ".join(ip_fields)
    queries["CortexAnalyticsIP"] = (
        f"SELECT * from tms.analytics where "  # guardrails-disable-line
        f"{query_cortex_analytics_ip}"
    )

    # Cortex Traffic IP
    ip_fields = ["src='{0}' OR dst='{0}'".format(ip) for ip in ips]
    query_cortex_traffic_ip = " OR ".join(ip_fields)
    queries["CortexTrafficIP"] = (
        f"SELECT * from panw.traffic where "  # guardrails-disable-line
        f"{query_cortex_traffic_ip}"
    )

    # Cortex Threat IP
    ip_fields = ["src='{0}' OR dst='{0}'".format(ip) for ip in ips]
    query_cortex_threat_ip = " OR ".join(ip_fields)
    queries["CortexThreatIP"] = (
        f"SELECT * from panw.threat where "  # guardrails-disable-line
        f"{query_cortex_threat_ip}"
    )

    # Autofocus Sessions IP
    children = [{"field": "alias.ip_address", "operator": "contains", "value": ip} for ip in ips]
    query_autofocus_sessions_ip = {"operator": "any", "children": children}
    queries["AutofocusSessionsIP"] = json.dumps(query_autofocus_sessions_ip)

    # Panorama IP
    ip_fields = ["( addr.src in {0} ) or ( addr.dst in {0} )".format(ip) for ip in ips]
    query_panorama_ip = " or ".join(ip_fields)
    queries["PanoramaIP"] = query_panorama_ip

    return queries


def generate_hash_queries(hashes: list):
    if not hashes:
        return {}

    queries = {}
    # Cortex traps Hash
    hash_fields = ["messageData.files.sha256='{}'".format(hash) for hash in hashes]
    query_cortex_traps_hash = " OR ".join(hash_fields)
    queries["CortexTrapsHash"] = (
        f"SELECT * from tms.threat where "  # guardrails-disable-line
        f"{query_cortex_traps_hash}"
    )

    # Cortex Analytics Hash
    hash_fields = ["messageData.sha256='{}'".format(hash) for hash in hashes]
    query_cortex_analytics_hash = " OR ".join(hash_fields)
    queries["CortexAnalyticsHash"] = (
        f"SELECT * from tms.analytics where "  # guardrails-disable-line
        f"{query_cortex_analytics_hash}"
    )

    # Cortex Threat Hash
    hash_fields = ["filedigest='{}'".format(hash) for hash in hashes]
    query_cortex_threat_hash = " OR ".join(hash_fields)
    queries["CortexThreatHash"] = (
        f"SELECT * from panw.threat where "  # guardrails-disable-line
        f"{query_cortex_threat_hash}"
    )

    # Autofocus Hash
    children = [{"field": "alias.hash_lookup", "operator": "contains", "value": hash} for hash in hashes]
    query_autofocus_sessions_hash = {"operator": "any", "children": children}
    queries["AutofocusSessionsHash"] = json.dumps(query_autofocus_sessions_hash)

    # Panorama IP
    hash_fields = ["( filedigest eq {} )".format(hash) for hash in hashes]
    query_panorama_hash = " or ".join(hash_fields)
    queries["PanoramaHash"] = query_panorama_hash

    return queries


def generate_domain_queries(domains: list):
    if not domains:
        return {}

    queries = {}

    # Cortex Threat Domain
    domain_fields = ["misc LIKE '{}'".format(domain) for domain in domains]
    query_cortex_threat_domain = " OR ".join(domain_fields)
    queries["CortexThreatDomain"] = (
        f"SELECT * from panw.threat where "  # guardrails-disable-line
        f"{query_cortex_threat_domain}"
    )

    # Autofocus Domain
    children = [{"field": "alias.domain", "operator": "contains", "value": domain} for domain in domains]
    query_autofocus_sessions_domain = {"operator": "any", "children": children}
    queries["AutofocusSessionsDomain"] = json.dumps(query_autofocus_sessions_domain)

    # Panorama Domain
    domain_fields = ["( url contains {} )".format(domain) for domain in domains]
    query_panorama_domain = " or ".join(domain_fields)
    queries["PanoramaDomain"] = query_panorama_domain

    return queries


def main() -> None:
    try:
        args = demisto.args()
        ips = argToList(args.get("ip"))
        hashes = argToList(args.get("hash"))
        domains = argToList(args.get("domain"))

        ip_queries = generate_ip_queries(ips)
        hash_queries = generate_hash_queries(hashes)
        domain_queries = generate_domain_queries(domains)

        human_readable = "".join(
            [
                tableToMarkdown("IP Queries", ip_queries),
                tableToMarkdown("Hashes Queries", hash_queries),
                tableToMarkdown("Domains Queries", domain_queries),
            ]
        )
        outputs = {
            "Query.IP": ip_queries,
            "Query.Hash": hash_queries,
            "Query.Domain": domain_queries,
        }

        return_outputs(human_readable, outputs)

    except Exception as err:
        return_error(f"Unexpected error: {err}.\ntraceback: {traceback.format_exc()}")


if __name__ in ("builtins", "__builtin__"):
    main()
