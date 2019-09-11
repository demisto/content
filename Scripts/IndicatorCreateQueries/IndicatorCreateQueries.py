"""
The script accepts indicators and creates relevant queries in relevant products
"""
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def generate_ip_queries(ips):
    ips = [ip for ip in ips if is_ip_valid(ip)]
    if not ips:
        return {}

    queries = {}
    # Cortex traps IP
    ip_fields = ["endPointHeader.agentIp='{}'".format(ip) for ip in ips]
    query_cortex_traps_ip = ' OR '.join(ip_fields)
    queries['CortexTrapsIP'] = 'SELECT * from tms.threat where {}'.format(query_cortex_traps_ip)

    # Cortex Analytics IP
    ip_fields = ["endPointHeader.agentIp='{}'".format(ip) for ip in ips]
    query_cortex_analytics_ip = ' OR '.join(ip_fields)
    queries['CortexAnalyticsIP'] = 'SELECT * from tms.analytics where {}'.format(query_cortex_analytics_ip)

    # Cortex Traffic IP
    ip_fields = ["src='{0}' OR dst='{0}'".format(ip) for ip in ips]
    query_cortex_traffic_ip = ' OR '.join(ip_fields)
    queries['CortexTrafficIP'] = 'SELECT * from panw.traffic where {}'.format(query_cortex_traffic_ip)

    # Cortex Threat IP
    ip_fields = ["src='{0}' OR dst='{0}'".format(ip) for ip in ips]
    query_cortex_threat_ip = ' OR '.join(ip_fields)
    queries['CortexThreatIP'] = 'SELECT * from panw.threat where {}'.format(query_cortex_threat_ip)

    # Autofocus Sessions IP
    children = [{
        'field': 'alias.ip_address',
        'operator': 'contains',
        'value': ip
    } for ip in ips]
    query_autofocus_sessions_ip = {
        'operator': 'any',
        'children': children
    }
    queries['AutofocusSessionsIP'] = json.dumps(query_autofocus_sessions_ip)

    # Panorama IP
    ip_fields = ["( addr.src in {0} ) or ( addr.dst in {0} )".format(ip) for ip in ips]
    query_panorama_ip = ' or '.join(ip_fields)
    queries['PanoramaIP'] = query_panorama_ip

    return queries


def generate_hash_queries(hashes):
    if not hashes:
        return {}

    queries = {}

    # TBD
    #     ### Cortex traps Hash ###
    #     seperatorCortexTrapsHash = "' OR messageData.files.sha256='"
    #     queryCortexTrapsHash = seperatorCortexTrapsHash.join(HASHList)
    #     print("SELECT * from tms.threat  where messageData.files.sha256 ='" + queryCortexTrapsHash + "'")
    #
    #     ### Cortex Analytics Hash ###
    #     seperatorCortexAnalyticsHash = "' OR messageData.sha256='"
    #     queryCortexAnalyticsHash = seperatorCortexAnalyticsHash.join(HASHList)
    #     print("SELECT * from tms.analytics  where messageData.sha256='" + queryCortexAnalyticsHash + "'")
    #
    #     ### Cortex threat Hash ###
    #     seperatorCortexThreatHash = "' OR filedigest='"
    #     queryCortexThreatHash = seperatorCortexThreatHash.join(HASHList)
    #     print("SELECT * from panw.threat WHERE filedigest='" + queryCortexThreatHash + "'")
    #
    #     ### Autofocus Hash ###
    #     seperatorAutofocusSessionsHash = "\"}" + ",{\"field\":\"alias.hash\"" + "," + "\"operator\":\"contains\"" + "," + "\"value\":\""
    #     queryAutofocusSessionsHash = seperatorAutofocusSessionsHash.join(HASHList)
    #     print(
    #         "{\"operator\":\"any\",\"children\":[{\"field\":\"alias.hash\",\"operator\":\"contains\",\"value\":" + "\"" + queryAutofocusSessionsHash + "\"" + "}]}")
    #
    #     ### Panorama Hash ###
    #     seperatorPanoramaHash = " ) or ( filedigest eq "
    #     queryPanoramaHash = seperatorPanoramaHash.join(HASHList)
    #     print("( filedigest eq " + queryPanoramaHash + " )")

    return queries


def generate_domain_queries(domains):
    if not domains:
        return {}

    queries = {}

    # TBD
    # Cortex Threat Domain
    #     seperatorCortexThreatDomain = "'* OR misc LIKE '*"
    #     queryCortexThreatDomain = seperatorCortexThreatDomain.join(DOMAINList)
    #     print("SELECT * from panw.threat WHERE misc LIKE '*" + queryCortexThreatDomain + "*'")
    #
    #     ### Autofocus Domain ###
    #     seperatorAutofocusSessionsDomain = "\"}" + ",{\"field\":\"alias.domain\"" + "," + "\"operator\":\"contains\"" + "," + "\"value\":\""
    #     queryAutofocusSessionsDomain = seperatorAutofocusSessionsDomain.join(DOMAINList)
    #     print(
    #         "{\"operator\":\"any\",\"children\":[{\"field\":\"alias.domain\",\"operator\":\"contains\",\"value\":" + "\"" + queryAutofocusSessionsDomain + "\"" + "}]}")
    #
    #     ### Panorama Domain ###
    #     seperatorPanoramaDomain = " ) or ( url contains "
    #     queryPanoramaDomain = seperatorPanoramaDomain.join(DOMAINList)
    #     print("( url contains " + queryPanoramaDomain + " )")

    return queries


def main(args):
    ips = argToList(args.get('ip'))
    hashes = argToList(args.get('hash'))
    domains = argToList(args.get('domain'))

    ip_queries = generate_ip_queries(ips)
    hash_queries = generate_hash_queries(hashes)
    domain_queries = generate_domain_queries(domains)

    human_readable = ''.join([
        tableToMarkdown('IP Queries', ip_queries),
        tableToMarkdown('Hashes Queries', hash_queries),
        tableToMarkdown('Domains Queries', domain_queries),
    ])
    outputs = {
        'Query.IP': ip_queries,
        'Query.Hash': hash_queries,
        'Query.Domain': domain_queries,
    }

    return_outputs(human_readable, outputs)


if __name__ in ('builtins', '__main__'):
    main(demisto.args())
