import json
import subprocess

from CommonServerPython import *

TWIST_EXE = '/dnstwist/dnstwist.py'

if demisto.command() == 'dnstwist-domain-variations':

    KEYS_TO_MD = ["whois_updated", "whois_created", "dns_a", "dns_mx", "dns_ns"]
    DOMAIN = demisto.args()['domain']
    LIMIT = int(demisto.args()['limit'])
    WHOIS = demisto.args().get('whois')

    def get_dnstwist_result(domain, include_whois):
        args = [TWIST_EXE, '-f', 'json']
        if include_whois:
            args.append('-w')
        args.append(domain)
        res = subprocess.check_output(args)
        return json.loads(res)

    def get_domain_to_info_map(dns_twist_result):
        results = []
        for x in dns_twist_result:
            temp = {}  # type: dict
            for k, v in x.items():
                if k in KEYS_TO_MD:
                    if x["domain"] not in temp:
                        temp["domain-name"] = x["domain"]
                    if k == "dns_a":
                        temp["IP Address"] = v
                    else:
                        temp[k] = v
            if temp:
                results.append(temp)
        return results

    dnstwist_result = get_dnstwist_result(DOMAIN, WHOIS == 'yes')
    new_result = get_domain_to_info_map(dnstwist_result)
    md = tableToMarkdown('dnstwist for domain - ' + DOMAIN, new_result,
                         headers=["domain-name", "IP Address", "dns_mx", "dns_ns", "whois_updated", "whois_created"])

    domain_context = new_result[0]  # The requested domain for variations
    domains_context_list = new_result[1:LIMIT + 1]  # The variations domains

    domains = []
    for item in domains_context_list:
        temp = {"Name": item["domain-name"]}
        if "IP Address" in item:
            temp["IP"] = item["IP Address"]
        if "dns_mx" in item:
            temp["DNS-MX"] = item["dns_mx"]
        if "dns_ns" in item:
            temp["DNS-NS"] = item["dns_ns"]
        if "whois_updated" in item:
            temp["WhoisUpdated"] = item["whois_updated"]
        if "whois_created" in item:
            temp["WhoisCreated"] = item["whois_created"]
        domains.append(temp)

    ec = {"Domains": domains}
    if "domain-name" in domain_context:
        ec["Name"] = domain_context["domain-name"]
    if "IP Address" in domain_context:
        ec["IP"] = domain_context["IP Address"]
    if "dns_mx" in domain_context:
        ec["DNS-MX"] = domain_context["dns_mx"]
    if "dns_ns" in domain_context:
        ec["DNS-NS"] = domain_context["dns_ns"]
    if "whois_updated" in domain_context:
        ec["WhoisUpdated"] = domain_context["whois_updated"]
    if "whois_created" in domain_context:
        ec["WhoisCreated"] = domain_context["whois_created"]

    entry_result = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': dnstwist_result,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {'dnstwist.Domain(val.Name == obj.Name)': ec}
    }

    demisto.results(entry_result)

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    subprocess.check_output([TWIST_EXE, '-h'], stderr=subprocess.STDOUT)
    demisto.results('ok')
    sys.exit(0)
