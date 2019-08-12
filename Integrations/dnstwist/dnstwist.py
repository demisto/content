import json
import subprocess

from CommonServerPython import *

TWIST_EXE = '/dnstwist/dnstwist.py'

if demisto.command() == 'dnstwist-domain-variations':

    KEYS_TO_MD = ["whois-updated", "whois-created", "dns-a", "dns-mx", "dns-ns"]
    DOMAIN = demisto.args()['domain']
    LIMIT = int(demisto.args()['limit'])
    WHOIS = demisto.args().get('whois')

    def get_dnstwist_result(domain, include_whois):
        args = [TWIST_EXE, '-j']
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
                    if x["domain-name"] not in temp:
                        temp["domain-name"] = x["domain-name"]
                    if k == "dns-a":
                        temp["IP Address"] = v
                    else:
                        temp[k] = v
            if temp:
                results.append(temp)
        return results

    dnstwist_result = get_dnstwist_result(DOMAIN, WHOIS == 'yes')
    new_result = get_domain_to_info_map(dnstwist_result)
    md = tableToMarkdown('dnstwist for domain - ' + DOMAIN, new_result,
                         headers=["domain-name", "IP Address", "dns-mx", "dns-ns", "whois-updated", "whois-created"])

    domain_context = new_result[0]  # The requested domain for variations
    domains_context_list = new_result[1:LIMIT + 1]  # The variations domains

    domains = []
    for item in domains_context_list:
        temp = {"Name": item["domain-name"]}
        if "IP Address" in item:
            temp["IP"] = item["IP Address"]
        if "dns-mx" in item:
            temp["DNS-MX"] = item["dns-mx"]
        if "dns-ns" in item:
            temp["DNS-NS"] = item["dns-ns"]
        if "whois-updated" in item:
            temp["WhoisUpdated"] = item["whois-updated"]
        if "whois-created" in item:
            temp["WhoisCreated"] = item["whois-created"]
        domains.append(temp)

    ec = {"Domains": domains}
    if "domain-name" in domain_context:
        ec["Name"] = domain_context["domain-name"]
    if "IP Address" in domain_context:
        ec["IP"] = domain_context["IP Address"]
    if "dns-ns" in domain_context:
        ec["DNS-MX"] = domain_context["dns-mx"]
    if "dns-ns" in domain_context:
        ec["DNS-NS"] = domain_context["dns-ns"]
    if "whois-updated" in domain_context:
        ec["WhoisUpdated"] = domain_context["whois-updated"]
    if "whois-created" in domain_context:
        ec["WhoisCreated"] = domain_context["whois-created"]

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
