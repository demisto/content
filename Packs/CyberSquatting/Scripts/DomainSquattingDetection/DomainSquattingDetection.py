import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# check https://dnstwister.report/
# the code takes a website name and checks simialr websites

# {"domain_fuzzer_url":"http://dnstwister.report/api/fuzz/{domain_as_hexadecimal}",
# "domain_to_hexadecimal_url":"http://dnstwister.report/api/to_hex/{domain}",
# "google_safe_browsing_url":"http://dnstwister.report/api/safebrowsing/{domain_as_hexadecimal}",
# "ip_resolution_url":"http://dnstwister.report/api/ip/{domain_as_hexadecimal}",
# "parked_check_url":"http://dnstwister.report/api/parked/{domain_as_hexadecimal}",
# "url":"http://dnstwister.report/api/",
# "whois_url":"http://dnstwister.report/api/whois/{domain_as_hexadecimal}"}
requests.packages.urllib3.disable_warnings()


def squatter(domain):
    import requests

    # twsiter APIs need data in hexadecimanl format
    # this one converts domain name to hexadecomal
    twister_to_hex = "https://dnstwister.report/api/to_hex/"

    base_domain = domain

    url_hex = twister_to_hex + base_domain
    twister_urls_for_base = requests.get(url_hex).json()
    # print(twister_urls_for_base)
    fuzz_url = twister_urls_for_base['fuzz_url'].replace("http://", "https://")
    # print(fuzz_url)

    # now our URL to Fuzz is ready
    fuzz_result = requests.get(fuzz_url).json()
    print(fuzz_result)

    # new get IP address of fuzz domains
    fuzzed_domains = []
    for fuzzy in fuzz_result['fuzzy_domains']:
        #IP = requests.get(fuzzy['resolve_ip_url'].replace("http://","https://")).json()['ip']
        # get IP locally
        import socket
        hostname = fuzzy['domain']

        # IP lookup from hostname
        try:
            ip = socket.gethostbyname(hostname)
            #print(f'The {hostname} IP Address is {ip}')
            parked_score = requests.get(fuzzy['parked_score_url'].replace("http://", "https://")).json()
            google_safe = requests.get("https://dnstwister.report/api/safebrowsing/"
                                       + fuzz_result['domain_as_hexadecimal']).json()

            fuzzed_domains.append(
                {"domain": hostname,
                 "IP": ip,
                 "parked_score": parked_score['score'],
                 "google_safe_issue_detected": google_safe['issue_detected']
                 })
        except socket.gaierror as e:
            pass
            #print(f'Invalid hostname {hostname}, error raised is {e}')

    return {"query_domain": hostname,
            "all_domains": fuzz_result['fuzzy_domains'],
            "fuzzed_domains": fuzzed_domains}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    data = squatter(**demisto.args())
    results = CommandResults(
        outputs_prefix='Squatter',
        outputs_key_field='data',
        outputs=data
    )
    return_results(results)
