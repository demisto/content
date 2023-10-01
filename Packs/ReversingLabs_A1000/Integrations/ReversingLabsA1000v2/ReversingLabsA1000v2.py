from CommonServerPython import *
from ReversingLabs.SDK.a1000 import A1000


VERSION = "v2.3.0"
USER_AGENT = f"ReversingLabs XSOAR A1000 {VERSION}"
HOST = demisto.getParam('host')
TOKEN = demisto.getParam('token')
VERIFY_CERT = demisto.getParam('verify')
RELIABILITY = demisto.params().get('reliability', 'C - Fairly reliable')
WAIT_TIME_SECONDS = demisto.params().get('wait_time_seconds')
NUM_OF_RETRIES = demisto.params().get('num_of_retries')

HTTP_PROXY = demisto.params().get("http_proxy", None)
HTTP_PROXY_USERNAME = demisto.params().get("http_credentials", {}).get("identifier", None)
HTTP_PROXY_PASSWORD = demisto.params().get("http_credentials", {}).get("password", None)

HTTPS_PROXY = demisto.params().get("https_proxy", None)
HTTPS_PROXY_USERNAME = demisto.params().get("https_credentials", {}).get("identifier", None)
HTTPS_PROXY_PASSWORD = demisto.params().get("https_credentials", {}).get("password", None)


def format_proxy(addr, username=None, password=None):
    if addr.startswith("http://"):
        protocol = addr[:7]
        proxy_name = addr[7:]
    elif addr.startswith("https://"):
        protocol = addr[:8]
        proxy_name = addr[8:]
    else:
        return_error("Proxy address needs to start with either 'http://' or 'https://'")

    if username:
        if password:
            proxy = f"{protocol}{username}:{password}@{proxy_name}"
        else:
            proxy = f"{protocol}{username}@{proxy_name}"
    else:
        proxy = f"{protocol}{proxy_name}"

    return proxy


def return_proxies():
    proxies = {}

    if HTTP_PROXY:
        http_proxy = format_proxy(
            addr=HTTP_PROXY,
            username=HTTP_PROXY_USERNAME,
            password=HTTP_PROXY_PASSWORD
        )

        proxies["http"] = http_proxy

    if HTTPS_PROXY:
        https_proxy = format_proxy(
            addr=HTTPS_PROXY,
            username=HTTPS_PROXY_USERNAME,
            password=HTTPS_PROXY_PASSWORD
        )

        proxies["https"] = https_proxy

    if proxies:
        return proxies
    else:
        return None


def classification_to_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "UNCLASSIFIED": 0,
        "KNOWN": 1,
        "GOODWARE": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification, 0)


def test(a1000):
    """
    Test credentials and connectivity
    """
    try:
        a1000.test_connection()
        return 'ok'
    except Exception as e:
        return_error(str(e))


def get_results(a1000):
    """
    Get A1000 report
    """
    try:
        hash_value = demisto.getArg('hash')
        response_json = a1000.get_summary_report_v2(hash_value).json()
    except Exception as e:
        return_error(str(e))

    command_result = a1000_report_output(response_json)

    file_result = fileResult('A1000 report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return_results([command_result, file_result])


def upload_sample_and_get_results(a1000):
    """
    Upload file to A1000 and get report
    """
    file_entry = demisto.getFilePath(demisto.getArg('entryId'))

    try:
        with open(file_entry['path'], 'rb') as f:
            response_json = a1000.upload_sample_and_get_summary_report_v2(file_source=f,
                                                                          custom_filename=file_entry.get('name'),
                                                                          tags=demisto.getArg('tags'),
                                                                          comment=demisto.getArg('comment')).json()
    except Exception as e:
        return_error(str(e))

    command_result = a1000_report_output(response_json)

    file_result = fileResult('A1000 report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def a1000_report_output(response_json):
    results = response_json.get('results')
    result = results[0] if results else {}
    status = result.get('classification', '')
    d_bot_score = classification_to_score(status.upper())

    md5 = result.get('md5')
    sha1 = result.get('sha1')
    sha256 = result.get('sha256')
    sha512 = result.get('sha512')
    file_type = result.get('file_type')
    file_subtype = result.get('file_subtype')
    file_size = result.get('file_size')

    markdown = f'''## ReversingLabs A1000 results for: {sha1}\n **Type:** {file_type}/{file_subtype}
    **Size:** {file_size} bytes \n'''

    if md5:
        markdown += f'**MD5:** {md5}\n'
    if sha1:
        markdown += f'**SHA1:** {sha1}\n'
    if sha256:
        markdown += f'**SHA256:** {sha256}\n'
    if sha512:
        markdown += f'**SHA512:** {sha512}\n'

    markdown += f'''**ID:** {demisto.get(result, 'summary.id')}
    **Malware status:** {format(status)}
    **Local first seen:** {result.get('local_first_seen')}
    **Local last seen:** {result.get('local_last_seen')}
    **First seen:** {demisto.gets(result, 'ticloud.first_seen')}
    **Last seen:** {demisto.gets(result, 'ticloud.last_seen')}
    **DBot score:** {d_bot_score}
    **Risk score:** {result.get('riskscore')} \n'''
    if status == 'malicious':
        markdown += f'''**Threat name:** {result.get('classification_result')}'''
    markdown += f'''\n **Category:** {result.get('category')}
    **Classification origin:** {result.get('classification_origin')}
    **Classification reason:** {result.get('classification_reason')}
    **Aliases:** {','.join(result.get('aliases'))}
    **Extracted file count:** {result.get('extracted_file_count')}
    **Identification name:** {result.get('identification_name')}
    **Identification version:** {result.get('identification_version')}\n'''
    indicators = demisto.get(result, 'summary.indicators')
    if indicators:
        markdown += tableToMarkdown('ReversingLabs threat indicators', indicators)

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs A1000 v2',
        score=d_bot_score,
        malicious_description=f"{result.get('classification_reason')} - {result.get('classification_result')}",
        reliability=RELIABILITY
    )

    common_file = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    command_results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_report': response_json},
        readable_output=markdown,
        indicator=common_file
    )

    return command_results


def upload_sample(a1000):
    """
    Upload file to A1000 for analysis
    """
    file_entry = demisto.getFilePath(demisto.getArg('entryId'))

    try:
        with open(file_entry['path'], 'rb') as f:
            response_json = a1000.upload_sample_from_file(f,
                                                          custom_filename=file_entry.get('name'),
                                                          tags=demisto.getArg('tags'),
                                                          comment=demisto.getArg('comment')).json()
    except Exception as e:
        return_error(str(e))

    markdown = f'''## ReversingLabs A1000 upload sample\n **Message:** {response_json.get('message')}
    **ID:** {demisto.get(response_json, 'detail.id')}
    **SHA1:** {demisto.get(response_json, 'detail.sha1')}
    **Created:** {demisto.get(response_json, 'detail.created')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_upload_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('Upload sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def delete_sample(a1000):
    """
    Delete a file from A1000
    """
    hash_value = demisto.getArg('hash')
    try:
        response_json = a1000.delete_samples(hash_value).json()
    except Exception as e:
        return_error(str(e))

    res = response_json.get('results')
    markdown = f'''## ReversingLabs A1000 delete sample\n **Message:** {res.get('message')}
    **MD5:** {demisto.get(res, 'detail.md5')}
    **SHA1:** {demisto.get(res, 'detail.sha1')}
    **SHA256:** {demisto.get(res, 'detail.sha256')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_delete_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('Delete sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def reanalyze(a1000):
    """
    Re-Analyze a sample already existing on A1000
    """
    hash_value = demisto.getArg('hash')
    try:
        response_json = a1000.reanalyze_samples_v2(hash_input=hash_value,
                                                   titanium_core=True,
                                                   titanium_cloud=True,
                                                   rl_cloud_sandbox=True,
                                                   cuckoo_sandbox=True,
                                                   fireeye=True,
                                                   joe_sandbox=True,
                                                   cape=True,
                                                   rl_cloud_sandbox_platform="windows10").json()
    except Exception as e:
        return_error(str(e))

    try:
        result = response_json.get("results")[0]
    except Exception as e:
        return_error(str(e))

    markdown = f'''## ReversingLabs A1000 re-analyze sample\n**Message:** Sample is queued for analysis.
    **MD5:** {demisto.get(result, 'detail.md5')}
    **SHA1:** {demisto.get(result, 'detail.sha1')}
    **SHA256:** {demisto.get(result, 'detail.sha256')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_reanalyze_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('ReAnalyze sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def list_extracted_files(a1000):
    """
    Get the list of extracted files for a given sample
    """
    hash_value = demisto.getArg('hash')

    try:
        response = a1000.list_extracted_files_v2_aggregated(hash_value)
    except Exception as e:
        return_error(str(e))

    command_result = list_extracted_files_output(response)

    file_result = fileResult('List extracted files report file', json.dumps(response, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def list_extracted_files_output(response):
    file_list = []

    for result in response:
        sha1 = demisto.get(result, 'sample.sha1')
        status = demisto.get(result, 'sample.classification')
        file_data = {
            'SHA1': sha1,
            'Name': result.get('filename'),
            'Info': demisto.get(result, 'sample.type_display'),
            'Size': demisto.get(result, 'sample.file_size'),
            'Path': result.get('path'),
            'Local First Seen': demisto.get(result, 'sample.local_first_seen'),
            'Local Last Seen': demisto.get(result, 'sample.local_last_seen'),
            'Malware Status': status,
            'Risk Score': demisto.get(result, 'sample.riskscore'),
            'Identification Name': demisto.get(result, 'sample.identification_name'),
            'Identification Version': demisto.get(result, 'sample.identification_version'),
            'Type Display': demisto.get(result, 'sample.type_display')
        }

        file_list.append(file_data)

    markdown = tableToMarkdown('Extracted files', file_list,
                               ['SHA1', 'Name', 'Path', 'Info', 'Size', 'Local First Seen', 'Local Last Seen',
                                'Malware Status', 'Risk Score', 'Identification Name', 'Identification Version',
                                'Type Display'])

    command_results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_list_extracted_report': response},
        readable_output=markdown,
    )

    return command_results


def download_extracted_files(a1000):
    """
    Download samples obtained through the unpacking process
    """
    hash_value = demisto.getArg('hash')
    try:
        response = a1000.download_extracted_files(hash_value)
    except Exception as e:
        return_error(str(e))

    filename = hash_value + '.zip'
    command_results = CommandResults(
        readable_output=f"## ReversingLabs A1000 download extraced files \nExtracted files are available for download "
                        f"under the name {filename}"
    )

    file_result = fileResult(filename, response.content, file_type=EntryType.FILE)

    return [command_results, file_result]


def download_sample(a1000):
    """
    Download a sample from A1000
    """
    hash_value = demisto.getArg('hash')

    try:
        response = a1000.download_sample(hash_value)
    except Exception as e:
        return_error(str(e))

    command_results = CommandResults(
        readable_output=f"## ReversingLabs A1000 download sample \nRequested sample is available for download under "
                        f"the name {hash_value}"
    )

    file_result = fileResult(hash_value, response.content, file_type=EntryType.FILE)

    return [command_results, file_result]


def get_classification(a1000):
    """
    Get the classification of a selected sample
    """
    hash_value = demisto.getArg('hash')
    local_only = argToBoolean(demisto.getArg('localOnly'))

    try:
        response_json = a1000.get_classification_v3(hash_value,
                                                    local_only=local_only,
                                                    av_scanners=True).json()
    except Exception as e:
        return_error(str(e))

    command_result = get_classification_output(response_json)
    file_result = fileResult('Get classification report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def get_classification_output(response_json):
    markdown = f"## ReversingLabs A1000 get classification for sha1: {response_json.get('sha1')}\n"
    for key, value in response_json.items():
        markdown += f'**{str.capitalize(key.replace("_", " "))}:** {value}\n'

    status = response_json.get('classification')
    if status:
        d_bot_score = classification_to_score(status.upper())

        dbot_score = Common.DBotScore(
            indicator=response_json.get('sha1'),
            indicator_type=DBotScoreType.FILE,
            integration_name='ReversingLabs A1000 v2',
            score=d_bot_score,
            malicious_description=status,
            reliability=RELIABILITY
        )

        common_file = Common.File(
            md5=response_json.get('md5'),
            sha1=response_json.get('sha1'),
            sha256=response_json.get('sha256'),
            dbot_score=dbot_score
        )

        command_results = CommandResults(
            outputs_prefix='ReversingLabs',
            outputs={'a1000_classification_report': response_json},
            indicator=common_file,
            readable_output=markdown
        )

        return command_results


def advanced_search(a1000):
    """
    Advanced Search by query
    """
    query = demisto.getArg("query")
    ticloud = argToBoolean(demisto.getArg("ticloud"))

    try:
        limit = demisto.getArg("result_limit")
        if not isinstance(limit, int):
            limit = int(limit)
    except KeyError:
        limit = 5000

    try:
        result_list = a1000.advanced_search_v2_aggregated(
            query_string=query,
            ticloud=ticloud,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_advanced_search_report': result_list},
        readable_output="## Reversinglabs A1000 advanced Search \nFull report is returned in a downloadable file"
    )

    file_result = fileResult('Advanced search report file', json.dumps(result_list, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def get_url_report(a1000):
    """
    Get a report for a submitted URL
    """
    url = demisto.getArg("url")

    try:
        response = a1000.network_url_report(requested_url=url)
        response_json = response.json()
    except Exception as e:
        return_error(str(e))

    results = url_report_output(url=url, response_json=response_json)

    return results


def url_report_output(url, response_json):
    classification = response_json.get("classification")
    analysis = response_json.get("analysis", {})
    analysis_statistics = analysis.get("statistics", {})
    last_analysis = tableToMarkdown("Last analysis", analysis.get("last_analysis"))
    analysis_history = tableToMarkdown("Analysis history", analysis.get("analysis_history"))
    reputations = response_json.get("third_party_reputations")
    reputation_statistics = reputations.get("statistics")
    reputation_sources = tableToMarkdown("Sources", reputations.get("sources"))

    markdown = f"""## ReversingLabs A1000 URL Report for {url}\n **Classification**: {classification}
    \n## Third party reputation statistics\n **Total**: {reputation_statistics.get("total")}
    **Malicious**: {reputation_statistics.get("malicious")}
    **Clean**: {reputation_statistics.get("clean")}
    **Undetected**: {reputation_statistics.get("undetected")}
    \n## Analysis statistics\n **Unknown**: {analysis_statistics.get("unknown")}
    **Suspicious**: {analysis_statistics.get("suspicious")}
    **Malicious**: {analysis_statistics.get("malicious")}
    **Goodware**: {analysis_statistics.get("goodware")}
    **Total**: {analysis_statistics.get("total")}
    \n**First analysis**: {analysis.get("first_analysis")}
    **Analysis count**: {analysis.get("analysis_count")}
    """

    markdown = f"{markdown}\n ## Third party reputation sources\n"
    markdown = f"{markdown}\n {reputation_sources}"

    markdown = f"{markdown}\n {last_analysis}"
    markdown = f"{markdown}\n {analysis_history}"

    d_bot_score = classification_to_score(classification.upper())

    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name="ReversingLabs A1000 v2",
        score=d_bot_score,
        malicious_description=classification,
        reliability=RELIABILITY
    )

    indicator = Common.URL(
        url=url,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_url_report": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def get_domain_report(a1000):
    """
    Get a report for a submitted domain
    """
    domain = demisto.getArg("domain")

    try:
        response = a1000.network_domain_report(domain=domain)
        response_json = response.json()
    except Exception as e:
        return_error(str(e))

    results = domain_report_output(domain=domain, response_json=response_json)

    return results


def domain_report_output(domain, response_json):
    top_threats = tableToMarkdown("Top threats", response_json.get("top_threats"))
    file_statistics = response_json.get("downloaded_files_statistics")

    last_dns_records = tableToMarkdown("Last DNS records", response_json.get("last_dns_records"))

    reputations = response_json.get("third_party_reputations")
    reputation_statistics = reputations.get("statistics")
    reputation_sources = tableToMarkdown("Third party reputation sources", reputations.get("sources"))

    markdown = f"""## ReversingLabs A1000 Domain Report for {domain}\n **Modified time**: {response_json.get("modified_time")}"""
    markdown = f"{markdown}\n {top_threats}"

    markdown = f"""{markdown}\n ### Third party reputation statistics\n **Malicious**: {reputation_statistics.get("malicious")}
    **Undetected**: {reputation_statistics.get("undetected")}
    **Clean**: {reputation_statistics.get("clean")}
    **Total**: {reputation_statistics.get("total")}
    """

    markdown = f"""{markdown}\n ### Downloaded files statistics\n **Unknown**: {file_statistics.get("unknown")}
    **Suspicious**: {file_statistics.get("suspicious")}
    **Malicious**: {file_statistics.get("malicious")}
    **Goodware**: {file_statistics.get("goodware")}
    **Total**: {file_statistics.get("total")}
    \n**Last DNS records time**: {response_json.get("last_dns_records_time")}
    """

    markdown = f"{markdown}\n {last_dns_records}"

    markdown = f"{markdown}\n {reputation_sources}"

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs A1000 v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_domain_report": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def get_ip_report(a1000):
    """
    Get a report for a submitted IP address
    """
    ip = demisto.getArg("ip_address")

    try:
        response = a1000.network_ip_addr_report(ip_addr=ip)
        response_json = response.json()
    except Exception as e:
        return_error(str(e))

    results = ip_report_output(ip=ip, response_json=response_json)

    return results


def ip_report_output(ip, response_json):
    top_threats = tableToMarkdown("Top threats", response_json.get("top_threats"))
    file_statistics = response_json.get("downloaded_files_statistics")

    reputations = response_json.get("third_party_reputations")
    reputation_statistics = reputations.get("statistics")
    reputation_sources = tableToMarkdown("Third party reputation sources", reputations.get("sources"))

    markdown = f"""## ReversingLabs A1000 IP Address Report for {ip}\n **Modified time**: {response_json.get("modified_time")}"""
    markdown = f"{markdown}\n {top_threats}"

    markdown = f"""{markdown}\n ### Third party reputation statistics\n **Malicious**: {reputation_statistics.get("malicious")}
    **Undetected**: {reputation_statistics.get("undetected")}
    **Clean**: {reputation_statistics.get("clean")}
    **Total**: {reputation_statistics.get("total")}
    """

    markdown = f"""{markdown}\n ### Downloaded files statistics\n **Unknown**: {file_statistics.get("unknown")}
    **Suspicious**: {file_statistics.get("suspicious")}
    **Malicious**: {file_statistics.get("malicious")}
    **Goodware**: {file_statistics.get("goodware")}
    **Total**: {file_statistics.get("total")}
    """

    markdown = f"{markdown}\n {reputation_sources}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs A1000 v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_ip_address_report": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def get_files_from_ip(a1000):
    """
    Get a list of hashes and classifications for files found on the requested IP address.
    """
    ip = demisto.getArg("ip_address")
    extended = argToBoolean(demisto.getArg("extended_results"))
    classification = demisto.getArg("classification")
    page_size = int(demisto.getArg("page_size"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = a1000.network_files_from_ip_aggregated(
            ip_addr=ip,
            extended_results=extended,
            classification=classification,
            page_size=page_size,
            max_results=max_results
        )
    except Exception as e:
        return_error(str(e))

    results = files_from_ip_output(ip=ip, response=response)

    return results


def files_from_ip_output(ip, response):
    returned_files = tableToMarkdown("Files downloaded from IP address", response)

    markdown = f"## ReversingLabs A1000 Files Downloaded From IP Address {ip}\n"
    markdown = f"{markdown} {returned_files}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs A1000 v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_ip_address_downloaded_files": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def get_ip_domain_resolutions(a1000):
    """
    Get a list of IP-to-domain resolutions.
    """
    ip = demisto.getArg("ip_address")
    page_size = int(demisto.getArg("page_size"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = a1000.network_ip_to_domain_aggregated(
            ip_addr=ip,
            page_size=page_size,
            max_results=max_results
        )
    except Exception as e:
        return_error(str(e))

    results = ip_domain_resolutions_output(ip=ip, response=response)

    return results


def ip_domain_resolutions_output(ip, response):
    returned_domains = tableToMarkdown("IP-to-domain resolutions", response)

    markdown = f"## ReversingLabs A1000 IP-to-domain Resolutions for IP address {ip}\n"
    markdown = f"{markdown} {returned_domains}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs A1000 v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_ip_domain_resolutions": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def get_urls_from_ip(a1000):
    """
    Get a list of URL-s hosted on an IP address.
    """
    ip = demisto.getArg("ip_address")
    page_size = int(demisto.getArg("page_size"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = a1000.network_urls_from_ip_aggregated(
            ip_addr=ip,
            page_size=page_size,
            max_results=max_results
        )
    except Exception as e:
        return_error(str(e))

    results = urls_from_ip_output(ip=ip, response=response)

    return results


def urls_from_ip_output(ip, response):
    returned_urls = tableToMarkdown("URL-s hosted on the IP address", response)

    markdown = f"## ReversingLabs A1000 URL-s Hosted On IP Address {ip}\n"
    markdown = f"{markdown} {returned_urls}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs A1000 v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_ip_urls": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def main():
    try:
        wait_time_seconds = int(WAIT_TIME_SECONDS)
    except ValueError:
        return_error("Integration parameter <Wait between retries> has to be of type integer.")

    try:
        num_of_retries = int(NUM_OF_RETRIES)
    except ValueError:
        return_error("Integration parameter <Number of retries> has to be of type integer.")

    proxies = return_proxies()

    a1000 = A1000(
        host=HOST,
        token=TOKEN,
        verify=VERIFY_CERT,
        user_agent=USER_AGENT,
        wait_time_seconds=wait_time_seconds,
        retries=num_of_retries,
        proxies=proxies
    )

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'test-module':
            return_results(test(a1000))
        elif demisto.command() == 'reversinglabs-a1000-get-results':
            return_results(get_results(a1000))
        elif demisto.command() == 'reversinglabs-a1000-upload-sample-and-get-results':
            return_results(upload_sample_and_get_results(a1000))
        elif demisto.command() == 'reversinglabs-a1000-upload-sample':
            return_results(upload_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-delete-sample':
            return_results(delete_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-list-extracted-files':
            return_results(list_extracted_files(a1000))
        elif demisto.command() == 'reversinglabs-a1000-download-sample':
            return_results(download_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-reanalyze':
            return_results(reanalyze(a1000))
        elif demisto.command() == 'reversinglabs-a1000-download-extracted-files':
            return_results(download_extracted_files(a1000))
        elif demisto.command() == 'reversinglabs-a1000-get-classification':
            return_results(get_classification(a1000))
        elif demisto.command() == 'reversinglabs-a1000-advanced-search':
            return_results(advanced_search(a1000))
        elif demisto.command() == "reversinglabs-a1000-url-report":
            return_results(get_url_report(a1000))
        elif demisto.command() == 'reversinglabs-a1000-domain-report':
            return_results(get_domain_report(a1000))
        elif demisto.command() == 'reversinglabs-a1000-ip-address-report':
            return_results(get_ip_report(a1000))
        elif demisto.command() == 'reversinglabs-a1000-ip-downloaded-files':
            return_results(get_files_from_ip(a1000))
        elif demisto.command() == 'reversinglabs-a1000-ip-domain-resolutions':
            return_results(get_ip_domain_resolutions(a1000))
        elif demisto.command() == 'reversinglabs-a1000-ip-urls':
            return_results(get_urls_from_ip(a1000))
        else:
            return_error(f'Command [{demisto.command()}] not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
