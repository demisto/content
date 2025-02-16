from CommonServerPython import *
from ReversingLabs.SDK.a1000 import A1000


VERSION = "v2.4.4"
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
    protocol: str
    proxy_name: str
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
    **Aliases:** {','.join(result.get('aliases', []))}
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

    results, file_result = upload_sample_output(response_json=response_json)
    return [results, file_result]


def upload_sample_output(response_json):
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

    return command_result, file_result


def delete_sample(a1000):
    """
    Delete a file from A1000
    """
    hash_value = demisto.getArg('hash')
    try:
        response_json = a1000.delete_samples(hash_value).json()
    except Exception as e:
        return_error(str(e))

    results, file_result = delete_sample_output(response_json=response_json)
    return [results, file_result]


def delete_sample_output(response_json):
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

    return command_result, file_result


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

    results, file_result = reanalyze_output(response_json=response_json)
    return [results, file_result]


def reanalyze_output(response_json):
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

    return command_result, file_result


def list_extracted_files(a1000):
    """
    Get the list of extracted files for a given sample
    """
    hash_value = demisto.getArg('hash')
    max_results = int(demisto.getArg("max_results"))

    try:
        response = a1000.list_extracted_files_v2_aggregated(sample_hash=hash_value, max_results=max_results)
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
    av_scanners = argToBoolean(demisto.getArg('avScanners'))

    try:
        response_json = a1000.get_classification_v3(hash_value,
                                                    local_only=local_only,
                                                    av_scanners=av_scanners).json()
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
    return None


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

    results, file_result = advanced_search_output(result_list=result_list)
    return [results, file_result]


def advanced_search_output(result_list):
    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_advanced_search_report': result_list},
        readable_output="## Reversinglabs A1000 advanced Search \nFull report is returned in a downloadable file"
    )

    file_result = fileResult('Advanced search report file', json.dumps(result_list, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return command_result, file_result


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


def user_tags_command(a1000: A1000):
    action = demisto.getArg("action")
    sample_hash = demisto.getArg("hash")
    tags = demisto.getArg("tags")

    try:
        if action == "GET":
            resp = a1000.get_user_tags(sample_hash=sample_hash)

        elif action == "CREATE":
            tags_list = tags.split(",")
            resp = a1000.post_user_tags(sample_hash=sample_hash, tags=tags_list)

        elif action == "DELETE":
            tags_list = tags.split(",")
            resp = a1000.delete_user_tags(sample_hash=sample_hash, tags=tags_list)

        else:
            raise Exception("This action is not supported.")

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results = user_tags_output(resp=resp, action=action)
    return results


def user_tags_output(resp, action):
    markdown = f"## ReversingLabs A1000 user tags - {action} tags\n **Tag list**: {resp.text}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_user_tags": resp.json()},
        readable_output=markdown
    )

    return results


def file_analysis_status_command(a1000: A1000):
    sample_hashes = demisto.getArg("hashes")
    hash_list = sample_hashes.split(",")

    analysis_status = demisto.getArg("analysis_status")

    try:
        resp = a1000.file_analysis_status(sample_hashes=hash_list, sample_status=analysis_status)

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results = file_analysis_status_output(resp_json=resp.json(), status=analysis_status)
    return results


def file_analysis_status_output(resp_json, status=None):
    markdown = f"""## ReversingLabs A1000 file analysis status\n **Hash type**: {resp_json.get("hash_type")}\n"""

    if status:
        markdown = markdown + f"**Only status**: {status}\n"

    results_table = tableToMarkdown("Analysis status", resp_json.get("results"))

    markdown = markdown + results_table

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_file_analysis_status": resp_json},
        readable_output=markdown
    )

    return results


def pdf_report_command(a1000: A1000):
    sample_hash = demisto.getArg("hash")
    action = demisto.getArg("action")

    try:
        if action == "CREATE REPORT":
            resp = a1000.create_pdf_report(sample_hash=sample_hash).json()

        elif action == "CHECK STATUS":
            resp = a1000.check_pdf_report_creation(sample_hash=sample_hash).json()

        elif action == "DOWNLOAD REPORT":
            resp = a1000.download_pdf_report(sample_hash=sample_hash)

        else:
            raise Exception("This action is not supported.")

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results, file_result = pdf_report_output(resp=resp, action=action, sample_hash=sample_hash)
    if file_result:
        return [results, file_result]
    else:
        return results


def pdf_report_output(resp, action, sample_hash):
    markdown = f"## ReversingLabs A1000 PDF report - {action}\n"

    file_result = None

    if action == "CREATE REPORT":
        markdown = (markdown + f"""**Status endpoint**: {resp.get("status_endpoint")}\n"""
                    + f"""**Download endpoint**: {resp.get("download_endpoint")}""")
        context = resp

    elif action == "CHECK STATUS":
        markdown = markdown + f"""**Status**: {resp.get("status")}\n **Status message**: {resp.get("status_message")}"""
        context = resp

    else:
        markdown = markdown + "The PDF report is returned as a downloadable file below."
        file_result = fileResult(f"{sample_hash}.pdf", resp.content, file_type=EntryType.FILE)
        context = None

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_pdf_report": context},
        readable_output=markdown
    )

    return results, file_result


def static_analysis_report_command(a1000: A1000):
    sample_hash = demisto.getArg("hash")

    try:
        resp = a1000.get_titanium_core_report_v2(sample_hash=sample_hash)

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results = static_analysis_report_output(resp_json=resp.json(), sample_hash=sample_hash)
    return results


def static_analysis_report_output(resp_json, sample_hash):
    classification_obj = resp_json.get("classification")
    indicators_table = tableToMarkdown("Indicators", resp_json.get("indicators"))
    tags_table = tableToMarkdown("Tags", resp_json.get("tags"))

    markdown = f"## ReversingLabs A1000 static analysis report for {sample_hash}\n"

    fields = f"""**Classification**: {classification_obj.get("classification")}
    **Factor**: {classification_obj.get("factor")}
    **Result**: {classification_obj.get("result")}
    **SHA-1**: {resp_json.get("sha1")}
    **MD5**: {resp_json.get("md5")}
    **SHA-256**: {resp_json.get("sha256")}
    **SHA-512**: {resp_json.get("sha512")}
    **Story**: {resp_json.get("story")}\n {indicators_table} {tags_table}
    """

    markdown = markdown + fields

    dbot_score = Common.DBotScore(
        indicator=sample_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs A1000 v2',
        score=classification_obj.get("classification"),
        malicious_description=classification_obj.get("result"),
        reliability=RELIABILITY
    )

    indicator = Common.File(
        md5=resp_json.get("md5"),
        sha1=resp_json.get("sha1"),
        sha256=resp_json.get("sha256"),
        dbot_score=dbot_score
    )

    command_results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_static_analysis_report": resp_json},
        indicator=indicator,
        readable_output=markdown
    )

    return command_results


def dynamic_analysis_report_command(a1000: A1000):
    sample_hash = demisto.getArg("hash")
    action = demisto.getArg("action")
    report_format = demisto.getArg("report_format")

    try:
        if action == "CREATE REPORT":
            resp = a1000.create_dynamic_analysis_report(sample_hash=sample_hash, report_format=report_format).json()

        elif action == "CHECK STATUS":
            resp = a1000.check_dynamic_analysis_report_status(sample_hash=sample_hash, report_format=report_format).json()

        elif action == "DOWNLOAD REPORT":
            resp = a1000.download_dynamic_analysis_report(sample_hash=sample_hash, report_format=report_format)

        else:
            raise Exception("This action is not supported.")

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results, file_result = dynamic_analysis_report_output(
        resp=resp,
        action=action,
        sample_hash=sample_hash,
        report_format=report_format
    )
    if file_result:
        return [results, file_result]
    else:
        return results


def dynamic_analysis_report_output(resp, action, sample_hash, report_format):
    markdown = f"## ReversingLabs A1000 dynamic analysis report - {action}\n"

    file_result = None

    if action == "CREATE REPORT":
        markdown = (markdown + f"""**Status endpoint**: {resp.get("status_endpoint")}\n"""
                    + f"""**Download endpoint**: {resp.get("download_endpoint")}""")
        context = resp

    elif action == "CHECK STATUS":
        markdown = markdown + f"""**Status**: {resp.get("status")}\n **Status message**: {resp.get("message")}"""
        context = resp

    else:
        markdown = markdown + "The dynamic analysis report is returned as downloadable file below."
        file_result = fileResult(f"{sample_hash}.{report_format}", resp.content, file_type=EntryType.FILE)
        context = None

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_dynamic_analysis_report": context},
        readable_output=markdown
    )

    return results, file_result


def sample_classification_command(a1000: A1000):
    sample_hash = demisto.getArg("hash")
    action = demisto.getArg("action")
    system = demisto.getArg("system")
    av_scanners = False

    try:
        if action == "GET CLASSIFICATION":
            local_only = False
            if demisto.getArg("local_only"):
                local_only = argToBoolean(demisto.getArg("local_only"))

            if demisto.getArg("av_scanners"):
                av_scanners = argToBoolean(demisto.getArg("av_scanners"))

            resp = a1000.get_classification_v3(
                sample_hash=sample_hash,
                local_only=local_only,
                av_scanners=av_scanners
            )

        elif action == "SET CLASSIFICATION":
            classification = demisto.getArg("classification")
            risk_score = arg_to_number(demisto.getArg("risk_score"))
            threat_platform = demisto.getArg("threat_platform")
            threat_name = demisto.getArg("threat_name")
            threat_type = demisto.getArg("threat_type")
            resp = a1000.set_classification(
                sample_hash=sample_hash,
                classification=classification,
                system=system,
                risk_score=risk_score,
                threat_platform=threat_platform,
                threat_name=threat_name,
                threat_type=threat_type
            )

        elif action == "DELETE CLASSIFICATION":
            resp = a1000.delete_classification(sample_hash=sample_hash, system=system)

        else:
            raise Exception("This action is not supported.")

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results = sample_classification_output(
        resp_json=resp.json(),
        action=action,
        av_scanners=av_scanners,
        sample_hash=sample_hash
    )

    return results


def sample_classification_output(resp_json, action, av_scanners, sample_hash):
    markdown = f"""## ReversingLabs A1000 sample classification - {action}\n"""

    if action == "GET CLASSIFICATION":
        if resp_json.get("classification"):
            markdown = markdown + f"""**Classification**: {resp_json.get("classification")}
            **Risk score**: {resp_json.get("riskscore")}
            **First seen**: {resp_json.get("first_seen")}
            **Last seen**: {resp_json.get("last_seen")}
            **Classification result**: {resp_json.get("classification_result")}
            **Classification reason**: {resp_json.get("classification_reason")}
            **SHA-1**: {resp_json.get("sha1")}
            **SHA-256**: {resp_json.get("sha256")}
            **MD5**: {resp_json.get("md5")}
            """
            if av_scanners:
                scanners_table = tableToMarkdown("Scanner results", resp_json.get("av_scanners"))
                markdown = markdown + f"\n{scanners_table}"

            d_bot_score = classification_to_score(resp_json.get("classification").upper())
            dbot_score = Common.DBotScore(
                indicator=sample_hash,
                indicator_type=DBotScoreType.FILE,
                integration_name='ReversingLabs A1000 v2',
                score=d_bot_score,
                malicious_description=resp_json.get("classification_result"),
                reliability=RELIABILITY
            )

            indicator = Common.File(
                md5=resp_json.get("md5"),
                sha1=resp_json.get("sha1"),
                sha256=resp_json.get("sha256"),
                dbot_score=dbot_score
            )

        else:
            markdown = markdown + "There were no results for the given hash."
            indicator = None

        command_results = CommandResults(
            outputs_prefix="ReversingLabs",
            outputs={"a1000_sample_classification": resp_json},
            indicator=indicator,
            readable_output=markdown
        )

        return command_results

    elif action == "SET CLASSIFICATION":
        set_table = tableToMarkdown("Set classification response", resp_json)
        markdown = markdown + set_table

    elif action == "DELETE CLASSIFICATION":
        markdown = markdown + "Custom classification removed."

    command_results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_sample_classification": resp_json},
        readable_output=markdown
    )

    return command_results


def yara_command(a1000: A1000):
    action = demisto.getArg("action")
    ruleset_name = demisto.getArg("ruleset_name")
    ruleset_content = demisto.getArg("ruleset_content")
    publish = argToBoolean(demisto.args().get("publish", False))
    sync_time = demisto.getArg("sync_time")

    if action == "GET RULESETS":
        resp = a1000.get_yara_rulesets_on_the_appliance_v2()

    elif action == "GET CONTENTS":
        resp = a1000.get_yara_ruleset_contents(ruleset_name=ruleset_name)

    elif action == "GET MATCHES":
        resp = a1000.get_yara_ruleset_matches_v2(ruleset_name=ruleset_name)

    elif action == "UPDATE RULESET":
        resp = a1000.create_or_update_yara_ruleset(name=ruleset_name, content=ruleset_content, publish=publish)

    elif action == "DELETE RULESET":
        resp = a1000.delete_yara_ruleset(name=ruleset_name, publish=publish)

    elif action == "ENABLE RULESET":
        resp = a1000.enable_or_disable_yara_ruleset(enabled=True, name=ruleset_name, publish=publish)

    elif action == "DISABLE RULESET":
        resp = a1000.enable_or_disable_yara_ruleset(enabled=False, name=ruleset_name, publish=publish)

    elif action == "GET SYNCHRONIZATION TIME":
        resp = a1000.get_yara_ruleset_synchronization_time()

    elif action == "UPDATE SYNCHRONIZATION TIME":
        resp = a1000.update_yara_ruleset_synchronization_time(sync_time=sync_time)

    else:
        raise Exception("This action is not supported.")

    results = yara_output(resp_json=resp.json(), action=action)
    return results


def yara_output(resp_json, action):
    markdown = f"""## ReversingLabs A1000 YARA - {action}"""
    resp_table = tableToMarkdown("", resp_json)
    markdown = markdown + f"""\n{resp_table}"""

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_yara": resp_json},
        readable_output=markdown
    )

    return results


def yara_retro_command(a1000: A1000):
    action = demisto.getArg("action")
    ruleset_name = demisto.getArg("ruleset_name")
    operation = demisto.getArg("operation")

    if action == "MANAGE LOCAL SCAN":
        resp = a1000.start_or_stop_yara_local_retro_scan(operation=operation)

    elif action == "LOCAL SCAN STATUS":
        resp = a1000.get_yara_local_retro_scan_status()

    elif action == "MANAGE CLOUD SCAN":
        resp = a1000.start_or_stop_yara_cloud_retro_scan(operation=operation, ruleset_name=ruleset_name)

    elif action == "CLOUD SCAN STATUS":
        resp = a1000.get_yara_cloud_retro_scan_status(ruleset_name=ruleset_name)

    else:
        raise Exception("This action is not supported.")

    results = yara_retro_output(resp_json=resp.json(), action=action)
    return results


def yara_retro_output(resp_json, action):
    markdown = f"""## ReversingLabs A1000 YARA Retroactive Hunt - {action}"""
    resp_table = tableToMarkdown("", resp_json)
    markdown = markdown + f"""\n{resp_table}"""

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_yara_retro": resp_json},
        readable_output=markdown
    )

    return results


def list_containers_command(a1000: A1000):
    sample_hashes = demisto.getArg("sample_hashes")
    hash_list = sample_hashes.split(",")

    if not len(hash_list) > 0:
        raise Exception("Please enter at least one sample hash or check the formatting. "
                        "The hashes should be comma-separated with no whitespaces")

    try:
        resp = a1000.list_containers_for_hashes(sample_hashes=hash_list)

    except Exception as e:
        if hasattr(e, "response_object"):
            raise Exception(e.response_object.content)  # type: ignore[attr-defined]
        else:
            raise

    results = list_containers_output(resp_json=resp.json())
    return results


def list_containers_output(resp_json):
    markdown = "## ReversingLabs A1000 List containers for hashes"
    resp_table = tableToMarkdown("", resp_json)
    markdown = markdown + f"""\n{resp_table}"""

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_list_containers": resp_json},
        readable_output=markdown
    )

    return results


def upload_from_url_command(a1000: A1000):
    action = demisto.getArg("action")
    file_url = demisto.getArg("file_url")
    crawler = demisto.getArg("crawler")
    archive_password = demisto.getArg("archive_password")
    sandbox_platform = demisto.getArg("sandbox_platform")
    task_id = demisto.getArg("task_id")
    retry = argToBoolean(demisto.args().get("retry", False))

    if action == "UPLOAD":
        resp = a1000.upload_sample_from_url(
            file_url=file_url,
            crawler=crawler,
            archive_password=archive_password,
            rl_cloud_sandbox_platform=sandbox_platform
        )

    elif action == "GET REPORT":
        resp = a1000.get_submitted_url_report(task_id=task_id, retry=retry)

    elif action == "UPLOAD AND GET REPORT":
        resp = a1000.upload_sample_from_url_and_get_report(
            file_url=file_url,
            crawler=crawler,
            archive_password=archive_password,
            rl_cloud_sandbox_platform=sandbox_platform,
            retry=retry
        )

    elif action == "CHECK ANALYSIS STATUS":
        resp = a1000.check_submitted_url_status(task_id=task_id)

    else:
        raise Exception("This action is not supported.")

    results = upload_from_url_output(resp_json=resp.json(), action=action)
    return results


def upload_from_url_output(resp_json, action):
    markdown = f"""## ReversingLabs A1000 URL sample actions - {action}\n"""

    if action == "UPLOAD":
        output = tableToMarkdown("Upload results", resp_json)
        indicator = None

    else:
        report = resp_json.get("report")

        output = f"""**Processing status**: {resp_json.get("processing_status")}
        **Classification**: {report.get("classification")}
        **Risk score**: {report.get("riskscore")}
        **ID**: {report.get("id")}
        **SHA-1**: {report.get("sha1")}
        **SHA-256**: {report.get("sha256")}
        **SHA-512**: {report.get("sha512")}
        **MD5**: {report.get("md5")}
        **IMPHASH**: {report.get("imphash")}
        **Category**: {report.get("category")}
        **File type**: {report.get("file_type")}
        **File subtype**: {report.get("file_subtype")}
        **File size**: {report.get("file_size")}
        **Classification origin**: {report.get("classification_origin")}
        **Classification reason**: {report.get("classification_reason")}
        """

        av_scanners = tableToMarkdown("AV Scanners", report.get("av_scanners_summary"))
        rl_sandbox = tableToMarkdown("RL Cloud Sandbox", report.get("rl_cloud_sandbox"))

        output = output + "\n" + av_scanners + rl_sandbox

        score = classification_to_score(report.get("classification").upper())

        dbot_score = Common.DBotScore(
            indicator=report.get("sha1"),
            indicator_type=DBotScoreType.FILE,
            integration_name="ReversingLabs A1000 v2",
            score=score,
            malicious_description=report.get("file_subtype"),
            reliability=RELIABILITY
        )

        indicator = Common.File(
            md5=report.get("md5"),
            sha1=report.get("sha1"),
            sha256=report.get("sha256"),
            dbot_score=dbot_score
        )

    markdown = markdown + output

    command_results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"a1000_upload_from_url_actions": resp_json},
        indicator=indicator,
        readable_output=markdown
    )

    return command_results


def main():  # pragma: no cover
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
        elif demisto.command() == 'reversinglabs-a1000-user-tags':
            return_results(user_tags_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-file-analysis-status':
            return_results(file_analysis_status_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-pdf-report':
            return_results(pdf_report_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-static-analysis-report':
            return_results(static_analysis_report_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-dynamic-analysis-report':
            return_results(dynamic_analysis_report_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-sample-classification':
            return_results(sample_classification_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-yara':
            return_results(yara_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-yara-retro':
            return_results(yara_retro_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-list-containers':
            return_results(list_containers_command(a1000))
        elif demisto.command() == 'reversinglabs-a1000-upload-from-url-actions':
            return_results(upload_from_url_command(a1000))
        else:
            return_error(f'Command [{demisto.command()}] not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
