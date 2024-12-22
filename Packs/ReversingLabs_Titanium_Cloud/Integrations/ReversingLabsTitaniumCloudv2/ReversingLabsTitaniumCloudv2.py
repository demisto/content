from copy import deepcopy

from requests import Response

from CommonServerPython import *
from ReversingLabs.SDK.ticloud import FileReputation, AVScanners, FileAnalysis, RHA1FunctionalSimilarity, \
    RHA1Analytics, URIStatistics, URIIndex, AdvancedSearch, ExpressionSearch, FileDownload, FileUpload, \
    URLThreatIntelligence, AnalyzeURL, DynamicAnalysis, CertificateAnalytics, YARAHunting, YARARetroHunting, \
    ReanalyzeFile, ImpHashSimilarity, DomainThreatIntelligence, IPThreatIntelligence, NetworkReputation, \
    NetworkReputationUserOverride, CustomerUsage
from ReversingLabs.SDK.helper import NotFoundError


VERSION = "v2.5.0"
USER_AGENT = f"ReversingLabs XSOAR TitaniumCloud {VERSION}"

TICLOUD_URL = demisto.params().get("base")
USERNAME = demisto.params().get("credentials", {}).get("identifier")
PASSWORD = demisto.params().get("credentials", {}).get("password")
RELIABILITY = demisto.params().get("reliability", "C - Fairly reliable")

VERIFY_CERTS = demisto.getParam("verify_certs")

HTTP_PROXY = demisto.params().get("http_proxy", None)
HTTP_PROXY_USERNAME = demisto.params().get("http_credentials", {}).get("identifier", None)
HTTP_PROXY_PASSWORD = demisto.params().get("http_credentials", {}).get("password", None)

HTTPS_PROXY = demisto.params().get("https_proxy", None)
HTTPS_PROXY_USERNAME = demisto.params().get("https_credentials", {}).get("identifier", None)
HTTPS_PROXY_PASSWORD = demisto.params().get("https_credentials", {}).get("password", None)


def format_proxy(addr, username=None, password=None):
    protocol = ''
    proxy_name = ''
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


PROXIES = return_proxies()


def classification_to_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "KNOWN": 1,
        "NO_THREATS_FOUND": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification, 0)


def test_module_command():
    mwp = FileReputation(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    try:
        _ = mwp.get_file_reputation(hash_input="6a95d3d00267c9fd80bd42122738e726")
    except Exception as e:
        return_error(str(e))

    result = "ok"
    return_results(result)


def file_reputation_command():
    mwp = FileReputation(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    hash_value = demisto.getArg("hash")

    try:
        response = mwp.get_file_reputation(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = file_reputation_output(response_json=response_json, hash_value=hash_value)
    return_results(results)


def file_reputation_output(response_json, hash_value):
    malware_presence = response_json.get("rl", {}).get("malware_presence")
    if not malware_presence:
        return_error("There is no malware_presence object in the response JSON.")

    classification = malware_presence.get("status")
    reason = malware_presence.get("reason")
    threat_name = malware_presence.get("threat_name")

    md5 = malware_presence.get("md5")
    sha1 = malware_presence.get("sha1")
    sha256 = malware_presence.get("sha256")

    markdown = f"""## ReversingLabs File Reputation for hash {hash_value}\n **Classification**: {classification}
    **Classification reason**: {reason}
    **First seen**: {malware_presence.get("first_seen")}
    **Last seen**: {malware_presence.get("last_seen")}
    **AV scanner hits / total number of scanners**: {malware_presence.get("scanner_match")} / {malware_presence.get(
        "scanner_count")}
    **AV scanner hit percentage**: {malware_presence.get("scanner_percent")}%
    **MD5 hash**: {md5}
    **SHA-1 hash**: {sha1}
    **SHA-256 hash**: {sha256}"""
    if classification.upper() in ("MALICIOUS", "SUSPICIOUS"):
        markdown = f"""{markdown}
        **Threat name**: {threat_name}
        **Threat level**: {malware_presence.get("threat_level")}
        """
    elif classification.upper() == "KNOWN":
        markdown = f"""{markdown}
        **Trust factor**: {malware_presence.get("trust_factor")}
        """
    else:
        markdown = f"""## ReversingLabs File Reputation for hash {hash_value}\n **Classification**: {classification}
        **No references were found for this hash.**
        """

    d_bot_score = classification_to_score(classification)

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=d_bot_score,
        malicious_description=f"{reason} - {threat_name}",
        reliability=RELIABILITY
    )

    indicator = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'file_reputation': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def av_scanners_command():
    xref = AVScanners(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )
    hash_value = demisto.getArg("hash")

    try:
        response = xref.get_scan_results(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = av_scanners_output(response_json=response_json, hash_value=hash_value)
    return_results(results)


def av_scanners_output(response_json, hash_value):
    sample = response_json.get("rl", {}).get("sample")
    if not sample:
        return_error("There is no sample object in the response JSON.")

    md5 = sample.get("md5")
    sha1 = sample.get("sha1")
    sha256 = sample.get("sha256")

    markdown = f"""## ReversingLabs AV Scan results for hash {hash_value}\n **First scanned on**: {sample.get(
        "first_scanned_on")}
    **First seen on**: {sample.get("first_seen_on")}
    **Last scanned on**: {sample.get("last_scanned_on")}
    **Last seen on**: {sample.get("last_seen_on")}
    **Sample size**: {sample.get("sample_size")} bytes
    **Sample type**: {sample.get("sample_type")}
    **MD5 hash**: {md5}
    **SHA-1 hash**: {sha1}
    **SHA-256 hash**: {sha256}
    **SHA-512 hash**: {sample.get("sha512")}
    **SHA-384 hash**: {sample.get("sha384")}
    **RIPEMD-160 hash**: {sample.get("ripemd160")}
    """

    xref_list = sample.get("xref")

    if xref_list and len(xref_list) > 0:
        latest_xref = xref_list[0]

        xref_results = latest_xref.get("results")

        if len(xref_results) > 0:
            markdown = f"""{markdown}**Scanner count**: {latest_xref.get("scanner_count")}
            **Scanner match**: {latest_xref.get("scanner_match")}
            """

            results_table = tableToMarkdown("Latest scan results", xref_results)
            markdown = f"{markdown}\n{results_table}"

    dbot_score = Common.DBotScore(
        indicator=hash_value,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=0,
    )

    indicator = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'av_scanners': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def file_analysis_command():
    rldata = FileAnalysis(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )
    hash_value = demisto.getArg("hash")

    try:
        response = rldata.get_analysis_results(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = file_analysis_output(response_json=response_json, hash_value=hash_value)

    file_results = fileResult(
        f'File Analysis report file for hash {hash_value}',
        json.dumps(response_json, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE

    )
    return_results([results, file_results])


def file_analysis_output(response_json, hash_value):
    sample = response_json.get("rl", {}).get("sample")
    if not sample:
        return_error("There is no sample object in the response JSON.")

    md5 = sample.get("md5")
    sha1 = sample.get("sha1")
    sha256 = sample.get("sha256")

    entries = sample.get("analysis").get("entries")
    if len(entries) == 0:
        return_error("The entries list is empty")

    tc_report = entries[0].get("tc_report")

    file_type = tc_report.get("info").get("file").get("file_type")
    file_subtype = tc_report.get("info").get("file").get("file_subtype")

    rldata_xref = sample.get("xref")

    markdown = f"""## ReversingLabs File Analysis results for hash {hash_value}\n **File type**: {file_type}
    **File subtype**: {file_subtype}
    **Sample type**: {rldata_xref.get("sample_type")}
    **Sample size**: {sample.get("sample_size")} bytes
    **Extended description**: {tc_report.get("story")}
    **First seen**: {rldata_xref.get("first_seen")}
    **Last seen**: {rldata_xref.get("last_seen")}
    **MD5 hash**: {sample.get("md5")}
    **SHA-1 hash**: {sample.get("sha1")}
    **SHA-256 hash**: {sample.get("sha256")}
    **SHA-384 hash**: {sample.get("sha384")}
    **SHA-512 hash**: {sample.get("sha512")}
    **SSDEEP hash**: {sample.get("ssdeep")}
    **RIPEMD-160 hash**: {sample.get("ripemd160")}
    """

    dbot_score = Common.DBotScore(
        indicator=hash_value,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=0,
    )

    indicator = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'file_analysis': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def functional_similarity_command():
    similarity = RHA1FunctionalSimilarity(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )
    hash_value = demisto.getArg("hash")
    limit = demisto.getArg("result_limit")

    try:
        sha1_list = similarity.get_similar_hashes_aggregated(hash_input=hash_value, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

    results = functional_similarity_output(sha1_list)

    file_results = fileResult(
        f'RHA1 Functional Similarity report file for hash {hash_value}',
        json.dumps(sha1_list, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return_results([results, file_results])


def functional_similarity_output(sha1_list):
    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'functional_similarity': sha1_list},
        readable_output="Full report is returned in a downloadable file"
    )

    return results


def rha1_analytics_command():
    rha_analytics = RHA1Analytics(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )
    hash_value = demisto.getArg("hash")

    try:
        response = rha_analytics.get_rha1_analytics(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = rha1_analytics_output(response_json=response_json, hash_value=hash_value)
    return_results(results)


def rha1_analytics_output(response_json, hash_value):
    rha1_counters = response_json.get("rl", {}).get("rha1_counters")
    if not rha1_counters:
        return_error("There is no rha1_counters object in the response JSON.")

    md5 = demisto.get(rha1_counters, "sample_metadata.md5")
    sha1 = hash_value
    sha256 = demisto.get(rha1_counters, "sample_metadata.sha256")

    sample_counters = rha1_counters.get("sample_counters")
    sample_metadata = rha1_counters.get("sample_metadata")
    classification = sample_metadata.get("classification")
    threat_name = sample_metadata.get("threat_name")

    markdown = f"""## ReversingLabs RHA1 Analytics results for hash {sha1}\n ### Sample counters\n **KNOWN**: {
    sample_counters.get("known")}
    **MALICIOUS**:  {sample_counters.get("malicious")}
    **SUSPICIOUS**: {sample_counters.get("suspicious")}
    **TOTAL**:    {sample_counters.get("total")}\n ### Sample metadata\n **Classification**: {classification}
    **MD5 hash**: {md5}
    **SHA-256 hash**: {sha256}
    **First seen**: {sample_metadata.get("first_seen")}
    **Last seen**: {sample_metadata.get("last_seen")}
    **Sample available**: {sample_metadata.get("sample_available")}
    **Sample size**: {sample_metadata.get("sample_size")} bytes
    **Sample type**: {sample_metadata.get("sample_type")}"""
    if classification.upper() in ("MALICIOUS", "SUSPICIOUS"):
        markdown = f"""{markdown}
        **Threat name**: {threat_name}
        **Threat level**: {sample_metadata.get("threat_level")}"""
    else:
        markdown = f"""{markdown}
        **Trust factor**: {sample_metadata.get("trust_factor")}"""

    d_bot_score = classification_to_score(classification)

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=d_bot_score,
        malicious_description=threat_name,
        reliability=RELIABILITY
    )

    indicator = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'rha1_analytics': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def uri_statistics_command():
    uri_stats = URIStatistics(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )
    uri = demisto.getArg("uri")

    try:
        response = uri_stats.get_uri_statistics(uri_input=uri)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = uri_statistics_output(response_json=response_json, uri=uri)
    return_results(results)


def uri_statistics_output(response_json, uri):
    uri_state = response_json.get("rl", {}).get("uri_state")
    if not uri_state:
        return_error("There is no uri_state object in the response JSON.")

    counters = uri_state.get("counters")
    uri_type = uri_state.get("uri_type")
    uri_types = {
        "domain": f"**Domain**: {uri}",
        "url": f"**URL**: {uri}",
        "ipv4": f"**IPv4**: {uri}",
        "email": f"**Email**: {uri}"
    }

    markdown = f"""## ReversingLabs URI Statistics results for URI {uri}\n ### Sample counters\n **KNOWN**: {
    counters.get("known")}
    **MALICIOUS**: {counters.get("malicious")}
    **SUSPICIOUS**: {counters.get("suspicious")}
    **SHA-1 hash**: {uri_state.get("sha1")}
    **URI type**: {uri_type}
    {uri_types.get(uri_type)}"""

    indicator: Union[Common.Domain, Common.URL, Common.IP, Common.EMAIL, None] = None

    if uri_type == "domain":
        indicator = Common.Domain(
            domain=uri,
            dbot_score=Common.DBotScore(
                indicator=uri,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name='ReversingLabs TitaniumCloud v2',
                score=0,
            )
        )
    elif uri_type == "url":
        indicator = Common.URL(
            url=uri,
            dbot_score=Common.DBotScore(
                indicator=uri,
                indicator_type=DBotScoreType.URL,
                integration_name='ReversingLabs TitaniumCloud v2',
                score=0,
            )
        )
    elif uri_type == "ipv4":
        indicator = Common.IP(
            ip=uri,
            dbot_score=Common.DBotScore(
                indicator=uri,
                indicator_type=DBotScoreType.IP,
                integration_name='ReversingLabs TitaniumCloud v2',
                score=0,
            )
        )
    elif uri_type == "email":
        indicator = Common.EMAIL(
            address=uri,
            dbot_score=Common.DBotScore(
                indicator=uri,
                indicator_type=DBotScoreType.EMAIL,
                integration_name='ReversingLabs TitaniumCloud v2',
                score=0,
            )
        )
    else:
        return_error("This integration does not currently support this URI type")

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'uri_statistics': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def uri_index_command():
    uri_index = URIIndex(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    uri = demisto.getArg("uri")
    limit = demisto.getArg("result_limit")

    try:
        sha1_list = uri_index.get_uri_index_aggregated(uri_input=uri, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

    results, file_results = uri_index_output(sha1_list, uri)

    return_results([results, file_results])


def uri_index_output(sha1_list, uri):
    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'uri_index': sha1_list},
        readable_output="Full report is returned in a downloadable file"
    )

    file_results = fileResult(
        f'URI Index report file for URI {uri}',
        json.dumps(sha1_list, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def advanced_search_command():
    advanced_search = AdvancedSearch(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    query = demisto.getArg("query")
    limit = demisto.getArg("result_limit")

    try:
        result_list = advanced_search.search_aggregated(query_string=query, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

    results, file_results = advanced_search_output(result_list)

    return_results([results, file_results])


def advanced_search_output(result_list):
    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'advanced_search': result_list},
        readable_output="Full report is returned in a downloadable file"
    )

    file_results = fileResult(
        'Advanced Search report file',
        json.dumps(result_list, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def expression_search_command():
    expression_search = ExpressionSearch(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    query = demisto.getArg("query")
    date = demisto.getArg("date")
    limit = demisto.getArg("result_limit")
    query_list = query.split(" ")

    try:
        result_list = expression_search.search_aggregated(
            query=query_list,
            date=date,
            max_results=int(limit)
        )
    except Exception as e:
        return_error(str(e))

    results, file_results = expression_search_output(result_list)

    return_results([results, file_results])


def expression_search_output(result_list):
    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'expression_search': result_list},
        readable_output="Full report is returned in a downloadable file"
    )

    file_results = fileResult(
        'Expression Search report file',
        json.dumps(result_list, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def file_download_command():
    file_download = FileDownload(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    hash_value = demisto.getArg("hash")

    try:
        response = file_download.download_sample(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    results = file_download_output(hash_value)

    file_results = fileResult(hash_value, response.content)

    return_results([results, file_results])


def file_download_output(hash_value):
    results = CommandResults(
        readable_output=f"Requested sample is available for download under the name {hash_value}"
    )

    return results


def file_upload_command():
    file_upload = FileUpload(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    file_entry = demisto.getFilePath(demisto.getArg("entryId"))
    filename = file_entry["name"]

    with open(file_entry["path"], "rb") as file_handle:
        _ = file_upload.upload_sample_from_file(file_handle=file_handle, sample_name=filename)

        results = CommandResults(
            readable_output=f"Successfully uploaded file {filename}"
        )

        return_results(results)


def url_report_command():
    url_ti = URLThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    url = demisto.getArg("url")

    try:
        response = url_ti.get_url_report(url_input=url)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = url_report_output(response_json=response_json, url=url)
    return_results(results)


def url_report_output(response_json, url):
    report_base = response_json.get("rl")

    if not report_base:
        return_error("There is no rl object in the response JSON.")

    classification = report_base.get("classification", "UNAVAILABLE").upper()
    markdown = f"""## ReversingLabs URL Threat Intelligence report for URL {url}\n **Requested URL**: {report_base.get(
        "requested_url")}
    **Classification**: {classification}"""

    analysis = report_base.get("analysis")
    if analysis:
        statistics = analysis.get("statistics")
        analysis_history = analysis.get("analysis_history")
        last_analysis = analysis.get("last_analysis")

        markdown += f"""\n    **First analysis**: {analysis.get("first_analysis")}
        **Analysis count**: {analysis.get("analysis_count")}\n ### Last analysis\n **Analysis ID**: {last_analysis.get(
            "analysis_id")}
        **Analysis time**: {last_analysis.get("analysis_time")}
        **Final URL**: {last_analysis.get("final_url")}
        **Availability status**: {last_analysis.get("availability_status")}
        **Domain**: {last_analysis.get("domain")}
        **Serving IP Address**: {last_analysis.get("serving_ip_address")}\n ### Statistics\n **KNOWN**: {statistics.get(
            "known")}
        **SUSPICIOUS**: {statistics.get("suspicious")}
        **MALICIOUS**: {statistics.get("malicious")}
        **UNKNOWN**: {statistics.get("unknown")}
        **TOTAL**: {statistics.get("total")}"""

        analysis_table = tableToMarkdown("Analysis history", analysis_history)
        markdown = f"{markdown}\n {analysis_table}"

    third_party = report_base.get("third_party_reputations")
    if third_party:
        third_party_statistics = third_party.get("statistics")
        third_party_sources = third_party.get("sources")

        markdown += f"""\n ### Third party statistics\n **TOTAL**: {third_party_statistics.get("total")}
        **MALICIOUS**: {third_party_statistics.get("malicious")}
        **CLEAN**: {third_party_statistics.get("clean")}
        **UNDETECTED**: {third_party_statistics.get("undetected")}\n"""

        sources_table = tableToMarkdown("Third party sources", third_party_sources)
        markdown = f"{markdown}\n {sources_table}"

    d_bot_score = classification_to_score(classification)

    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=d_bot_score,
        malicious_description=classification.upper(),
        reliability=RELIABILITY
    )

    indicator = Common.URL(
        url=url,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'url_report': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def analyze_url_command():
    analyze_url = AnalyzeURL(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    url = demisto.getArg("url")

    try:
        response = analyze_url.submit_url(url_input=url)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = analyze_url_output(response_json=response_json, url=url)
    return_results(results)


def analyze_url_output(response_json, url):
    report_base = response_json.get("rl", {})

    markdown = f"""## ReversingLabs Analyze URL response for URL {url}\n **Status**: {report_base.get("status")}
    **Analysis ID**: {report_base.get("analysis_id")}
    **Requested URL**: {report_base.get("requested_url")}"""

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'analyze_url': response_json},
        readable_output=markdown
    )

    return results


def create_da_object():
    da = DynamicAnalysis(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    return da


def detonate_sample_command():
    da = create_da_object()

    sha1 = demisto.getArg("sha1")
    platform = demisto.getArg("platform")

    try:
        response = da.detonate_sample(sample_sha1=sha1, platform=platform)
    except Exception as e:
        if hasattr(e, "response_object"):
            return_error(f"status code: {e.response_object.status_code}, "  # type: ignore[attr-defined]
                         f"message: {e.response_object.text}")  # type: ignore[attr-defined]

        return_error(str(e))

    response_json = response.json()
    results = detonate_sample_output(response_json=response_json, sha1=sha1)

    return_results(results)


def detonate_sample_output(response_json, sha1):
    report_base = response_json.get("rl", {})

    markdown = f"""## ReversingLabs submit sample {sha1} for Dynamic Analysis\n **Status**: {report_base.get("status")}
    **Requested hash**: {report_base.get("requested_hash")}
    **Analysis ID**: {report_base.get("analysis_id")}"""

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'detonate_sample_dynamic': response_json},
        readable_output=markdown
    )

    return results


def sample_dynamic_analysis_results_command():
    da = create_da_object()

    sha1 = demisto.getArg("sha1")
    analysis_id = demisto.getArg("analysis_id")
    latest_analysis = argToBoolean(demisto.getArg("latest_analysis"))

    try:
        response = da.get_dynamic_analysis_results(
            sample_hash=sha1,
            analysis_id=analysis_id if analysis_id else None,
            latest=latest_analysis if latest_analysis else None
        )
    except Exception as e:
        if hasattr(e, "response_object"):
            return_error(f"status code: {e.response_object.status_code}, "  # type: ignore[attr-defined]
                         f"message: {e.response_object.text}")  # type: ignore[attr-defined]

        return_error(str(e))

    response_json = response.json()
    results, file_results = sample_dynamic_analysis_results_output(response_json, sha1)

    return_results([results, file_results])


def sample_dynamic_analysis_results_output(response_json, sha1):
    classification = response_json.get("rl", {}).get("report", {}).get("classification")
    md5 = response_json.get("rl", {}).get("report", {}).get("md5")
    sha256 = response_json.get("rl", {}).get("report", {}).get("sha256")
    last_analysis = response_json.get("rl", {}).get("report", {}).get("last_analysis")

    markdown = f"""## ReversingLabs Sample Dynamic Analysis output for sample {sha1}\n **Classification**: {classification}
    **Sample SHA1**: {sha1}
    **Sample MD5**: {md5}
    **Sample SHA256**: {sha256}
    **Last analysis**: {last_analysis}\n ### Full report is returned as JSON in a downloadable file
    """

    d_bot_score = classification_to_score(classification.upper())

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        malicious_description=classification,
        score=d_bot_score,
        reliability=RELIABILITY
    )

    indicator = Common.File(
        sha1=sha1,
        md5=md5,
        sha256=sha256,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'sample_dynamic_analysis_results': response_json},
        readable_output=markdown,
        indicator=indicator
    )

    file_results = fileResult(
        f'Dynamic analysis report file for sample {sha1}',
        json.dumps(response_json, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def detonate_url_command():
    da = create_da_object()

    url = demisto.getArg("url")
    platform = demisto.getArg("platform")

    try:
        response = da.detonate_url(url_string=url, platform=platform)
    except Exception as e:
        if hasattr(e, "response_object"):
            return_error(f"status code: {e.response_object.status_code}, "  # type: ignore[attr-defined]
                         f"message: {e.response_object.text}")  # type: ignore[attr-defined]

        return_error(str(e))

    response_json = response.json()
    results = detonate_url_output(response_json=response_json, url=url)

    return_results(results)


def detonate_url_output(response_json, url):
    report_base = response_json.get("rl", {})

    markdown = f"""## ReversingLabs submit URL {url} for Dynamic Analysis\n **Status**: {report_base.get("status")}
    **Requested URL**: {report_base.get("url")}
    **URL SHA1**: {report_base.get("sha1")}
    **URL BASE64**: {report_base.get("url_base64")}
    **Analysis ID**: {report_base.get("analysis_id")}
    """

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"detonate_url_dynamic": response_json},
        readable_output=markdown
    )

    return results


def url_dynamic_analysis_results_command():
    da = create_da_object()

    sha1 = demisto.getArg("sha1")
    url = demisto.getArg("url")
    analysis_id = demisto.getArg("analysis_id")
    latest_analysis = argToBoolean(demisto.getArg("latest_analysis"))

    try:
        response = da.get_dynamic_analysis_results(
            url_sha1=sha1 if sha1 else None,
            url=url if url else None,
            analysis_id=analysis_id if analysis_id else None,
            latest=latest_analysis if latest_analysis else None
        )

    except Exception as e:
        if hasattr(e, "response_object"):
            return_error(f"status code: {e.response_object.status_code}, "  # type: ignore[attr-defined]
                         f"message: {e.response_object.text}")  # type: ignore[attr-defined]

        return_error(str(e))

    response_json = response.json()
    results, file_results = url_dynamic_analysis_results_output(
        response_json=response_json,
        passed_url=url,
        passed_sha1=sha1
    )

    return_results([results, file_results])


def url_dynamic_analysis_results_output(response_json, passed_url=None, passed_sha1=None):
    report = response_json.get("rl", {}).get("report", {})
    is_merged = report.get("history_analysis")
    classification = report.get("classification")
    url = report.get("url", passed_url)

    markdown = f"""## ReversingLabs URL Dynamic Analysis output for URL\n **URL**: {url}
    **Classification**: {classification}
    **URL SHA1**: {report.get("sha1", passed_sha1)}
    **URL BASE64**: {report.get("url_base64")}
    **Risk score**: {report.get("risk_score")}
    """

    if is_merged:
        markdown = markdown + f"**Last analysis**: {report.get('last_analysis')}\n"

    else:
        markdown = markdown + f"""**Analysis ID**: {report.get("analysis_id")}\n **Analysis time**: {report.get("analysis_time")}
        **Analysis duration**: {report.get("analysis_duration")}
        **Platform**: {report.get("platform")}
        **Configuration**: {report.get("configuration")}
        **PCAP link**: {report.get("pcap")}
        **Memory strings link**: {report.get("memory_strings")}
        **Screenshots lin**: {report.get("screenshots")}
        **Dropped files link**: {report.get("dropped_files_url")}
        """

    network = report.get("network", {})
    if network:
        markdown = markdown + "\n### Network"

        for key in network:
            table = tableToMarkdown(key, network.get(key))
            markdown = markdown + "\n" + table

    signatures_table = tableToMarkdown("Signatures", report.get("signatures"))
    markdown = f"{markdown}\n {signatures_table}\n"

    if not is_merged:
        dropped_files_table = tableToMarkdown("Dropped files", report.get("dropped_files"))
        markdown = f"{markdown}\n {dropped_files_table}"

    d_bot_score = classification_to_score(classification.upper())

    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name="ReversingLabs TitaniumCloud v2",
        malicious_description=classification,
        score=d_bot_score,
        reliability=RELIABILITY
    )

    indicator = Common.URL(
        url=url,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"url_dynamic_analysis_results": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    file_results = fileResult(
        f"Dynamic analysis report file for URL {url}",
        json.dumps(response_json, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def certificate_analytics_command():
    cert_analytics = CertificateAnalytics(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    thumbprint = demisto.getArg("certificate_thumbprint")

    try:
        response = cert_analytics.get_certificate_analytics(certificate_thumbprints=thumbprint)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results, file_results = certificate_analytics_output(response_json, thumbprint)

    return_results([results, file_results])


def certificate_analytics_output(response_json, thumbprint):
    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'certificate_analytics': response_json},
        readable_output="Full report is returned in a downloadable file"
    )

    file_results = fileResult(
        f'Certificate Analytics report file for thumbprint {thumbprint}',
        json.dumps(response_json, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return results, file_results


def yara_ruleset_command():
    response = Response()
    output_key = ''
    yara = YARAHunting(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    yara_action = demisto.getArg("yara_action")
    ruleset_name = demisto.getArg("ruleset_name")
    ruleset_text = demisto.getArg("ruleset_text")
    sample_available = demisto.getArg("sample_available")

    if yara_action == "CREATE RULESET":
        if ruleset_text:
            ruleset_text = str(ruleset_text)
        else:
            return_error("When using the CREATE RULESET action, the rulesetText argument is required.")

        if sample_available:
            sample_available = argToBoolean(sample_available)

        try:
            response = yara.create_ruleset(
                ruleset_name=ruleset_name,
                ruleset_text=ruleset_text,
                sample_available=sample_available
            )
        except Exception as e:
            return_error(str(e))

        output_key = "create_yara_ruleset"

    elif yara_action == "DELETE RULESET":
        try:
            response = yara.delete_ruleset(
                ruleset_name=ruleset_name
            )
        except Exception as e:
            return_error(str(e))

        output_key = "delete_yara_ruleset"

    elif yara_action == "GET RULESET INFO":
        try:
            response = yara.get_ruleset_info(
                ruleset_name=ruleset_name
            )
        except Exception as e:
            return_error(str(e))

        output_key = "get_yara_ruleset_info"

    elif yara_action == "GET RULESET TEXT":
        try:
            response = yara.get_ruleset_text(
                ruleset_name=ruleset_name
            )
        except Exception as e:
            return_error(str(e))

        output_key = "get_yara_ruleset_text"

    else:
        return_error(f"Yara ruleset action {yara_action} does not exist.")

    response_json = response.json()

    results = yara_ruleset_output(output_key, response_json)

    return_results(results)


def yara_ruleset_output(output_key, response_json):
    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={output_key: response_json},
        readable_output=response_json
    )

    return results


def yara_matches_feed_command():
    yara = YARAHunting(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    time_format = demisto.getArg("time_format")
    time_value = demisto.getArg("time_value")

    try:
        response = yara.yara_matches_feed(
            time_format=time_format,
            time_value=time_value
        )
    except Exception as e:
        return_error(str(e))

    response_json = response.json()
    results = yara_matches_feed_output(response_json=response_json, time_value=time_value)

    return_results(results)


def yara_matches_feed_output(response_json, time_value):
    feed = response_json.get("rl", {}).get("feed", {})
    entries = tableToMarkdown("Entries", feed.get("entries", []))
    last_timestamp = feed.get("last_timestamp")
    range_from = feed.get("time_range", {}).get("from")
    range_to = feed.get("time_range", {}).get("to")

    markdown = f"""## ReversingLabs YARA Matches Feed for time value {time_value}\n **Last timestamp**: {last_timestamp}
    **From**: {range_from}
    **To**: {range_to}
    """
    markdown = f"{markdown}\n {entries}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"yara_matches_feed": response_json},
        readable_output=markdown
    )

    return results


def yara_retro_actions_command():
    response = Response()
    output_key = ''
    retro = YARARetroHunting(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    retro_action = demisto.getArg("yara_retro_action")
    ruleset_name = demisto.getArg("ruleset_name")

    if retro_action == "ENABLE RETRO HUNT":
        try:
            response = retro.enable_retro_hunt(ruleset_name=ruleset_name)
        except Exception as e:
            return_error(str(e))

        output_key = "enable_yara_retro"

    elif retro_action == "START RETRO HUNT":
        try:
            response = retro.start_retro_hunt(ruleset_name=ruleset_name)
        except Exception as e:
            return_error(str(e))

        output_key = "start_yara_retro"

    elif retro_action == "CHECK STATUS":
        try:
            response = retro.check_status(ruleset_name=ruleset_name)
        except Exception as e:
            return_error(str(e))

        output_key = "check_yara_retro_status"

    elif retro_action == "CANCEL RETRO HUNT":
        try:
            response = retro.cancel_retro_hunt(ruleset_name=ruleset_name)
        except Exception as e:
            return_error(str(e))

        output_key = "cancel_yara_retro"

    else:
        return_error(f"YARA Retro action {retro_action} does not exist.")

    response_json = response.json()

    results = yara_retro_actions_output(output_key, response_json)

    return_results(results)


def yara_retro_actions_output(output_key, response_json):
    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={output_key: response_json},
        readable_output=response_json
    )

    return results


def yara_retro_matches_feed_command():
    yara = YARARetroHunting(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    time_format = demisto.getArg("time_format")
    time_value = demisto.getArg("time_value")

    try:
        response = yara.yara_retro_matches_feed(
            time_format=time_format,
            time_value=time_value
        )
    except Exception as e:
        return_error(str(e))

    response_json = response.json()
    results = yara_retro_matches_feed_output(response_json=response_json, time_value=time_value)

    return_results(results)


def yara_retro_matches_feed_output(response_json, time_value):
    feed = response_json.get("rl", {}).get("feed", {})
    entries = tableToMarkdown("Entries", feed.get("entries", []))
    last_timestamp = feed.get("last_timestamp")
    range_from = feed.get("time_range", {}).get("from")
    range_to = feed.get("time_range", {}).get("to")

    markdown = f"""## ReversingLabs YARA Retro Matches Feed for time value {time_value}\n **Last timestamp**: {last_timestamp}
    **From**: {range_from}
    **To**: {range_to}
    """
    markdown = f"{markdown}\n {entries}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"yara_retro_matches_feed": response_json},
        readable_output=markdown
    )

    return results


def reanalyze_sample_command():
    reanalyze = ReanalyzeFile(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    sample_hash = demisto.getArg("hash")

    try:
        response = reanalyze.reanalyze_samples(
            sample_hashes=sample_hash
        )
    except Exception as e:
        return_error(str(e))

    results = reanalyze_sample_output(response.text)

    return_results(results)


def reanalyze_sample_output(response_text):
    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"reanalyze_sample": response_text},
        readable_output=response_text
    )

    return results


def imphash_similarity_command():
    imphash_similarity = ImpHashSimilarity(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    imphash = demisto.getArg("imphash")
    max_results = int(demisto.getArg("max_results"))

    try:
        response = imphash_similarity.get_imphash_index_aggregated(
            imphash=imphash,
            max_results=max_results
        )
    except Exception as e:
        return_error(str(e))

    results = imphash_similarity_output(response=response, imphash=imphash)

    return_results(results)


def imphash_similarity_output(response, imphash):
    hashes = tableToMarkdown("SHA-1 list", response, headers="Hashes")
    markdown = f"## ReversingLabs Imphash Similarity for {imphash}\n {hashes}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"imphash_similarity": response},
        readable_output=markdown
    )

    return results


def url_downloaded_files_command():
    url_ti = URLThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    url = demisto.getArg("url")
    extended = argToBoolean(demisto.getArg("extended_results"))
    classification = demisto.getArg("classification")
    last_analysis = argToBoolean(demisto.getArg("last_analysis"))
    analysis_id = demisto.getArg("analysis_id")
    if analysis_id:
        analysis_id = int(analysis_id)
    results_per_page = int(demisto.getArg("results_per_page"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = url_ti.get_downloaded_files_aggregated(
            url_input=url,
            extended=extended,
            classification=classification,
            last_analysis=last_analysis,
            analysis_id=analysis_id,
            results_per_page=results_per_page,
            max_results=max_results
        )
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    results = url_downloaded_files_output(response, url)

    return_results(results)


def url_downloaded_files_output(response, url):
    files = tableToMarkdown("Downloaded files", response)
    markdown = f"## ReversingLabs Files Downloaded from URL {url}\n {files}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"url_downloaded_files": response},
        readable_output=markdown
    )

    return results


def url_latest_analyses_feed_command():
    url_ti = URLThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    results_per_page = int(demisto.getArg("results_per_page"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = url_ti.get_latest_url_analysis_feed_aggregated(
            results_per_page=results_per_page,
            max_results=max_results
        )
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    results, file_results = url_latest_analyses_feed_output(response)

    return_results([results, file_results])


def url_latest_analyses_feed_output(response):
    analyses = tableToMarkdown("Latest URL analyses", response)
    markdown = f"## ReversingLabs Latest URL Analyses Feed\n {analyses}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"url_latest_analyses_feed": response},
        readable_output=markdown
    )

    file_results = fileResult(
        "ReversingLabs Latest URL Analyses Feed",
        json.dumps(response, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE

    )

    return results, file_results


def url_analyses_feed_from_date_command():
    url_ti = URLThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    time_format = demisto.getArg("time_format")
    start_time = demisto.getArg("start_time")
    results_per_page = int(demisto.getArg("results_per_page"))
    max_results = int(demisto.getArg("max_results"))

    try:
        response = url_ti.get_url_analysis_feed_from_date_aggregated(
            time_format=time_format,
            start_time=start_time,
            results_per_page=results_per_page,
            max_results=max_results
        )
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    results, file_results = url_analyses_feed_from_date_output(response, start_time)

    return_results([results, file_results])


def url_analyses_feed_from_date_output(response, start_time):
    analyses = tableToMarkdown("URL analyses from specified date", response)
    markdown = f"## ReversingLabs URL Analyses Feed From Date {start_time}\n {analyses}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"url_analyses_feed_from_date": response},
        readable_output=markdown
    )

    file_results = fileResult(
        f"ReversingLabs URL Analyses Feed From Date {start_time}",
        json.dumps(response, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE

    )

    return results, file_results


def create_domain_ti_object():
    """Creates a DomainThreatIntelligence object."""
    domain_ti = DomainThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    return domain_ti


def bold_classification(input_list, key, value):
    for obj in input_list:
        if obj.get(key) == value:
            obj[key] = f"**{value}**"
    return input_list


def domain_report_command():
    domain_ti = create_domain_ti_object()

    domain = demisto.getArg("domain")

    try:
        response = domain_ti.get_domain_report(domain=domain)
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    results = domain_report_output(response_json=response_json, domain=domain)
    return_results(results)


def domain_report_output(response_json, domain):
    last_dns_records = response_json.get("rl", {}).get("last_dns_records", [])
    dns_records_table = tableToMarkdown(name="Last DNS records", t=last_dns_records)
    dns_records_time = response_json.get("rl", {}).get("last_dns_records_time")

    markdown = f"""## ReversingLabs Domain Report for {domain}\n {dns_records_table}
    \n**Last DNS records time**: {dns_records_time}
    """

    top_threats = response_json.get("rl", {}).get("top_threats", [])
    if top_threats:
        threats_table = tableToMarkdown(
            name="Top threats",
            t=top_threats
        )
        markdown = f"{markdown}\n {threats_table}"

    third_party = response_json.get("rl", {}).get("third_party_reputations")
    if third_party:
        third_party_statistics = third_party.get("statistics")

        markdown = f"""{markdown}\n ### Third party statistics\n **CLEAN**: {third_party_statistics.get("clean")}
        **MALICIOUS**: {third_party_statistics.get("malicious")}
        **UNDETECTED**: {third_party_statistics.get("undetected")}
        **TOTAL**: {third_party_statistics.get("total")}
        """

        tp_sources = deepcopy(third_party.get("sources"))
        tp_sources = bold_classification(tp_sources, "detection", "malicious")
        sources_table = tableToMarkdown(
            name="Third party sources",
            t=tp_sources,
        )
        markdown = f"{markdown}\n {sources_table}"

    files_statistics = response_json.get("rl", {}).get("downloaded_files_statistics")
    markdown = f"""{markdown}\n ### Downloaded files statistics\n **KNOWN**: {files_statistics.get("known")}
    **MALICIOUS**: {files_statistics.get("malicious")}
    **SUSPICIOUS**: {files_statistics.get("suspicious")}
    **UNKNOWN**: {files_statistics.get("unknown")}
    **TOTAL**: {files_statistics.get("total")}
    """

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"domain_report": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def domain_downloaded_files_command():
    domain_ti = create_domain_ti_object()

    domain = demisto.getArg("domain")
    classification = demisto.getArg("classification")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = domain_ti.get_downloaded_files_aggregated(
            domain=domain,
            classification=classification,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = domain_downloaded_files_output(response=response, domain=domain)
    return_results(results)


def domain_downloaded_files_output(response, domain):
    files_table = tableToMarkdown(
        name="Downloaded files",
        t=response
    )

    markdown = f"## ReversingLabs Files downloaded from domain {domain}\n {files_table}"

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"domain_downloaded_files": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def domain_urls_command():
    domain_ti = create_domain_ti_object()

    domain = demisto.getArg("domain")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = domain_ti.urls_from_domain_aggregated(
            domain=domain,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = domain_urls_output(response=response, domain=domain)
    return_results(results)


def domain_urls_output(response, domain):
    urls_table = tableToMarkdown(
        name="URL list",
        t=response
    )

    markdown = f"## ReversingLabs URL-s associated with domain {domain}\n {urls_table}"

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"domain_urls": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def domain_to_ip_command():
    domain_ti = create_domain_ti_object()

    domain = demisto.getArg("domain")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = domain_ti.domain_to_ip_resolutions_aggregated(
            domain=domain,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = domain_to_ip_output(response=response, domain=domain)
    return_results(results)


def domain_to_ip_output(response, domain):
    ip_table = tableToMarkdown(
        name="IP address list",
        t=response
    )

    markdown = f"## ReversingLabs IP addresses resolved from domain {domain}\n {ip_table}"

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"domain_to_ip": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def domain_related_domains_command():
    domain_ti = create_domain_ti_object()

    domain = demisto.getArg("domain")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = domain_ti.related_domains_aggregated(
            domain=domain,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = domain_related_domains_output(response=response, domain=domain)
    return_results(results)


def domain_related_domains_output(response, domain):
    domain_table = tableToMarkdown(
        name="Domain list",
        t=response
    )

    markdown = f"## ReversingLabs domains related to domain {domain}\n {domain_table}"

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"domain_related_domains": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def create_ip_ti_object():
    """Creates an IPThreatIntelligence object."""
    ip_ti = IPThreatIntelligence(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    return ip_ti


def ip_report_command():
    ip_ti = create_ip_ti_object()

    ip = demisto.getArg("ip")

    try:
        response = ip_ti.get_ip_report(ip_address=ip)
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    response_json = response.json()
    results = ip_report_output(response_json=response_json, ip=ip)
    return_results(results)


def ip_report_output(response_json, ip):
    files_statistics = response_json.get("rl", {}).get("downloaded_files_statistics")

    markdown = f"""## ReversingLabs IP address report for {ip}\n ### Downloaded files statistics\n **KNOWN**: {
    files_statistics.get("known")}
    **MALICIOUS**: {files_statistics.get("malicious")}
    **SUSPICIOUS**: {files_statistics.get("suspicious")}
    **UNKNOWN**: {files_statistics.get("unknown")}
    **TOTAL**: {files_statistics.get("total")}
    """

    third_party = response_json.get("rl", {}).get("third_party_reputations")
    if third_party:
        third_party_statistics = third_party.get("statistics")

        markdown = f"""{markdown}\n ### Third party statistics\n **CLEAN**: {third_party_statistics.get("clean")}
        **MALICIOUS**: {third_party_statistics.get("malicious")}
        **UNDETECTED**: {third_party_statistics.get("undetected")}
         **TOTAL**: {third_party_statistics.get("total")}
        """

        tp_sources = deepcopy(third_party.get("sources"))
        tp_sources = bold_classification(tp_sources, "detection", "malicious")
        sources_table = tableToMarkdown(
            name="Third party sources",
            t=tp_sources
        )
        markdown = f"{markdown}\n {sources_table}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"ip_report": response_json},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def ip_downloaded_files_command():
    ip_ti = create_ip_ti_object()

    ip = demisto.getArg("ip")
    classification = demisto.getArg("classification")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = ip_ti.get_downloaded_files_aggregated(
            ip_address=ip,
            classification=classification,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = ip_downloaded_files_output(response=response, ip=ip)
    return_results(results)


def ip_downloaded_files_output(response, ip):
    readable = deepcopy(response)
    readable = bold_classification(readable, "classification", "MALICIOUS")
    files_table = tableToMarkdown(
        name="Downloaded files",
        t=readable
    )

    markdown = f"## ReversingLabs Files downloaded from IP address {ip}\n {files_table}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"ip_downloaded_files": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def ip_urls_command():
    ip_ti = create_ip_ti_object()

    ip = demisto.getArg("ip")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = ip_ti.urls_from_ip_aggregated(
            ip_address=ip,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = ip_urls_output(response=response, ip=ip)
    return_results(results)


def ip_urls_output(response, ip):
    urls_table = tableToMarkdown(
        name="URL list",
        t=response
    )

    markdown = f"## ReversingLabs URL-s associated with IP address {ip}\n {urls_table}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"ip_urls": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def ip_to_domain_command():
    ip_ti = create_ip_ti_object()

    ip = demisto.getArg("ip")
    limit = int(demisto.getArg("result_limit"))
    per_page = int(demisto.getArg("results_per_page"))

    try:
        response = ip_ti.ip_to_domain_resolutions_aggregated(
            ip_address=ip,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        return_error(str(e))

    results = ip_to_domain_output(response=response, ip=ip)
    return_results(results)


def ip_to_domain_output(response, ip):
    domain_table = tableToMarkdown(
        name="Domain list",
        t=response
    )

    markdown = f"## ReversingLabs IP to domain mappings for IP address {ip}\n {domain_table}"

    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="ReversingLabs TitaniumCloud v2",
        score=0,
        reliability=RELIABILITY
    )

    indicator = Common.IP(
        ip=ip,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"ip_to_domain": response},
        readable_output=markdown,
        indicator=indicator
    )

    return results


def network_reputation_command():
    net_reputation = NetworkReputation(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    network_locations = argToList(demisto.getArg("network_locations"))

    try:
        response = net_reputation.get_network_reputation(
            network_locations=network_locations
        )
    except NotFoundError:
        return_results("No results were found for this input.")
        return
    except Exception as e:
        return_error(str(e))

    response_json = response.json()
    results = network_reputation_output(response_json=response_json, network_locations=network_locations)
    return_results(results)


def network_reputation_output(response_json, network_locations):
    entries = deepcopy(response_json.get("rl").get("entries"))
    entries = bold_classification(entries, "classification", "malicious")

    for entry in entries:
        tp_reputations = entry.get("third_party_reputations")
        if tp_reputations:
            entry["third_party_reputations_malicious"] = tp_reputations.get("malicious")
            entry["third_party_reputations_clean"] = tp_reputations.get("clean")
            entry["third_party_reputations_undetected"] = tp_reputations.get("undetected")
            entry["third_party_reputations_total"] = tp_reputations.get("total")
            del entry["third_party_reputations"]

    entries_table = tableToMarkdown(
        name="Network locations",
        t=entries
    )

    network_locations = ", ".join(network_locations)
    markdown = f"## ReversingLabs Reputation for the following network locations: {network_locations}\n {entries_table}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"network_reputation": response_json},
        readable_output=markdown
    )

    return results


def create_net_rep_override_obj():
    """Creates an NetworkReputationUserOverride object."""
    net_rep_override = NetworkReputationUserOverride(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    return net_rep_override


def create_override_payload(piped_string, action=None):
    """A function for creating the Network Reputation User Override objects."""
    split_by_pipe = piped_string.split("|")
    list_of_dicts = []

    for one_location in split_by_pipe:
        values_list = one_location.split(",")
        location_dict = {
            "network_location": values_list[0],
            "type": values_list[1]
        }
        if action == "set_override":
            location_dict["classification"] = values_list[2]
        list_of_dicts.append(location_dict)

    return list_of_dicts


def network_reputation_override_command():
    net_rep_override = create_net_rep_override_obj()

    set_override_str = demisto.getArg("set_overrides_list")
    remove_override_str = demisto.getArg("remove_overrides_list")

    set_list = create_override_payload(piped_string=set_override_str, action="set_override") if set_override_str else []
    remove_list = create_override_payload(piped_string=remove_override_str) if remove_override_str else []

    try:
        response = net_rep_override.reputation_override(
            override_list=set_list,
            remove_overrides_list=remove_list
        )
    except Exception as e:
        return_error(str(e))

    response_json = response.json()
    results = network_reputation_override_output(response_json=response_json)

    return_results(results)


def network_reputation_override_output(response_json):
    created_overrides = response_json.get("rl", {}).get("user_override", {}).get("created_overrides")
    removed_overrides = response_json.get("rl", {}).get("user_override", {}).get("removed_overrides")
    invalid = response_json.get("rl", {}).get("user_override", {}).get("invalid_network_locations")

    markdown = "## ReversingLabs Network reputation user override"

    if created_overrides:
        created_overrides_table = tableToMarkdown(
            name="Created overrides",
            t=created_overrides
        )

        markdown = f"{markdown}\n {created_overrides_table}"

    if removed_overrides:
        removed_overrides_table = tableToMarkdown(
            name="Removed overrides",
            t=removed_overrides
        )

        markdown = f"{markdown}\n {removed_overrides_table}"

    if invalid:
        invalid_table = tableToMarkdown(
            name="Invalid network locations",
            t=invalid
        )

        markdown = f"{markdown}\n {invalid_table}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"network_reputation_override": response_json},
        readable_output=markdown
    )

    return results


def network_reputation_overrides_list_command():
    net_rep_override = create_net_rep_override_obj()

    limit = int(demisto.getArg("result_limit"))

    try:
        response = net_rep_override.list_overrides_aggregated(max_results=limit)
    except Exception as e:
        return_error(str(e))

    results = network_reputation_overrides_list_output(response=response)
    return_results(results)


def network_reputation_overrides_list_output(response):
    entries_table = tableToMarkdown(
        name="Network location list",
        t=response
    )

    markdown = f"## ReversingLabs Network reputation active user overrides list\n {entries_table}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"network_reputation_overrides_list": response},
        readable_output=markdown
    )

    return results


def create_customer_usage_obj():
    cu = CustomerUsage(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD,
        user_agent=USER_AGENT,
        proxies=PROXIES,
        verify=VERIFY_CERTS
    )

    return cu


def customer_usage_data_command():
    cu = create_customer_usage_obj()

    data_type = demisto.getArg("data_type")
    from_time = demisto.getArg("from")
    to_time = demisto.getArg("to")
    single_time_unit = demisto.getArg("single_time_unit")
    whole_company = argToBoolean(demisto.getArg("whole_company"))

    if data_type == "DAILY USAGE":
        response = cu.daily_usage(
            single_date=single_time_unit,
            from_date=from_time,
            to_date=to_time,
            whole_company=whole_company
        )

    elif data_type == "MONTHLY USAGE":
        response = cu.monthly_usage(
            single_month=single_time_unit,
            from_month=from_time,
            to_month=to_time,
            whole_company=whole_company
        )

    elif data_type == "DATE RANGE USAGE":
        response = cu.date_range_usage(
            whole_company=whole_company
        )

    elif data_type == "QUOTA LIMITS":
        response = cu.quota_limits(
            whole_company=whole_company
        )

    else:
        raise Exception("Unknown data type request. Precisely one of the following values needs to be set as data_type: "
                        "DAILY USAGE, MONTHLY USAGE, DATE RANGE USAGE, QUOTA LIMITS")

    response_json = response.json()
    results = customer_usage_data_output(
        data_type=data_type,
        whole_company=whole_company,
        response_json=response_json
    )
    return_results(results)


def customer_usage_data_output(data_type, whole_company, response_json):
    markdown = f"## ReversingLabs {data_type} data for {USERNAME} \n Results for the whole company: {whole_company}"

    if "usage_reports" in response_json.get("rl"):
        data_to_use = response_json.get("rl").get("usage_reports")

    else:
        data_to_use = response_json.get("rl")

    if data_to_use:
        usage_table = tableToMarkdown("Usage data", data_to_use)
        markdown = f"{markdown} \n {usage_table}"

    else:
        markdown = f"{markdown} \n There were no results."

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"customer_usage_data": response_json},
        readable_output=markdown
    )

    return results


def customer_usage_yara_command():
    cu = create_customer_usage_obj()

    response = cu.active_yara_rulesets()
    response_json = response.json()

    results = customer_usage_yara_output(response_json=response_json)
    return_results(results)


def customer_usage_yara_output(response_json):
    markdown = f"## ReversingLabs active YARA rulesets for {USERNAME}"

    response_table = tableToMarkdown("Results", response_json.get("rl"))
    markdown = f"{markdown} \n {response_table}"

    results = CommandResults(
        outputs_prefix="ReversingLabs",
        outputs={"customer_usage_yara": response_json},
        readable_output=markdown
    )

    return results


def main():
    command = demisto.command()

    if command == "test-module":
        test_module_command()

    elif command == "reversinglabs-titaniumcloud-file-reputation":
        file_reputation_command()

    elif command == "reversinglabs-titaniumcloud-av-scanners":
        av_scanners_command()

    elif command == "reversinglabs-titaniumcloud-file-analysis":
        file_analysis_command()

    elif command == "reversinglabs-titaniumcloud-rha1-functional-similarity":
        functional_similarity_command()

    elif command == "reversinglabs-titaniumcloud-rha1-analytics":
        rha1_analytics_command()

    elif command == "reversinglabs-titaniumcloud-uri-statistics":
        uri_statistics_command()

    elif command == "reversinglabs-titaniumcloud-uri-index":
        uri_index_command()

    elif command == "reversinglabs-titaniumcloud-advanced-search":
        advanced_search_command()

    elif command == "reversinglabs-titaniumcloud-expression-search":
        expression_search_command()

    elif command == "reversinglabs-titaniumcloud-file-download":
        file_download_command()

    elif command == "reversinglabs-titaniumcloud-file-upload":
        file_upload_command()

    elif command == "reversinglabs-titaniumcloud-url-report":
        url_report_command()

    elif command == "reversinglabs-titaniumcloud-analyze-url":
        analyze_url_command()

    elif command == "reversinglabs-titaniumcloud-submit-sample-for-dynamic-analysis":
        detonate_sample_command()

    elif command == "reversinglabs-titaniumcloud-get-sample-dynamic-analysis-results":
        sample_dynamic_analysis_results_command()

    elif command == "reversinglabs-titaniumcloud-submit-url-for-dynamic-analysis":
        detonate_url_command()

    elif command == "reversinglabs-titaniumcloud-get-url-dynamic-analysis-results":
        url_dynamic_analysis_results_command()

    elif command == "reversinglabs-titaniumcloud-certificate-analytics":
        certificate_analytics_command()

    elif command == "reversinglabs-titaniumcloud-yara-ruleset-actions":
        yara_ruleset_command()

    elif command == "reversinglabs-titaniumcloud-yara-matches-feed":
        yara_matches_feed_command()

    elif command == "reversinglabs-titaniumcloud-yara-retro-hunt-actions":
        yara_retro_actions_command()

    elif command == "reversinglabs-titaniumcloud-yara-retro-matches-feed":
        yara_retro_matches_feed_command()

    elif command == "reversinglabs-titaniumcloud-reanalyze-sample":
        reanalyze_sample_command()

    elif command == "reversinglabs-titaniumcloud-imphash-similarity":
        imphash_similarity_command()

    elif command == "reversinglabs-titaniumcloud-url-downloaded-files":
        url_downloaded_files_command()

    elif command == "reversinglabs-titaniumcloud-url-latest-analyses-feed":
        url_latest_analyses_feed_command()

    elif command == "reversinglabs-titaniumcloud-url-analyses-feed-from-date":
        url_analyses_feed_from_date_command()

    elif command == "reversinglabs-titaniumcloud-domain-report":
        domain_report_command()

    elif command == "reversinglabs-titaniumcloud-domain-downloaded-files":
        domain_downloaded_files_command()

    elif command == "reversinglabs-titaniumcloud-domain-urls":
        domain_urls_command()

    elif command == "reversinglabs-titaniumcloud-domain-to-ip":
        domain_to_ip_command()

    elif command == "reversinglabs-titaniumcloud-domain-related-domains":
        domain_related_domains_command()

    elif command == "reversinglabs-titaniumcloud-ip-report":
        ip_report_command()

    elif command == "reversinglabs-titaniumcloud-ip-downloaded-files":
        ip_downloaded_files_command()

    elif command == "reversinglabs-titaniumcloud-ip-urls":
        ip_urls_command()

    elif command == "reversinglabs-titaniumcloud-ip-to-domain":
        ip_to_domain_command()

    elif command == "reversinglabs-titaniumcloud-network-reputation":
        network_reputation_command()

    elif command == "reversinglabs-titaniumcloud-network-reputation-override":
        network_reputation_override_command()

    elif command == "reversinglabs-titaniumcloud-network-reputation-overrides-list":
        network_reputation_overrides_list_command()

    elif command == "reversinglabs-titaniumcloud-customer-usage-data":
        customer_usage_data_command()

    elif command == "reversinglabs-titaniumcloud-customer-usage-yara":
        customer_usage_yara_command()

    else:
        return_error(f"Command {command} does not exist")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
