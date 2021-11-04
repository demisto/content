from typing import Union
import demistomock as demisto
from CommonServerPython import *
from ReversingLabs.SDK.ticloud import FileReputation, AVScanners, FileAnalysis, RHA1FunctionalSimilarity, \
    RHA1Analytics, URIStatistics, URIIndex, AdvancedSearch, ExpressionSearch, FileDownload, FileUpload, \
    URLThreatIntelligence, AnalyzeURL, DynamicAnalysis, CertificateAnalytics

VERSION = "v2.0.0"
USER_AGENT = f"ReversingLabs XSOAR TitaniumCloud {VERSION}"

TICLOUD_URL = demisto.params().get("base")
USERNAME = demisto.params().get("credentials", {}).get("identifier")
PASSWORD = demisto.params().get("credentials", {}).get("password")
RELIABILITY = demisto.params().get("reliability", "C - Fairly reliable")


def classification_to_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "KNOWN": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification, 0)


def test_module_command():
    mwp = FileReputation(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
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
        password=PASSWORD
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
        password=PASSWORD
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
        password=PASSWORD
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
        password=PASSWORD
    )
    hash_value = demisto.getArg("hash")
    limit = demisto.getArg("result_limit")

    try:
        sha1_list = similarity.get_similar_hashes_aggregated(hash_input=hash_value, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'functional_similarity': sha1_list},
        readable_output="Full report is returned in a downloadable file"
    )

    file_results = fileResult(
        f'RHA1 Functional Similarity report file for hash {hash_value}',
        json.dumps(sha1_list, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )
    return_results([results, file_results])


def rha1_analytics_command():
    rha_analytics = RHA1Analytics(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
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
        password=PASSWORD
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
        password=PASSWORD
    )

    uri = demisto.getArg("uri")
    limit = demisto.getArg("result_limit")

    try:
        sha1_list = uri_index.get_uri_index_aggregated(uri_input=uri, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

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

    return_results([results, file_results])


def advanced_search_command():
    advanced_search = AdvancedSearch(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
    )

    query = demisto.getArg("query")
    limit = demisto.getArg("result_limit")

    try:
        result_list = advanced_search.search_aggregated(query_string=query, max_results=int(limit))
    except Exception as e:
        return_error(str(e))

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

    return_results([results, file_results])


def expression_search_command():
    expression_search = ExpressionSearch(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
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

    return_results([results, file_results])


def file_download_command():
    file_download = FileDownload(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
    )

    hash_value = demisto.getArg("hash")

    try:
        response = file_download.download_sample(hash_input=hash_value)
    except Exception as e:
        return_error(str(e))

    results = CommandResults(
        readable_output=f"Requested sample is available for download under the name {hash_value}"
    )

    return_results([results, fileResult(hash_value, response.content)])


def file_upload_command():
    file_upload = FileUpload(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
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
        password=PASSWORD
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
        password=PASSWORD
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


def detonate_sample_command():
    sandbox = DynamicAnalysis(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
    )

    sha1 = demisto.getArg("sha1")
    platform = demisto.getArg("platform")

    try:
        response = sandbox.detonate_sample(sample_sha1=sha1, platform=platform)
    except Exception as e:
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


def dynamic_analysis_results_command():
    sandbox = DynamicAnalysis(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
    )

    sha1 = demisto.getArg("sha1")

    try:
        response = sandbox.get_dynamic_analysis_results(sample_hash=sha1, latest=True)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs TitaniumCloud v2',
        score=0
    )

    indicator = Common.File(
        sha1=sha1,
        dbot_score=dbot_score
    )

    results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'dynamic_analysis_results': response_json},
        readable_output="Full report is returned in a downloadable file",
        indicator=indicator
    )

    file_results = fileResult(
        f'Dynamic analysis report file for sample {sha1}',
        json.dumps(response_json, indent=4),
        file_type=EntryType.ENTRY_INFO_FILE
    )

    return_results([results, file_results])


def certificate_analytics_command():
    cert_analytics = CertificateAnalytics(
        host=TICLOUD_URL,
        username=USERNAME,
        password=PASSWORD
    )

    thumbprint = demisto.getArg("certificate_thumbprint")

    try:
        response = cert_analytics.get_certificate_analytics(certificate_thumbprints=thumbprint)
    except Exception as e:
        return_error(str(e))

    response_json = response.json()

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

    return_results([results, file_results])


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

    elif command == "reversinglabs-titaniumcloud-submit-for-dynamic-analysis":
        detonate_sample_command()

    elif command == "reversinglabs-titaniumcloud-get-dynamic-analysis-results":
        dynamic_analysis_results_command()

    elif command == "reversinglabs-titaniumcloud-certificate-analytics":
        certificate_analytics_command()

    else:
        return_error(f"Command {command} does not exist")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
