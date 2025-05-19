from CommonServerPython import *
from collections import defaultdict
from datetime import date


def header_transform(key: str) -> str:
    """
    Function returns header key in human readable

    :param key: header key
    :return: translated headers
    """
    header_dict = {
        "Cve": "CVE ID",
        "CVSS": "CVSS Score",
        "VRR": "VRR Score",
        "ThreatCount": "Threat Count",
        "VulnLastTrendingOn": "Last Trending On Date",
        "Trending": "Trending",
    }

    return header_dict.get(key, "")


def get_ransomware_trending_cves(ransomware_cves) -> list:
    """
    Filter last 7 days trending reansomware cves from ransomware cves.

    :param ransomware_cves: list of ransomware cves.
    :return: list of trending ransomware.
    """
    ransomware_trending = []

    today_date = date.today()
    week_ago_date = today_date - timedelta(days=7)
    demisto.setContext("Date.CurrentDate", str(today_date))
    demisto.setContext("Date.WeekAgoDate", str(week_ago_date))

    for cve in ransomware_cves:
        if cve.get("VulnLastTrendingOn") and cve.get("VulnLastTrendingOn") != "Not Found":
            vuln_last_trending_on_date = datetime.strptime(cve.get("VulnLastTrendingOn", "2000-01-01"), "%Y-%m-%d").date()
            if (today_date - vuln_last_trending_on_date).days <= 7:
                ransomware_trending.append(cve)

    return ransomware_trending


def get_ransomware_cves(host_findings):
    """
    Retrieves ransomware cves from host findings details.

    :param host_findings: list of host findings details
    :return: list of ransomware cves
    """
    all_cves: dict = defaultdict(dict)

    for findings in host_findings:
        risk_rating = findings.get("RiskRating", 0)
        threat_list = defaultdict(list)

        threats = findings.get("Threat") if findings.get("Threat", []) else []
        vulns = findings.get("Vulnerability") if findings.get("Vulnerability", []) else []

        # if dict response receive from context data then convert it to list
        threats = [threats] if isinstance(threats, dict) else threats
        vulns = [vulns] if isinstance(vulns, dict) else vulns

        for threat in threats:
            for cve in threat.get("Cve", []):
                threat_list[cve].append(
                    {
                        "Title": threat.get("Title", ""),
                        "Category": threat.get("Category", ""),
                        "Severity": threat.get("Severity", ""),
                        "Description": threat.get("Description", ""),
                        "Cve": threat.get("Cve", ""),
                        "Source": threat.get("Source", ""),
                        "Published": threat.get("Published", ""),
                        "Updated": threat.get("Updated", ""),
                        "ThreatLastTrendingOn": threat.get("ThreatLastTrendingOn", ""),
                        "Trending": threat.get("Trending", ""),
                    }
                )

        for vulnerability in vulns:
            last_trending = vulnerability.get("VulnLastTrendingOn", "")
            all_cves[vulnerability.get("Cve", "No ID Found")] = {
                "Cve": vulnerability.get("Cve", ""),
                "CVSS": vulnerability.get("BaseScore", ""),
                "VRR": risk_rating,
                "ThreatCount": len(threat_list.get(vulnerability.get("Cve", ""), [])),
                "Trending": vulnerability.get("Trending", ""),
                "VulnLastTrendingOn": last_trending if last_trending else "Not Found",
                "Threats": threat_list.get(vulnerability.get("Cve", ""), []),
                "Description": vulnerability.get("Description", ""),
            }
    cve_list = []
    for cve in all_cves.values():
        if isinstance(cve, list):
            cve_list.extend(cve)
        else:
            cve_list.append(cve)
    ransomware_cves = []
    for cve in cve_list:
        for threat in cve.get("Threats", []):
            if threat.get("Category", "").lower() == "ransomware":
                ransomware_cves.append(cve)
                break
    return ransomware_cves


def display_ransomware_cve_results(ransomware_cves):
    """
    Set context data and human readable for ransomware cves.
    will raise an error message if no ransomware cves found.

    :param ransomware_cves: list of ransomware cves
    :return: standard output
    """
    ransomware_cves_count = len(ransomware_cves)
    if ransomware_cves_count <= 0:
        return_results("No ransomware CVEs found.")

    demisto.setContext("CVECount", ransomware_cves_count)
    readable_output = "### Total CVEs found: " + str(len(ransomware_cves)) + "\n"
    readable_output += tableToMarkdown(
        "List of CVEs that have ransomware threat",
        ransomware_cves,
        ["Cve", "CVSS", "VRR", "ThreatCount", "VulnLastTrendingOn", "Trending"],
        header_transform,
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="RiskSense.RansomwareCves",
        outputs_key_field="Cve",
        outputs=ransomware_cves,
        readable_output=readable_output,
        raw_response={},
    )


def display_ransomware_trending_cve_results(ransomware_cves):
    """
    Retrieve trending ransomware cves and Set context data and human readable for trending ransomware cves.
    will raise an error message if no trending ransomware cves found.

    :param ransomware_cves: list of ransomware cves.
    :return: standard output.
    """
    ransomware_trending = get_ransomware_trending_cves(ransomware_cves)
    ransomware_trending_cves_count = len(ransomware_trending)
    if ransomware_trending_cves_count <= 0:
        return_results("No CVEs found With trending ransomware.")

    demisto.setContext("TrendingCVECount", ransomware_trending_cves_count)
    readable_output = "### Total CVEs found: " + str(len(ransomware_trending)) + "\n"
    readable_output += tableToMarkdown(
        "List of CVEs that are ransomware trending",
        ransomware_trending,
        ["Cve", "CVSS", "VRR", "ThreatCount", "VulnLastTrendingOn", "Trending"],
        header_transform,
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="RiskSense.RansomwareTrendingCves",
        outputs_key_field="Cve",
        outputs=ransomware_trending,
        readable_output=readable_output,
        raw_response={},
    )


def main() -> None:
    LOG("Start RiskSense get ransomeware cves script")

    # Fetch Parameter
    trending = demisto.args().get("trending")

    results = demisto.executeCommand(
        "risksense-get-host-findings",
        {"fieldname": "threat_categories", "operator": "EXACT", "value": "Ransomware", "size": 1000, "status": "Open"},
    )

    host_findings = results[0].get("EntryContext", {}).get("RiskSense.HostFinding(val.ID == obj.ID)")

    if not host_findings:
        return_results("Key [RiskSense.HostFinding] was not found in context data.")

    host_findings = [host_findings] if isinstance(host_findings, dict) else host_findings

    ransomware_cves = get_ransomware_cves(host_findings)

    if argToBoolean(trending):
        result = display_ransomware_trending_cve_results(ransomware_cves)
        return_results(result)
    else:
        result = display_ransomware_cve_results(ransomware_cves)
        return_results(result)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
