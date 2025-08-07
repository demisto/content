EXPECTED_RANSOMWARE_CVES = [
    {
        "Cve": "CVE-0000-0000",
        "CVSS": 7.5,
        "VRR": 5.67,
        "ThreatCount": 1,
        "Trending": "false",
        "VulnLastTrendingOn": "2018-05-01",
        "Description": "remote code execution",
        "Threats": [
            {
                "Title": "Hunter Exploit Kit",
                "Category": "Ransomware",
                "Severity": "null",
                "Description": "",
                "Cve": ["CVE-0000-0000"],
                "Source": "MCAFEE",
                "Published": "2017-08-03T00:00:00",
                "Updated": "2019-08-16T15:50:04",
                "ThreatLastTrendingOn": "2018-02-23",
                "Trending": "false",
            }
        ],
    }
]

HOST_FINDING_DATA = [
    {
        "HostID": 3569982,
        "Vulnerability": [
            {
                "Cve": "CVE-0000-0000",
                "BaseScore": 7.5,
                "ThreatCount": 0,
                "AttackVector": "Network",
                "AccessComplexity": "Low",
                "Authentication": "None",
                "ConfidentialityImpact": "Partial",
                "Integrity": "Partial",
                "AvailabilityImpact": "Partial",
                "Trending": "false",
                "VulnLastTrendingOn": "2018-05-01",
                "Description": "remote code execution",
            }
        ],
        "ThreatCount": 0,
        "Threat": [
            {
                "Title": "Hunter Exploit Kit",
                "Category": "Ransomware",
                "Severity": "null",
                "Description": "",
                "Details": "",
                "Cve": ["CVE-0000-0000"],
                "Source": "MCAFEE",
                "Published": "2017-08-03T00:00:00",
                "Updated": "2019-08-16T15:50:04",
                "ThreatLastTrendingOn": "2018-02-23",
                "Trending": "false",
                "Link": "",
            }
        ],
        "RiskRating": 5.67,
    }
]


def test_header_transform():
    from RiskSenseGetRansomewareCVEScript import header_transform

    assert header_transform("CVSS") == "CVSS Score"
    assert header_transform("VRR") == "VRR Score"
    assert header_transform("ThreatCount") == "Threat Count"
    assert header_transform("VulnLastTrendingOn") == "Last Trending On Date"
    assert header_transform("Trending") == "Trending"


def test_get_ransomware_cves():
    from RiskSenseGetRansomewareCVEScript import get_ransomware_cves

    ransomware_cves = get_ransomware_cves(HOST_FINDING_DATA)
    assert ransomware_cves == EXPECTED_RANSOMWARE_CVES


def test_display_ransomware_trending_cve_results():
    from RiskSenseGetRansomewareCVEScript import display_ransomware_trending_cve_results

    result = display_ransomware_trending_cve_results(EXPECTED_RANSOMWARE_CVES)

    assert result.outputs_prefix == "RiskSense.RansomwareTrendingCves"
    assert result.outputs_key_field == "Cve"


def test_display_ransomware_cve_results():
    from RiskSenseGetRansomewareCVEScript import display_ransomware_cve_results

    result = display_ransomware_cve_results(EXPECTED_RANSOMWARE_CVES)

    assert result.outputs_prefix == "RiskSense.RansomwareCves"
    assert result.outputs_key_field == "Cve"
    assert result.outputs == EXPECTED_RANSOMWARE_CVES
