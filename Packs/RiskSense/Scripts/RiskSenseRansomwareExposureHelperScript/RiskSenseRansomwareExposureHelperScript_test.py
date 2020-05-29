from CommonServerPython import *

import pytest

HOST_FINDING_DATA = [{
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
            "Description": "remote code execution"
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
            "Cve": [
                "CVE-0000-0000"
            ],
            "Source": "MCAFEE",
            "Published": "2017-08-03T00:00:00",
            "Updated": "2019-08-16T15:50:04",
            "ThreatLastTrendingOn": "2018-02-23",
            "Trending": "false",
            "Link": ""
        }
    ],
    "RiskRating": 5.67
}]

CVE_CONTEXT = [
    {
        "Cve": "CVE-0000-0000",
        "CVSS": 7.5,
        "VRR": 5.67,
        "ThreatCount": 1,
        "Trending": "false",
        "VulnLastTrendingOn": "2018-05-01",
        "Description": "remote code execution",
        "Threats": [{
            "Title": "Hunter Exploit Kit",
            "Category": "Ransomware",
            "Severity": "null",
            "Description": "",
            "Cve": [
                "CVE-0000-0000"
            ],
            "Source": "MCAFEE",
            "Published": "2017-08-03T00:00:00",
            "Updated": "2019-08-16T15:50:04",
            "ThreatLastTrendingOn": "2018-02-23",
            "Trending": "false"
        }]
    }
]

ENTRY_RESULT = entry_result = {
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": [
            {
                "data": [
                    0
                ],
                "name": "CVEs that have ransomware threat",
                "label": "CVEs that have ransomware threat",
                "color": "rgb(0, 0, 255)"
            },
            {
                "data": [
                    0
                ],
                "name": "CVEs that are ransomware trending",
                "label": "CVEs that are ransomware trending",
                "color": "rgb(255, 0, 0)"
            },
        ],
        "params": {
            "layout": "horizontal"
        }
    }
}


def test_header_transform():
    from RiskSenseRansomwareExposureHelperScript import header_transform
    assert header_transform('CVSS') == 'CVSS Score'


def test_get_ransomware_cves(mocker):
    from RiskSenseRansomwareExposureHelperScript import get_ransomware_cves
    mocker.patch.object(demisto, 'get', return_value=HOST_FINDING_DATA)
    hr, ec, raw = get_ransomware_cves()
    assert ec['RiskSense.RansomwareCves(val.Cve && val.Cve == obj.Cve)'] == CVE_CONTEXT


def test_get_ransomware_trending_cves(mocker):
    from RiskSenseRansomwareExposureHelperScript import get_ransomware_trending_cves
    mocker.patch.object(demisto, 'get', return_value=CVE_CONTEXT)
    hr, ec, raw = get_ransomware_trending_cves()

    assert 'RiskSense.RansomwareWithRcePeCves(val.Cve && val.Cve == obj.Cve)' not in ec.values()


def test_display_chart(mocker):
    from RiskSenseRansomwareExposureHelperScript import display_cve_chart
    mocker.patch.object(demisto, 'get', return_value=CVE_CONTEXT[0])
    try:
        display_cve_chart()
    except Exception:
        pytest.fail("Unexpected MyError ..")
