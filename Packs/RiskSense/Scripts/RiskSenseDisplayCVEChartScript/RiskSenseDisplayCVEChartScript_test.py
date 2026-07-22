import pytest

import demistomock as demisto

CVE_CONTEXT = [
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


def test_display_chart(mocker):
    from RiskSenseDisplayCVEChartScript import display_cve_chart

    mocker.patch.object(demisto, "get", return_value=CVE_CONTEXT[0])
    try:
        display_cve_chart()
    except Exception:
        pytest.fail("Unexpected MyError ..")
