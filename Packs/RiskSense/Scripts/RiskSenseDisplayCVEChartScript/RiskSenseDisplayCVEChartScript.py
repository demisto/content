from CommonServerPython import *
from typing import Any


def display_cve_chart() -> dict[str, Any]:
    cves_count = demisto.args().get("CvesCount", 0)
    trending_cves_count = demisto.args().get("TrendingCvesCount", 0)

    entry_result = {
        "Type": 17,
        "ContentsFormat": "bar",
        "Contents": {
            "stats": [
                {
                    "data": [
                        cves_count,
                    ],
                    "name": "CVEs that have ransomware threat",
                    "label": "CVEs that have ransomware threat",
                    "color": "rgb(0, 0, 255)",
                },
                {
                    "data": [trending_cves_count],
                    "name": "CVEs that are ransomware trending",
                    "label": "CVEs that are ransomware trending",
                    "color": "rgb(255, 0, 0)",
                },
            ],
            "params": {"layout": "horizontal"},
        },
    }
    return entry_result


def main() -> None:
    entry_result = display_cve_chart()
    demisto.results(entry_result)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
