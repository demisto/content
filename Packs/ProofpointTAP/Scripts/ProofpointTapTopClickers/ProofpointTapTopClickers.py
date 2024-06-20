import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    users = []
    users_res_for_chart = []
    results: dict = demisto.executeCommand('proofpoint-get-top-clickers', {'window': 90})[0]  # type: ignore
    contents = results.get('Contents')
    if isinstance(contents, dict):
        users = contents.get('users', [])

    for user in users:
        users_res_for_chart.append({"name": user.get("identity").get("emails", [""])[0],
                                    "data": [user.get("clickStatistics").get("clickCount")]})
    default_empty_chart_data = [
        {"name": "", "data": [], "color": ""},
    ]

    final_res = users_res_for_chart if users_res_for_chart else default_empty_chart_data
    return_results(json.dumps(final_res))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
