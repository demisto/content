import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main() -> None:
    groups = [{"name": "", "data": [], "color": "", "groups": []}]
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(groups)})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
