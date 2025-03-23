import json
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def hook(obj: dict) -> dict:
    """Hook to convert string to json if possible"""
    new_obj = {}
    for k, v in obj.items():
        try:
            new_obj[k] = json.loads(v)
        except Exception:
            new_obj[k] = v
    return new_obj


def unescape(args: dict) -> dict | list:
    """Unescape json string"""
    json_str = json.dumps(args.get("value"))
    return json.loads(json_str, object_hook=hook)


def main():  # pragma: no cover  # noqa: F841
    args = demisto.args()
    try:
        return_results(unescape(args))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
