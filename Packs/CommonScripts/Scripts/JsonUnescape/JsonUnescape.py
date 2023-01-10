import json
import traceback
from typing import Dict, List, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def hook(obj: Dict) -> Dict:
    new_obj = {}
    for k, v in obj.items():
        try:
            new_obj[k] = json.loads(v)
        except Exception:
            new_obj[k] = v
    return new_obj


def unescape(args: Dict) -> Union[Dict, List]:
    json_str = json.dumps(args.get("value"))
    return json.loads(json_str, object_hook=hook)


def main():
    try:
        return_results(unescape(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
