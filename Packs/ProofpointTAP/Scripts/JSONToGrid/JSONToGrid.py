import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def json_to_grid(value):
    if not isinstance(value, dict):
        return value
    return {k.lower().replace(" ", ""): v for k, v in value.items()}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(json_to_grid(**demisto.args()))
