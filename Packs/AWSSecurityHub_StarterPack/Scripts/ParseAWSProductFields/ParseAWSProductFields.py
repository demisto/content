import demistomock as demisto
from CommonServerPython import *  # noqa: F401

value = demisto.args()["value"]


def parse_product(paths):
    r: dict = {}
    for k, v in paths.items():
        parts = k.split("/")
        if parts:
            m = r
            for i, key in enumerate(parts[:-1]):
                if key in m:
                    m = m[key]
                    continue
                m[key] = {}
                m = m[key]
            m[parts[-1]] = v

    return r


demisto.results(parse_product(value))
