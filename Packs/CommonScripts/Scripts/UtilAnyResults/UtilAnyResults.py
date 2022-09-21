import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def util_any_results(args):
    try:
        res = []
        data = demisto.get(args, 'data')
        if isinstance(data, list) and data:
            res.append("yes")
        elif isinstance(data, str) and data:
            if data[0] in ['[', '{']:
                data = data[1:]
            if data[-1] in [']', '}']:
                data = data[:-1]
            # If data resembles one of ",,," or "[,,]" or "[]" it is considered empty of results.
            res.append('yes' if data.replace(',', '') else 'no')
        else:
            res.append("no")
    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while parsing data. Exception info:\n" + str(
                        ex) + "\n\nInvalid data:\n" + str(data)})  # type: ignore
    return res


def main():
    args = demisto.args()
    demisto.results(util_any_results(args))
