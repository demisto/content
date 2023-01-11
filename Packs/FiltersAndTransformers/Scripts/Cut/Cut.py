import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def cut(value, fields, delim):

    if delim == "''":
        delim = ""

    data = value.split(delim)
    fields = [int(_) for _ in fields.split(",")]

    max_index = max(fields)
    if len(data) < max_index:
        raise Exception("Invalid field index {}, should be between 1 to {}.".format(max_index, len(data)))

    return delim.join([str(data[i - 1]) for i in fields])


def main():
    try:
        args = demisto.args()
        value = args.get("value")
        fields = args.get("fields")
        delim = args.get("delimiter")
        return_results(cut(value, fields, delim))
    except Exception as e:
        return_error(f'Failed to execute Cut. Error: {str(e)}', e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
