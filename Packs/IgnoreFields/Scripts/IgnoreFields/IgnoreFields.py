import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def ignore_fields(value, fields):

    fields = fields.split(',')
    if isinstance(value, dict):
        for key_value in fields:
            value.pop(key_value, None)
    return value


def main():
    try:
        args = demisto.args()
        value = args.get("value")
        fields = args.get("fields")
        return_results(ignore_fields(value, fields))
    except Exception as e:
        return_error(str(e), e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
