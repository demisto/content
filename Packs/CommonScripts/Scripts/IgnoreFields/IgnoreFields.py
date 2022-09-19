import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def ignore_fields(value, fields):

    if isinstance(value, dict):
        for key_value in fields:
            value.pop(key_value, None)
    return value


def main():
    try:
        args = demisto.args()
        json_obj = args.get("json_object")
        fields_to_ignore = argToList(args.get("fields"))
        return_results(ignore_fields(json_obj, fields_to_ignore))
    except Exception as e:
        return_error(str(e), e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
