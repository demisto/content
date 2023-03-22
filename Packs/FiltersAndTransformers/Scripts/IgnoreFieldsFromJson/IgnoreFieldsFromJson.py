import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def ignore_fields(value, fields):
    fields = argToList(fields)
    if not isinstance(value, dict):
        try:
            value = json.loads(value)
        except (json.decoder.JSONDecodeError, AttributeError):
            demisto.debug(f"Could not parse {value} to Json. Please insert a valid json format.")
            return value

    for key_value in fields:
        value.pop(key_value, None)
    return value


def main():   # pragma: no cover
    try:
        args = demisto.args()
        json_obj = args.get("value") or args.get("json_object")
        fields_to_ignore = args.get("fields")
        return_results(ignore_fields(json_obj, fields_to_ignore))
    except Exception as e:
        return_error(str(e), e)


if __name__ in ('__main__', '__builtin__', 'builtins'):   # pragma: no cover
    main()
