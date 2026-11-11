import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from json import loads, dumps, JSONDecodeError


def sanitize_value(value, stringify):
    if stringify:
        if isinstance(value, (dict, list)):
            value = dumps(value)
        else:
            value = str(value)
    else:
        try:
            value = loads(value)
        except (JSONDecodeError, TypeError):
            pass
    return value


def main():
    try:
        args = demisto.args()
        con = demisto.context()
        key = args["key"]
        value = args["value"]
        stringify = argToBoolean(args["stringify"])
        value = sanitize_value(value, stringify)
        key_exists = con.get(key)
        if key_exists is not None:
            if not isinstance(key_exists, list):
                key_exists = [key_exists]
            key_exists.append(value)
            demisto.setContext(key, key_exists)
        else:
            demisto.setContext(key, value)
        return_results(f"Key {key} set")
    except Exception as e:
        return_error("ERROR :" + str(e))


if __name__ in ("__main__", "builtins", "__builtin__"):
    main()
