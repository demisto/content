import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_inbetween(value: str, start: str, end: str) -> str:
    if isinstance(value, str):
        if start in value and end in value:
            start_index = value.index(start)
            end_index = value.index(end)
            value = value[start_index + 1:end_index]
    return value


def main():
    args = demisto.args()
    value = args.get('value')
    start = args.get('start')
    end = args.get('end')
    try:
        return_results(extract_inbetween(value, start, end))
    except Exception as err:
        return_error(f"An error occurred - {err}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
