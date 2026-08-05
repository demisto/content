import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def count_dict(value):
    if not isinstance(value, str):
        return value
    users = value.split(",")

    return [{"User": user} for user in users]


def main():
    try:
        return_results(count_dict(**demisto.args()))
    except Exception as e:
        return_error(f"Failed to execute MS365DefenderUserListToTable. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
