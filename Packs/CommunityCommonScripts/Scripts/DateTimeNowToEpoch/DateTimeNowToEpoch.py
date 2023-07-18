import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def retrieve_epoch() -> int:
    # Return current epoch value for datetime.now
    return int(time.time())


def main():
    demisto.results(retrieve_epoch)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
