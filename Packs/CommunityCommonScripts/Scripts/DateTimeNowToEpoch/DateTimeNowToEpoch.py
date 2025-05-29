import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def retrieve_epoch() -> int:
    # Return current epoch value for datetime.now
    return int(time.time())


def main():  # pragma: no cover
    epoch = retrieve_epoch()
    demisto.setContext("DateTimeNowEpoch", epoch)
    return_results(epoch)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
