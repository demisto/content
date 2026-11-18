import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from SlackV3ApiModule import *  # noqa: E402


def main() -> None:  # pragma: no cover
    run_slack_v3_integration()


from CommonServerUserPython import *  # noqa: E402  # pylint: disable=wrong-import-position

if __name__ in ("__main__", "__builtin__", "builtins"):
    register_signal_handler_profiling_dump(profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT)
    main()
