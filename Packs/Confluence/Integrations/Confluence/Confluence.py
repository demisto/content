import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from ConfluenceServerApiModule import *  # noqa: E402


def main() -> None:  # pragma: no cover
    run_confluence_server_integration()


from CommonServerUserPython import *  # noqa: E402  # pylint: disable=wrong-import-position

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
