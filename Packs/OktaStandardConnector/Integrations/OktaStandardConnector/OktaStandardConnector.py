import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from OktaApiModule import *  # noqa: E402


def main() -> None:
    run_okta_v2_integration()


from CommonServerUserPython import *  # noqa: E402  # pylint: disable=wrong-import-position

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
