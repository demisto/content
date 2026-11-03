import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from OktaIAMApiModule import *  # noqa: E402


def main() -> None:
    run_okta_iam_integration()


from CommonServerUserPython import *  # noqa: E402  # pylint: disable=wrong-import-position

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
