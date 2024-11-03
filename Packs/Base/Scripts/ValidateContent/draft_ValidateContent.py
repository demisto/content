import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pkg_resources import get_distribution
import os

def log_demisto_sdk_version():
    try:
        demisto.debug(f'Using demisto-sdk version {get_distribution("demisto-sdk").version}')
    except Exception as e:
        demisto.debug(f'Could not get demisto-sdk version. Error: {e}')

def main():
    os.environ['DEMISTO_SDK_IGNORE_CONTENT_WARNING'] = "false"

    args = demisto.args()
    # setup_proxy(args)
    verify_ssl = argToBoolean(args.get('trust_any_certificate'))

    file_name = args.get('file_name', None)
    file_contents = args.get('file_contents', None)
    entry_id = args.get('entry_id', None)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    log_demisto_sdk_version()
    main()
