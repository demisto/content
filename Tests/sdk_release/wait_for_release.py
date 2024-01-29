import argparse
import sys
import time
import requests
import urllib3
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

ARTIFACTS_URL = 'https://art.code.pan.run/artifactory/api/pypi/pypi.org/simple/demisto-sdk'  # disable-secrets-detection
TIMEOUT = 60 * 60 * 6  # 6 hours


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    install_logging("WaitForSDKRelease.log", logger=logging)

    options = options_handler()
    release_branch_name = options.release_branch_name
    release_branch_name = '1.25.3'  # TODO: remove
    # initialize timer
    start = time.time()
    elapsed: float = 0

    demisto_sdk_versions = ''

    while f'demisto_sdk-{release_branch_name}' not in demisto_sdk_versions and elapsed < TIMEOUT:
        res = requests.get(ARTIFACTS_URL, verify=False)
        if res.status_code != 200:
            logging.error(f'Failed to get the artifacts from {ARTIFACTS_URL}')
            sys.exit(1)

        demisto_sdk_versions = res.text
        logging.info(f'The release {release_branch_name} is not yet in the artifacts')
        time.sleep(300)  # 5 minutes

        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        logging.critical('Timeout reached while waiting for SDK release artifacts')
        sys.exit(1)

    logging.success(f'SDK release version {release_branch_name} is out')


if __name__ == "__main__":
    main()
