import argparse
import sys
import os
import time
import requests
import urllib3
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

ARTIFACTORY_URL = os.getenv('ARTIFACTORY_URL', 'art.code.pan.run')  # disable-secrets-detection
ARTIFACTS_URL = f'https://{ARTIFACTORY_URL}/artifactory/api/pypi/pypi.org/simple/demisto-sdk'  # disable-secrets-detection
TIMEOUT = 60 * 60 * 6  # 6 hours


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    install_logging("wait_for_release.log", logger=logging)

    options = options_handler()
    release_branch_name = options.release_branch_name

    # initialize timer
    start = time.time()
    elapsed: float = 0

    while elapsed < TIMEOUT:
        res = requests.get(ARTIFACTS_URL, verify=False)
        if res.status_code != requests.codes.ok:
            logging.error(f'Failed to get the artifacts from {ARTIFACTS_URL}')
            sys.exit(1)

        if f'demisto_sdk-{release_branch_name}' in res.text:
            break

        logging.info(f'The release {release_branch_name} is not yet in the artifacts')
        time.sleep(300)  # 5 minutes
        elapsed = time.time() - start

        if elapsed >= TIMEOUT:
            logging.critical('Timeout reached while waiting for SDK release artifacts')
            sys.exit(1)

    logging.success(f'SDK release version {release_branch_name} is out')


if __name__ == "__main__":
    main()
