import argparse
import sys
import time
import requests

ARTIFACTS_URL = 'https://art.code.pan.run/artifactory/api/pypi/pypi.org/simple/demisto-sdk'  # disable-secrets-detection
TIMEOUT = 60 * 60 * 6  # 6 hours


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    release_branch_name = options.release_branch_name

    # initialize timer
    start = time.time()
    elapsed: float = 0

    demisto_sdk_versions = ''

    while f'demisto_sdk-{release_branch_name}' not in demisto_sdk_versions and elapsed < TIMEOUT:
        res = requests.get(ARTIFACTS_URL, verify=False)
        if res.status_code != 200:
            sys.exit(1)
        demisto_sdk_versions = res.text
        time.sleep(300)

        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        sys.exit(1)


if __name__ == "__main__":
    main()
