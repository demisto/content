

import argparse
from pathlib import Path
import logging as logger
import shutil
import slack_sdk

from Tests.scripts.utils.log_util import install_logging

install_logging('collect_tests.log', logger=logger)

CONTENT_CHANNEL = 'dmst-build-test'


def extract(
    content_path: Path,
    content_test_conf_path: Path,
    slack_token: str | None = None,
    slack_channel: str = CONTENT_CHANNEL
):
    missing_content_packs = []
    content_packs = {pack.name for pack in (content_path / "Packs").iterdir()}
    for pack in (content_test_conf_path / "content" / "Packs").iterdir():
        if pack.name not in content_packs:
            missing_content_packs.append(pack.name)
            logger.warning(f"Pack {pack.name} exists in in content-test-conf but not in content")
            continue
        logger.info(f"Copying {pack.name} from content-test-conf")
        shutil.copytree(pack, content_path / "Packs" / pack.name, dirs_exist_ok=True)
    if slack_token and missing_content_packs:
        slack_sdk.WebClient(token=slack_token).chat_postMessage(
            channel=slack_channel,
            text=f"The following packs were merged to content-test-conf, but not to content: {missing_content_packs}"
        )


def main():
    parser = argparse.ArgumentParser(description='Compare content and content-test-conf')
    parser.add_argument('--content-path', required=True, help='Path to content repo')
    parser.add_argument('--content-test-conf-path', required=True, help='Path to content-test-conf repo')
    parser.add_argument('-s', '--slack-token', help='The token for slack')
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    args = parser.parse_args()

    extract(Path(args.content_path), Path(args.content_test_conf_path), args.slack_token, args.slack_channel)


if __name__ == "__main__":
    main()
