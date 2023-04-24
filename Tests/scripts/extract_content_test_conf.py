

import argparse
from pathlib import Path
import logging
import shutil
import slack_sdk


def extract(content_path: Path, content_test_conf_path: Path, slack_token: str | None = None):
    missing_content_packs = []
    content_packs = set((content_path / "Packs").iterdir())
    for pack in (content_test_conf_path / "content" / "Packs").iterdir():
        if pack.name not in content_packs:
            missing_content_packs.append(pack.name)
            logging.warning(f"Pack {pack.name} is in content-test-conf but not in content")
            continue
        shutil.copytree(pack, content_path / "Packs" / pack.name)
    if slack_token and missing_content_packs:
        slack_sdk.WebClient(token=slack_token).chat_postMessage(
            channel="dmst-build",
            text=f"The following packs were merged to content-test-conf, but not to content: {missing_content_packs}"
        )


def main():
    parser = argparse.ArgumentParser(description='Compare content and content-test-conf')
    parser.add_argument('--content-path', required=True, help='Path to content repo')
    parser.add_argument('--content-test-conf-path', required=True, help='Path to content-test-conf repo')
    parser.add_argument('-s', '--slack_token', help='The token for slack')
    args = parser.parse_args()

    extract(Path(args.content_path), Path(args.content_test_conf_path), args.slack_token)


if __name__ == "__main__":
    main()
