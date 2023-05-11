

import argparse
import os
from pathlib import Path
import logging as logger
import shutil

from Tests.scripts.utils.log_util import install_logging

install_logging('extract_test_conf.log', logger=logger)


def extract(
    content_path: Path,
    content_test_conf_path: Path,
):
    missing_content_packs = []
    content_packs = {pack.name for pack in (content_path / "Packs").iterdir()}
    for pack in (content_test_conf_path / "content" / "Packs").iterdir():
        if pack.name not in content_packs:
            missing_content_packs.append(pack.name)
            logger.warning(f"Pack {pack.name} exists in content-test-conf but not in content")
            continue
        destination = content_path / "Packs" / pack.name
        logger.info(f"Copying {pack.name} from {pack} to {destination} from content-test-conf")
        shutil.copytree(pack, destination, dirs_exist_ok=True)
    if artifacts_folder := os.getenv("ARTIFACTS_FOLDER"):
        with open(Path(artifacts_folder) / "missing_content_packs_test_conf.txt", "w") as f:
            f.write("\n".join(missing_content_packs))


def main():
    parser = argparse.ArgumentParser(description='Compare content and content-test-conf')
    parser.add_argument('--content-path', required=True, help='Path to content repo')
    parser.add_argument('--content-test-conf-path', required=True, help='Path to content-test-conf repo')
    args = parser.parse_args()

    extract(Path(args.content_path), Path(args.content_test_conf_path))


if __name__ == "__main__":
    main()
