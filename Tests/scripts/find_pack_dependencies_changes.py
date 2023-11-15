import json
import logging as logger
import os
from argparse import ArgumentParser, Namespace
from pathlib import Path

from demisto_sdk.commands.common.logger import logging_setup

from Tests.scripts.gitlab_client import GitlabClient
from Tests.scripts.utils.log_util import install_logging

PACKS_DEPENDENCIES_FILENAME = "packs_dependencies.json"
DIFF_FILENAME = "packs_dependencies_diff.json"
ARTIFACTS_DIR_LOCATION = os.getenv("CI_PROJECT_DIR", "/builds/xsoar/content")

DEPENDENCIES_FIELDS = ["dependencies", "allLevelDependencies"]


logging_setup(logger.DEBUG)
install_logging("find_pack_dependencies_changes.log", logger=logger)


def parse_args() -> Namespace:
    options = ArgumentParser()
    options.add_argument('--gitlab-token', required=True, help='A GitLab API token')
    options.add_argument('--master-sha', required=True, help='master branch commit SHA')
    options.add_argument('--job-name', required=True, help='The job name to take the artifact from')
    options.add_argument('--artifacts-folder', required=True, help='Artifacts folder to write the output to')
    return options.parse_args()


def log_deps_change(pack_id: str, data: dict, change_type: str) -> None:
    data_str = json.dumps(data, indent=4)
    logger.debug(
        f"{change_type.title()} pack {pack_id} dependencies: {data_str}"
    )


def compare_field(pack_id: str, previous: dict, current: dict, res: dict, field: str) -> None:
    def dict_diff(a: dict, b: dict) -> dict:
        return {k: v for k, v in a.items() if k not in b}

    if previous[field] == current[field]:
        return  # no changes

    if added := dict_diff(current[field], previous[field]):
        log_deps_change(pack_id, added, "added")
        res.setdefault("added", {})[field] = added

    if removed := dict_diff(previous[field], current[field]):
        log_deps_change(pack_id, removed, "removed")
        res.setdefault("removed", {})[field] = removed

    if modified := {
        k: v for k, v in current[field].items()
        if k in previous[field]
        and v["mandatory"] != previous[field][k]["mandatory"]
    }:
        log_deps_change(pack_id, modified, "modified")
        res.setdefault("modified", {})[field] = modified


def get_pack_diff(pack_id: str, previous: dict, current: dict) -> dict:
    def all_pack_dependencies(pack_data: dict) -> dict:
        return {field: pack_data[field] for field in DEPENDENCIES_FIELDS}

    if pack_id not in previous:
        new_pack_deps = all_pack_dependencies(current[pack_id])
        log_deps_change(pack_id, new_pack_deps, "added")
        return {"added": new_pack_deps}

    if pack_id not in current:
        removed_pack_deps = all_pack_dependencies(previous[pack_id])
        log_deps_change(pack_id, removed_pack_deps, "removed")
        return {"removed": removed_pack_deps}

    res: dict = {}
    for field in DEPENDENCIES_FIELDS:
        compare_field(pack_id, previous[pack_id], current[pack_id], res, field)
    return res


def compare(previous: dict, current: dict) -> dict:
    diff: dict = {}
    for pack_id in (previous.keys() | current.keys()):
        if pack_diff := get_pack_diff(pack_id, previous, current):
            diff[pack_id] = pack_diff
    return diff


def get_diff(args: Namespace) -> dict:  # pragma: no cover
    logger.info(
        f"Comparing {PACKS_DEPENDENCIES_FILENAME} of current branch "
        f"and master branch (commit: {args.master_sha})"
    )
    absolute_artifacts_folder = Path(args.artifacts_folder)
    relative_artifacts_folder = absolute_artifacts_folder.relative_to(ARTIFACTS_DIR_LOCATION)
    gitlab_client = GitlabClient(args.gitlab_token)
    previous = gitlab_client.get_packs_dependencies_json(
        args.master_sha,
        args.job_name,
        relative_artifacts_folder / PACKS_DEPENDENCIES_FILENAME,
    )
    current = json.loads((absolute_artifacts_folder / PACKS_DEPENDENCIES_FILENAME).read_text())
    return compare(previous, current)


def main():  # pragma: no cover
    args = parse_args()
    diff = get_diff(args)
    diff_file = Path(args.artifacts_folder) / DIFF_FILENAME
    logger.info(f"Dumping the diff to an artifact file: {diff_file}")
    diff_file.write_text(json.dumps(diff, indent=4))


if __name__ == '__main__':
    main()
