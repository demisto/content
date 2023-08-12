import json
import logging as logger
from argparse import ArgumentParser, Namespace
from pathlib import Path
from string import Template

from demisto_sdk.commands.common.logger import logging_setup

from Tests.scripts.github_client import GithubPullRequest
from Tests.scripts.gitlab_client import GitlabClient
from Tests.scripts.utils.log_util import install_logging

DEPENDENCIES_FIELDS = ["dependencies", "allLevelDependencies"]
BOOL_TO_M_LEVEL: dict = {
    True: "mandatory",
    False: "optional",
}
CHANGE_TYPE_TO_TEMPLATE: dict[str, Template] = {
    "added": Template("   - A new $m_level dependency $dep_id was added.\n"),
    "removed": Template("   - The $m_level dependency $dep_id is no longer a dependency.\n"),
    "modified": Template("   - The dependency $dep_id was changed from $previous_m_level to $m_level.\n"),
}


logging_setup(logger.DEBUG)
install_logging("find_pack_dependencies_changes.log", logger=logger)


def parse_args() -> Namespace:
    args = ArgumentParser()
    args.add_argument('--gitlab-token', required=True, help='A GitLab API token')
    args.add_argument('--github-token', required=True, help='A GitHub API token')
    args.add_argument('--master-sha', required=True, help='master branch commit SHA')
    args.add_argument('--job-name', required=True, help='The job name to take the artifact from')
    args.add_argument('--marketplace', required=True, help='The marketplace name')
    args.add_argument('--current-file', required=True, help='Path to current pack_dependencies.json')
    args.add_argument('--current-sha', required=True, help='Current branch commit SHA')
    args.add_argument('--current-branch', required=True, help='Current branch name')
    args.add_argument('--output', required=True, help='Path to diff output file')
    return args.parse_args()


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


def get_summary(diff: dict) -> str:
    """ Logs and returns a string reperesentation of the pack dependencies changes.

    `diff` is expected to contain key-value pairs of pack IDs and their changes.
    The data is expected to be in the following structure:
    {
        "pack_id": {
            "added": {
                "dependencies": {  // first-level dependencies
                    "dep_id": {
                        "display_name": str,
                        "mandatory": bool,
                        ...
                    }
                },
                "allLevelDependencies": {
                    "dep_id": {
                        "display_name": str,
                        "mandatory": bool,
                        ...
                    }
                }
            },
            "removed": {...},
            "modified": {...}
        },
        ...
    }
    """
    if not diff:
        return "### No difference in packs dependencies."

    s = "### This pull request introduces changes in packs dependencies.\n"

    pack_data: dict[str, dict[str, dict]]
    for pack_id, pack_data in diff.items():
        for change_type, change_data in pack_data.items():
            for dep_field in DEPENDENCIES_FIELDS:
                if dependencies_data := change_data.get(dep_field):
                    s += (
                        f"- In the {'all' if dep_field.startswith('all') else 'first'}-"
                        f"level dependencies of pack {pack_id}:\n"
                    )
                    for dep_id, dep_data in dependencies_data.items():
                        s += CHANGE_TYPE_TO_TEMPLATE[change_type].safe_substitute(
                            dep_id=dep_id,
                            m_level=BOOL_TO_M_LEVEL[dep_data["mandatory"]],
                            previous_m_level=BOOL_TO_M_LEVEL[not dep_data["mandatory"]],
                        )
    logger.info(s)
    return s


def get_diff(args: ArgumentParser) -> dict:  # pragma: no cover
    gitlab_client = GitlabClient(args.gitlab_token)
    previous = gitlab_client.get_packs_dependencies_json(
        args.master_sha,
        args.job_name,
        args.marketplace,
    )
    current = json.loads(Path(args.current_file).read_text())
    return compare(previous, current)


def main():  # pragma: no cover
    args = parse_args()
    diff = get_diff(args)
    summary = get_summary(diff)
    pull_request = GithubPullRequest(
        args.github_token,
        sha1=args.current_sha,
        branch=args.current_branch,
    )
    pull_request.edit_comment(summary, append=True)
    Path(args.output).write_text(json.dumps(diff, indent=4))


if __name__ == '__main__':
    main()
