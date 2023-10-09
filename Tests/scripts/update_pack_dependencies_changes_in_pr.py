import json
import logging as logger
from argparse import ArgumentParser, Namespace
from pathlib import Path
from string import Template

from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.common.logger import logging_setup
from demisto_sdk.commands.common.tools import get_marketplace_to_core_packs, str2bool

from Tests.scripts.find_pack_dependencies_changes import DIFF_FILENAME
from Tests.scripts.github_client import GithubPullRequest
from Tests.scripts.utils.log_util import install_logging

BOOL_TO_M_LEVEL: dict = {
    True: "mandatory",
    False: "optional",
}
CHANGE_TYPE_TO_TEMPLATE: dict[str, Template] = {
    "added": Template("   - A new *$m_level* dependency **$dep_id** was added."),
    "removed": Template("   - Pack **$dep_id** is no longer a dependency."),
    "modified": Template("   - The dependency **$dep_id** was changed to *$m_level*."),
}
MP_VERSION_TO_DISPLAY: dict = {
    MarketplaceVersions.XSOAR: "XSOAR",
    MarketplaceVersions.XSOAR_SAAS: "XSOAR SAAS",
    MarketplaceVersions.MarketplaceV2: "XSIAM",
    MarketplaceVersions.XPANSE: "XPANSE",
}
NO_CHANGES_MSG = "**No changes in packs dependencies were made on this pull request.**"
NO_MANDATORY_CHANGES_MSG = "**No mandatory dependencies were added on this pull request.**"
CHANGES_MSG_TITLE = "## This pull request introduces changes in packs dependencies\n"


logging_setup(logger.DEBUG)
install_logging("update_pack_dependencies_changes_in_pr.log", logger=logger)


def parse_args() -> Namespace:
    options = ArgumentParser()
    options.add_argument('--artifacts-folder', required=True, help='The artifacts folder')
    options.add_argument('--github-token', required=True, help='A GitHub API token')
    options.add_argument('--current-sha', required=True, help='Current branch commit SHA')
    options.add_argument('--current-branch', required=True, help='Current branch name')
    options.add_argument(
        '--mandatory-only',
        type=str2bool,
        help='If true, shows only new/modified mandatory dependencies',
        default=False,
    )
    return options.parse_args()


def get_summary(diff: dict, core_packs: set, mandatory_only: bool) -> str:
    """Logs and returns a string reperesentation of the pack dependencies changes.

    Args:
        diff (dict): key-value pairs of pack IDs and their changes.
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
        core_packs (set): A set of all core packs in a marketplace.
        mandatory_only (bool): If true, returns a compact version of the summary
            that includes only new/modified mandatory dependencies.
    """
    s_lines = []

    def drop_non_mandatory_dependencies(pack_data: dict[str, dict[str, dict]]) -> dict:
        return {
            change_type: {
                dep_field: {
                    dep_id: dep_data
                    for dep_id, dep_data in dependencies_data.items()
                    if dep_data["mandatory"]
                }
                for dep_field, dependencies_data in change_data.items()
            }
            for change_type, change_data in pack_data.items()
            if change_type != "removed"
        }

    pack_data: dict[str, dict[str, dict]]
    for pack_id, pack_data in diff.items():
        if mandatory_only:
            pack_data = drop_non_mandatory_dependencies(pack_data)
        for change_type, change_data in pack_data.items():
            for dep_field, dependencies_data in change_data.items():
                if not dependencies_data:
                    continue
                s_lines.append(
                    f"- Pack **{pack_id}**"
                    f"{' (core pack)' if pack_id in core_packs else ''} - "
                    f"{'all' if dep_field.startswith('all') else 'first'}-level dependencies:"
                )
                s_lines.extend([
                    CHANGE_TYPE_TO_TEMPLATE[change_type].safe_substitute(
                        dep_id=dep_id,
                        m_level=BOOL_TO_M_LEVEL[dep_data['mandatory']],
                    ) for dep_id, dep_data in dependencies_data.items()
                ])
    if s := "\n".join(s_lines):
        logger.info(s)
    return s


def aggregate_summaries(artifacts_folder: str, mandatory_only: bool = False) -> dict:
    """Aggregates summaries of pack dependencies changes in all marketplaces.

    Args:
        artifacts_folder (str): The artifacts folder.
        mandatory_only (bool, default: False): If true, prints a compact version of the summary
            that includes only new/modified mandatory dependencies.

    Returns:
        dict: a key-value pairs of marketplaces and their pack dependencies changes' summary.
    """
    summaries: dict = {}
    core_packs = get_marketplace_to_core_packs()
    for marketplace in list(MarketplaceVersions):
        diff_path = Path(artifacts_folder) / marketplace.value / DIFF_FILENAME
        if diff_path.is_file():
            diff = json.loads(diff_path.read_text())
            if summary := get_summary(diff, core_packs[marketplace], mandatory_only):
                summaries[marketplace.value] = summary
    return summaries


def format_summaries_to_single_comment(summaries: dict, mandatory_only: bool) -> str:
    if not any(bool(s) for s in summaries.values()):
        return NO_MANDATORY_CHANGES_MSG if mandatory_only else NO_CHANGES_MSG
    s = CHANGES_MSG_TITLE
    for marketplace, summary in summaries.items():
        if summary:
            title = MP_VERSION_TO_DISPLAY.get(marketplace) or str(marketplace).upper()
            s += f"### {title}\n{summary}\n"
    return s


def main():  # pragma: no cover
    args = parse_args()
    summaries = aggregate_summaries(args.artifacts_folder, args.mandatory_only)
    pull_request = GithubPullRequest(
        args.github_token,
        sha1=args.current_sha,
        branch=args.current_branch,
        fail_on_error=True,
    )

    pull_request.edit_comment(
        format_summaries_to_single_comment(summaries, args.mandatory_only),
        section_name="Packs dependencies diff",
    )


if __name__ == '__main__':
    main()
