# function to compare two zip files

import argparse
import filecmp
import json
import os
from pathlib import Path
import shutil
from zipfile import ZipFile

import difflib
import dictdiffer

from ruamel.yaml import YAML
from slack_sdk import WebClient
from demisto_sdk.commands.content_graph.parsers.content_item import ContentItemParser
yaml = YAML()

SKIPPED_FILES = {"signatures.sf", "script-CommonServerPython.yml", "changelog.json"}
ARTIFACTS_FOLDER: Path


def sort_dict(dct: dict):
    for k, v in dct.items():
        if isinstance(v, dict):
            sort_dict(v)
        if isinstance(v, list):
            try:
                v.sort()
            except TypeError:
                if v and v[0].get("id"):
                    v.sort(key=lambda x: x["id"])
                elif v and v[0].get("name"):
                    v.sort(key=lambda x: x["name"])
                elif v and v[0].get("display_name"):
                    v.sort(key=lambda x: x["display_name"])
                else:
                    print("Could not sort list", v)


def compare_indexes(index_id_set_path: Path, index_graph_path: Path, output_path: Path) -> bool:
    with index_id_set_path.open() as f1, index_graph_path.open() as f2:
        index_id_set = json.load(f1)
        index_graph = json.load(f2)
        index_id_set.pop("modified", None)
        index_graph.pop("modified", None)
        sort_dict(index_id_set)
        sort_dict(index_graph)
        diff_list = list(dictdiffer.diff(index_id_set, index_graph))
    if diff_list:
        with (output_path / "index-diff.json").open("w") as output:
            json.dump(diff_list, output, indent=4)
        shutil.copyfile(index_id_set_path, output_path / "index-id_set.json")
        shutil.copyfile(index_graph_path, output_path / "index-graph.json")
        return True
    return False


def compare_dirs(dir1: str, dir2: str, output_path: Path) -> list[str]:
    dir_compare = filecmp.dircmp(dir1, dir2)

    diff_files: list[str] = []
    compare_files(dir_compare, dir1, dir2, output_path, diff_files)
    return diff_files


def compare_zips(zip1: Path, zip2: Path, output_path: Path) -> list[str]:
    """Compare two zip files content"""
    # extract zip files
    output_path.mkdir(parents=True, exist_ok=True)
    zip1_files = str(output_path / "id_set_tmp")
    zip2_files = str(output_path / "graph_tmp")
    with ZipFile(zip1, "r") as zip1_content, ZipFile(zip2, "r") as zip2_content:
        # get the list of files in the zip files
        zip1_content.extractall(path=zip1_files)
        zip2_content.extractall(path=zip2_files)

    # compare the directories
    return compare_dirs(zip1_files, zip2_files, output_path)


def compare_files(
    dir_compare: filecmp.dircmp[str], zip1_files: str, zip2_files: str, output_path: Path, diff_files: list[str]
):
    for file in dir_compare.common_files:
        if file not in dir_compare.same_files and file not in SKIPPED_FILES:
            file_diff(output_path, zip1_files, zip2_files, file, diff_files)
    for subdir in dir_compare.subdirs.values():
        compare_files(subdir, subdir.left, subdir.right, output_path / Path(subdir.left).name, diff_files)


def file_diff_text(file1_path: Path, file2_path: Path, output_path_file: Path):
    output_path_file.unlink(missing_ok=True)

    with output_path_file.open("w") as f:
        with open(file1_path) as f1, open(file2_path) as f2:
            f1lines = f1.readlines()
            f2lines = f2.readlines()
            d = difflib.Differ()
            diffs = [x for x in d.compare(f1lines, f2lines) if x[0] in ("+", "-")]
            if diffs:
                f.writelines(diffs)
                return True
    return False


def remove_known_diffs(dct1: dict, dct2: dict, known_diff: list[str]):
    for diff in known_diff:
        dct1.pop(diff, None)
        dct2.pop(diff, None)


def file_diff(output_path: Path, zip1_files: str, zip2_files: str, file: str, diff_files: list[str]):
    output_path.mkdir(exist_ok=True, parents=True)
    try:
        file1_path = Path(zip1_files) / file
        file2_path = Path(zip2_files) / file
        file_diff_text(file1_path, file2_path, output_path / f"{file}-textdiff.log")
        if file1_path.suffix == ".yml":
            load_func = yaml.load
        elif file1_path.suffix == ".json":
            load_func = json.load  # type: ignore[assignment]
        else:
            print(f"not yaml or json: {output_path / file}. continue")
            return
        output_dict_diff = output_path / f"{file}-dictdiff.json"
        output_dict_diff.unlink(missing_ok=True)
        with open(output_dict_diff, "w") as f:
            with open(file1_path) as f1, open(file2_path) as f2:
                dct1 = load_func(f1)
                dct2 = load_func(f2)
                remove_known_diffs(dct1, dct2, ["updated", "downloads", "created"])
                if file == "metadata.json":
                    sort_dict(dct1)
                    sort_dict(dct2)
                diff_found = list(dictdiffer.diff(dct1, dct2))
                if diff_found:
                    json.dump(diff_found, f, indent=4)
                    shutil.copyfile(file1_path, output_path / f"id-set-{file1_path.name}")
                    shutil.copyfile(file2_path, output_path / f"graph-{file2_path.name}")
                    diff_files.append(file1_path.name)

    except Exception as e:
        print(f"could not diff files {file1_path}:{file2_path}: {e}")


def compare(
    marketplace: str,
    zip_id_set: Path,
    zip_graph: Path,
    index_id_set_path: Path,
    index_graph_path: Path,
    collected_packs_id_set: Path,
    collected_packs_graph: Path,
    message: list[str],
    output_path: Path,
):
    diff_found = False
    output_path.mkdir(exist_ok=True, parents=True)
    # compare directories
    dir_cmp = filecmp.dircmp(zip_id_set, zip_graph)
    # capture stdout
    for file in dir_cmp.common_files:
        pack = file.removesuffix(".zip")
        diff_files = compare_zips(zip_id_set / file, zip_graph / file, output_path / pack)
        if diff_files:
            diff_found = True
            message.append(f'Detected differences in the following files for pack {pack}: {", ".join(diff_files)}')
    if compare_indexes(index_id_set_path, index_graph_path, output_path):
        diff_found = True
        message.append("Detected differences between index.json files")
    if file_diff_text(collected_packs_id_set, collected_packs_graph, output_path / "collect_tests_diff.log"):
        diff_found = True
        message.append("Detected differences between collect tests results")
        shutil.copy(collected_packs_id_set, output_path / "collected_packs-id_set.txt")
        shutil.copy(collected_packs_graph, output_path / "collected_packs-graph.txt")

    shutil.make_archive(str(output_path / f"diff-{marketplace}"), "zip", output_path)
    if not diff_found:
        message.append("No difference were found!")
    return message


def compare_content_packs(
    marketplace: str,
    content_packs_id_set: Path,
    content_packs_graph: Path,
    output_path: Path,
    message: list[str],
):
    with (ARTIFACTS_FOLDER / f'removed_from_marketplace-{marketplace}.json').open() as f:
        reasons = json.load(f)
    ZipFile(content_packs_id_set).extractall(output_path / "id_set")
    ZipFile(content_packs_graph).extractall(output_path / "graph")
    list_files_id_set = list((output_path / "id_set").rglob("*"))
    assert list_files_id_set, "No files in content packs id_set"
    missing = [
        path
        for path in list_files_id_set
        if not Path(str(path).replace("id_set", "graph")).exists() and "NonSupported" not in str(path)
        and path.is_file()
    ]
    content_items = []
    for path in missing:
        try:
            content_item = ContentItemParser.from_path(path)
            if content_item:
                content_items.append(content_item)
        except Exception as e:
            print(f"could not parse {path}: {e}")
    missing = [(content_item.node_id, reasons[reasons.get(content_item.node_id, "Reason not found")]) for content_item in content_items]
    message.append(f"Missing files in graph: {json.dumps(missing, indent=4)}")


def format_reason(reasons: list[dict]) -> str:
    message = []
    for reason in reasons:
        message.append(
            f"Reason: {reason.get('source')} -> {reason.get('target')} (mandatorily: {reason.get('mandatorily')})"
        )
    return "\n".join(message)


def compare_dependencies(
    dependencies_id_set: Path,
    dependencies_graph: Path,
    message: list[str],
):
    dependencies_id_set = json.load(dependencies_id_set.open())
    dependencies_graph = json.load(dependencies_graph.open())
    with (ARTIFACTS_FOLDER / "depends_on.json").open() as f:
        reasons = json.load(f)
    for pack_idset, deps_idset in dependencies_id_set.items():
        deps_graph = dependencies_graph.get(pack_idset)
        if not deps_graph:
            continue
        compare_first_level_dependencies(pack_idset, deps_idset, deps_graph, reasons, message)


def compare_first_level_dependencies(pack: str, deps_idset: dict, deps_graph: dict, reasons: dict, message: list[str]):
    first_level_dependencies_idset = deps_idset["dependencies"]
    first_level_dependencies_graph = deps_graph["dependencies"]
    if first_level_dependencies_idset != first_level_dependencies_graph:
        mandatory_deps_idset = {dep for dep, data in first_level_dependencies_idset.items() if data.get("mandatory")}
        mandatory_deps_graph = {dep for dep, data in first_level_dependencies_graph.items() if data.get("mandatory")}
        optional_deps_idset = {dep for dep, data in first_level_dependencies_idset.items() if not data.get("mandatory")}
        optional_deps_graph = {dep for dep, data in first_level_dependencies_graph.items() if not data.get("mandatory")}

        if moved_to_optional := (mandatory_deps_idset & optional_deps_graph):
            message.append(f"Moved to optional dependencies for pack {pack}: {sorted(moved_to_optional)}")
            for dep in moved_to_optional:
                message.append(f"Reason: {pack} depends on {dep} because of {format_reason(reasons[pack][dep])}")

        if moved_to_mandatory := (optional_deps_idset & mandatory_deps_graph):
            message.append(f"Moved to mandatory dependencies for pack {pack}: {sorted(moved_to_mandatory)}")
            for dep in moved_to_mandatory:
                message.append(f"Reason: {pack} depends on {dep} because of {format_reason(reasons[pack][dep])}")

        if missing_in_graph := mandatory_deps_idset - mandatory_deps_graph - moved_to_optional - moved_to_mandatory:
            message.append(f"Missing mandatory dependencies for pack {pack}: {sorted(missing_in_graph)}")

        if extra_in_graph := mandatory_deps_graph - mandatory_deps_idset - moved_to_optional - moved_to_mandatory:
            message.append(f"Extra mandatory dependencies for pack {pack}: {sorted(extra_in_graph)}")
            for dep in extra_in_graph:
                message.append(f"Reason: {pack} depends on {dep} because of {format_reason(reasons[pack][dep])}")

        if missing_in_graph := optional_deps_idset - optional_deps_graph - moved_to_optional - moved_to_mandatory:
            message.append(f"Missing optional dependencies for pack {pack}: {sorted(missing_in_graph)}")
        if extra_in_graph := optional_deps_graph - optional_deps_idset - moved_to_optional - moved_to_mandatory:
            message.append(f"Extra optional dependencies for pack {pack}: {sorted(extra_in_graph)}")
            for dep in extra_in_graph:
                message.append(f"Reason: {pack} depends on {dep} because of {format_reason(reasons[pack][dep])}")


def main():
    global ARTIFACTS_FOLDER
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", help="artifacts of the build")
    parser.add_argument("--marketplace", "--mp", help="Marketplace to use")
    parser.add_argument("--output-path", help="Output path")
    parser.add_argument("--slack-token", "-s", help="Slack token", required=False)
    args = parser.parse_args()
    ARTIFACTS_FOLDER = Path(args.artifacts)
    output_path = Path(args.output_path)
    slack_token = args.slack_token
    marketplace = args.marketplace

    zip_id_set = ARTIFACTS_FOLDER / "uploaded_packs-id_set"
    zip_graph = ARTIFACTS_FOLDER / "uploaded_packs-graph"

    index_id_set_path = ARTIFACTS_FOLDER / "index.json"
    index_graph_path = ARTIFACTS_FOLDER / "index-graph.json"

    collected_packs_id_set = ARTIFACTS_FOLDER / "content_packs_to_install.txt"
    collected_packs_graph = ARTIFACTS_FOLDER / "content_packs_to_install-graph.txt"

    content_packs_id_set = ARTIFACTS_FOLDER / "content_packs_id_set.zip"
    content_packs_graph = ARTIFACTS_FOLDER / "content_packs_graph.zip"

    dependencies_id_set = ARTIFACTS_FOLDER / "packs_dependencies_id_set.json"
    dependencies_graph = ARTIFACTS_FOLDER / "packs_dependencies_graph.json"

    message = [
        f"Diff report for {marketplace}",
        f'Job URL: {os.getenv("CI_JOB_URL")}',
    ]

    compare_content_packs(marketplace, content_packs_id_set, content_packs_graph, output_path / "content_packs", message)
    try:
        compare_dependencies(dependencies_id_set, dependencies_graph, message)
    except Exception as e:
        print("Failed to compare dependencies", e)
    if not zip_graph.exists():
        message.append("No packs were uploaded for id_set")
    if not zip_id_set.exists():
        message.append("No packs were uploaded for graph")

    else:
        message = compare(
            marketplace,
            zip_id_set,
            zip_graph,
            index_id_set_path,
            index_graph_path,
            collected_packs_id_set,
            collected_packs_graph,
            message,
            output_path,
        )
    print("\n".join(message))
    if slack_token:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(
            channel="dmst-graph-tests",
            text="Check out\n" f"Job URL: {os.getenv('CI_JOB_URL')}",
        )


if __name__ == "__main__":
    main()
