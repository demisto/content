from argparse import ArgumentParser
import json
from Tests.scripts.utils import logging_wrapper as logging


def parse_args():
    args = ArgumentParser()
    args.add_argument('--previous', required=True, help='Path to previous pack_dependencies.json')
    args.add_argument('--current', required=True, help='Path to current pack_dependencies.json')
    args.add_argument('--output', required=True, help='Path to diff output file')
    return args.parse_args()


def load_json(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)


def compare_pack_field(pack_id: str, previous: dict, current: dict, res: dict, field: str) -> None:
    if previous[pack_id][field] != current[pack_id][field]:
        if added := {
            k: v for k, v in current[pack_id][field].items()
            if k not in previous[pack_id][field]
        }:
            if "added" not in res:
                res["added"] = {}
            res["added"][field] = added
        if removed := {
            k: v for k, v in previous[pack_id][field].items()
            if k not in current[pack_id][field]
        }:
            if "removed" not in res:
                res["removed"] = {}
            res["removed"][field] = removed
        if modified := {
            k: v for k, v in current[pack_id][field].items()
            if k in previous[pack_id][field]
            and v["mandatory"] != previous[pack_id][field][k]["mandatory"]
        }:
            if "modified" not in res:
                res["modified"] = {}
            res["modified"][field] = modified


def get_pack_diff(pack_id: str, previous: dict, current: dict) -> dict:
    if pack_id not in previous:
        return {
            "added": {
                "dependencies": current[pack_id]["dependencies"],
                "allLevelDependencies": current[pack_id]["allLevelDependencies"]
            }
        }
    if pack_id not in current:
        return {
            "removed": {
                "dependencies": previous[pack_id]["dependencies"],
                "allLevelDependencies": previous[pack_id]["allLevelDependencies"]
            }
        }
    res: dict = {}
    for field in ["dependencies", "allLevelDependencies"]:
        compare_pack_field(pack_id, previous, current, res, field)
    return res


def compare(previous: dict, current: dict) -> dict:
    diff: dict = {
    }
    all_packs = set(previous.keys()).union(current.keys())
    for pack_id in all_packs:
        if pack_diff := get_pack_diff(pack_id, previous, current):
            diff[pack_id] = pack_diff
    return diff


def log_outputs(diff: dict) -> None:
    if not diff:
        logging.info("No difference in dependencies.")

    s = "\n".join([f"{pack}:\n{json.dumps(data, indent=4)}" for pack, data in diff.items()])
    logging.info(f"Found the following differences:\n{s}")


def write_json(diff: dict, filepath: str) -> None:
    with open(filepath, "w") as f:
        f.write(json.dumps(diff, indent=4))


def main():
    args = parse_args()
    previous = load_json(args.previous)
    current = load_json(args.current)
    diff = compare(previous, current)
    log_outputs(diff)
    write_json(diff, args.output)


if __name__ == '__main__':
    main()
