import os
import json
import argparse
from Tests.Marketplace.upload_packs import PACKS_FULL_PATH, IGNORED_FILES

from demisto_sdk.commands.find_dependencies.find_dependencies import PackDependencies, parse_for_pack_metadata


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Create json file of all packs dependencies.")
    parser.add_argument('-o', '--output_path', help="The full path to store created file", required=True)
    parser.add_argument('-i', '--id_set_path', help="The full path of id set", required=True)
    return parser.parse_args()


def load_id_set(id_set_path):
    """
    #todo
    """
    with open(id_set_path, 'r') as id_set_file:
        id_set = json.load(id_set_file)

    return id_set


def main():
    """
    #todo
    """
    option = option_handler()
    output_path = option.output_path
    id_set_path = option.id_set_path
    # loading id set json
    with open(id_set_path, 'r') as id_set_file:
        id_set = json.load(id_set_file)

    pack_dependencies_result = {}

    print("Starting dependencies calculation")
    # starting iteration over pack folders
    for pack in os.scandir(PACKS_FULL_PATH):
        if not pack.is_dir() or pack.name in IGNORED_FILES:
            continue  # skipping ignored packs
        print(f"Calculating {pack.name} pack dependencies.")

        dependency_graph = PackDependencies.build_dependency_graph(pack_id=pack.name, id_set=id_set)
        first_level_dependencies, all_level_dependencies = parse_for_pack_metadata(dependency_graph, pack.name)

        pack_dependencies_result[pack.name] = {
            "dependencies": first_level_dependencies,
            "displayedImages": all_level_dependencies,
        }

    print("Finished dependencies calculation")

    with open(output_path, 'w') as pack_dependencies_file:
        json.dump(pack_dependencies_result, pack_dependencies_file, indent=4)

    print(f"Created packs dependencies file at: {output_path}")


if __name__ == "__main__":
    main()
