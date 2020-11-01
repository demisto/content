import os
import json
import argparse
import logging

from Tests.Marketplace.upload_packs import PACKS_FULL_PATH, IGNORED_FILES, PACKS_FOLDER
from Tests.Marketplace.marketplace_services import GCPConfig
from demisto_sdk.commands.find_dependencies.find_dependencies import VerboseFile, PackDependencies,\
    parse_for_pack_metadata

from Tests.scripts.utils.log_util import install_logging


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Create json file of all packs dependencies.")
    parser.add_argument('-o', '--output_path', help="The full path to store created file", required=True)
    parser.add_argument('-i', '--id_set_path', help="The full path of id set", required=True)
    return parser.parse_args()


def main():
    """ Main function for iterating over existing packs folder in content repo and creating json of all
    packs dependencies. The logic of pack dependency is identical to sdk find-dependencies command.

    """
    install_logging('Calculate Packs Dependencies.log')
    option = option_handler()
    output_path = option.output_path
    id_set_path = option.id_set_path
    IGNORED_FILES.append(GCPConfig.BASE_PACK)  # skip dependency calculation of Base pack
    # loading id set json
    with open(id_set_path, 'r') as id_set_file:
        id_set = json.load(id_set_file)

    pack_dependencies_result = {}

    logging.info("Starting dependencies calculation")
    # starting iteration over pack folders
    for pack in os.scandir(PACKS_FULL_PATH):
        if not pack.is_dir() or pack.name in IGNORED_FILES:
            logging.warning(f"Skipping dependency calculation of {pack.name} pack.")
            continue  # skipping ignored packs
        logging.info(f"Calculating {pack.name} pack dependencies.")

        try:
            dependency_graph = PackDependencies.build_dependency_graph(pack_id=pack.name,
                                                                       id_set=id_set,
                                                                       verbose_file=VerboseFile(''),
                                                                       )
            first_level_dependencies, all_level_dependencies = parse_for_pack_metadata(dependency_graph, pack.name)

        except Exception:
            logging.exception(f"Failed calculating {pack.name} pack dependencies")
            continue

        pack_dependencies_result[pack.name] = {
            "dependencies": first_level_dependencies,
            "displayedImages": list(first_level_dependencies.keys()),
            "allLevelDependencies": all_level_dependencies,
            "path": os.path.join(PACKS_FOLDER, pack.name),
            "fullPath": pack.path
        }

    logging.info(f"Number of created pack dependencies entries: {len(pack_dependencies_result.keys())}")
    # finished iteration over pack folders
    logging.success("Finished dependencies calculation")

    with open(output_path, 'w') as pack_dependencies_file:
        json.dump(pack_dependencies_result, pack_dependencies_file, indent=4)

    logging.success(f"Created packs dependencies file at: {output_path}")


if __name__ == "__main__":
    main()
