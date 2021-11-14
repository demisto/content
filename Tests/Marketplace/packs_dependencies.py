import argparse
import json
import logging
import os
from concurrent.futures import as_completed
from contextlib import contextmanager
from pprint import pformat
from typing import Tuple, Iterable, List, Callable

from Tests.Marketplace.marketplace_constants import GCPConfig, PACKS_FOLDER, PACKS_FULL_PATH, IGNORED_FILES
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.find_dependencies.find_dependencies import PackDependencies, parse_for_pack_metadata, \
    get_id_set, calculate_all_packs_dependencies, select_packs_for_calculation
from pebble import ProcessPool, ProcessFuture

PROCESS_FAILURE = False


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
    install_logging('Calculate_Packs_Dependencies.log', include_process_name=True)
    option = option_handler()
    output_path = option.output_path
    id_set_path = option.id_set_path
    id_set = get_id_set(id_set_path)

    pack_dependencies_result = {}

    logging.info("Selecting packs for dependencies calculation")
    packs = select_packs_for_calculation()

    calculate_all_packs_dependencies(pack_dependencies_result, id_set_path, packs)

    logging.info(f"Number of created pack dependencies entries: {len(pack_dependencies_result.keys())}")
    # finished iteration over pack folders
    logging.success("Finished dependencies calculation")

    with open(output_path, 'w') as pack_dependencies_file:
        json.dump(pack_dependencies_result, pack_dependencies_file, indent=4)

    logging.success(f"Created packs dependencies file at: {output_path}")


if __name__ == "__main__":
    main()
