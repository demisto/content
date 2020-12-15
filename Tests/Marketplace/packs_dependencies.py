import os
import json
import argparse
import logging
from pprint import pformat
from multiprocessing import cpu_count

from pebble import ProcessPool, ProcessFuture
from Tests.Marketplace.upload_packs import PACKS_FULL_PATH, IGNORED_FILES, PACKS_FOLDER
from Tests.Marketplace.marketplace_services import GCPConfig
from demisto_sdk.commands.find_dependencies.find_dependencies import VerboseFile, PackDependencies,\
    parse_for_pack_metadata
from typing import Tuple, Iterable
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


def calculate_single_pack_dependencies(pack: str, dependency_graph: object) -> Tuple[dict, list, str]:
    """
    Calculates pack dependencies given a pack and a dependencies graph.
    First is extract the dependencies subgraph of the given graph only using DFS algorithm with the pack as source.

    Then, for all the dependencies of that pack it Replaces the 'mandatory_for_packs' key with a boolean key 'mandatory'
    which indicates whether this dependency is mandatory for this pack or not.

    Then using that subgraph we get the first-level dependencies and all-levels dependencies.

    Args:
        pack: The pack for which we need to calculate the dependencies
        dependency_graph: The full dependencies graph

    Returns:
        first_level_dependencies: A dict of the form {'dependency_name': {'mandatory': < >, 'display_name': < >}}
        all_level_dependencies: A list with all dependencies names
        pack: The pack name
    """
    install_logging('Calculate_Packs_Dependencies.log', include_process_name=True)
    first_level_dependencies = {}
    all_level_dependencies = []
    try:
        logging.info(f"Calculating {pack} pack dependencies.")
        subgraph = PackDependencies.get_dependencies_subgraph_by_dfs(dependency_graph, pack)
        for dependency_pack, additional_data in subgraph.nodes(data=True):
            logging.debug(f'Iterating dependency {dependency_pack} for pack {pack}')
            additional_data['mandatory'] = pack in additional_data['mandatory_for_packs']
            del additional_data['mandatory_for_packs']
            first_level_dependencies, all_level_dependencies = parse_for_pack_metadata(subgraph, pack)
    except Exception:
        logging.exception(f"Failed calculating {pack} pack dependencies")
    return first_level_dependencies, all_level_dependencies, pack


def get_all_packs_dependency_graph(id_set: dict, packs: list) -> Iterable:
    """
    Gets a graph with dependencies for all packs
    Args:
        id_set: The content of id_set file
        packs: The packs that should be part of the dependencies calculation

    Returns:
        A graph with all packs dependencies
    """
    logging.info("Calculating pack dependencies.")
    try:
        dependency_graph = PackDependencies.build_all_dependencies_graph(packs,
                                                                         id_set=id_set,
                                                                         verbose_file=VerboseFile(''))
        return dependency_graph
    except Exception:
        logging.exception("Failed calculating dependencies graph")
        exit(2)


def select_packs_for_calculation() -> list:
    """
    Select the packs on which the dependencies will be calculated on
    Returns:
        A list of packs
    """
    IGNORED_FILES.append(GCPConfig.BASE_PACK)  # skip dependency calculation of Base pack
    packs = []
    for pack in os.scandir(PACKS_FULL_PATH):
        if not pack.is_dir() or pack.name in IGNORED_FILES:
            logging.warning(f"Skipping dependency calculation of {pack.name} pack.")
            continue  # skipping ignored packs
        packs.append(pack.name)
    return packs


def get_id_set(id_set_path: str) -> dict:
    """
    Parses the content of id_set_path and returns its content.
    Args:
        id_set_path: The path of the id_set file

    Returns:
        The parsed content of id_set
    """
    with open(id_set_path, 'r') as id_set_file:
        id_set = json.load(id_set_file)
    return id_set


def calculate_all_packs_dependencies(pack_dependencies_result: dict, id_set: dict, packs: list) -> None:
    """
    Calculates the pack dependencies and adds them to 'pack_dependencies_result' in parallel.
    First - the method generates the full dependency graph.

    Them - using a process pool we extract the dependencies of each pack and adds them to the 'pack_dependencies_result'
    Args:
        pack_dependencies_result: The dict to which the results should be added
        id_set: The id_set content
        packs: The packs that should be part of the dependencies calculation
    """
    def add_pack_metadata_results(future: ProcessFuture) -> None:
        """
        This is a callback that should be called once the result of the future is ready.
        The results include: first_level_dependencies, all_level_dependencies, pack_name
        Using these results we write the dependencies
        """
        try:
            first_level_dependencies, all_level_dependencies, pack_name = future.result()  # blocks until results ready
            logging.debug(f'Got dependencies for pack {pack_name}\n: {pformat(all_level_dependencies)}')
            pack_dependencies_result[pack_name] = {
                "dependencies": first_level_dependencies,
                "displayedImages": list(first_level_dependencies.keys()),
                "allLevelDependencies": all_level_dependencies,
                "path": os.path.join(PACKS_FOLDER, pack_name),
                "fullPath": os.path.abspath(os.path.join(PACKS_FOLDER, pack_name))
            }
        except Exception:
            logging.exception('Failed to collect pack dependencies results')

    # Generating one graph with dependencies for all packs
    dependency_graph = get_all_packs_dependency_graph(id_set, packs)

    with ProcessPool(max_workers=cpu_count(), max_tasks=100) as pool:
        for pack in dependency_graph:
            future_object = pool.schedule(calculate_single_pack_dependencies, args=(pack, dependency_graph), timeout=10)
            future_object.add_done_callback(add_pack_metadata_results)


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

    calculate_all_packs_dependencies(pack_dependencies_result, id_set, packs)

    logging.info(f"Number of created pack dependencies entries: {len(pack_dependencies_result.keys())}")
    # finished iteration over pack folders
    logging.success("Finished dependencies calculation")

    with open(output_path, 'w') as pack_dependencies_file:
        json.dump(pack_dependencies_result, pack_dependencies_file, indent=4)

    logging.success(f"Created packs dependencies file at: {output_path}")


if __name__ == "__main__":
    main()
