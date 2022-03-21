import argparse
import json
import os
import sys
from concurrent.futures import as_completed
from contextlib import contextmanager
from pprint import pformat
from typing import Tuple, Iterable, List, Callable

from Tests.Marketplace.marketplace_constants import GCPConfig, PACKS_FOLDER, PACKS_FULL_PATH, IGNORED_FILES
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from demisto_sdk.commands.find_dependencies.find_dependencies import PackDependencies, \
    calculate_single_pack_dependencies
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


@contextmanager
def ProcessPoolHandler() -> ProcessPool:
    """ Process pool Handler which terminate all processes in case of Exception.

    Yields:
        ProcessPool: Pebble process pool.
    """
    with ProcessPool(max_workers=3) as pool:
        try:
            yield pool
        except Exception:
            logging.exception("Gracefully release all resources due to Error...")
            raise
        finally:
            pool.close()
            pool.join()


def wait_futures_complete(futures: List[ProcessFuture], done_fn: Callable):
    """Wait for all futures to complete, Raise exception if occurred.

    Args:
        futures: futures to wait for.
        done_fn: Function to run on result.
    Raises:
        Exception: Raise caught exception for further cleanups.
    """
    for future in as_completed(futures):
        try:
            result = future.result()
            done_fn(result)
        except Exception as e:
            logging.exception(e)
            raise


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
        dependency_graph = PackDependencies.build_all_dependencies_graph(packs, id_set=id_set, verbose=False)
        return dependency_graph
    except Exception:
        logging.exception("Failed calculating dependencies graph")
        sys.exit(2)


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

    def add_pack_metadata_results(results: Tuple) -> None:
        """
        This is a callback that should be called once the result of the future is ready.
        The results include: first_level_dependencies, all_level_dependencies, pack_name
        Using these results we write the dependencies
        """
        try:
            first_level_dependencies, all_level_dependencies, pack_name = results
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
            raise

    # Generating one graph with dependencies for all packs
    dependency_graph = get_all_packs_dependency_graph(id_set, packs)

    with ProcessPoolHandler() as pool:
        futures = []
        for pack in dependency_graph:
            futures.append(pool.schedule(calculate_single_pack_dependencies, args=(pack, dependency_graph), timeout=10))
        wait_futures_complete(futures=futures, done_fn=add_pack_metadata_results)


def main():
    """ Main function for iterating over existing packs folder in content repo and creating json of all
    packs dependencies. The logic of pack dependency is identical to sdk find-dependencies command.

    """
    install_logging('Calculate_Packs_Dependencies.log', include_process_name=True, logger=logging)
    option = option_handler()
    output_path = option.output_path
    id_set_path = option.id_set_path
    id_set = get_id_set(id_set_path)

    pack_dependencies_result: dict = {}

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
