import math
import time
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any
import os
import typer
from dotenv import load_dotenv
from neo4j import Transaction

from demisto_sdk.commands.common.handlers import DEFAULT_JSON_HANDLER as json
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import (
    Neo4jContentGraphInterface as ContentGraphInterface,
)
from demisto_sdk.commands.common.docker.docker_image import (DockerImage)

logging.basicConfig(level=logging.INFO)
load_dotenv()
app = typer.Typer(no_args_is_help=True)
CWD = os.getcwd()

def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def filter_content_items_to_run_on(
    batch_config: dict[str, Any],
    content_items_coverage: dict[str, int],
    content_items_by_docker_image: list[dict[str, Any]],
    target_docker_tag: str,
    nightly_packs: list[str],
) -> dict[str, Any]:
    """Collect the content items with respect to the batch config.

    Args:
        batch_config (dict[str, Any]): The batch config. (Default or custom)
        content_items_coverage (dict[str, int]): Coverage of content items.
        content_items_by_docker_image (list[dict[str, Any]]): A list of content items per docker image to check if they fit
        into the current batch.
        target_docker_tag (str): The target docker tag.
        nightly_packs (list[str]): The nightly packs.

    Returns:
        dict[str, Any]: A dictionary where the key is the docker image, and the values are
        the affected content items, pr tags, and target tag for a specific docker image.
    """
    affected_content_items: list[str] = []
    only_nightly: bool = batch_config.get("only_nightly", False)
    min_cov: int = batch_config["min"]
    max_cov: int = batch_config["max"]

    support_levels = batch_config.get("support", [])
    for content_item in content_items_by_docker_image:
        content_item_path = Path(content_item["content_item"])
        content_item_support = content_item["support_level"]
        content_pack_path = content_item["pack_path"]
        
        if only_nightly and content_pack_path not in nightly_packs:
            logging.info(f"Pack path {content_pack_path} for {content_item} is not in nightly, skipping.")
            continue
        if content_item_cov := content_items_coverage.get(str(content_item_path)):
            content_item_cov_floor = math.floor(content_item_cov)
            if support_levels and content_item_support not in support_levels:
                # If support levels is not empty, and the content item's support level is not in the allowed support levels,
                # then we skip it.
                logging.info(f"Is not of {support_levels=}, skipping")
            elif content_item_cov_floor >= min_cov and (content_item_cov <= max_cov and content_item_cov_floor <= max_cov):
                # NOTE We added the second clause to deal with the following scenario:
                # If max_cov=70, and content_item_cov=70.12, then content_item_cov_floor will be equal to 70,
                # if not handled correctly, we will collect the content item, which is wrong, therefore,
                # we added the condition content_item_cov <= max_cov

                # We check the coverage of the content item
                # Since the content item that we get will be a python file, and we want to
                # return a YML
                affected_content_items.append(str(content_item_path.with_suffix('.yml')))
            else:
                logging.info(f"{content_item} not within coverage, skipping")
        else:
            logging.warning(f"Could not find coverage of content item {content_item_path}, skipping")

    return {
        "content_items": affected_content_items,
        "pr_labels": batch_config.get("pr_labels", []),
        "target_tag": target_docker_tag,
        "coverage": f"{min}-{max}"
    } if affected_content_items else {}

def get_docker_image_tag(docker_image: str, images_tag: dict[str, str]) -> str:
    """Return the docker image tag from the 'images_tag' file supplied to the program, if not found,
    will query DockerHub to retrieve the latest tag of the docker image.

    Args:
        docker_image (str): The docker image to query on.
        images_tag (dict[str, str]): A dictionary of docker images and their tags supplied to the program.

    Returns:
        str: The tag of the docker image, either from 'images_tag' or DockerHub.
    """
    if docker_image in images_tag:
        image_tag = images_tag[docker_image]
        logging.info(f"{docker_image} was found in images tag file with tag {image_tag}")
        return image_tag
    latest_tag = DockerImage(docker_image).latest_tag
    return latest_tag.base_version

def get_docker_batch_config(docker_image: str, custom_images: list[str], default_batches: list[dict[str, Any]],
                      image_custom_configs: dict[str, Any], current_batch_index: int) -> dict[str, Any]:
    """_summary_

    Args:
        docker_image (str): The docker image to retrieve its relevant batch config.
        custom_images (list[str]): Dockers that have custom configs.
        default_batches (list[dict[str, Any]]): The default batches' configs.
        image_custom_configs (dict[str, Any]): Custom batches' configs for specific dockers.
        current_batch_index (int): The default batches' configs.

    Returns:
        dict[str, Any]: The relevant batch config for the docker image
    """
    batches_configs_to_use = default_batches  # Holds the default list of the batches' configurations
    if docker_image in custom_images:
        # Get custom configs for docker image
        batches_configs_to_use: list[dict[str, Any]] = image_custom_configs[docker_image]["batches"]

    return batches_configs_to_use[current_batch_index] if current_batch_index < len(batches_configs_to_use) else {}
    

def get_affected_content_items_by_docker_image(
    default_batches: list[dict[str, Any]],
    current_batch_index: int,  # Since custom configs for images might be configured
    image_custom_configs: dict[str, Any],
    content_items_coverage: dict[str, int],
    affected_docker_images: list[str],
    content_items_by_docker_image: dict[str, list[dict[str, Any]]],
    images_tag: dict[str, str],
    nightly_packs: list[str],
) -> dict[str, dict[str, Any]]:
    """Returns the affected content items with respect to the configurations of the current
    batch.

    Args:
        default_batches (list[dict[str, Any]]): The default batches' configs.
        current_batch_index (int): Batch index.
        image_custom_configs (dict[str, Any]): Custom batches' configs for specific dockers.
        content_items_coverage (dict[str, int]): Coverage of content items.
        affected_docker_images (list[str]): Affected docker images.
        content_items_by_docker_image (dict[str, list[dict[str, Any]]]): A dictionary that holds docker images as keys,
        and the value will be a list containing data about the content items and respective pack.
        images_tag (dict[str, str]): A dictionary of docker images and their tags supplied to the program.
        nightly_packs (list[str]): The nightly packs.

    Returns:
        dict[str, dict[str, Any]]: A dictionary where the keys are docker images, and their values are data containing
        the affected content items, pr tags, and target tag of each docker image.
    """
    affected_content_items_by_docker_image: dict[str, Any] = {}
    custom_images: list[str] = list(image_custom_configs.keys())
    for docker_image in affected_docker_images:
        affected_content_items: dict[str, Any] = {}
        docker_image_tag = get_docker_image_tag(docker_image=docker_image,
                                                images_tag=images_tag)
        docker_batch_config = get_docker_batch_config(
            docker_image=docker_image,
            custom_images=custom_images,
            default_batches=default_batches,
            image_custom_configs=image_custom_configs,
            current_batch_index=current_batch_index)
        if docker_batch_config:
            affected_content_items = filter_content_items_to_run_on(
                batch_config=docker_batch_config,
                content_items_coverage=content_items_coverage,
                content_items_by_docker_image=content_items_by_docker_image[docker_image],
                target_docker_tag=docker_image_tag,
                nightly_packs=nightly_packs,
                )
        else:
            logging.info(f"No batch config was found for {docker_image = }, and {current_batch_index = }")
        if affected_content_items:
            affected_content_items_by_docker_image[docker_image] = affected_content_items
        else:
            logging.info(f"{docker_image = } does not have any content items to update")
    return affected_content_items_by_docker_image


def calculate_affected_docker_images(
    docker_images_arg: str,
    images_to_exclude: list[str],
    all_docker_images: list[str],
) -> list[str]:
    """Calculates the docker images that will be used in the current batch.
    Docker images in the 'images_to_exclude' list will ALWAYS be excluded.
    Args:
        docker_images_arg (str): Docker images arg supplied by the user. This will either be:
            i) ALL - Use all docker images\n
            ii) docker1,docker2,... - A list of docker images to use.\n
            iii) ALL/docker1,docker2,... - All docker images, excluding docker1,docker2,...\n
        images_to_exclude (list[str]): A list of images that will be excluded.
        all_docker_images (list[str]): All docker images returned from the graph.

    Returns:
        list[str]: A list of docker images that will be used in the current batch.
    """
    images_without_excluded_ones = set(all_docker_images) - set(images_to_exclude)
    if docker_images_arg == "ALL":
        return list(images_without_excluded_ones)
    images_args = docker_images_arg.split("/")
    if len(images_args) == 1:
        # Comma separated list case
        specific_images = images_args[0].split(",")
        return list(images_without_excluded_ones.intersection(set(specific_images)))
    elif len(images_args) == 2:
        # All/docker1,docker2 case
        specific_images_to_exclude = images_args[1].split(",")
        return list(images_without_excluded_ones - set(specific_images_to_exclude))
    else:
        logging.error("Wrong docker images args")
        return []


def query_used_dockers_per_content_item(tx: Transaction) -> list[tuple[str, str, bool, str, str]]:
    """
    Queries the content graph for the following data:
    1. Docker image.
    2. Path of the content items.
    3. If content item is configured for auto updating its docker image.
    4. Pack path.
    5. Pack support
    """
    return list(
        tx.run(
            """
            MATCH (pack:Pack) <-[:IN_PACK] - (iss)
            WHERE iss.content_type IN ["Integration", "Script"]
            AND NOT iss.deprecated
            AND NOT iss.type = 'javascript'
            AND NOT pack.support = 'community'
            AND NOT pack.object_id = 'ApiModules'
            AND iss.docker_image IS NOT NULL
            AND NOT pack.hidden
            Return iss.docker_image, iss.path, iss.auto_update_docker_image, pack.path, pack.support
            """
        )
    )


def get_content_items_by_docker_image() -> dict[str, list[dict[str, Any]]]:
    """Return all content items of type 'integration' and 'script', with their respective
    docker images.

    Returns:
        dict[str, list[dict[str, Any]]]: The key will be the docker image, and the value will be a list
        containing data about the content items and respective pack.
    """
    content_images: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with ContentGraphInterface() as graph, graph.driver.session() as session:
        content_items_info = session.execute_read(query_used_dockers_per_content_item)
        for docker_image, content_item, auto_update_docker_image, full_pack_path, support_level in content_items_info:
            if auto_update_docker_image:
                content_item_py = Path(content_item).with_suffix('.py')
                if content_item_py.is_file():
                    # Since the full_pack_path is in the format "Packs/{pack path}"
                    pack_path = full_pack_path.split("/")[1]

                    # Since the docker image returned will include the tag, we only need the image
                    docker_image_without_tag = docker_image.split(":")[0]

                    content_images[docker_image_without_tag].append({"content_item": content_item_py,
                                                                    "support_level": support_level,
                                                                    "pack_path": pack_path})
                else:
                    logging.warning(f"{content_item_py} was returned from the graph, but not found in repo")
            else:
                logging.warning(f"{auto_update_docker_image=} configured for {content_item}, skipping")
    return content_images

@app.command()
def get_affected_content_items(
    config_path: str = typer.Option(
        # default="Utils/auto_update_docker/auto_update_docker_config.json",
        help="The config file that holds all the configuration of the batches and docker images",
    ),
    coverage_report: str = typer.Option(
        # default="Utils/auto_update_docker/coverage_report.json",
        help="The coverage report from last nightly",
    ),
    docker_images_arg: str = typer.Option(
        default="ALL",
        help=("The docker images that should be affected by the auto update, either a comma"
        " separated list, the string 'ALL', or 'ALL/docker1,docker2',"
        " where the last option will exclude the stated docker images"),
    ),
    batch_index: int = typer.Option(
        default="0",
        help="The batch index",
    ),
    flow_index: int = typer.Option(
        default="0",
        help="The flow index",
    ),
    docker_images_target_tags_path: str = typer.Option(
        default="",
        help=("The file that contains the docker images tag, if given an empty string,"
              " will retrieve them latest tags from DockerHub"),
    ),
    auto_update_dir: str = typer.Option(
        default="",
        help=("The directory that will hold the output files. The default will be the current working directory"),
    ),
):
    # IMPORTANT - "demisto-sdk create-content-graph" must be ran before
    # Entry point of code
    # TODO Will need to delete later, and add default value for the argument docker_images_target_tags_path
    # docker_images_target_tags_path = f"{CWD}/Utils/auto_update_docker/images_tag.json"

    # TODO Will need to delete later
    # dir = f"{CWD}/Utils/auto_update_docker"

    path_dir = Path(auto_update_dir) if dir else Path(CWD)
    if not path_dir.exists():
        raise Exception(f"{path_dir = } was not found, aborting")

    tests_conf = load_json('Tests/conf.json')
    # Get nightly packs from tests conf
    nightly_packs: list[str] = tests_conf.get('nightly_packs', [])


    images_tag: dict[str, str] = {}
    if docker_images_target_tags_path:
        images_tag = load_json(docker_images_target_tags_path)

    coverage_report_dict: dict[str, Any] = load_json(coverage_report)
    # The content items and their coverage are found under the key "files"
    content_items_coverage: dict[str, int] = coverage_report_dict["files"]

    config_dict: dict[str, Any] = load_json(config_path)
    image_configs: dict[str, Any] = config_dict["image_configs"]
    images_to_exclude: list[str] = image_configs["images_to_exclude"]
    image_custom_configs: dict[str, Any] = image_configs["custom_configs"]

    content_items_by_docker_image: dict[str, list[dict[str, Any]]] = get_content_items_by_docker_image()

    affected_docker_images = calculate_affected_docker_images(
        docker_images_arg=docker_images_arg,
        images_to_exclude=images_to_exclude,
        all_docker_images=list(content_items_by_docker_image.keys()),
    )
    default_batches: list[dict[str, Any]] = image_configs["default"]["batches"]
    affected_content_items_by_docker_image = get_affected_content_items_by_docker_image(
        default_batches=default_batches,
        current_batch_index=batch_index,
        image_custom_configs=image_custom_configs,
        content_items_coverage=content_items_coverage,
        affected_docker_images=affected_docker_images,
        content_items_by_docker_image=content_items_by_docker_image,
        images_tag=images_tag,
        nightly_packs=nightly_packs
    )

    docker_images_target_tag = {docker_image: affected_items["target_tag"] for docker_image, affected_items in
                                affected_content_items_by_docker_image.items()}
    
    current_time_str = time.strftime("%Y-%m-%d-%H:%M:%S")

    # Creates flow directory if it does not exist, else it does nothing
    flow_dir = auto_update_dir / Path(f"flow_{flow_index}")
    flow_dir.mkdir(exist_ok=True)

    # Create current batch directory if it does not exist, else it does nothing
    batch_dir = flow_dir / Path(f"batch_{batch_index}")
    batch_dir.mkdir(exist_ok=True)

    # Output the docker images tags that were gathered in the batch
    with open(f"{batch_dir}/images_tag.json", "w") as images_tag_output:
        json.dump(docker_images_target_tag, images_tag_output)

    # Output the affected content items
    with open(f"{batch_dir}/affected_content_items.json", "w") as affected_content_items:
        json.dump(affected_content_items_by_docker_image, affected_content_items)

def main():
    app()


if __name__ == "__main__":
    main()
