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


def calculate_affected_content_items(
    batch_config: dict[str, Any],
    content_items_coverage: dict[str, int],
    content_items_by_docker_image: list[dict[str, Any]],
    target_docker_tag: str,
    nightly_packs: list[str],
) -> dict[str, Any]:
    """Calculate the affected content items with respect to the batch config.

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
    # If the key is not found, then support_levels will equal {""}
    support_levels = set(batch_config.get("support", "").split(","))
    for content_item in content_items_by_docker_image:
        content_item_path = Path(content_item["content_item"])
        content_item_support = content_item["support_level"]
        content_pack_path = content_item["pack_path"]
        
        if only_nightly and content_pack_path not in nightly_packs:
            logging.info(f"Pack path {content_pack_path} for {content_item} is not in nightly, skipping.")
            continue
        if content_item_cov := content_items_coverage.get(str(content_item_path)):
            if support_levels != {""} and content_item_support not in support_levels:
                # If support levels is not empty, and the content item's support level is not in the allowed support levels,
                # then we skip it.
                logging.info(f"Is not of {support_levels=}, skipping")
            elif content_item_cov >= min_cov and content_item_cov <= max_cov:
                # Since the content item that we get will be a python file, and we want to
                # return a YML
                affected_content_items.append(str(content_item_path.with_suffix('.yml')))
            else:
                logging.info(f"{content_item} not within coverage, skipping")
        else:
            logging.warning(f"Could not find coverage of content item {content_item_path}, skipping")

    return {
        "content_items": affected_content_items,
        "pr_tags": batch_config.get("pr_tags", []),
        "target_tag": target_docker_tag,
    }

def get_docker_image_tag(docker_image: str, images_tag: dict[str, str]) -> str:
    """Return the docker image tag from the 'images_tag' file supplied to the program, if not found,
    will query DockerHub to retrieve the latest tag for the docker image.

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

def get_affected_content_items_by_docker_image(
    default_batch_config: dict[str, Any],
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
        default_batch_config (dict[str, Any]): The default batch config.
        current_batch_index (int): Batch index.
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
        affected_content_items_by_docker_image[docker_image] = {}
        affected_content_items: dict[str, Any] = {}
        docker_image_tag = get_docker_image_tag(docker_image=docker_image,
                                                images_tag=images_tag)
        if docker_image in custom_images:
            image_custom_batches: list[dict[str, Any]] = image_custom_configs[
                docker_image
            ]["batches"]
            if current_batch_index < len(image_custom_batches):
                custom_batch_config: dict[str, Any] = image_custom_batches[
                    current_batch_index
                ]
                affected_content_items = calculate_affected_content_items(
                    batch_config=custom_batch_config,
                    content_items_coverage=content_items_coverage,
                    content_items_by_docker_image=content_items_by_docker_image[docker_image],
                    target_docker_tag=docker_image_tag,
                    nightly_packs=nightly_packs,
                )
            else:
                logging.info(f"{current_batch_index=} is larger than the batches number of custom image {docker_image}")

        elif default_batch_config:
            affected_content_items = calculate_affected_content_items(
                batch_config=default_batch_config,
                content_items_coverage=content_items_coverage,
                content_items_by_docker_image=content_items_by_docker_image[docker_image],
                target_docker_tag=docker_image_tag,
                nightly_packs=nightly_packs,
            )
        else:
            # Should we throw an error?
            logging.error("No default or custom configs were given")
        affected_content_items_by_docker_image[docker_image] = affected_content_items
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
    config_path: str = typer.Argument(
        default="Utils/auto_update_docker/auto_update_docker_config.json",
        help="The config file that holds all the configuration of the batches and docker images",
    ),
    docker_images_arg: str = typer.Argument(
        default="ALL",
        help=("The docker images that should be affected by the auto update, either a comma"
        " separated list, the string 'ALL', or 'ALL/docker1,docker2',"
        " where the last option will exclude the stated docker images"),
    ),
    batch_index: int = typer.Argument(
        default="0",
        help="The batch index",
    ),
    coverage_report: str = typer.Argument(
        default="Utils/auto_update_docker/coverage_report.json",
        help="The coverage report from last nightly",
    ),
    docker_images_latest_tag_path: str = typer.Argument(
        default="",
        help=("The file that contains the docker images tag, if given an empty string,"
              " will retrieve them latest tags from DockerHub"),
    ),
):
    # IMPORTANT - "demisto-sdk create-content-graph" must be ran before
    # Entry point of code
    # TODO Will need to delete later, and add default value for the argument docker_images_latest_tag_path
    docker_images_latest_tag_path = f"{CWD}/Utils/auto_update_docker/images_tag.json"

    tests_conf = load_json('Tests/conf.json')
    # Get nightly packs from tests condf
    nightly_packs: list[str] = tests_conf.get('nightly_packs', [])

    
    images_tag: dict[str, str] = {}
    if docker_images_latest_tag_path:
        images_tag = load_json(docker_images_latest_tag_path)

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
    default_batches = image_configs["default"]["batches"]
    affected_content_items_by_docker_image = get_affected_content_items_by_docker_image(
        default_batch_config=default_batches[batch_index]
        if batch_index < len(default_batches)
        else {},
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
    # Output the docker images tags that were gathered in the batch
    with open(f"{CWD}/Utils/auto_update_docker/images_tag_output.json", "w") as images_tag_output:
        json.dump(docker_images_target_tag, images_tag_output)

    # Output the affected content items
    with open(f"{CWD}/content/Utils/auto_update_docker/affected_content_items.json", "w") as affected_content_items:
        json.dump(affected_content_items_by_docker_image, affected_content_items)

def main():
    app()


if __name__ == "__main__":
    main()
