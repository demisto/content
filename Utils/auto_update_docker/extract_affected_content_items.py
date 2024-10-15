import math
from packaging.version import Version
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any
import os
import typer
from neo4j import Transaction

from demisto_sdk.commands.common.handlers import DEFAULT_JSON_HANDLER as json
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import (
    Neo4jContentGraphInterface as ContentGraphInterface,
)
from demisto_sdk.commands.common.docker.docker_image import DockerImage

logging.basicConfig(level=logging.INFO)
app = typer.Typer(no_args_is_help=True)
CWD = os.getcwd()


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_content_item_to_add(
    only_nightly: bool,
    content_item_pack_path: str,
    nightly_packs: list[str],
    content_item_path: Path,
    benchmark_docker_tags: dict[str, str],
    docker_image: str,
    content_item_docker_image_tag: str,
    content_item_cov: int,
    support_levels: list[str],
    content_item_support: str,
    min_cov: int,
    max_cov: int,
) -> str | None:
    """Returns the content item if it complies with the batch configuration.

    Args:
        only_nightly (bool): If to run on nightly packs.
        content_item_pack_path (str): The content item's pack's path.
        nightly_packs (list[str]): List of nightly packs.
        content_item_path (Path): The content item's path
        benchmark_docker_tags (dict[str, str]): A dictionary where the keys are docker images, and values are the
        biggest tag of all the effected CVEs tags for a given image, and if an image has a tag equal or less than it,
        then it will be updated to the latest tag.
        docker_image (str): The docker image to check.
        content_item_docker_image_tag (str): The docker image tag of the content item.
        content_item_cov (int): The coverage of the content item.
        support_levels (list[str]): The support levels of the batch. If empty, this means all support levels
        should be considered.
        content_item_support (str): The support level of the content item.
        min_cov (int): Minimum coverage
        of the configuration.
        max_cov (int): Maximum coverage of the configuration.

    Returns:
        str | None: _description_
    """
    if only_nightly and content_item_pack_path not in nightly_packs:
        logging.info(f"Pack path {content_item_pack_path} for {content_item_path} is not in nightly, skipping.")
        return None

    if docker_image in benchmark_docker_tags:
        docker_image_tag_benchmark = benchmark_docker_tags[docker_image]
        if Version(content_item_docker_image_tag) > Version(docker_image_tag_benchmark):
            # If content item's docker tag is larger than the benchmark docker tag, then we
            # don't need to update the content item, skipping
            logging.info(f"{content_item_path} tag {content_item_docker_image_tag} > {docker_image_tag_benchmark = }, skipping.")
            return None

    # If content item is not in coverage report, then we consider it's coverage to be 0
    # content_item_cov = content_items_coverage.get(str(content_item_path), 0)
    logging.info(f"{content_item_path = } {content_item_cov = }")
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
        return str(content_item_path.with_suffix(".yml"))
        # affected_content_items.append(str(content_item_path.with_suffix(".yml")))
    else:
        logging.info(f"{content_item_path} not within coverage, skipping")
    return None


def filter_content_items_to_run_on(
    batch_config: dict[str, Any],
    content_items_coverage: dict[str, int],
    content_items_by_docker_image: list[dict[str, Any]],
    target_docker_tag: str,
    nightly_packs: list[str],
    docker_image: str,
    benchmark_docker_tags: dict[str, str],
) -> dict[str, Any]:
    """Collect the content items with respect to the batch config.

    Args:
        batch_config (dict[str, Any]): The batch config. (Default or custom)
        content_items_coverage (dict[str, int]): Coverage of content items.
        content_items_by_docker_image (list[dict[str, Any]]): A list of content items per docker image to check if they fit
        into the current batch.
        target_docker_tag (str): The target docker tag.
        nightly_packs (list[str]): The nightly packs.
        docker_image (str): The docker image to check.
        benchmark_docker_tags (dict[str, str]): A dictionary where the keys are docker images, and values are the
        biggest tag of all the effected CVEs tags for a given image, and if an image has a tag equal or less than it,
        then it will be updated to the latest tag.

    Returns:
        dict[str, Any]: A dictionary where the key is the docker image, and the values are
        the affected content items, pr tags, and target tag for a specific docker image.
    """
    affected_content_items: list[str] = []
    only_nightly: bool = batch_config.get("only_nightly", False)
    min_cov: int = batch_config["min"]
    max_cov: int = batch_config["max"]
    logging.info(f"{min_cov} - {max_cov} in filter_content_items_to_run_on")
    support_levels = batch_config.get("support", [])
    for content_item in content_items_by_docker_image:
        content_item_path = Path(content_item["content_item"])
        content_item_support = content_item["support_level"]
        content_item_pack_path = content_item["pack_path"]
        content_item_docker_image_tag = content_item["docker_image_tag"]

        content_item_to_add = get_content_item_to_add(
            only_nightly=only_nightly,
            content_item_pack_path=content_item_pack_path,
            nightly_packs=nightly_packs,
            content_item_path=content_item_path,
            benchmark_docker_tags=benchmark_docker_tags,
            docker_image=docker_image,
            content_item_docker_image_tag=content_item_docker_image_tag,
            # If content item is not in coverage report, then we consider it's coverage to be 0
            content_item_cov=content_items_coverage.get(str(content_item_path), 0),
            support_levels=support_levels,
            content_item_support=content_item_support,
            min_cov=min_cov,
            max_cov=max_cov,
        )
        if content_item_to_add:
            affected_content_items.append(content_item_to_add)
    return {
        "content_items": affected_content_items,
        "pr_labels": batch_config.get("pr_labels", []),
        "target_tag": target_docker_tag,
        "coverage": f"{min_cov}-{max_cov}",
    }


def get_docker_image_target_tag(docker_image: str, images_tag: dict[str, str]) -> str:
    """Return the docker image tag from the 'images_tag' file under {flow_dir / Path("images_tag.json")}, if not found,
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


def get_docker_batch_config(
    docker_image: str,
    custom_images: list[str],
    default_batches: list[dict[str, Any]],
    image_custom_configs: dict[str, Any],
    current_batch_index: int,
) -> dict[str, Any]:
    """Get the relevant docker batch, whether the default or custom batch.

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
    benchmark_docker_tags: dict[str, str],
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
        logging.info(f"Getting content items for {docker_image = }")
        affected_content_items: dict[str, Any] = {}
        docker_image_target_tag = get_docker_image_target_tag(docker_image=docker_image, images_tag=images_tag)
        docker_batch_config = get_docker_batch_config(
            docker_image=docker_image,
            custom_images=custom_images,
            default_batches=default_batches,
            image_custom_configs=image_custom_configs,
            current_batch_index=current_batch_index,
        )
        if docker_batch_config:
            affected_content_items = filter_content_items_to_run_on(
                batch_config=docker_batch_config,
                content_items_coverage=content_items_coverage,
                content_items_by_docker_image=content_items_by_docker_image[docker_image],
                target_docker_tag=docker_image_target_tag,
                nightly_packs=nightly_packs,
                docker_image=docker_image,
                benchmark_docker_tags=benchmark_docker_tags,
            )
        else:
            logging.info(f"No batch config was found for {docker_image = }, and {current_batch_index = }")

        if not affected_content_items["content_items"]:
            logging.info(f"{docker_image = } does not have any content items to update")
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
            iii) ALL@docker1,docker2,... - All docker images, excluding docker1,docker2,...\n
        images_to_exclude (list[str]): A list of images that will be excluded.
        all_docker_images (list[str]): All docker images returned from the graph.

    Returns:
        list[str]: A list of docker images that will be used in the current batch.
    """
    images_without_excluded_ones = set(all_docker_images) - set(images_to_exclude)
    if docker_images_arg == "ALL":
        return list(images_without_excluded_ones)
    # TODO Update to @ in Confluence and Jira ticket
    images_args = docker_images_arg.split("@")
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


def query_used_dockers_per_content_item(tx: Transaction) -> list[tuple[str, str, str, str, str]]:
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
            AND iss.auto_update_docker_image
            AND NOT iss.type = 'javascript'
            AND NOT pack.object_id = 'ApiModules'
            AND iss.docker_image IS NOT NULL
            AND NOT pack.hidden
            Return iss.docker_image, iss.path, iss.type, pack.path, pack.support
            """
        )
    )


def return_content_item_with_suffix(content_item_yml: str, content_item_type: str) -> Path:
    if content_item_type == "python":
        return Path(content_item_yml).with_suffix(".py")
    elif content_item_type == "powershell":
        return Path(content_item_yml).with_suffix(".ps1")
    else:
        raise Exception(f"Unknown {content_item_type=}")


def get_content_items_by_docker_image() -> dict[str, list[dict[str, Any]]]:
    """Return all content items of type 'integration' and 'script', with their respective
    docker images, support level, and pack path.

    Returns:
        dict[str, list[dict[str, Any]]]: The key will be the docker image, and the value will be a list
        containing data about the content items and respective pack and support level.
    """
    content_images: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with ContentGraphInterface() as graph, graph.driver.session() as session:
        content_items_info = session.execute_read(query_used_dockers_per_content_item)
        # content_item_type holds the type of the script that runs the integration or script, either ps1 or python
        for docker_image, content_item_yml, content_item_type, full_pack_path, support_level in content_items_info:
            content_item = return_content_item_with_suffix(content_item_yml=content_item_yml, content_item_type=content_item_type)
            pack_path = full_pack_path.split("/")[1]
            # Since the docker image returned will include the tag, we only need the image
            docker_image_split = docker_image.split(":")
            docker_image_without_tag = docker_image_split[0]
            docker_image_tag = docker_image_split[1]
            content_images[docker_image_without_tag].append(
                {
                    "content_item": content_item,
                    "support_level": support_level,
                    "pack_path": pack_path,
                    "docker_image_tag": docker_image_tag,
                }
            )
    return content_images


def docker_tags_parser(benchmark_docker_tags: str) -> dict[str, str]:
    if not benchmark_docker_tags:
        return {}

    # Remove spaces, if input has spaces between comma
    # docker_tags_no_spaces = benchmark_docker_tags.replace(" ", "")

    # Split the input string into key-value pairs
    pairs = benchmark_docker_tags.split(",")

    # Initialize an empty dictionary to store the key-value pairs
    result_dict = {}

    # Iterate over each key-value pair
    for pair in pairs:
        # Split the pair into key and value
        key, value = pair.split(":")
        # strip() to remove spaces
        result_dict[key.strip()] = value.strip()

    return result_dict


@app.command()
def get_affected_content_items(
    config_path: str = typer.Option(
        help="The config file that holds all the configuration of the batches and docker images",
    ),
    coverage_report: str = typer.Option(
        help="The coverage report from last nightly",
    ),
    batch_index: int = typer.Option(
        help="The batch index",
    ),
    flow_index: int = typer.Option(
        help="The flow index, where a flow is simply the process of going over all the batches in the config file",
    ),
    benchmark_docker_tags: dict[str, str] = typer.Option(
        default="",
        help=(
            "A comma separated key:value pair, where the keys are docker images, and values are the"
            " biggest tag of all the affected CVEs tags for a given image, and if an image has a tag equal or less than it,"
            " then it will be updated to the latest tag."
        ),
        parser=docker_tags_parser,
    ),
    docker_images_arg: str = typer.Option(
        default="ALL",
        help=(
            "The docker images that should be affected by the auto update, either a comma"
            " separated list, the string 'ALL', or 'ALL@docker1,docker2',"
            " where the last option will exclude the stated docker images"
        ),
    ),
    auto_update_dir: str = typer.Option(
        default="",
        help=("The directory that will hold the output files. The default will be the current working directory"),
    ),
):
    # IMPORTANT - "demisto-sdk graph create" must be ran before
    # Entry point of code
    path_dir = Path(auto_update_dir) if dir else Path(CWD)
    if not path_dir.exists():
        raise Exception(f"{path_dir = } was not found, aborting")

    tests_conf = load_json("Tests/conf.json")
    # Get nightly packs from tests conf
    nightly_packs: list[str] = tests_conf.get("nightly_packs", [])

    # Creates flow directory if it does not exist, else it does nothing
    flow_dir = path_dir / Path(f"flow_{flow_index}")
    flow_dir.mkdir(exist_ok=True)

    # Create current batch directory if it does not exist, else it does nothing
    batch_dir = flow_dir / Path(f"batch_{batch_index}")
    batch_dir.mkdir(exist_ok=True)

    # Get images tags of the flow, if they exist
    images_tags_path = flow_dir / Path("images_tag.json")
    images_tag: dict[str, str] = {}
    if images_tags_path.exists():
        images_tag = load_json(str(images_tags_path))

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
        nightly_packs=nightly_packs,
        benchmark_docker_tags=benchmark_docker_tags,
    )

    docker_images_target_tag = {
        docker_image: affected_items["target_tag"]
        for docker_image, affected_items in affected_content_items_by_docker_image.items()
    }

    # Output docker_images_target_tag | images_tag
    images_tags_path.touch(exist_ok=True)
    images_tags_path.write_text(json.dumps(docker_images_target_tag | images_tag))

    # Output the affected content items
    affected_content_items_path = batch_dir / Path("affected_content_items.json")
    affected_content_items_path.touch(exist_ok=True)
    # Only dump docker images that have content items to update
    docker_images_to_dump = {
        docker_image: affected_items
        for docker_image, affected_items in affected_content_items_by_docker_image.items()
        if affected_items["content_items"]
    }
    affected_content_items_path.write_text(json.dumps(docker_images_to_dump))


def main():
    app()


if __name__ == "__main__":
    main()
