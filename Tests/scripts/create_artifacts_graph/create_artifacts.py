from argparse import ArgumentParser
from pathlib import Path
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import Neo4jContentGraphInterface
from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.content_graph.objects.repository import ContentDTO
from demisto_sdk.commands.content_graph.objects.pack import Pack
from Tests.scripts.utils.log_util import install_logging
import logging as logger
from demisto_sdk.commands.common.logger import logging_setup
from demisto_sdk.commands.common.tools import get_content_path, str2bool

import json

logging_setup(3)
install_logging("create_artifacts.log", logger=logger)


def create_zips(content_dto: ContentDTO, output: Path, marketplace: str, zip: bool):
    content_dto.dump(output, marketplace, zip)


def create_dependencies(content_dto: ContentDTO, is_bucket_upload: bool, output: Path):
    pack_dependencies = {}
    for pack in content_dto.packs:
        dependencies = pack.depends_on
        first_level_dependencies = {}
        all_level_dependencies = {}
        for dependency in dependencies:
            dependency_content_item_to: Pack = dependency.content_item_to
            if (is_bucket_upload and dependency.is_test) or dependency_content_item_to.hidden:
                continue
            if dependency.mandatorily:
                all_level_dependencies[dependency.content_item_to.object_id] = {
                    "display_name": dependency.content_item_to.name,
                    "mandatory": True,
                    "author": dependency.content_item_to.author,
                }
            if dependency.is_direct:
                first_level_dependencies[dependency.content_item_to.object_id] = {
                    "display_name": dependency.content_item_to.name,
                    "mandatory": dependency.mandatorily,
                    "is_test": dependency.is_test,
                }
        pack_dependencies[pack.object_id] = {
            "path": str(pack.path.relative_to(get_content_path())),
            "fullPath": str(pack.path),
            "dependencies": first_level_dependencies,
            "displayedImages": list(first_level_dependencies.keys()),
            "allLevelDependencies": all_level_dependencies,
        }
    with open(output, "w") as f:
        json.dump(pack_dependencies, f, indent=4)


def create_packs_json(content_dto: ContentDTO, packs_output: Path):
    """Create packs.json file, to be used by contribution management project

    Args:
        content_dto (ContentDTO): Content Repository DTO
        packs_output (Path): Output path for packs.json
    """
    packs = content_dto.packs
    packs_json = {pack.object_id: json.loads(
        pack.json(include={"name", "description", "author", "current_version"}, by_alias=True)) for pack in packs}
    with open(packs_output, "w") as f:
        json.dump(packs_json, f, indent=4)


def main():
    parser = ArgumentParser()
    parser.add_argument("-mp", "--marketplace", type=MarketplaceVersions, help="marketplace version", default="xsoar")
    parser.add_argument("-ao", "--artifacts-output", help="Artifacts output directory", required=True)
    parser.add_argument("-do", "--dependencies-output", help="Dependencies output file", required=True)
    parser.add_argument("-po", "--packs-output", help="Packs json output file", required=True)
    parser.add_argument(
        "-bu", "--bucket-upload", help="Upload to bucket", type=lambda x: str2bool(x or False), default=False
    )
    parser.add_argument("--zip", default=True, action="store_true")
    parser.add_argument("--no-zip", dest="zip", action="store_false")
    args = parser.parse_args()

    with Neo4jContentGraphInterface() as interface:
        content_dto: ContentDTO = interface.marshal_graph(args.marketplace, all_level_dependencies=True)

        logger.info("Creating pack dependencies mapping")
        create_dependencies(content_dto, args.bucket_upload, Path(args.dependencies_output))

        logger.info("Creating packs.json")
        create_packs_json(content_dto, Path(args.packs_output))

        logger.info("Creating content artifacts zips")
        create_zips(content_dto, Path(args.artifacts_output), args.marketplace, args.zip)


if __name__ == "__main__":
    main()
