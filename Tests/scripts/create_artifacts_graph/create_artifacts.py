from argparse import ArgumentParser
from pathlib import Path
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import Neo4jContentGraphInterface
from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.content_graph.objects.repository import ContentDTO
from Tests.scripts.utils.log_util import install_logging
import logging as logger
from demisto_sdk.commands.common.logger import logging_setup


import json

logging_setup(3)
install_logging("create_artifacts.log", logger=logger)


def main():
    parser = ArgumentParser()
    parser.add_argument("-mp", "--marketplace", type=MarketplaceVersions, help="marketplace version", default="xsoar")
    parser.add_argument("-ao", "--artifacts-output", help="Artifacts output directory", required=True)
    parser.add_argument("-do", "--dependencies-output", help="Dependencies output directory", required=True)
    parser.add_argument("--zip", default=True, action="store_true")
    parser.add_argument("--no-zip", dest="zip", action="store_false")
    args = parser.parse_args()

    with Neo4jContentGraphInterface() as interface:
        content_dto: ContentDTO = interface.marshal_graph(args.marketplace, all_level_dependencies=True)
        content_dto.dump(Path(args.artifacts_output), args.marketplace, args.zip)
        pack_dependencies = {}
        for pack in content_dto.packs:
            displayed_images = []
            dependencies = pack.depends_on
            first_level_dependencies = {}
            all_level_dependencies = []
            for dependency in dependencies:
                all_level_dependencies.append(dependency.content_item.object_id)
                if dependency.is_direct:
                    first_level_dependencies[dependency.content_item.object_id] = {
                        "display_name": dependency.content_item.name,
                        "mandatory": dependency.is_direct,
                    }

                    displayed_images.extend((integration.object_id for integration in pack.content_items.integration))
            pack_dependencies[pack.object_id] = {
                "path": str(pack.path.relative_to(Path.cwd())),
                "fullPath": str(pack.path),
                "dependencies": first_level_dependencies,
                "displayedImages": displayed_images,
                "allLevelDependencies": all_level_dependencies,
            }
        with open(args.dependencies_output, "w") as f:
            json.dump(pack_dependencies, f)


if __name__ == "__main__":
    main()
