from argparse import ArgumentParser
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import Neo4jContentGraphInterface
from demisto_sdk.commands.common.constants import MarketplaceVersions

def main():
    parser = ArgumentParser()
    parser.add_argument('-mp', '--marketplace', type=MarketplaceVersions, help='marketplace version',
                        default='xsoar')
    parser.add_argument("-ao", "--artifacts-output", help="Artifacts output directory", required=True)
    parser.add_argument("-do", "--dependencies-output", help="Dependencies output directory", required=True)
    parser.add_argument('--zip', default=True, action='store_true')
    parser.add_argument('--no-zip', dest='zip', action='store_false')
    args = parser.parse_args()

    with Neo4jContentGraphInterface() as interface:
        content_dto = interface.marshal_graph(args.marketplace, all_level_dependencies=True)
        content_dto.dump(args.artifacts_output, args.marketplace, args.zip)
        
        