import argparse
import json
import os
import requests
import docker
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from demisto_sdk.commands.common.tools import str2bool


def get_docker_image_with_tag(pack_name) -> str:
    """ Given a pack name returns its docker image with its latest tag"""
    pass


def get_pack_name(user_input) -> str:
    """ Given the user input try and parse it into a pack name as appears in content repo"""
    pass


def download_and_save_packs(pack_names: list, output_path: str, insecure: bool) -> None:
    logging.info("Starting to download packs with dependencies")
    for pack_name in pack_names:
        logging.info(f"Download {pack_name} Pack with mandatory dependencies")
        r = requests.request(method='GET', url='https://marketplace-dist.storage.googleapis.com/content/packs/'
                                               f'{pack_name}/{pack_name}_with_dependencies.zip', verify=not insecure)
        with open(os.path.join(output_path, pack_name + '.zip'), 'wb') as f:
            f.write(r.content)


def download_and_save_docker_images(pack_names: list, output_path: str) -> None:
    logging.info("Starting to download docker images for given packs")
    cli = docker.from_env()
    for pack_name in pack_names:
        logging.info(f"Fetching docker image: for {pack_name}")
        docker_image = get_docker_image_with_tag(pack_name)
        logging.info(f"Download docker image: {docker_image}")
        image = cli.images.get(docker_image)
        with open(os.path.join(output_path, pack_name + '.tar'), 'wb') as f:
            for chunk in image.save():
                f.write(chunk)
    logging.info("Finished docker images download")


def options_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Downloads XSOAR packs as zip and their latest docker images as tar.")
    # disable-secrets-detection-start
    parser.add_argument('-p', '--packs',
                        help="Comma separated list of pack names as they appear in https://xsoar.pan.dev/marketplace",
                        required=True)
    parser.add_argument('-dd', '--download_docker_images',
                        help="Download docker images with the packs.zip",
                        required=False, type=str2bool, default=False)
    parser.add_argument('-o', '--output_path',
                        help="The path where the files will be saved to.",
                        required=True, default=".")
    parser.add_argument('--insecure',
                        help="Skip certificate validation.", type=str2bool, default=False)

    # TODO: Maybe add an option to choose download mode, i.e. 1. pack, 2. docker, 3. pack+docker

    return parser.parse_args()


def get_last_updated_from_file(min_filename: str) -> str:
    with open(min_filename, 'r') as min_file:
        return json.load(min_file)['last_updated']


def main():
    install_logging("DownloadPacksAndDockerImages.log", logger=logging)
    options = options_handler()
    output_path = options.output_path
    pack_display_names = options.packs.split(',')
    insecure = options.insecure
    pack_names = [get_pack_name(pack) for pack in pack_display_names]
    download_and_save_packs(pack_names, output_path, insecure)
    if options.download_docker_images:
        download_and_save_docker_images(pack_names, output_path)


if __name__ == '__main__':
    main()
