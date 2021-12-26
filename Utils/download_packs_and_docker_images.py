import argparse
import json
import os
import requests
import docker
import tempfile
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from demisto_sdk.commands.common.tools import str2bool


ID_SET_URL = "https://storage.googleapis.com/marketplace-dist/content/id_set.json"
BUCKET_PACKS_URL = "https://marketplace-dist.storage.googleapis.com/content/packs"


def create_content_item_id_set(id_set_list: list) -> dict:
    """ Given an id_set.json content item list, creates a dictionary representation"""
    res = dict()
    for item in id_set_list:
        for key, val in item.items():
            res[key] = val
    return res


def get_docker_images_with_tag(pack_names: str, id_set_json: dict) -> list:
    """ Given a pack name returns its docker images with its latest tag"""
    integration_names_id_set = create_content_item_id_set(id_set_json['integrations'])
    script_names_id_set = create_content_item_id_set(id_set_json['scripts'])
    docker_images = set()
    for pack_name in pack_names:
        if pack_name not in id_set_json['Packs']:
            logging.error(f"Pack {pack_name} was not found in id_set.json.")
            continue
        content_items = id_set_json['Packs'][pack_name]['ContentItems']
        integrations = content_items['integrations'] if 'integrations' in content_items else []
        scripts = content_items['scripts'] if 'scripts' in content_items else []
        for integration in integrations:
            docker_images.add(integration_names_id_set[integration]['docker_image'])
        for script in scripts:
            docker_images.add(script_names_id_set[script]['docker_image'])

    return list(docker_images)


def get_pack_names(pack_display_names, id_set_json) -> list:
    """ Given pack_display_names try and parse it into a pack name as appears in content repo"""
    pack_names = set()
    if 'Packs' not in id_set_json:
        raise ValueError('Packs is missing from id_set.json.')
    d_names_id_set = dict()
    for pack_name, pack_value in id_set_json['Packs'].items():
        d_names_id_set[pack_value['name']] = pack_name
    for d_name in pack_display_names:
        if d_name not in d_names_id_set:
            logging.error(f"Couldn't find pack {d_name}. Skipping pack.")
            continue
        pack_names.add(d_names_id_set[d_name])
    return list(pack_names)


def download_and_save_packs(pack_names: list, id_set_json: dict, output_path: str, verify_ssl: bool) -> None:
    if 'Packs' not in id_set_json:
        raise ValueError('Packs missing from id_set.json.')
    id_set_packs = id_set_json['Packs']
    logging.info("Starting to download packs with dependencies")
    for pack_name in pack_names:
        if pack_name not in id_set_packs:
            logging.error(f"Couldn't find {pack_name} in id_set.json. Skipping pack download.")
            continue
        pack_version = id_set_packs[pack_name]['current_version']
        logging.info(f"Downloading {pack_name} Pack.")
        r = requests.request(method='GET',
                             url=f'{BUCKET_PACKS_URL}/{pack_name}/{pack_version}/{pack_name}.zip',
                             verify=verify_ssl)
        with open(os.path.join(output_path, pack_name + '.zip'), 'wb') as f:
            f.write(r.content)
    # TODO: Zip all content packs into a unified zip


def download_and_save_docker_images(pack_names: list, output_path: str) -> None:
    logging.info("Starting to download docker images for given packs")
    cli = docker.from_env()
    for pack_name in pack_names:
        logging.info(f"Fetching docker image: for {pack_name}")
        docker_image = get_docker_images_with_tag(pack_name)
        # TODO: docker_images should be a list
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


def load_bucket_id_set(verify_ssl) -> dict:
    r = requests.request(method='GET', url=ID_SET_URL, verify=verify_ssl)
    return r.json()


def main():
    install_logging("DownloadPacksAndDockerImages.log", logger=logging)
    options = options_handler()
    output_path = options.output_path
    pack_display_names = options.packs.split(',')
    verify_ssl = not options.insecure
    temp_dir = tempfile.TemporaryDirectory()
    try:
        id_set_json = load_bucket_id_set(verify_ssl)
        pack_names = get_pack_names(pack_display_names, id_set_json)
        download_and_save_packs(pack_names, id_set_json, output_path, verify_ssl)
        if options.download_docker_images:
            download_and_save_docker_images(pack_names, output_path)
    finally:
        temp_dir.cleanup()


if __name__ == '__main__':
    main()
