# Perquisites to run this script:
#
# 1. Python 3.8+
# 2. requests python lib should be installed (can be installed by running "pip install requests" or "pip3 install requests")
# 3. docker is installed (if docker is not install, you can skip docker download using the `-sd` option)
# 4. docker python is installed (install it by running "pip install docker" or "pip3 install docker" or use the `-sd` option)


import argparse
import os
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile
from pathlib import Path

import requests

ID_SET_URL = "https://storage.googleapis.com/marketplace-dist/content/id_set.json"
BUCKET_PACKS_URL = "https://marketplace-dist.storage.googleapis.com/content/packs"


def load_bucket_id_set(verify_ssl: bool) -> dict:
    """ Loads the bucket id_set.json"""
    r = requests.request(method='GET', url=ID_SET_URL, verify=verify_ssl)
    return r.json()


def create_content_item_id_set(id_set_list: list) -> dict:
    """ Given an id_set.json content item list, creates a dictionary representation"""
    res = {}
    for item in id_set_list:
        for key, val in item.items():
            res[key] = val
    return res


def zip_folder(source_path, output_path):
    """ Zips the folder and its containing files"""
    with ZipFile(output_path + '.zip', 'w', ZIP_DEFLATED) as source_zip:
        for root, _dirs, files in os.walk(source_path, topdown=True):
            for f in files:
                full_file_path = os.path.join(root, f)
                source_zip.write(filename=full_file_path, arcname=f)


def get_docker_images_with_tag(pack_names: dict, id_set_json: dict) -> set:
    """ Given a pack name returns its docker images with its latest tag"""
    print('Starting to collect docker images')
    integration_names_id_set = create_content_item_id_set(id_set_json['integrations'])
    script_names_id_set = create_content_item_id_set(id_set_json['scripts'])
    docker_images = set()
    for pack_d_name, pack_name in pack_names.items():
        if pack_name not in id_set_json['Packs']:
            print(f"\tPack {pack_d_name} was not found in id_set.json.")
            continue
        content_items = id_set_json['Packs'][pack_name].get('ContentItems', {})
        if not content_items:
            print(f"\tPack {pack_d_name} has no ContentItems - skipping pack.")
        integrations = content_items['integrations'] if 'integrations' in content_items else []
        scripts = content_items['scripts'] if 'scripts' in content_items else []
        if integrations:
            print(f"\t{pack_d_name} docker images found for integrations:")
            for integration in integrations:
                if 'docker_image' in integration_names_id_set[integration]:
                    docker_image = integration_names_id_set[integration]['docker_image']
                    print(f"\t\t{docker_image} - used by {integration}")
                    docker_images.add(docker_image)
        if scripts:
            print(f"\t{pack_d_name} docker images found for scripts:")
            for script in scripts:
                if 'docker_image' in script_names_id_set[script]:
                    docker_image = script_names_id_set[script]['docker_image']
                    print(f"\t\t{docker_image} - used by {script}")
                    docker_images.add(docker_image)

    return docker_images


def get_pack_names(pack_display_names: list, id_set_json: dict) -> dict:
    """ Given pack_display_names try and parse it into a pack name as appears in content repo"""
    pack_names = {}
    if 'Packs' not in id_set_json:
        raise ValueError('Packs is missing from id_set.json.')
    d_names_id_set = {}
    # create display name id_set.json
    for pack_name, pack_value in id_set_json['Packs'].items():
        d_names_id_set[pack_value['name']] = pack_name

    # create result given display name id_set.json
    if pack_display_names == ['']:
        return d_names_id_set
    for d_name in pack_display_names:
        if d_name not in d_names_id_set:
            print(f"Couldn't find pack {d_name}. Skipping pack.")
            continue
        pack_names[d_name] = d_names_id_set[d_name]
    return pack_names


def should_filter_out_pack(pack_data: dict, fields: dict, remove_deprecated: bool = False):
    """
    Check if the pack should be filtered out based on given fields.

    Parameters:
    pack_data (dict): The dictionary containing the actual data. Based on id_set.
    fields (dict): The dictionary containing the expected values for certain keys.
    remove_deprecated (bool): If False, keys including "(Deprecated)" are not filtered out. Default is False.

    Returns:
    bool: True if all the values in fields match the values in data for the given keys, False otherwise.
    """
    if remove_deprecated and "(Deprecated)" in pack_data['name']:
        return True

    return any(pack_data.get(key) != value for key, value in fields.items())


def download_and_save_packs(pack_names: dict, id_set_json: dict, output_path: str, verify_ssl: bool,
                            use_defaut_filter: bool = False) -> None:
    """ Download and save packs under """
    if 'Packs' not in id_set_json:
        raise ValueError('Packs missing from id_set.json.')
    id_set_packs = id_set_json['Packs']
    print("Starting to download packs")
    temp_dir = tempfile.TemporaryDirectory()
    try:
        for pack_d_name, pack_name in pack_names.items():
            if pack_name not in id_set_packs:
                print(f"\tCouldn't find {pack_d_name} in id_set.json. Skipping pack download.")
                continue
            # In case no input is given (and only in that case) we automatically get all packs,
            # we want to get only relevant packs.
            if use_defaut_filter and should_filter_out_pack(id_set_packs[pack_name],
                                                            fields={"author": 'Cortex XSOAR'},
                                                            remove_deprecated=True):
                print(f"\t{pack_d_name} filtered out. Skipping pack download.")
                continue

            pack_version = id_set_packs[pack_name]['current_version']
            print(f"\tDownloading {pack_d_name} Pack")
            r = requests.request(method='GET',
                                 url=f'{BUCKET_PACKS_URL}/{pack_name}/{pack_version}/{pack_name}.zip',
                                 verify=verify_ssl)
            with open(os.path.join(temp_dir.name, pack_name + '.zip'), 'wb') as f:
                f.write(r.content)
        zip_folder(temp_dir.name, output_path)
    finally:
        temp_dir.cleanup()


def download_and_save_docker_images(docker_images: set, output_path: str) -> None:
    """ Downloads and saves the docker images into docker.zip in output_path"""
    import docker  # import docker only when required
    print("Starting to download docker images for given packs")
    cli = docker.from_env(timeout=120)
    temp_dir = tempfile.TemporaryDirectory()
    try:
        for image in docker_images:
            print(f"\tDownloading docker image: {image}")
            image_pair = image.split(':')
            image_data = cli.images.pull(image_pair[0], image_pair[1])
            image_file_name = os.path.join(temp_dir.name, os.path.basename(f"{image_pair[0]}_{image_pair[1]}.tar"))
            with open(image_file_name, 'wb') as f:
                for chunk in image_data.save(named=True):
                    f.write(chunk)
        zip_folder(temp_dir.name, output_path)
    finally:
        temp_dir.cleanup()
    print("Finished docker images download")


def options_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Downloads XSOAR packs as zip and their latest docker images as tar.")
    parser.add_argument('-p', '--packs',
                        help="A list of pack names as they appear in https://xsoar.pan.dev/marketplaceEither provided "
                             "via a path to a file that contains the packs list (separated by new lines) or "
                             "a string of comma separated packs (e.g. Base,AutoFocus)",
                        required=False)
    parser.add_argument('-o', '--output_path',
                        help="The path where the files will be saved to.",
                        required=False, default=".")
    parser.add_argument('-sp', '--skip_packs',
                        help="Don't download packs.",
                        required=False, action='store_true')
    parser.add_argument('-sd', '--skip_docker',
                        help="Don't download docker images.",
                        required=False, action='store_true')
    parser.add_argument('--insecure',
                        help="Skip certificate validation.", dest='feature', action='store_true')
    parser.set_defaults(skip_packs=False, skip_docker=False, insecure=False)

    return parser.parse_args()


def main():
    options = options_handler()
    output_path = options.output_path
    packs = options.packs or ''
    if os.path.isfile(packs):
        pack_display_names = []
        with open(packs) as file:
            for line in file:
                pack_display_names.append(line.rstrip())
    else:
        pack_display_names = packs.split(',')
    verify_ssl = not options.insecure
    id_set_json = load_bucket_id_set(verify_ssl)
    pack_names = get_pack_names(pack_display_names, id_set_json)
    Path(output_path).mkdir(parents=True, exist_ok=True)
    if not options.skip_packs and pack_names:
        download_and_save_packs(pack_names, id_set_json,
                                os.path.join(output_path, 'packs'),
                                verify_ssl,
                                use_defaut_filter=not bool(packs))
    else:
        print('Skipping packs.zip creation')
    if pack_names:
        docker_images = get_docker_images_with_tag(pack_names, id_set_json)
        if not options.skip_docker:
            download_and_save_docker_images(docker_images, os.path.join(output_path, 'docker'))
        else:
            print('Skipping dockers.zip creation')
    else:
        print('Skipping docker images collection since no packs were found')


if __name__ == '__main__':
    main()
