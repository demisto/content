# Perquisites to run this script:
#
# 1. Python 3.8+ soon will deprecate and will be supported from python 3.10+
# 2. requests python lib should be installed (can be installed by running "pip install requests" or "pip3 install requests")
# 3. docker is installed (if docker is not install, you can skip docker download using the `-sd` option)
# 4. docker python is installed (install it by running "pip install docker" or "pip3 install docker" or use the `-sd` option)


from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from zipfile import ZIP_DEFLATED, ZipFile
from pathlib import Path

import requests

ID_SET_URL = "https://storage.googleapis.com/marketplace-dist/content/id_set.json"
INDEX_ZIP_URL = "https://marketplace-dist.storage.googleapis.com/content/packs/index.zip"
BUCKET_PACKS_URL = "https://marketplace-dist.storage.googleapis.com/content/packs"
MAX_WORKERS = 10


def load_bucket_id_set(verify_ssl: bool) -> dict:
    """Loads the bucket id_set.json (used only for docker image resolution)."""
    r = requests.request(method="GET", url=ID_SET_URL, verify=verify_ssl)
    return r.json()


def load_index_packs(verify_ssl: bool) -> dict:
    """Downloads index.zip from the marketplace bucket and extracts pack metadata.

    Each pack folder in the index contains a metadata.json with fields including:
    - id: pack ID (used in download URLs)
    - name / display_name: human-readable pack name
    - currentVersion: the latest published version
    - author: pack author (e.g. "Cortex XSOAR")
    - deprecated: whether the pack is deprecated

    Returns:
        dict: Mapping of pack_id -> metadata dict.
    """
    print("Downloading index.zip from marketplace bucket...")  # noqa: T201
    r = requests.request(method="GET", url=INDEX_ZIP_URL, verify=verify_ssl)
    r.raise_for_status()
    packs: dict = {}
    with ZipFile(io.BytesIO(r.content), "r") as z:
        for name in z.namelist():
            parts = name.split("/")
            # Match paths like "index/<PackName>/metadata.json" (not versioned metadata files)
            if len(parts) == 3 and parts[0] == "index" and parts[2] == "metadata.json":
                pack_folder_name = parts[1]
                try:
                    metadata = json.loads(z.read(name))
                    pack_id = metadata.get("id", pack_folder_name)
                    packs[pack_id] = metadata
                except (json.JSONDecodeError, KeyError):
                    continue
    print(f"Loaded metadata for {len(packs)} packs from index.zip")  # noqa: T201
    return packs


def create_content_item_id_set(id_set_list: list) -> dict:
    """Given an id_set.json content item list, creates a dictionary representation"""
    res = {}
    for item in id_set_list:
        for key, val in item.items():
            res[key] = val
    return res


def zip_folder(source_path: str, output_path: str) -> None:
    """Zips the folder and its containing files"""
    with ZipFile(output_path + ".zip", "w", ZIP_DEFLATED) as source_zip:
        for root, _dirs, files in os.walk(source_path, topdown=True):
            for f in files:
                full_file_path = os.path.join(root, f)
                source_zip.write(filename=full_file_path, arcname=f)


def get_docker_images_with_tag(pack_names: dict, id_set_json: dict) -> set:
    """Given a pack name returns its docker images with its latest tag.

    Uses id_set.json because index.zip metadata does not contain docker image references.
    """
    print("Starting to collect docker images")  # noqa: T201
    integration_names_id_set = create_content_item_id_set(id_set_json["integrations"])
    script_names_id_set = create_content_item_id_set(id_set_json["scripts"])
    docker_images = set()
    for pack_d_name, pack_id in pack_names.items():
        if pack_id not in id_set_json.get("Packs", {}):
            print(f"\tPack {pack_d_name} was not found in id_set.json.")  # noqa: T201
            continue
        content_items = id_set_json["Packs"][pack_id].get("ContentItems", {})
        if not content_items:
            print(f"\tPack {pack_d_name} has no ContentItems - skipping pack.")  # noqa: T201
        integrations = content_items.get("integrations", [])
        scripts = content_items.get("scripts", [])
        if integrations:
            print(f"\t{pack_d_name} docker images found for integrations:")  # noqa: T201
            for integration in integrations:
                if integration in integration_names_id_set and "docker_image" in integration_names_id_set[integration]:
                    docker_image = integration_names_id_set[integration]["docker_image"]
                    print(f"\t\t{docker_image} - used by {integration}")  # noqa: T201
                    docker_images.add(docker_image)
        if scripts:
            print(f"\t{pack_d_name} docker images found for scripts:")  # noqa: T201
            for script in scripts:
                if script in script_names_id_set and "docker_image" in script_names_id_set[script]:
                    docker_image = script_names_id_set[script]["docker_image"]
                    print(f"\t\t{docker_image} - used by {script}")  # noqa: T201
                    docker_images.add(docker_image)

    return docker_images


def get_pack_names(pack_display_names: list, index_packs: dict) -> dict:
    """Given pack_display_names, resolve them to pack IDs using index metadata.

    Args:
        pack_display_names: List of display names provided by the user.
        index_packs: Dict of pack_id -> metadata from load_index_packs().

    Returns:
        dict: Mapping of display_name -> pack_id for matched packs.
    """
    # Build reverse lookup: display_name -> pack_id
    display_name_to_id: dict[str, str] = {}
    for pack_id, metadata in index_packs.items():
        display_name = metadata.get("name") or metadata.get("display_name", pack_id)
        display_name_to_id[display_name] = pack_id

    # If no specific packs requested, return all packs
    if pack_display_names == [""]:
        return display_name_to_id

    # Resolve requested display names to pack IDs
    pack_names: dict = {}
    for d_name in pack_display_names:
        if d_name not in display_name_to_id:
            print(f"Couldn't find pack {d_name}. Skipping pack.")  # noqa: T201
            continue
        pack_names[d_name] = display_name_to_id[d_name]
    return pack_names


def should_filter_out_pack(pack_metadata: dict, fields: dict, remove_deprecated: bool = False) -> bool:
    """
    Check if the pack should be filtered out based on given fields.

    Parameters:
        pack_metadata (dict): Pack metadata from index.zip.
        fields (dict): The dictionary containing the expected values for certain keys.
        remove_deprecated (bool): If True, packs marked as deprecated are filtered out.

    Returns:
        bool: True if the pack should be filtered out, False otherwise.
    """
    if remove_deprecated and pack_metadata.get("deprecated", False):
        return True

    return any(pack_metadata.get(key) != value for key, value in fields.items())


def download_and_save_packs(
    pack_names: dict,
    index_packs: dict,
    output_path: str,
    verify_ssl: bool,
    use_default_filter: bool = False,
) -> None:
    """Download and save packs under output_path.

    Uses index.zip metadata for pack ID and version resolution.

    Args:
        pack_names: Mapping of display_name -> pack_id.
        index_packs: Dict of pack_id -> metadata from load_index_packs().
        output_path: Directory to save the packs zip.
        verify_ssl: Whether to verify SSL certificates.
        use_default_filter: When True, filter to only Cortex XSOAR authored, non-deprecated packs.
    """
    print("Starting to download packs")  # noqa: T201

    # Build list of packs to download (apply filters first)
    packs_to_download: list[tuple[str, str, str]] = []  # (display_name, pack_id, version)
    for pack_d_name, pack_id in pack_names.items():
        if pack_id not in index_packs:
            print(f"\tCouldn't find {pack_d_name} in index. Skipping pack download.")  # noqa: T201
            continue

        pack_metadata = index_packs[pack_id]

        # When downloading all packs (no user input), apply default filters
        if use_default_filter and should_filter_out_pack(
            pack_metadata, fields={"author": "Cortex XSOAR"}, remove_deprecated=True
        ):
            print(f"\t{pack_d_name} filtered out. Skipping pack download.")  # noqa: T201
            continue

        pack_version = pack_metadata.get("currentVersion")
        if not pack_version:
            print(f"\tCouldn't determine version for {pack_d_name}. Skipping pack download.")  # noqa: T201
            continue

        packs_to_download.append((pack_d_name, pack_id, pack_version))

    if not packs_to_download:
        print("\tNo packs to download after filtering.")  # noqa: T201
        return

    def _download_pack(pack_d_name: str, pack_id: str, pack_version: str, dest_dir: str) -> str | None:
        """Download a single pack. Returns the file path on success, None on failure."""
        print(f"\tDownloading {pack_d_name} Pack (id={pack_id}, version={pack_version})")  # noqa: T201
        r = requests.request(method="GET", url=f"{BUCKET_PACKS_URL}/{pack_id}/{pack_version}/{pack_id}.zip", verify=verify_ssl)
        if r.status_code != 200:
            print(f"\tFailed to download {pack_d_name} (HTTP {r.status_code}). Skipping.")  # noqa: T201
            return None
        file_path = os.path.join(dest_dir, pack_id + ".zip")
        with open(file_path, "wb") as f:
            f.write(r.content)
        return file_path

    temp_dir = tempfile.TemporaryDirectory()
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_download_pack, d_name, p_id, version, temp_dir.name): d_name
                for d_name, p_id, version in packs_to_download
            }
            for future in as_completed(futures):
                pack_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"\tError downloading {pack_name}: {e}")  # noqa: T201
        zip_folder(temp_dir.name, output_path)
    finally:
        temp_dir.cleanup()


def download_and_save_docker_images(docker_images: set, output_path: str) -> None:
    """Downloads and saves the docker images into docker.zip in output_path.

    Docker pulls run in parallel using a thread pool.
    """
    import docker  # import docker only when required

    print("Starting to download docker images for given packs")  # noqa: T201
    cli = docker.from_env(timeout=120)

    def _pull_and_save(image: str, dest_dir: str) -> str | None:
        """Pull a single docker image and save it as a tar file."""
        print(f"\tDownloading docker image: {image}")  # noqa: T201
        image_pair = image.split(":")
        image_data = cli.images.pull(image_pair[0], image_pair[1])
        image_file_name = os.path.join(dest_dir, os.path.basename(f"{image_pair[0]}_{image_pair[1]}.tar"))
        with open(image_file_name, "wb") as f:
            for chunk in image_data.save(named=True):
                f.write(chunk)
        return image_file_name

    temp_dir = tempfile.TemporaryDirectory()
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_pull_and_save, image, temp_dir.name): image for image in docker_images}
            for future in as_completed(futures):
                image_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"\tError downloading docker image {image_name}: {e}")  # noqa: T201
        zip_folder(temp_dir.name, output_path)
    finally:
        temp_dir.cleanup()
    print("Finished docker images download")  # noqa: T201


def options_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Downloads XSOAR packs as zip and their latest docker images as tar.")
    parser.add_argument(
        "-p",
        "--packs",
        help="A list of pack names as they appear in https://xsoar.pan.dev/marketplace. Either provided "
        "via a path to a file that contains the packs list (separated by new lines) or "
        "a string of comma separated packs (e.g. Base,AutoFocus)",
        required=False,
    )
    parser.add_argument("-o", "--output_path", help="The path where the files will be saved to.", required=False, default=".")
    parser.add_argument("-sp", "--skip_packs", help="Don't download packs.", required=False, action="store_true")
    parser.add_argument("-sd", "--skip_docker", help="Don't download docker images.", required=False, action="store_true")
    parser.add_argument("--insecure", help="Skip certificate validation.", action="store_true")
    parser.set_defaults(skip_packs=False, skip_docker=False, insecure=False)

    return parser.parse_args()


def main():
    options = options_handler()
    output_path = options.output_path
    packs = options.packs or ""
    if os.path.isfile(packs):
        pack_display_names = []
        with open(packs) as file:
            for line in file:
                pack_display_names.append(line.rstrip())
    else:
        pack_display_names = packs.split(",")
    verify_ssl = not options.insecure

    # Load pack metadata from index.zip (primary source of truth for pack discovery and versions)
    index_packs = load_index_packs(verify_ssl)
    pack_names = get_pack_names(pack_display_names, index_packs)

    Path(output_path).mkdir(parents=True, exist_ok=True)
    if not options.skip_packs and pack_names:
        download_and_save_packs(
            pack_names,
            index_packs,
            os.path.join(output_path, "packs"),
            verify_ssl,
            use_default_filter=not bool(packs),
        )
    else:
        print("Skipping packs.zip creation")  # noqa: T201

    if pack_names and not options.skip_docker:
        # Load id_set.json only when docker images are needed (it contains docker_image references)
        id_set_json = load_bucket_id_set(verify_ssl)
        docker_images = get_docker_images_with_tag(pack_names, id_set_json)
        if docker_images:
            download_and_save_docker_images(docker_images, os.path.join(output_path, "docker"))
        else:
            print("No docker images found for the selected packs")  # noqa: T201
    elif options.skip_docker:
        print("Skipping dockers.zip creation")  # noqa: T201
    else:
        print("Skipping docker images collection since no packs were found")  # noqa: T201


if __name__ == "__main__":
    main()
