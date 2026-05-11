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
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypedDict

from typing_extensions import NotRequired
from zipfile import ZIP_DEFLATED, ZipFile
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INDEX_ZIP_URL = "https://marketplace-dist.storage.googleapis.com/content/packs/index.zip"
BUCKET_PACKS_URL = "https://marketplace-dist.storage.googleapis.com/content/packs"
MAX_WORKERS_PACKS = 10
MAX_WORKERS_DOCKER = 5
RETRY_TOTAL = 3
RETRY_BACKOFF_FACTOR = 1  # seconds between retries

# Fields from id_set.json that have no equivalent in index.zip metadata.
# If a customer passes these to should_filter_out_pack(), a warning is emitted.
_REMOVED_IDSET_FIELDS: dict[str, str] = {
    "source": "The 'source' field (internal git source) is not available in index.zip metadata.",
    "ContentItems": "The 'ContentItems' field is not available in index.zip metadata. "
    "Content items can be inspected by examining the downloaded pack zip files.",
}


class PackInfo(TypedDict):
    """Structured metadata for a single pack extracted from index.zip.

    These fields mirror the keys previously used from id_set.json ``Packs`` entries,
    plus additional metadata fields available in index.zip to support generic filtering
    via :func:`should_filter_out_pack`.

    ====================  =======================  ============================
    PackInfo field         id_set.json key          index.zip metadata key
    ====================  =======================  ============================
    id                     (dict key)               id
    name                   name                     name
    current_version        current_version          currentVersion
    author                 author                   author
    certification          certification             certification
    tags                   tags                     tags
    use_cases              use_cases                useCases
    categories             categories               categories
    marketplaces           marketplaces             marketplaces
    deprecated             *(string check on name)* deprecated  (boolean)
    ====================  =======================  ============================
    """

    # Required fields (always present)
    id: str
    name: str
    current_version: str
    author: str
    deprecated: bool
    # Optional fields (may be absent in some metadata entries)
    certification: NotRequired[str]
    tags: NotRequired[list[str]]
    use_cases: NotRequired[list[str]]
    categories: NotRequired[list[str]]
    marketplaces: NotRequired[list[str]]


def load_index_packs(verify_ssl: bool) -> dict[str, PackInfo]:
    """Downloads index.zip from the marketplace bucket and extracts pack metadata.

    Extracts all available metadata fields from each pack's metadata.json into
    a :class:`PackInfo`.  Field names use ``snake_case`` to match the id_set.json
    convention (e.g. ``currentVersion`` → ``current_version``).

    The dict is keyed by the pack's display name (``name`` or ``display_name``).

    Returns:
        dict: Mapping of display_name -> PackInfo for each pack.
    """
    print("Downloading index.zip from marketplace bucket...")  # noqa: T201
    r = requests.request(method="GET", url=INDEX_ZIP_URL, verify=verify_ssl)
    r.raise_for_status()
    packs: dict[str, PackInfo] = {}
    with ZipFile(io.BytesIO(r.content), "r") as z:
        for name in z.namelist():
            # Match paths like "index/<PackName>/metadata.json" using string ops
            parts = name.rstrip("/").split("/")
            if len(parts) == 3 and parts[0] == "index" and parts[2] == "metadata.json":
                pack_folder_name = parts[1]
                try:
                    metadata = json.loads(z.read(name))
                    pack_id = metadata.get("id", pack_folder_name)
                    display_name = metadata.get("name") or metadata.get("display_name", pack_id)
                    pack_info = PackInfo(
                        id=pack_id,
                        name=display_name,
                        current_version=metadata.get("currentVersion", ""),
                        author=metadata.get("author", ""),
                        deprecated=metadata.get("deprecated", False),
                    )
                    # Populate optional fields when present in metadata
                    keys_to_map = {
                        "certification": "certification",
                        "tags": "tags",
                        "useCases": "use_cases",
                        "categories": "categories",
                        "marketplaces": "marketplaces",
                    }
                    for source, target in keys_to_map.items():
                        if source in metadata:
                            pack_info[target] = metadata[source]
                    packs[display_name] = pack_info
                except (json.JSONDecodeError, KeyError):
                    continue
    print(f"Loaded metadata for {len(packs)} packs from index.zip")  # noqa: T201
    return packs


def zip_folder(source_path: str, output_path: str) -> None:
    """Zips the folder and its containing files"""
    with ZipFile(output_path + ".zip", "w", ZIP_DEFLATED) as source_zip:
        for full_file_path in Path(source_path).rglob("*"):
            if full_file_path.is_file():
                source_zip.write(filename=full_file_path, arcname=full_file_path.name)


def extract_docker_images_from_pack_zips(packs_dir: str) -> set:
    """Extract docker image references from downloaded pack zip files.

    Only scans YAML files under ``Integrations/`` and ``Scripts/`` directories
    inside each pack zip for ``dockerimage`` fields.

    Args:
        packs_dir: Directory containing downloaded pack zip files.

    Returns:
        set: Unique docker image references (e.g. 'demisto/python3:3.10.13.12345').
    """
    print("Extracting docker images from downloaded packs")  # noqa: T201
    docker_images: set = set()
    docker_image_pattern = re.compile(r"^\s*dockerimage\d*:\s*['\"]?(.+?)['\"]?\s*$", re.MULTILINE)

    for zip_file in Path(packs_dir).glob("*.zip"):
        pack_name = zip_file.stem
        integration_images: list[tuple[str, str]] = []
        script_images: list[tuple[str, str]] = []
        try:
            with ZipFile(zip_file, "r") as z:
                for name in z.namelist():
                    if not name.endswith((".yml", ".yaml")):
                        continue
                    parts = name.split("/")
                    # Only process YAML files under Integrations/ or Scripts/ directories
                    if len(parts) < 2:
                        continue
                    content_type = parts[0]
                    if content_type not in ("Integrations", "Scripts"):
                        continue
                    item_name = parts[1] if len(parts) > 1 else parts[-1].rsplit(".", 1)[0]
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        matches = docker_image_pattern.findall(content)
                        for match in matches:
                            match = match.strip()
                            if match and ":" in match and "/" in match:
                                docker_images.add(match)
                                if content_type == "Integrations":
                                    integration_images.append((match, item_name))
                                else:
                                    script_images.append((match, item_name))
                    except Exception:
                        continue
        except Exception as e:
            print(f"\tError reading {zip_file.name}: {e}")  # noqa: T201
            continue

        if integration_images:
            print(f"\t{pack_name} docker images found for integrations:")  # noqa: T201
            for image, item in integration_images:
                print(f"\t\t{image} - used by {item}")  # noqa: T201
        if script_images:
            print(f"\t{pack_name} docker images found for scripts:")  # noqa: T201
            for image, item in script_images:
                print(f"\t\t{image} - used by {item}")  # noqa: T201

    print(f"Found {len(docker_images)} unique docker images")  # noqa: T201
    return docker_images


def get_pack_names(pack_display_names: list, index_packs: dict[str, PackInfo]) -> dict[str, PackInfo]:
    """Given pack_display_names, filter the index to only the requested packs.

    Args:
        pack_display_names: List of display names provided by the user.
        index_packs: Mapping of display_name -> PackInfo from load_index_packs().

    Returns:
        dict: Mapping of display_name -> PackInfo for matched packs.
    """
    # If no specific packs requested, return all packs
    if pack_display_names == [""]:
        return index_packs

    # Resolve requested display names
    pack_names: dict[str, PackInfo] = {}
    for d_name in pack_display_names:
        if d_name not in index_packs:
            print(f"Couldn't find pack {d_name}. Skipping pack.")  # noqa: T201
            continue
        pack_names[d_name] = index_packs[d_name]
    return pack_names


def should_filter_out_pack(pack_info: PackInfo | dict, fields: dict, remove_deprecated: bool = False) -> bool:
    """
    Check if the pack should be filtered out based on given fields.

    Emits a warning if any requested field is not available in the pack metadata
    (e.g. fields that existed in id_set.json but have no equivalent in index.zip).

    Parameters:
        pack_info (PackInfo | dict): Pack metadata.
        fields (dict): The dictionary containing the expected values for certain keys.
        remove_deprecated (bool): If True, packs marked as deprecated are filtered out.

    Returns:
        bool: True if the pack should be filtered out, False otherwise.
    """
    if remove_deprecated and pack_info.get("deprecated", False):
        return True

    for key, value in fields.items():
        if key in _REMOVED_IDSET_FIELDS:
            print(  # noqa: T201
                f"Warning: field '{key}' is no longer available after migration from id_set.json to index.zip. "
                f"{_REMOVED_IDSET_FIELDS[key]} Skipping this filter field."
            )
            continue
        if pack_info.get(key) != value:
            return True

    return False


def download_and_save_packs(
    pack_names: dict[str, PackInfo],
    output_path: str,
    verify_ssl: bool,
    use_default_filter: bool = False,
    extract_docker: bool = False,
) -> set:
    """Download and save packs under output_path.

    Uses index.zip metadata for pack ID and version resolution.
    When ``extract_docker`` is True, docker images are extracted from the
    downloaded pack zips.

    Args:
        pack_names: Mapping of display_name -> PackInfo.
        output_path: Directory to save the packs zip.
        verify_ssl: Whether to verify SSL certificates.
        use_default_filter: When True, filter to only Cortex XSOAR authored, non-deprecated packs.
        extract_docker: When True, extract docker image references from downloaded packs.

    Returns:
        set: Docker image references found (empty if ``extract_docker`` is False).
    """
    print("Starting to download packs")  # noqa: T201

    # Build list of packs to download (apply filters first)
    packs_to_download: list[tuple[str, str, str]] = []  # (display_name, pack_id, version)
    for pack_d_name, pack_info in pack_names.items():
        # When downloading all packs (no user input), apply default filters
        if use_default_filter and should_filter_out_pack(pack_info, fields={"author": "Cortex XSOAR"}, remove_deprecated=True):
            print(f"\t{pack_d_name} filtered out. Skipping pack download.")  # noqa: T201
            continue

        pack_version = pack_info["current_version"]
        if not pack_version:
            print(f"\tCouldn't determine version for {pack_d_name}. Skipping pack download.")  # noqa: T201
            continue

        packs_to_download.append((pack_d_name, pack_info["id"], pack_version))

    if not packs_to_download:
        print("\tNo packs to download after filtering.")  # noqa: T201
        return set()

    def _download_pack(pack_d_name: str, pack_id: str, pack_version: str, dest_dir: str, session: requests.Session) -> str | None:
        """Download a single pack with retry support. Returns the file path on success, None on failure."""
        print(f"\tDownloading {pack_d_name} Pack (id={pack_id}, version={pack_version})")  # noqa: T201
        url = f"{BUCKET_PACKS_URL}/{pack_id}/{pack_version}/{pack_id}.zip"
        r = session.get(url, verify=verify_ssl, stream=True)
        if r.status_code != 200:
            print(f"\tFailed to download {pack_d_name} (HTTP {r.status_code}). Skipping.")  # noqa: T201
            return None
        file_path = Path(dest_dir) / f"{pack_id}.zip"
        with open(file_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return str(file_path)

    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))

    docker_images: set = set()
    temp_dir = tempfile.TemporaryDirectory()
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_PACKS) as executor:
            futures = {
                executor.submit(_download_pack, d_name, p_id, version, temp_dir.name, session): d_name
                for d_name, p_id, version in packs_to_download
            }
            for future in as_completed(futures):
                pack_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"\tError downloading {pack_name}: {e}")  # noqa: T201
        # Extract docker images from downloaded packs BEFORE zipping (avoids double extraction)
        if extract_docker:
            docker_images = extract_docker_images_from_pack_zips(temp_dir.name)
        zip_folder(temp_dir.name, output_path)
    finally:
        temp_dir.cleanup()
    return docker_images


def download_and_save_docker_images(docker_images: set, output_path: str) -> None:
    """Downloads and saves the docker images into docker.zip in output_path.

    Docker pulls run in parallel using a thread pool.
    """
    import docker

    print("Starting to download docker images for given packs")  # noqa: T201
    cli = docker.from_env(timeout=120)

    def _pull_and_save(image: str, dest_dir: str) -> str | None:
        """Pull a single docker image and save it as a tar file."""
        print(f"\tDownloading docker image: {image}")  # noqa: T201
        image_pair = image.split(":")
        image_data = cli.images.pull(image_pair[0], image_pair[1])
        image_file_name = Path(dest_dir) / f"{Path(image_pair[0]).name}_{image_pair[1]}.tar"
        with open(image_file_name, "wb") as f:
            for chunk in image_data.save(named=True):
                f.write(chunk)
        return str(image_file_name)

    temp_dir = tempfile.TemporaryDirectory()
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_DOCKER) as executor:
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
    try:
        is_file = Path(packs).is_file()
    except OSError:
        is_file = False
    if is_file:
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
    docker_images: set = set()

    if not options.skip_packs and pack_names:
        # Download packs and optionally extract docker images in one pass (no double extraction)
        docker_images = download_and_save_packs(
            pack_names,
            str(Path(output_path) / "packs"),
            verify_ssl,
            use_default_filter=not bool(packs),
            extract_docker=not options.skip_docker,
        )
    else:
        print("Skipping packs.zip creation")  # noqa: T201

    if pack_names and not options.skip_docker:
        if docker_images:
            download_and_save_docker_images(docker_images, str(Path(output_path) / "docker"))
        else:
            print("No docker images found for the selected packs")  # noqa: T201
    elif options.skip_docker:
        print("Skipping dockers.zip creation")  # noqa: T201
    else:
        print("Skipping docker images collection since no packs were found")  # noqa: T201


if __name__ == "__main__":
    main()
