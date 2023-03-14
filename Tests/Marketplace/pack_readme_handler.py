import logging
import os
from pathlib import Path
import requests
import shutil
import urllib.parse
import fileinput
import re
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from typing import List


def upload_readme_images(storage_bucket, storage_base_path, pack_readme_path, pack_name, marketplace='xsoar') -> None | List[str]:
    """ Downloads pack readme links to images, and upload them to gcs.

        Searches for image links in pack readme.
        In case no images links were found does nothing

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where readme image will be uploaded.
            storage_base_path (str): the path under the bucket to upload to.
            diff_files_list (list): The list of all modified/added files found in the diff
            detect_changes (bool): Whether to detect changes or upload the readme images in any case.
            marketplace (str): The marketplace the upload is made for.
        Returns:
            bool: whether the operation succeeded.
    """
    reademe_images = []
    try:
        if not os.path.exists(pack_readme_path):
            return

        storage_pack_path = os.path.join(storage_base_path, pack_name)  # disable-secrets-detection

        # detect added/modified integration readme files
        logging.info(f'found a pack: {pack_name} with changes in README')
        readme_images_storage_paths = collect_images_from_readme_and_replace_with_storage_path(
            pack_readme_path, storage_pack_path, marketplace)

        # no external image urls were found in the readme file
        if not readme_images_storage_paths:
            logging.info(f'no image links were found in {pack_name} readme file')
            return

        for image_info in readme_images_storage_paths:
            readme_original_url = image_info.get('original_read_me_url')
            gcs_storage_path = str(image_info.get('new_gcs_image_path'))
            image_name = str(image_info.get('image_name'))

            download_readme_image_from_url_and_upload_to_gcs(readme_original_url,
                                                             gcs_storage_path,
                                                             image_name, storage_bucket)
            reademe_images.append(image_name)
            return reademe_images
    except Exception:
        logging.exception(f"Failed uploading {pack_name} pack readme image.")


def collect_images_from_readme_and_replace_with_storage_path(pack_readme_path, gcs_pack_path, pack_name, marketplace):
    """
    Replaces inplace all images links in the pack README.md with their new gcs location

    Args:
        pack_readme_path (str): A path to the pack README file.
        gcs_pack_path (str): A path to the pack in gcs
        marketplace (str): The marketplace this pack is going to be uploaded to.

    Returns:
        A list of dicts of all the image urls found in the README.md file with all related data
        (original_url, new_gcs_path, image_name)
    """
    if marketplace == 'xsoar':
        marketplace_bucket = "marketplace-dist"
    else:
        marketplace_bucket = "marketplace-v2-dist"

    google_api_readme_images_url = f'https://storage.googleapis.com/{marketplace_bucket}/content/packs/{pack_name}'
    url_regex = r"^!\[(.*)\]\((?P<url>.*)\)"
    urls_list = []

    for line in fileinput.input(pack_readme_path, inplace=True):
        if res := re.search(url_regex, line):
            url = res['url']

            parse_url = urllib.parse.urlparse(url)
            path = parse_url.path
            url_path = Path(path)
            image_name = url_path.name

            image_gcp_path = Path(gcs_pack_path, BucketUploadFlow.README_IMAGES, image_name)
            url_to_replace_linking_to_dist = os.path.join(google_api_readme_images_url,
                                                          BucketUploadFlow.README_IMAGES, image_name)

            line = line.replace(url, str(url_to_replace_linking_to_dist))

            urls_list.append({
                'original_read_me_url': url,
                'new_gcs_image_path': image_gcp_path,
                'image_name': image_name
            })

        print(line, end='')

    return urls_list


def download_readme_image_from_url_and_upload_to_gcs(readme_original_url: str, gcs_storage_path: str,
                                                     image_name: str, storage_bucket):
    """
        Download the image from the endpoint url and save locally.
        Upload The image to gcs.
        Remove the Temp file.

        Args:
             readme_original_url (str): The original url that was in the readme file
             gcs_storage_path (str): The path to save the image on gcp (was calculated in collect_images_from_readme_
             and_replace_with_storage_path)
             image_name(str): The name of the image we want to save
             storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where images will be uploaded.

    """
    # Open the url image, set stream to True, this will return the stream content.
    readme_original_url = urllib.parse.urlparse(readme_original_url)
    try:
        r = requests.get(readme_original_url.geturl(), stream=True)

        # Check if the image was retrieved successfully
        if r.status_code == 200:
            # Set decode_content value to True, otherwise the downloaded image file's size will be zero.
            r.raw.decode_content = True

            with open(image_name, 'wb') as f:
                shutil.copyfileobj(r.raw, f)

            # init the blob with the correct path to save the image on gcs
            readme_image = storage_bucket.blob(gcs_storage_path)

            # load the file from local memo to the gcs
            with open(image_name, "rb") as image_file:
                readme_image.upload_from_file(image_file)

            # remove local saved image
            os.remove(image_name)

            logging.info(f'Image sucessfully Downloaded: {image_name}')
            return True

        logging.error(f'Image {image_name} could not be retreived status code {r.status_code}')
        return False
    except Exception as e:
        logging.error(
            f'Failed downloading the image in url {readme_original_url}. '
            f'or failed uploading it to GCP error message {e}')
        return False
