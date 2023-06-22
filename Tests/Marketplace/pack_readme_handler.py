import os
from pathlib import Path
import requests
import shutil
import urllib.parse
import json
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.utils import logging_wrapper as logging


def download_readme_images_from_artifacts(readme_urls_data_dict_path: Path, storage_bucket):
    """
    Iterates over the readme_url_data_list and calls the download_readme_image_from_url_and_upload_to_gcs
    Args:
        readme_urls_data_list (list): A list containing the data on all the images that need to be downloaded,
                                        and then uplaoded to storage.
        storage_bucket: The storage bucket to upload the images to.
    """
    with open(readme_urls_data_dict_path, 'r') as f:
        # reading the file generated in the sdk of all the packs readme images data.
        readme_urls_data_dict = json.load(f)

    pack_images_names = {}

    for pack_name, images_data in readme_urls_data_dict.items():
        for readme_url_data in images_data:
            readme_original_url = readme_url_data.get('original_read_me_url')
            gcs_storage_path = str(readme_url_data.get('new_gcs_image_path'))
            image_name = str(readme_url_data.get('image_name'))

            download_readme_image_from_url_and_upload_to_gcs(readme_original_url,
                                                             gcs_storage_path,
                                                             image_name, storage_bucket)

        pack_images_names[pack_name] = [
            image_name.get('image_name') for image_name in images_data
        ]

    return pack_images_names


def download_readme_image_from_url_and_upload_to_gcs(readme_original_url: str, gcs_storage_path: str,
                                                     image_name: str, storage_bucket):
    # sourcery skip: extract-method
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
    readme_original_url_parsed = urllib.parse.urlparse(readme_original_url)
    try:
        logging.info(f'trying to download {readme_original_url_parsed.geturl()}')
        r = requests.get(readme_original_url_parsed.geturl(), stream=True)

        # Check if the image was retrieved successfully
        if r.status_code == 200:
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

        logging.error(f'Image {image_name} could not be retreived status code {r.status_code} reason {r.reason}')
        return False
    except Exception as e:
        logging.error(
            f'Failed downloading the image in url {readme_original_url_parsed}. '
            f'or failed uploading it to GCP error message {e}')
        return False


def copy_readme_images(production_bucket, build_bucket, images_data: dict, storage_base_path: str,
                       build_bucket_base_path: str):
    """ Copies pack's readme_images from the build bucket to the production bucket

    Args:
        production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
        build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
        images_data (dict): The images data structure from Prepare Content step
        storage_base_path (str): The target destination of the upload in the target bucket.
        build_bucket_base_path (str): The path of the build bucket in gcp.
    Returns:
        bool: Whether the operation succeeded.
    """
    logging.debug('Starting readme images copy.')
    readme_images = {}
    if readme_images := images_data.get(BucketUploadFlow.README_IMAGES, None):
        for pack_name, pack_readme_images_list in readme_images.items():
            task_status = True
            err_msg = f"Failed copying {pack_name} pack readme images."
            pc_uploaded_readme_images = pack_readme_images_list

            if not pc_uploaded_readme_images:
                logging.debug(f"No added/modified readme images were detected in {pack_name} pack.")
                continue

            for readme_image_name in pc_uploaded_readme_images:
                logging.debug(f'copying image {readme_image_name}')
                build_bucket_readme_image_path = os.path.join(build_bucket_base_path, pack_name,
                                                              BucketUploadFlow.README_IMAGES, readme_image_name)
                build_bucket_image_blob = build_bucket.blob(build_bucket_readme_image_path)

                if not build_bucket_image_blob.exists():
                    logging.error(f"Found changed/added readme image in pack {pack_name} in content repo but "
                                  f"{build_bucket_image_blob} does not exist in build bucket")
                    task_status = False
                else:
                    logging.info(f"Copying {pack_name} pack readme {readme_image_name} image")
                    try:
                        copied_blob = build_bucket.copy_blob(
                            blob=build_bucket_image_blob, destination_bucket=production_bucket,
                            new_name=os.path.join(storage_base_path, pack_name, BucketUploadFlow.README_IMAGES,
                                                  readme_image_name)
                        )
                        if not copied_blob.exists():
                            logging.error(
                                f"Copy {pack_name} integration readme image: {build_bucket_image_blob.name} "
                                f"blob to {copied_blob.name} blob failed.")
                            task_status = False

                    except Exception as e:
                        logging.exception(f"{err_msg}. Additional Info: {str(e)}")
                        return False

            if not task_status:
                logging.error(err_msg)
            else:
                logging.success(f"Copied readme images for {pack_name} pack.")

            return task_status
