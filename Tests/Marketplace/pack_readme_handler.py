import os
from pathlib import Path
import requests
import shutil
import urllib.parse
import json
from Tests.Marketplace.marketplace_constants import BucketUploadFlow, ImagesFolderNames
from Tests.scripts.utils import logging_wrapper as logging


def download_markdown_images_from_artifacts(
    markdown_urls_data_dict_path: Path, storage_bucket, storge_base_path: str
):
    """
    Iterates over the markdown_url_data_list and calls the download_markdown_image_from_url_and_upload_to_gcs
    Args:
        markdown_urls_data_dict_path (Path): A path to a json file generate in SDK prepare-content of all markdown images
                                            that need to be uploaded to GCS.
        storage_bucket: The storage bucket to upload the images to.
        storge_base_path: The path to the Pack dir in the storage.
    """
    with open(markdown_urls_data_dict_path) as f:
        # reading the file generated in the sdk of all the packs readme images data.
        readme_urls_data_dict = json.load(f)

    pack_images_names: dict = {}

    for pack_name, readme_description_images_data in readme_urls_data_dict.items():
        pack_images_names[pack_name] = {}
        for readme_desc_data, images_data in readme_description_images_data.items():
            for markdown_url_data in images_data:
                original_markdown_url = markdown_url_data.get("original_markdown_url")
                final_dst_image_path = str(markdown_url_data.get("final_dst_image_path"))
                image_name = str(markdown_url_data.get("image_name"))
                relative_image_path = str(markdown_url_data.get("relative_image_path"))

                logging.info(f"image_final_storage_des ={final_dst_image_path}")

                download_markdown_image_from_url_and_upload_to_gcs(
                    original_markdown_url,
                    relative_image_path,
                    image_name,
                    storge_base_path,
                    storage_bucket,
                )

            pack_images_names[pack_name][readme_desc_data] = [
                image_name.get("image_name") for image_name in images_data
            ]

    return pack_images_names


def download_markdown_image_from_url_and_upload_to_gcs(
    original_markdown_url: str,
    relative_image_path: str,
    image_name: str,
    storage_base_path,
    storage_bucket,
):
    # sourcery skip: extract-method
    """
    Download the image from the endpoint url and save locally.
    Upload The image to gcs.
    Remove the Temp file.

    Args:
         original_markdown_url (str): The original url that was in the readme file
         gcs_storage_path (str): The path to save the image on gcp (was calculated in collect_images_from_readme_
         and_replace_with_storage_path)
         image_name(str): The name of the image we want to save
         storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where images will be uploaded.

    """
    # Open the url image, set stream to True, this will return the stream content.
    original_markdown_url_parsed = urllib.parse.urlparse(original_markdown_url)
    try:
        logging.info(f"trying to download {original_markdown_url_parsed.geturl()}")
        r = requests.get(original_markdown_url_parsed.geturl(), stream=True)

        # Check if the image was retrieved successfully
        if r.status_code == 200:
            r.raw.decode_content = True

            with open(image_name, "wb") as f:
                shutil.copyfileobj(r.raw, f)
            # init the blob with the correct path to save the image on gcs
            gcs_storage_path = os.path.join(storage_base_path, relative_image_path)
            logging.info(f"{gcs_storage_path=}")
            markdown_image = storage_bucket.blob(gcs_storage_path)
            # load the file from local memo to the gcs
            with open(image_name, "rb") as image_file:
                markdown_image.upload_from_file(image_file)

            # remove local saved image
            os.remove(image_name)

            logging.info(f"Image sucessfully Downloaded: {image_name}")
            return True

        logging.error(
            f"Image {image_name} could not be retreived status code {r.status_code} reason {r.reason}"
        )
        return False
    except Exception as e:
        logging.error(
            f"Failed downloading the image in url {original_markdown_url_parsed}. "
            f"or failed uploading it to GCP error message {e}"
        )
        return False


def copy_markdown_images(
    production_bucket,
    build_bucket,
    images_data: dict,
    storage_base_path: str,
    build_bucket_base_path: str,
):
    """Copies pack's markdown_images from the build bucket to the production bucket

    Args:
        production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
        build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
        images_data (dict): The images data structure from Prepare Content step
        storage_base_path (str): The target destination of the upload in the target bucket.
        build_bucket_base_path (str): The path of the build bucket in gcp.
    Returns:
        bool: Whether the operation succeeded.
    """
    logging.info("Starting readme images copy.")
    markdown_images: dict = {}
    if markdown_images := images_data.get(BucketUploadFlow.MARKDOWN_IMAGES, {}):
        for pack_name, readme_description_md in markdown_images.items():
            task_status = True
            err_msg = f"Failed copying {pack_name} pack readme images."

            for readme_desc_folder, images_names_list in readme_description_md.items():
                pc_uploaded_markdown_images = images_names_list

                if not pc_uploaded_markdown_images:
                    logging.info(
                        f"No added/modified {readme_desc_folder} were detected in {pack_name} pack."
                    )
                    continue

                folder_names = [member.value for member in ImagesFolderNames]
                if readme_desc_folder not in folder_names:
                    logging.error(f'The folder is not one of {folder_names}')
                    continue

                for image_name in pc_uploaded_markdown_images:
                    logging.info(f"copying image {image_name}")
                    build_bucket_markdown_image_path = os.path.join(
                        build_bucket_base_path,
                        pack_name,
                        readme_desc_folder,
                        image_name,
                    )
                    build_bucket_image_blob = build_bucket.blob(
                        build_bucket_markdown_image_path
                    )

                    if not build_bucket_image_blob.exists():
                        logging.error(
                            f"Found changed/added {readme_description_md} in pack {pack_name} in content repo but "
                            f"{build_bucket_image_blob} does not exist in build bucket"
                        )
                        task_status = False
                    else:
                        logging.info(
                            f"Copying {pack_name=} {readme_desc_folder} {image_name=}"
                        )
                        try:
                            copied_blob = build_bucket.copy_blob(
                                blob=build_bucket_image_blob,
                                destination_bucket=production_bucket,
                                new_name=os.path.join(
                                    storage_base_path,
                                    pack_name,
                                    readme_desc_folder,
                                    image_name,
                                ),
                            )
                            if not copied_blob.exists():
                                logging.error(
                                    f"Copy {pack_name} integration readme image: {build_bucket_image_blob.name} "
                                    f"blob to {copied_blob.name} blob failed."
                                )
                                task_status = False

                        except Exception as e:
                            logging.exception(f"{err_msg}. Additional Info: {str(e)}")

                if not task_status:
                    logging.error(err_msg)
                else:
                    logging.success(f"Copied readme images for {pack_name} pack.")

    return task_status
