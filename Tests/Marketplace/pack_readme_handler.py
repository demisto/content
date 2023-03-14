import logging
import os
from pathlib import Path

def upload_readme_images(storage_bucket, storage_base_path, pack_readme_path, pack_name, marketplace='xsoar'):
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
        try:

            if not os.path.exists(pack_readme_path):
                return True

            storage_pack_path = os.path.join(storage_base_path, pack_name)  # disable-secrets-detection

            # detect added/modified integration readme files
            logging.info(f'found a pack: {pack_name} with changes in README')
            readme_images_storage_paths = collect_images_from_readme_and_replace_with_storage_path(
                pack_readme_path, storage_pack_path, marketplace)

            # no external image urls were found in the readme file
            if not readme_images_storage_paths:
                logging.info(f'no image links were found in {pack_name} readme file')
                return False

            for image_info in readme_images_storage_paths:
                readme_original_url = image_info.get('original_read_me_url')
                gcs_storage_path = str(image_info.get('new_gcs_image_path'))
                image_name = str(image_info.get('image_name'))

                task_status = self.download_readme_image_from_url_and_upload_to_gcs(readme_original_url,
                                                                                    gcs_storage_path,
                                                                                    image_name, storage_bucket)
                self._reademe_images.append(image_name)

        except Exception:
            logging.exception(f"Failed uploading {pack_name} pack readme image.")


def collect_images_from_readme_and_replace_with_storage_path(pack_readme_path, gcs_pack_path, marketplace):
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

        google_api_readme_images_url = f'https://storage.googleapis.com/{marketplace_bucket}/content/packs/{self.name}'
        url_regex = r"^!\[(.*)\]\((?P<url>.*)\)"
        urls_list = []

        for line in fileinput.input(pack_readme_path, inplace=True):
            res = re.search(url_regex, line)
            # we found a matching url and we want to modify the readme line.
            if res:
                url = res.group('url')

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