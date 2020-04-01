import json
import os
import sys
import subprocess
import fnmatch
import shutil
import yaml
import enum
from distutils.util import strtobool
from distutils.version import LooseVersion
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from Tests.test_utils import print_error, print_warning, print_color, LOG_COLORS

STORAGE_BASE_PATH = "content/packs"  # base path for packs in gcs
BASE_PACK = "Base"  # base pack name
USE_GCS_RELATIVE_PATH = True  # whether to use relative path in uploaded to gcs images
GCS_PUBLIC_URL = "https://storage.googleapis.com"  # disable-secrets-detection

# the format is defined in issue #19786, may change in the future
DIR_NAME_TO_CONTENT_TYPE = {
    "Classifiers": "classifier",
    "Dashboards": "dashboard",
    "IncidentFields": "incidentfield",
    "IncidentTypes": "incidenttype",
    "IndicatorFields": "reputation",
    "Integrations": "integration",
    "Layouts": "layout",
    "Playbooks": "playbook",
    "Reports": "report",
    "Scripts": "automation",
    "Widgets": "widget"
}


class Pack(object):
    """Class that manipulates and manages the upload of pack's artifact and metadata to cloud storage.

    Args:
        pack_name (str): Pack root folder name.
        pack_path (str): Full path to pack folder.

    Attributes:
        PACK_INITIAL_VERSION (str): pack initial version that will be used as default.
        DATE_FORMAT (str): date format of.
        CHANGELOG_JSON (str): changelog json full name, may be changed in the future.
        CHANGELOG_MD (str): changelog md full name.
        README (str): pack's readme file name.
        METADATA (str): pack's metadata file name, the one that will be deployed to cloud storage.
        USER_METADATA (str); user metadata file name, the one that located in content repo.
        INDEX_NAME (str): pack's index name, may be changed in the future.
        EXCLUDE_DIRECTORIES (list): list of directories to excluded before uploading pack zip to storage.
        AUTHOR_IMAGE_NAME (str): author image file name.

    """
    PACK_INITIAL_VERSION = "1.0.0"
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    CHANGELOG_JSON = "changelog.json"
    CHANGELOG_MD = "changelog.md"
    README = "README.md"
    USER_METADATA = "pack_metadata.json"
    METADATA = "metadata.json"
    AUTHOR_IMAGE_NAME = "Author_image.png"
    INDEX_NAME = "index"
    EXCLUDE_DIRECTORIES = ["TestPlaybooks"]

    def __init__(self, pack_name, pack_path):
        self._pack_name = pack_name
        self._pack_path = pack_path
        self._pack_repo_path = os.path.join(PACKS_FULL_PATH, pack_name)
        self._status = None
        self._relative_storage_path = ""

    @property
    def name(self):
        """str: pack root folder name.
        """
        return self._pack_name

    @property
    def path(self):
        """str: pack folder full path.
        """
        return self._pack_path

    @property
    def latest_version(self):
        """str: pack latest version from sorted keys of changelog.json file.
        """
        return self._get_latest_version()

    @property
    def status(self):
        """str: current status of the packs.
        """
        return self._status

    @status.setter
    def status(self, status_value):
        """setter of pack current status.
        """
        self._status = status_value

    @property
    def relative_storage_path(self):
        """str: relative gcs path of uploaded pack.
        """
        return self._relative_storage_path

    @relative_storage_path.setter
    def relative_storage_path(self, path_value):
        """setter of relative gcs path of uploaded pack.
        """
        self._relative_storage_path = path_value

    def _get_latest_version(self):
        """Return latest semantic version of the pack.

        In case that changelog.json file was not found, default value of 1.0.0 will be returned.
        Otherwise, keys of semantic pack versions will be collected and sorted in descending and return latest version.
        For additional information regarding changelog.json format go to issue #19786

        Returns:
            str: Pack latest version.

        """
        changelog_path = os.path.join(self._pack_path, Pack.CHANGELOG_JSON)

        if not os.path.exists(changelog_path):
            return self.PACK_INITIAL_VERSION

        with open(changelog_path, "r") as changelog_file:
            changelog = json.load(changelog_file)
            pack_versions = [LooseVersion(v) for v in changelog.keys()]
            pack_versions.sort(reverse=True)

            return pack_versions[0].vstring

    @staticmethod
    def _get_all_pack_images(pack_integration_images, display_dependencies_images, dependencies_data):
        """ Returns data of uploaded pack integration images and it's path in gcs. Pack dependencies integration images
        are added to that result as well.

        Args:
             pack_integration_images (list): list of uploaded to gcs integration images and it paths in gcs.
             display_dependencies_images (list): list of pack names of additional dependencies images to display.
             dependencies_data (dict): all level dependencies data.

        Returns:
            list: collection of integration display name and it's path in gcs.

        """
        additional_dependencies_data = {k: v for (k, v) in dependencies_data.items()
                                        if k in display_dependencies_images}

        for dependency_data in additional_dependencies_data.values():
            dependency_integration_images = dependency_data.get('integrations', [])

            for dependency_integration in dependency_integration_images:
                if dependency_integration not in pack_integration_images:
                    pack_integration_images.append(dependency_integration)

        return pack_integration_images

    @staticmethod
    def _parse_pack_dependencies(first_level_dependencies, all_level_pack_dependencies_data):
        """ Parses user defined dependencies and returns dictionary with relevant data about each dependency pack.

        Args:
            first_level_dependencies (dict): first lever dependencies that were retrieved
            from user pack_metadata.json file.
            all_level_pack_dependencies_data (dict): all level pack dependencies data.

        Returns:
            dict: parsed dictionary with pack dependency data.
        """
        parsed_result = {}
        dependencies_data = {k: v for (k, v) in all_level_pack_dependencies_data.items()
                             if k in first_level_dependencies.keys() or k == BASE_PACK}

        for dependency_id, dependency_data in dependencies_data.items():
            parsed_result[dependency_id] = {
                "mandatory": first_level_dependencies.get(dependency_id, {}).get('mandatory', True),
                "minVersion": dependency_data.get('currentVersion', Pack.PACK_INITIAL_VERSION),
                "author": dependency_data.get('author', ''),
                "name": dependency_data.get('name') if dependency_data.get('name') else dependency_id,
                "certification": dependency_data.get('certification', 'certified')
            }

        return parsed_result

    def collect_content_items(self):
        # todo rewrite this function, add docstring and unit tests
        """Collects specific pack content items.

        """
        YML_SUPPORTED_DIRS = [
            "Scripts",
            "Integrations",
            "Playbooks"
        ]
        data = {}
        task_status = True

        try:
            for directory in os.listdir(self._pack_path):
                if not os.path.isdir(os.path.join(self._pack_path, directory)) or directory == "TestPlaybooks":
                    continue

                dir_data = []
                dir_path = os.path.join(self._pack_path, directory)

                for dir_file in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, dir_file)
                    if dir_file.endswith('.json') or dir_file.endswith('.yml'):
                        file_info = {}

                        with open(file_path, 'r') as file_data:
                            if directory in YML_SUPPORTED_DIRS:
                                new_data = yaml.safe_load(file_data)
                            else:
                                new_data = json.load(file_data)

                            if directory == 'Layouts':
                                file_info['name'] = new_data.get('TypeName', '')
                            elif directory == 'Integrations':
                                file_info['name'] = new_data.get('display', '')
                                integration_commands = new_data.get('script', {}).get('commands', [])
                                file_info['commands'] = [
                                    {'name': c.get('name', ''), 'description': c.get('description', '')}
                                    for c in integration_commands]
                            elif directory == "Classifiers":
                                file_info['name'] = new_data.get('id', '')
                            else:
                                file_info['name'] = new_data.get('name', '')

                            if new_data.get('description', ''):
                                file_info['description'] = new_data.get('description', '')
                            if new_data.get('comment', ''):
                                file_info['description'] = new_data.get('comment', '')

                            dir_data.append(file_info)

                data[directory] = dir_data
        except Exception as e:
            task_status = False
            print_error(
                "Failed to collect pack content items at path :{}\n. Additional info {}".format(self._pack_path, e))
        finally:
            return task_status, data

    @staticmethod
    def _parse_pack_metadata(user_metadata, pack_content_items, pack_id, integration_images, author_image,
                             dependencies_data):
        """Parses pack metadata according to issue #19786 and #20091. Part of field may change over the time.

        Args:
            user_metadata (dict): user metadata that was created in pack initialization.
            pack_content_items (dict): content items located inside specific pack.
            pack_id (str): pack unique identifier.
            integration_images (list): list of gcs uploaded integration images.
            author_image (str): gcs uploaded author image
            dependencies_data (dict): mapping of pack dependencies data, of all levels.

        Returns:
            dict: parsed pack metadata.

        """
        pack_metadata = {}
        # part of old packs are initialized with empty list
        user_metadata = {} if isinstance(user_metadata, list) else user_metadata
        pack_metadata['name'] = user_metadata.get('name') if user_metadata.get('name') else pack_id
        pack_metadata['id'] = pack_id
        pack_metadata['description'] = user_metadata.get('description') if user_metadata.get('description') else pack_id
        pack_metadata['created'] = user_metadata.get('created', datetime.utcnow().strftime(Pack.DATE_FORMAT))
        pack_metadata['updated'] = datetime.utcnow().strftime(Pack.DATE_FORMAT)
        pack_metadata['legacy'] = user_metadata.get('legacy', True)
        pack_metadata['support'] = user_metadata.get('support', '')
        pack_metadata['supportDetails'] = {}
        support_url = user_metadata.get('url')
        if support_url:
            pack_metadata['supportDetails']['url'] = support_url

        support_email = user_metadata.get('email')
        if support_email:
            pack_metadata['supportDetails']['email'] = support_email
        pack_metadata['author'] = user_metadata.get('author', '')
        pack_metadata['authorImage'] = author_image
        is_beta = user_metadata.get('beta', False)
        pack_metadata['beta'] = bool(strtobool(is_beta)) if isinstance(is_beta, str) else is_beta
        is_deprecated = user_metadata.get('deprecated', False)
        pack_metadata['deprecated'] = bool(strtobool(is_beta)) if isinstance(is_deprecated, str) else is_deprecated
        pack_metadata['certification'] = user_metadata.get('certification', '')
        try:
            pack_metadata['price'] = int(user_metadata.get('price'))
        except Exception as e:
            print_warning(f"{pack_id} pack price is not valid. The price was set to 0. Additional "
                          f"details {e}")
            pack_metadata['price'] = 0
        pack_metadata['serverMinVersion'] = user_metadata.get('serverMinVersion', '')
        pack_metadata['serverLicense'] = user_metadata.get('serverLicense', '')
        pack_metadata['currentVersion'] = user_metadata.get('currentVersion', '')
        # todo check if this field is necessary
        pack_metadata['general'] = input_to_list(user_metadata.get('general'))
        pack_metadata['tags'] = input_to_list(user_metadata.get('tags'))
        pack_metadata['categories'] = input_to_list(user_metadata.get('categories'))
        pack_metadata['contentItems'] = {DIR_NAME_TO_CONTENT_TYPE[k]: v for (k, v) in pack_content_items.items()
                                         if k in DIR_NAME_TO_CONTENT_TYPE and v}
        pack_metadata['integrations'] = Pack._get_all_pack_images(integration_images,
                                                                  user_metadata.get('displayedImages', []),
                                                                  dependencies_data)
        pack_metadata['useCases'] = input_to_list(user_metadata.get('useCases'))
        pack_metadata['keywords'] = input_to_list(user_metadata.get('keywords'))
        pack_metadata['dependencies'] = Pack._parse_pack_dependencies(user_metadata.get('dependencies', {}),
                                                                      dependencies_data)

        return pack_metadata

    def _load_pack_dependencies(self, index_folder_path, first_level_dependencies, all_level_displayed_dependencies):
        """ Loads dependencies metadata and returns mapping of pack id and it's loaded data.

        Args:
            index_folder_path (str): full path to download index folder.
            first_level_dependencies (dict): user defined dependencies.
            all_level_displayed_dependencies (list): all level pack's images to display.

        Returns:
            dict: pack id as key and loaded metadata of packs as value.

        """
        dependencies_data_result = {}
        dependencies_ids = {d for d in first_level_dependencies.keys()}
        dependencies_ids.update(all_level_displayed_dependencies)

        if self._pack_name != BASE_PACK:  # check that current pack isn't Base Pack in order to prevent loop
            dependencies_ids.add(BASE_PACK)  # Base pack is always added as pack dependency

        for dependency_pack_id in dependencies_ids:
            dependency_metadata_path = os.path.join(index_folder_path, dependency_pack_id, Pack.METADATA)

            if os.path.exists(dependency_metadata_path):
                with open(dependency_metadata_path, 'r') as metadata_file:
                    dependency_metadata = json.load(metadata_file)
                    dependencies_data_result[dependency_pack_id] = dependency_metadata
            else:
                raise Exception(f"{self._pack_name} pack dependency with id {dependency_pack_id} was not found")

        return dependencies_data_result

    def remove_unwanted_files(self):
        """Iterates over pack folder and removes hidden files and unwanted folders.

        Returns:
            bool: whether the operation succeeded.
        """
        task_status = True

        try:
            for root, dirs, files in os.walk(self._pack_path, topdown=True):
                for pack_file in files:
                    full_file_path = os.path.join(root, pack_file)
                    # removing unwanted files
                    if pack_file.startswith('.') or pack_file in [Pack.AUTHOR_IMAGE_NAME, Pack.USER_METADATA]:
                        os.remove(full_file_path)
                        print(f"Deleted pack {pack_file} file for {self._pack_name} pack")
                        continue

                    current_directory = root.split(os.path.sep)[-1]

                    if current_directory in Pack.EXCLUDE_DIRECTORIES and os.path.isdir(root):
                        shutil.rmtree(root)
                        print(f"Deleted pack {current_directory} directory for {self._pack_name} pack")
                        continue

                    if current_directory == 'Misc' and not fnmatch.fnmatch(pack_file, 'reputation-*.json'):
                        # reputation in old format aren't supported in 6.0.0 server version
                        os.remove(full_file_path)
                        print(f"Deleted pack {pack_file} file for {self._pack_name} pack")
        except Exception as e:
            task_status = False
            print_error(f"Failed to delete ignored files for pack {self._pack_name} - {str(e)}")
        finally:
            return task_status

    def sign_pack(self, signature_string=None):
        """Signs pack folder and creates signature file.

        Args:
            signature_string (str): Base64 encoded string used to sign the pack.

        Returns:
            bool: whether the operation succeeded.
        """
        task_status = False

        try:
            if signature_string:
                with open("keyfile", "wb") as keyfile:
                    keyfile.write(signature_string.encode())
                arg = f'./signDirectory {self._pack_path} /keyfile base64'
                signing_process = subprocess.Popen(arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                output, err = signing_process.communicate()

                if err:
                    print_error(f"Failed to sign pack for {self._pack_name} - {str(err)}")
                    return

                print(f"Signed {self._pack_name} pack successfully")
            else:
                print(f"No signature provided. Skipped signing {self._pack_name} pack")
            task_status = True
        except Exception as e:
            print_error(f"Failed to sign pack for {self._pack_name} - {str(e)}")
        finally:
            return task_status

    def zip_pack(self):
        """Zips pack folder.

        Returns:
            bool: whether the operation succeeded.
            str: full path to created pack zip.
        """
        zip_pack_path = f"{self._pack_path}.zip"
        task_status = False

        try:
            with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
                for root, dirs, files in os.walk(self._pack_path, topdown=True):
                    for f in files:
                        full_file_path = os.path.join(root, f)
                        relative_file_path = os.path.relpath(full_file_path, self._pack_path)
                        pack_zip.write(filename=full_file_path, arcname=relative_file_path)

            task_status = True
            print_color(f"Finished zipping {self._pack_name} pack.", LOG_COLORS.GREEN)
        except Exception as e:
            print_error(f"Failed in zipping {self._pack_name} folder.\n Additional info: {e}")
        finally:
            return task_status, zip_pack_path

    def upload_to_storage(self, zip_pack_path, latest_version, storage_bucket, override_pack):
        """ Manages the upload of pack zip artifact to correct path in cloud storage.
        The zip pack will be uploaded to following path: /content/packs/pack_name/pack_latest_version.
        In case that zip pack artifact already exist at constructed path, the upload will be skipped.
        If flag override_pack is set to True, pack will forced for upload.

        Args:
            zip_pack_path (str): full path to pack zip artifact.
            latest_version (str): pack latest version.
            storage_bucket (google.cloud.storage.bucket.Bucket): google cloud storage bucket.
            override_pack (bool): whether to override existing pack.

        Returns:
            bool: whether the operation succeeded.
            bool: True in case of pack existence at targeted path and upload was skipped, otherwise returned False.

        """
        task_status = True

        try:
            version_pack_path = os.path.join(STORAGE_BASE_PATH, self._pack_name, latest_version)
            existing_files = [f.name for f in storage_bucket.list_blobs(prefix=version_pack_path)]

            if existing_files and not override_pack:
                print_warning(f"The following packs already exist at storage: {', '.join(existing_files)}")
                print_warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
                return task_status, True

            pack_full_path = f"{version_pack_path}/{self._pack_name}.zip"
            blob = storage_bucket.blob(pack_full_path)

            with open(zip_pack_path, "rb") as pack_zip:
                blob.upload_from_file(pack_zip)

            self.relative_storage_path = blob.name
            print_color(f"Uploaded {self._pack_name} pack to {pack_full_path} path.", LOG_COLORS.GREEN)

            return task_status, False
        except Exception as e:
            task_status = False
            print_error(f"Failed in uploading {self._pack_name} pack to gcs. Additional info:\n {e}")
            return task_status, True

    def format_metadata(self, pack_content_items, integration_images, author_image, index_folder_path):
        """Re-formats metadata according to marketplace metadata format defined in issue #19786 and writes back
        the result.

        Args:
            pack_content_items (dict): content items that are located inside specific pack. Possible keys of the dict:
            Classifiers, Dashboards, IncidentFields, IncidentTypes, IndicatorFields, Integrations, Layouts, Playbooks,
            Reports, Scripts and Widgets. Each key is mapped to list of items with name and description. Several items
            have no description.
            integration_images (list): list of uploaded integration images with integration display name and image gcs
            public url.
            author_image (str): uploaded public gcs path to author image.
            index_folder_path (str): downloaded index folder directory path.

        Returns:
            bool: True is returned in case metadata file was parsed successfully, otherwise False.

        """
        task_status = False

        try:
            user_metadata_path = os.path.join(self._pack_path, Pack.USER_METADATA)  # user metadata path before parsing
            metadata_path = os.path.join(self._pack_path, Pack.METADATA)  # deployed metadata path after parsing

            if not os.path.exists(user_metadata_path):
                print_error(f"{self._pack_name} pack is missing {Pack.USER_METADATA} file.")
                return task_status

            with open(user_metadata_path, "r") as user_metadata_file:
                user_metadata = json.load(user_metadata_file)  # loading user metadata

            dependencies_data = self._load_pack_dependencies(index_folder_path,
                                                             user_metadata.get('dependencies', {}),
                                                             user_metadata.get('displayedImages', []))
            formatted_metadata = Pack._parse_pack_metadata(user_metadata=user_metadata,
                                                           pack_content_items=pack_content_items,
                                                           pack_id=self._pack_name,
                                                           integration_images=integration_images,
                                                           author_image=author_image,
                                                           dependencies_data=dependencies_data)

            with open(metadata_path, "w") as metadata_file:
                json.dump(formatted_metadata, metadata_file, indent=4)  # writing back parsed metadata

            print_color(f"Finished formatting {self._pack_name} packs's {Pack.METADATA} {metadata_path} file.",
                        LOG_COLORS.GREEN)
            task_status = True
        except Exception as e:
            print_error(f"Failed in formatting {self._pack_name} pack metadata. Additional info:\n{e}")
        finally:
            return task_status

    def parse_release_notes(self):
        """Need to implement the changelog.md parsing and changelog.json creation after design is finalized.

        """
        changelog_md_path = os.path.join(self._pack_path, Pack.CHANGELOG_MD)

        if not os.path.exists(changelog_md_path):
            print_error(f"The pack {self._pack_name} is missing {Pack.CHANGELOG_MD} file.")
            sys.exit(1)

        # with open(changelog_md_path, 'r') as release_notes_file:
        #     release_notes = release_notes_file.read()
        # todo implement release notes logic and create changelog.json

        return {}

    def prepare_for_index_upload(self):
        """Removes and leaves only necessary files in pack folder.

        Returns:
            bool: whether the operation succeeded.
        """
        task_status = False
        files_to_leave = [Pack.METADATA, Pack.CHANGELOG_JSON, Pack.README]

        try:
            for file_or_folder in os.listdir(self._pack_path):
                files_or_folder_path = os.path.join(self._pack_path, file_or_folder)

                if file_or_folder in files_to_leave:
                    continue

                if os.path.isdir(files_or_folder_path):
                    shutil.rmtree(files_or_folder_path)
                else:
                    os.remove(files_or_folder_path)

            task_status = True
        except Exception as e:
            print_error(f"Failed in preparing index for upload in {self._pack_name} pack.\n Additional info: {e}")
        finally:
            return task_status

    def _search_for_images(self, target_folder, folder_depth=2):
        """Searches for png files in targeted folder.

        Args:
            target_folder (str): full path to directory to search.
            folder_depth (int): depth of traversal inside target folder.

        Returns:
            list: list of dictionaries that include image path and display name of integration, example:
            [{'repo_image_path': image_path, 'display_name': integration_display_name},...]
        """
        target_folder_path = os.path.join(self._pack_repo_path, target_folder)
        local_repo_images = []

        if os.path.exists(target_folder_path):
            for (root, _, target_folder_files) in os.walk(target_folder_path, topdown=True):
                image_data = {}

                if root[len(target_folder_path):].count(os.sep) < folder_depth:
                    for pack_file in target_folder_files:
                        if pack_file.startswith('.'):
                            continue
                        elif pack_file.endswith('_image.png'):
                            image_data['repo_image_path'] = os.path.join(root, pack_file)
                        elif pack_file.endswith('.yml'):
                            with open(os.path.join(root, pack_file), 'r') as integration_file:
                                integration_yml = yaml.safe_load(integration_file)
                                image_data['display_name'] = integration_yml.get('display', '')

                    if image_data:
                        local_repo_images.append(image_data)

        return local_repo_images

    def upload_integration_images(self, storage_bucket):
        """Uploads pack integrations images to gcs.

        The returned result of integration section are defined in issue #19786.

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where image will be uploaded.

        Returns:
            bool: whether the operation succeeded.
            list: list of dictionaries with uploaded pack integration images.

        """
        task_status = True
        uploaded_integration_images = []

        try:
            pack_local_images = self._search_for_images(target_folder=INTEGRATIONS_FOLDER)

            if not pack_local_images:
                return uploaded_integration_images  # returned empty list if not images found

            pack_storage_root_path = os.path.join(STORAGE_BASE_PATH, self._pack_name)

            for image_data in pack_local_images:
                image_local_path = image_data.get('repo_image_path')
                if not image_local_path:
                    raise Exception(f"{self._pack_name} pack integration image was not found")

                image_name = os.path.basename(image_local_path)
                image_storage_path = os.path.join(pack_storage_root_path, image_name)
                pack_image_blob = storage_bucket.blob(image_storage_path)

                with open(image_local_path, "rb") as image_file:
                    pack_image_blob.upload_from_file(image_file)
                    uploaded_integration_images.append({
                        'name': image_data.get('display_name', ''),
                        'imagePath': pack_image_blob.name if USE_GCS_RELATIVE_PATH else pack_image_blob.public_url
                    })

            print(f"Uploaded {len(pack_local_images)} images for {self._pack_name} pack.")
        except Exception as e:
            task_status = False
            print_error(f"Failed to upload {self._pack_name} pack integration images. Additional info:\n{e}")
        finally:
            return task_status, uploaded_integration_images

    def upload_author_image(self, storage_bucket):
        """Uploads pack author image to gcs.

        Searches for `Author_image.png` and uploads author image to gcs. In case no such image was found,
        default Base pack image path is used and it's gcp path is returned.

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where author image will be uploaded.

        Returns:
            bool: whether the operation succeeded.
            str: public gcp path of author image.

        """
        task_status = True
        author_image_storage_path = ""

        try:
            repo_author_image_path = os.path.join(self._pack_repo_path, Pack.AUTHOR_IMAGE_NAME)

            if os.path.exists(repo_author_image_path):
                image_to_upload_storage_path = os.path.join(STORAGE_BASE_PATH, self._pack_name, Pack.AUTHOR_IMAGE_NAME)
                pack_author_image_blob = storage_bucket.blob(image_to_upload_storage_path)

                with open(repo_author_image_path, "rb") as author_image_file:
                    pack_author_image_blob.upload_from_file(author_image_file)

                author_image_storage_path = pack_author_image_blob.name if USE_GCS_RELATIVE_PATH \
                    else pack_author_image_blob.public_url

                print_color(f"Uploaded successfully {self._pack_name} pack author image", LOG_COLORS.GREEN)
            else:  # use default Base pack image
                author_image_storage_path = os.path.join(STORAGE_BASE_PATH, BASE_PACK, Pack.AUTHOR_IMAGE_NAME)

                if not USE_GCS_RELATIVE_PATH:
                    # disable-secrets-detection-start
                    author_image_storage_path = os.path.join(GCS_PUBLIC_URL, storage_bucket.name,
                                                             author_image_storage_path)
                    # disable-secrets-detection-end
                print_color((f"Skipping uploading of {self._pack_name} pack author image "
                             f"and use default {BASE_PACK} pack image"), LOG_COLORS.GREEN)

        except Exception as e:
            print_error(f"Failed uploading {self._pack_name} pack author image. Additional info:\n {e}")
            task_status = False
            author_image_storage_path = ""
        finally:
            return task_status, author_image_storage_path

    def cleanup(self):
        """Finalization action, removes extracted pack folder.

        """
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path)
            print(f"Cleanup {self._pack_name} pack from: {self._pack_path}")


class PackStatus(enum.Enum):
    """Enum of pack upload status, is used in printing upload summary.

    """
    SUCCESS = "Successfully uploaded pack data to gcs"
    FAILED_IMAGES_UPLOAD = "Failed to upload pack integration images to gcs"
    FAILED_AUTHOR_IMAGE_UPLOAD = "Failed to upload pack author image to gcs"
    FAILED_METADATA_PARSING = "Failed to parse and create metadata.json"
    FAILED_COLLECT_ITEMS = "Failed to collect pack content items data"
    FAILED_ZIPPING_PACK_ARTIFACTS = "Failed zipping pack artifacts"
    FAILED_SIGNING_PACKS = "Failed to sign the packs"
    FAILED_PREPARING_INDEX_FOLDER = "Failed in preparing and cleaning necessary index files"
    FAILED_UPDATING_INDEX_FOLDER = "Failed updating index folder"
    FAILED_UPLOADING_PACK = "Failed in uploading pack zip to gcs"
    PACK_ALREADY_EXISTS = "Specified pack already exists in gcs under latest version"
    FAILED_REMOVING_PACK_SKIPPED_FOLDERS = "Failed to remove pack hidden and skipped folders"


def input_to_list(input_data):
    # todo add docstring and unit tests
    input_data = input_data if input_data else []
    return input_data if isinstance(input_data, list) else [s for s in input_data.split(',') if s]
