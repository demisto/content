import json
import os
import subprocess
import fnmatch
import re
import shutil
import yaml
import google.auth
from google.cloud import storage
import enum
import base64
import urllib.parse
import warnings
from distutils.util import strtobool
from distutils.version import LooseVersion
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
PACKS_FOLDER = "Packs"  # name of base packs folder inside content repo
PACKS_FULL_PATH = os.path.join(CONTENT_ROOT_PATH, PACKS_FOLDER)  # full path to Packs folder in content repo
IGNORED_FILES = ['__init__.py', 'ApiModules', 'NonSupported']  # files to ignore inside Packs folder
IGNORED_PATHS = [os.path.join(PACKS_FOLDER, p) for p in IGNORED_FILES]


class GCPConfig(object):
    """ Google cloud storage basic configurations

    """
    STORAGE_BASE_PATH = "content/packs"  # configurable base path for packs in gcs, can be modified
    IMAGES_BASE_PATH = "content/packs"  # images packs prefix stored in metadata
    STORAGE_CONTENT_PATH = "content"  # base path for content in gcs
    USE_GCS_RELATIVE_PATH = True  # whether to use relative path in uploaded to gcs images
    GCS_PUBLIC_URL = "https://storage.googleapis.com"  # disable-secrets-detection
    PRODUCTION_BUCKET = "marketplace-dist"
    BASE_PACK = "Base"  # base pack name
    INDEX_NAME = "index"  # main index folder name
    CORE_PACK_FILE_NAME = "corepacks.json"  # core packs file name
    CORE_PACKS_LIST = [BASE_PACK,
                       "rasterize",
                       "DemistoRESTAPI",
                       "DemistoLocking",
                       "ImageOCR",
                       "WhereIsTheEgg",
                       "FeedAutofocus",
                       "AutoFocus",
                       "UrlScan",
                       "Active_Directory_Query",
                       "FeedTAXII",
                       "VirusTotal",
                       "Whois",
                       "Phishing",
                       "CommonScripts",
                       "CommonPlaybooks",
                       "CommonTypes",
                       "CommonDashboards",
                       "CommonReports",
                       "CommonWidgets",
                       "TIM_Processing",
                       "TIM_SIEM",
                       "HelloWorld",
                       "ExportIndicators",
                       "Malware",
                       "DefaultPlaybook",
                       "CalculateTimeDifference"
                       ]  # cores packs list


class Metadata(object):
    """ Metadata constants and default values that are used in metadata parsing.
    """
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    XSOAR_SUPPORT = "xsoar"
    XSOAR_SUPPORT_URL = "https://www.paloaltonetworks.com/cortex"  # disable-secrets-detection
    XSOAR_AUTHOR = "Cortex XSOAR"
    SERVER_DEFAULT_MIN_VERSION = "6.0.0"
    CERTIFIED = "certified"
    EULA_URL = "https://github.com/demisto/content/blob/master/LICENSE"  # disable-secrets-detection


class PackFolders(enum.Enum):
    """ Pack known folders. Should be replaced by constants from demisto-sdk in later step.

    """
    SCRIPTS = "Scripts"
    PLAYBOOKS = "Playbooks"
    INTEGRATIONS = "Integrations"
    TEST_PLAYBOOKS = 'TestPlaybooks'
    REPORTS = "Reports"
    DASHBOARDS = 'Dashboards'
    WIDGETS = 'Widgets'
    INCIDENT_FIELDS = 'IncidentFields'
    INCIDENT_TYPES = 'IncidentTypes'
    INDICATOR_FIELDS = 'IndicatorFields'
    LAYOUTS = 'Layouts'
    CLASSIFIERS = 'Classifiers'
    INDICATOR_TYPES = 'IndicatorTypes'
    CONNECTIONS = "Connections"

    @classmethod
    def pack_displayed_items(cls):
        return {
            PackFolders.SCRIPTS.value, PackFolders.DASHBOARDS.value, PackFolders.INCIDENT_FIELDS.value,
            PackFolders.INCIDENT_TYPES.value, PackFolders.INTEGRATIONS.value, PackFolders.PLAYBOOKS.value,
            PackFolders.INDICATOR_FIELDS.value, PackFolders.REPORTS.value, PackFolders.INDICATOR_TYPES.value,
            PackFolders.LAYOUTS.value, PackFolders.CLASSIFIERS.value, PackFolders.WIDGETS.value
        }

    @classmethod
    def yml_supported_folders(cls):
        return {PackFolders.INTEGRATIONS.value, PackFolders.SCRIPTS.value, PackFolders.PLAYBOOKS.value,
                PackFolders.TEST_PLAYBOOKS.value}

    @classmethod
    def json_supported_folders(cls):
        return {PackFolders.CLASSIFIERS.value, PackFolders.CONNECTIONS.value, PackFolders.DASHBOARDS.value,
                PackFolders.INCIDENT_FIELDS.value, PackFolders.INCIDENT_TYPES.value, PackFolders.INDICATOR_FIELDS.value,
                PackFolders.LAYOUTS.value, PackFolders.INDICATOR_TYPES.value, PackFolders.REPORTS.value,
                PackFolders.WIDGETS.value}


class PackStatus(enum.Enum):
    """ Enum of pack upload status, is used in printing upload summary.

    """
    SUCCESS = "Successfully uploaded pack data to gcs"
    FAILED_LOADING_USER_METADATA = "Failed in loading user defined metadata"
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
    PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD = "Specific pack is not updated in current build"
    FAILED_REMOVING_PACK_SKIPPED_FOLDERS = "Failed to remove pack hidden and skipped folders"
    FAILED_RELEASE_NOTES = "Failed to generate changelog.json"
    FAILED_DETECTING_MODIFIED_FILES = "Failed in detecting modified files of the pack"


class Pack(object):
    """ Class that manipulates and manages the upload of pack's artifact and metadata to cloud storage.

    Args:
        pack_name (str): Pack root folder name.
        pack_path (str): Full path to pack folder.

    Attributes:
        PACK_INITIAL_VERSION (str): pack initial version that will be used as default.
        CHANGELOG_JSON (str): changelog json full name, may be changed in the future.
        README (str): pack's readme file name.
        METADATA (str): pack's metadata file name, the one that will be deployed to cloud storage.
        USER_METADATA (str); user metadata file name, the one that located in content repo.
        EXCLUDE_DIRECTORIES (list): list of directories to excluded before uploading pack zip to storage.
        AUTHOR_IMAGE_NAME (str): author image file name.
        RELEASE_NOTES (str): release notes folder name.

    """
    PACK_INITIAL_VERSION = "1.0.0"
    CHANGELOG_JSON = "changelog.json"
    README = "README.md"
    USER_METADATA = "pack_metadata.json"
    METADATA = "metadata.json"
    AUTHOR_IMAGE_NAME = "Author_image.png"
    EXCLUDE_DIRECTORIES = [PackFolders.TEST_PLAYBOOKS.value]
    RELEASE_NOTES = "ReleaseNotes"

    def __init__(self, pack_name, pack_path):
        self._pack_name = pack_name
        self._pack_path = pack_path
        self._status = None
        self._public_storage_path = ""
        self._remove_files_list = []  # tracking temporary files, in order to delete in later step
        self._sever_min_version = "1.0.0"  # initialized min version
        self._latest_version = None  # pack latest version found in changelog
        self._support_type = None  # initialized in load_user_metadata function
        self._current_version = None  # initialized in load_user_metadata function
        self._hidden = False  # initialized in load_user_metadata function
        self._description = None  # initialized in load_user_metadata function
        self._display_name = None  # initialized in load_user_metadata function

    @property
    def name(self):
        """ str: pack root folder name.
        """
        return self._pack_name

    @property
    def path(self):
        """ str: pack folder full path.
        """
        return self._pack_path

    @property
    def latest_version(self):
        """ str: pack latest version from sorted keys of changelog.json file.
        """
        if not self._latest_version:
            self._latest_version = self._get_latest_version()
            return self._latest_version
        else:
            return self._latest_version

    @property
    def status(self):
        """ str: current status of the packs.
        """
        return self._status

    @status.setter
    def status(self, status_value):
        """ setter of pack current status.
        """
        self._status = status_value

    @property
    def public_storage_path(self):
        """ str: public gcs path of uploaded pack.
        """
        return self._public_storage_path

    @public_storage_path.setter
    def public_storage_path(self, path_value):
        """ setter of public gcs path of uploaded pack.
        """
        self._public_storage_path = path_value

    @property
    def support_type(self):
        """ str: support type of the pack.
        """
        return self._support_type

    @support_type.setter
    def support_type(self, support_value):
        """ setter of support type of the pack.
        """
        self._support_type = support_value

    @property
    def current_version(self):
        """ str: current version of the pack (different from latest_version).
        """
        return self._current_version

    @current_version.setter
    def current_version(self, current_version_value):
        """ setter of current version of the pack.
        """
        self._current_version = current_version_value

    @property
    def hidden(self):
        """ bool: internal content field for preventing pack from being displayed.
        """
        return self._hidden

    @hidden.setter
    def hidden(self, hidden_value):
        """ setter of hidden property of the pack.
        """
        self._hidden = hidden_value

    @property
    def description(self):
        """ str: Description of the pack (found in pack_metadata.json).
        """
        return self._description

    @description.setter
    def description(self, description_value):
        """ setter of description property of the pack.
        """
        self._description = description_value

    @property
    def display_name(self):
        """ str: Display name of the pack (found in pack_metadata.json).
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name_value):
        """ setter of display name property of the pack.
        """
        self._display_name = display_name_value

    @property
    def server_min_version(self):
        """ str: server min version according to collected items.
        """
        if not self._sever_min_version or self._sever_min_version == "1.0.0":
            return Metadata.SERVER_DEFAULT_MIN_VERSION
        else:
            return self._sever_min_version

    def _get_latest_version(self):
        """ Return latest semantic version of the pack.

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
                dependency_integration_gcs_path = dependency_integration.get('imagePath', '')  # image public url
                dependency_pack_name = os.path.basename(
                    os.path.dirname(dependency_integration_gcs_path))  # extract pack name from public url

                if dependency_pack_name not in display_dependencies_images:
                    continue  # skip if integration image is not part of displayed pack

                if dependency_integration not in pack_integration_images:  # avoid duplicates in list
                    pack_integration_images.append(dependency_integration)

        return pack_integration_images

    @staticmethod
    def _clean_release_notes(release_notes_lines):
        return re.sub(r'<\!--.*?-->', '', release_notes_lines, flags=re.DOTALL)

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
                             if k in first_level_dependencies.keys() or k == GCPConfig.BASE_PACK}

        for dependency_id, dependency_data in dependencies_data.items():
            parsed_result[dependency_id] = {
                "mandatory": first_level_dependencies.get(dependency_id, {}).get('mandatory', True),
                "minVersion": dependency_data.get('currentVersion', Pack.PACK_INITIAL_VERSION),
                "author": dependency_data.get('author', ''),
                "name": dependency_data.get('name') if dependency_data.get('name') else dependency_id,
                "certification": dependency_data.get('certification', 'certified')
            }

        return parsed_result

    @staticmethod
    def _create_support_section(support_type, support_url=None, support_email=None):
        """ Creates support dictionary that is part of metadata.

        In case of support type xsoar, adds default support url. If support is xsoar and support url is defined and
        doesn't match xsoar default url, warning is raised.

        Args:
            support_type (str): support type of pack.
            support_url (str): support full url.
            support_email (str): support email address.

        Returns:
            dict: supported data dictionary.
        """
        support_details = {}

        if support_url:  # set support url from user input
            support_details['url'] = support_url
        elif support_type == Metadata.XSOAR_SUPPORT:  # in case support type is xsoar, set default xsoar support url
            support_details['url'] = Metadata.XSOAR_SUPPORT_URL
        # add support email if defined
        if support_email:
            support_details['email'] = support_email

        return support_details

    @staticmethod
    def _get_author(support_type, author=None):
        """ Returns pack author. In case support type is xsoar, more additional validation are applied.

        Args:
            support_type (str): support type of pack.
            author (str): author of the pack.

        Returns:
            str: returns author from the input.
        """
        if support_type == Metadata.XSOAR_SUPPORT and not author:
            return Metadata.XSOAR_AUTHOR  # returned xsoar default author
        elif support_type == Metadata.XSOAR_SUPPORT and author != Metadata.XSOAR_AUTHOR:
            print_warning(f"{author} author doest not match {Metadata.XSOAR_AUTHOR} default value")
            return author
        else:
            return author

    @staticmethod
    def _get_certification(support_type, certification=None):
        """ Returns pack certification.

        In case support type is xsoar, CERTIFIED is returned.
        In case support is not xsoar but pack_metadata has certification field, certification value will be taken from
        pack_metadata defined value.
        Otherwise empty certification value (empty string) will be returned

        Args:
            support_type (str): support type of pack.
            certification (str): certification value from pack_metadata, if exists.

        Returns:
            str: certification value
        """
        if support_type == Metadata.XSOAR_SUPPORT:
            return Metadata.CERTIFIED
        elif support_type != Metadata.XSOAR_SUPPORT and certification:
            return certification
        else:
            return ""

    @staticmethod
    def _parse_pack_metadata(user_metadata, pack_content_items, pack_id, integration_images, author_image,
                             dependencies_data, server_min_version, build_number, commit_hash):
        """ Parses pack metadata according to issue #19786 and #20091. Part of field may change over the time.

        Args:
            user_metadata (dict): user metadata that was created in pack initialization.
            pack_content_items (dict): content items located inside specific pack.
            pack_id (str): pack unique identifier.
            integration_images (list): list of gcs uploaded integration images.
            author_image (str): gcs uploaded author image
            dependencies_data (dict): mapping of pack dependencies data, of all levels.
            server_min_version (str): server minimum version found during the iteration over content items.
            build_number (str): circleCI build number.
            commit_hash (str): current commit hash.

        Returns:
            dict: parsed pack metadata.

        """
        pack_metadata = {}
        pack_metadata['name'] = user_metadata.get('name') or pack_id
        pack_metadata['id'] = pack_id
        pack_metadata['description'] = user_metadata.get('description') or pack_id
        pack_metadata['created'] = user_metadata.get('created', datetime.utcnow().strftime(Metadata.DATE_FORMAT))
        pack_metadata['updated'] = datetime.utcnow().strftime(Metadata.DATE_FORMAT)
        pack_metadata['legacy'] = user_metadata.get('legacy', True)
        pack_metadata['support'] = user_metadata.get('support') or Metadata.XSOAR_SUPPORT
        pack_metadata['supportDetails'] = Pack._create_support_section(support_type=pack_metadata['support'],
                                                                       support_url=user_metadata.get('url'),
                                                                       support_email=user_metadata.get('email'))
        pack_metadata['eulaLink'] = Metadata.EULA_URL
        pack_metadata['author'] = Pack._get_author(support_type=pack_metadata['support'],
                                                   author=user_metadata.get('author', ''))
        pack_metadata['authorImage'] = author_image
        pack_metadata['certification'] = Pack._get_certification(support_type=pack_metadata['support'],
                                                                 certification=user_metadata.get('certification'))
        pack_metadata['price'] = convert_price(pack_id=pack_id, price_value_input=user_metadata.get('price'))
        pack_metadata['serverMinVersion'] = user_metadata.get('serverMinVersion') or server_min_version
        pack_metadata['currentVersion'] = user_metadata.get('currentVersion', '')
        pack_metadata['versionInfo'] = build_number
        pack_metadata['commit'] = commit_hash
        pack_metadata['tags'] = input_to_list(input_data=user_metadata.get('tags'))
        pack_metadata['categories'] = input_to_list(input_data=user_metadata.get('categories'), capitalize_input=True)
        pack_metadata['contentItems'] = pack_content_items
        pack_metadata['integrations'] = Pack._get_all_pack_images(integration_images,
                                                                  user_metadata.get('displayedImages', []),
                                                                  dependencies_data)
        pack_metadata['useCases'] = input_to_list(input_data=user_metadata.get('useCases'), capitalize_input=True)
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

        if self._pack_name != GCPConfig.BASE_PACK:  # check that current pack isn't Base Pack in order to prevent loop
            dependencies_ids.add(GCPConfig.BASE_PACK)  # Base pack is always added as pack dependency

        for dependency_pack_id in dependencies_ids:
            dependency_metadata_path = os.path.join(index_folder_path, dependency_pack_id, Pack.METADATA)

            if os.path.exists(dependency_metadata_path):
                with open(dependency_metadata_path, 'r') as metadata_file:
                    dependency_metadata = json.load(metadata_file)
                    dependencies_data_result[dependency_pack_id] = dependency_metadata
            else:
                print_warning(f"{self._pack_name} pack dependency with id {dependency_pack_id} was not found")
                continue

        return dependencies_data_result

    @staticmethod
    def _create_changelog_entry(release_notes, version_display_name, build_number, new_version=True):
        """ Creates dictionary entry for changelog.

        Args:
            release_notes (str): release notes md.
            version_display_name (str): display name version.
            build_number (srt): current build number.
            new_version (bool): whether the entry is new or not. If not new, R letter will be appended to build number.

        Returns:
            dict: release notes entry of changelog

        """
        if new_version:
            return {'releaseNotes': release_notes,
                    'displayName': f'{version_display_name} - {build_number}',
                    'released': datetime.utcnow().strftime(Metadata.DATE_FORMAT)}
        else:
            return {'releaseNotes': release_notes,
                    'displayName': f'{version_display_name} - R{build_number}',
                    'released': datetime.utcnow().strftime(Metadata.DATE_FORMAT)}

    def remove_unwanted_files(self, delete_test_playbooks=True):
        """ Iterates over pack folder and removes hidden files and unwanted folders.

        Args:
            delete_test_playbooks (bool): whether to delete test playbooks folder.

        Returns:
            bool: whether the operation succeeded.
        """
        task_status = True

        try:
            for root, dirs, files in os.walk(self._pack_path, topdown=True):
                for pack_file in files:
                    full_file_path = os.path.join(root, pack_file)
                    # removing unwanted files
                    if pack_file.startswith('.') \
                            or pack_file in [Pack.AUTHOR_IMAGE_NAME, Pack.USER_METADATA] \
                            or pack_file in self._remove_files_list:
                        os.remove(full_file_path)
                        print(f"Deleted pack {pack_file} file for {self._pack_name} pack")
                        continue

                    current_directory = root.split(os.path.sep)[-1]

                    if current_directory in Pack.EXCLUDE_DIRECTORIES and os.path.isdir(root) and delete_test_playbooks:
                        shutil.rmtree(root)
                        print(f"Deleted pack {current_directory} directory for {self._pack_name} pack")
                        continue

        except Exception as e:
            task_status = False
            print_error(f"Failed to delete ignored files for pack {self._pack_name} - {str(e)}")
        finally:
            return task_status

    def sign_pack(self, signature_string=None):
        """ Signs pack folder and creates signature file.

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
                arg = f'./signDirectory {self._pack_path} keyfile base64'
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
        """ Zips pack folder.

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
            print_error(f"Failed in zipping {self._pack_name} folder. Additional info:\n {e}")
        finally:
            return task_status, zip_pack_path

    def detect_modified(self, content_repo, index_folder_path, current_commit_hash, remote_previous_commit_hash):
        """ Detects pack modified files.

        The diff is done between current commit and previous commit that was saved in metadata that was downloaded from
        index. In case that no commit was found in index (initial run), the default value will be set to previous commit
        from origin/master.

        Args:
            content_repo (git.repo.base.Repo): content repo object.
            index_folder_path (str): full path to downloaded index folder.
            current_commit_hash (str): last commit hash of head.
            remote_previous_commit_hash (str): previous commit of origin/master (origin/master~1)

        Returns:
            bool: whether the operation succeeded.
            bool: whether pack was modified and override will be required.
        """
        task_status = False
        pack_was_modified = False

        try:
            pack_index_metadata_path = os.path.join(index_folder_path, self._pack_name, Pack.METADATA)

            if not os.path.exists(pack_index_metadata_path):
                print(f"{self._pack_name} pack was not found in index, skipping detection of modified pack.")
                task_status = True
                return

            with open(pack_index_metadata_path, 'r') as metadata_file:
                downloaded_metadata = json.load(metadata_file)

            previous_commit_hash = downloaded_metadata.get('commit', remote_previous_commit_hash)
            # set 2 commits by hash value in order to check the modified files of the diff
            current_commit = content_repo.commit(current_commit_hash)
            previous_commit = content_repo.commit(previous_commit_hash)

            for modified_file in current_commit.diff(previous_commit).iter_change_type('M'):
                if modified_file.a_path.startswith(PACKS_FOLDER):
                    modified_file_path_parts = os.path.normpath(modified_file.a_path).split(os.sep)

                    if modified_file_path_parts[1] and modified_file_path_parts[1] == self._pack_name:
                        print(f"Detected modified files in {self._pack_name} pack")
                        task_status, pack_was_modified = True, True
                        return

            task_status = True
        except Exception as e:
            print_error(f"Failed in detecting modified files of {self._pack_name} pack. Additional info:\n {e}")
        finally:
            return task_status, pack_was_modified

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
            version_pack_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name, latest_version)
            existing_files = [f.name for f in storage_bucket.list_blobs(prefix=version_pack_path)]

            if existing_files and not override_pack:
                print_warning(f"The following packs already exist at storage: {', '.join(existing_files)}")
                print_warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
                return task_status, True

            pack_full_path = f"{version_pack_path}/{self._pack_name}.zip"
            blob = storage_bucket.blob(pack_full_path)
            blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob

            with open(zip_pack_path, "rb") as pack_zip:
                blob.upload_from_file(pack_zip)

            self.public_storage_path = blob.public_url
            print_color(f"Uploaded {self._pack_name} pack to {pack_full_path} path.", LOG_COLORS.GREEN)

            return task_status, False
        except Exception as e:
            task_status = False
            print_error(f"Failed in uploading {self._pack_name} pack to gcs. Additional info:\n {e}")
            return task_status, True

    def prepare_release_notes(self, index_folder_path, build_number):
        """
        Handles the creation and update of the changelog.json files.

        Args:
            index_folder_path (str): Path to the unzipped index json.
            build_number (str): circleCI build number.
        Returns:
            bool: whether the operation succeeded.
            bool: whether running build has not updated pack release notes.
        """
        task_status = False
        not_updated_build = False

        try:
            if os.path.exists(os.path.join(index_folder_path, self._pack_name, Pack.CHANGELOG_JSON)):
                print_color(f"Found Changelog for: {self._pack_name}", LOG_COLORS.NATIVE)
                # load changelog from downloaded index
                changelog_index_path = os.path.join(index_folder_path, self._pack_name, Pack.CHANGELOG_JSON)
                with open(changelog_index_path, "r") as changelog_file:
                    changelog = json.load(changelog_file)

                release_notes_dir = os.path.join(self._pack_path, Pack.RELEASE_NOTES)

                if os.path.exists(release_notes_dir):
                    found_versions = []
                    for filename in os.listdir(release_notes_dir):
                        _version = filename.replace('.md', '')
                        version = _version.replace('_', '.')
                        found_versions.append(LooseVersion(version))
                    found_versions.sort(reverse=True)
                    latest_release_notes = found_versions[0].vstring

                    print_color(f"Latest ReleaseNotes version is: {latest_release_notes}", LOG_COLORS.GREEN)
                    # load latest release notes
                    latest_rn_file = latest_release_notes.replace('.', '_')
                    latest_rn_path = os.path.join(release_notes_dir, latest_rn_file + '.md')

                    with open(latest_rn_path, 'r') as changelog_md:
                        release_notes_lines = changelog_md.read()
                    release_notes_lines = self._clean_release_notes(release_notes_lines)

                    if self._current_version != latest_release_notes:
                        # TODO Need to implement support for pre-release versions
                        print_error(f"Version mismatch detected between current version: {self._current_version} "
                                    f"and latest release notes version: {latest_release_notes}")
                        task_status = False
                        return task_status, not_updated_build
                    else:
                        if latest_release_notes in changelog:
                            print(f"Found existing release notes for version: {latest_release_notes}")
                            version_changelog = Pack._create_changelog_entry(release_notes=release_notes_lines,
                                                                             version_display_name=latest_release_notes,
                                                                             build_number=build_number,
                                                                             new_version=False)

                        else:
                            print(f"Created new release notes for version: {latest_release_notes}")
                            version_changelog = Pack._create_changelog_entry(release_notes=release_notes_lines,
                                                                             version_display_name=latest_release_notes,
                                                                             build_number=build_number,
                                                                             new_version=True)

                        changelog[latest_release_notes] = version_changelog
                else:  # will enter only on initial version and release notes folder still was not created
                    if len(changelog.keys()) > 1 or Pack.PACK_INITIAL_VERSION not in changelog:
                        print_warning(
                            f"{self._pack_name} pack mismatch between {Pack.CHANGELOG_JSON} and {Pack.RELEASE_NOTES}")
                        task_status, not_updated_build = True, True
                        return task_status, not_updated_build

                    changelog[Pack.PACK_INITIAL_VERSION] = Pack._create_changelog_entry(
                        release_notes=self.description,
                        version_display_name=Pack.PACK_INITIAL_VERSION,
                        build_number=build_number,
                        new_version=False)

                    print(f"Found existing release notes for version: {Pack.PACK_INITIAL_VERSION} "
                          f"in the {self._pack_name} pack.")

            elif self._current_version == Pack.PACK_INITIAL_VERSION:
                version_changelog = Pack._create_changelog_entry(
                    release_notes=self.description,
                    version_display_name=Pack.PACK_INITIAL_VERSION,
                    build_number=build_number,
                    new_version=True
                )
                changelog = {
                    Pack.PACK_INITIAL_VERSION: version_changelog
                }
            else:
                print_error(f"No release notes found for: {self._pack_name}")
                task_status = False
                return task_status, not_updated_build

            # write back changelog with changes to pack folder
            with open(os.path.join(self._pack_path, Pack.CHANGELOG_JSON), "w") as pack_changelog:
                json.dump(changelog, pack_changelog, indent=4)

            task_status = True
            print_color(f"Finished creating {Pack.CHANGELOG_JSON} for {self._pack_name}", LOG_COLORS.GREEN)
        except Exception as e:
            print_error(f"Failed creating {Pack.CHANGELOG_JSON} file for {self._pack_name}.\n "
                        f"Additional info: {e}")
        finally:
            return task_status, not_updated_build

    def collect_content_items(self):
        """ Iterates over content items folders inside pack and collects content items data.

        Returns:
            dict: Parsed content items
            .
        """
        task_status = False
        content_items_result = {}

        try:
            # the format is defined in issue #19786, may change in the future
            content_item_name_mapping = {
                PackFolders.SCRIPTS.value: "automation",
                PackFolders.PLAYBOOKS.value: "playbook",
                PackFolders.INTEGRATIONS.value: "integration",
                PackFolders.INCIDENT_FIELDS.value: "incidentfield",
                PackFolders.INCIDENT_TYPES.value: "incidenttype",
                PackFolders.DASHBOARDS.value: "dashboard",
                PackFolders.INDICATOR_FIELDS.value: "indicatorfield",
                PackFolders.REPORTS.value: "report",
                PackFolders.INDICATOR_TYPES.value: "reputation",
                PackFolders.LAYOUTS.value: "layout",
                PackFolders.CLASSIFIERS.value: "classifier",
                PackFolders.WIDGETS.value: "widget"
            }

            for root, pack_dirs, pack_files_names in os.walk(self._pack_path, topdown=False):
                current_directory = root.split(os.path.sep)[-1]

                folder_collected_items = []
                for pack_file_name in pack_files_names:
                    if not pack_file_name.endswith(('.json', '.yml')):
                        continue

                    pack_file_path = os.path.join(root, pack_file_name)

                    # reputation in old format aren't supported in 6.0.0 server version
                    if current_directory == PackFolders.INDICATOR_TYPES.value \
                            and not fnmatch.fnmatch(pack_file_name, 'reputation-*.json'):
                        os.remove(pack_file_path)
                        print(f"Deleted pack {pack_file_name} reputation file for {self._pack_name} pack")
                        continue

                    with open(pack_file_path, 'r') as pack_file:
                        if current_directory in PackFolders.yml_supported_folders():
                            content_item = yaml.safe_load(pack_file)
                        elif current_directory in PackFolders.json_supported_folders():
                            content_item = json.load(pack_file)
                        else:
                            continue

                    # check if content item has to version
                    to_version = content_item.get('toversion') or content_item.get('toVersion')

                    if to_version and LooseVersion(to_version) < LooseVersion(Metadata.SERVER_DEFAULT_MIN_VERSION):
                        os.remove(pack_file_path)
                        print(f"{self._pack_name} pack content item {pack_file_name} has to version: {to_version}. "
                              f"{pack_file_name} file was deleted.")
                        continue

                    if current_directory not in PackFolders.pack_displayed_items():
                        continue  # skip content items that are not displayed in contentItems

                    print(f"Iterating over {pack_file_path} file and collecting items of {self._pack_name} pack")
                    # updated min server version from current content item
                    self._sever_min_version = get_higher_server_version(self._sever_min_version, content_item,
                                                                        self._pack_name)

                    if current_directory == PackFolders.SCRIPTS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'description': content_item.get('comment', ""),
                            'tags': content_item.get('tags', [])
                        })
                    elif current_directory == PackFolders.PLAYBOOKS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'description': content_item.get('description', "")
                        })
                    elif current_directory == PackFolders.INTEGRATIONS.value:
                        integration_commands = content_item.get('script', {}).get('commands', [])

                        folder_collected_items.append({
                            'name': content_item.get('display', ""),
                            'description': content_item.get('description', ""),
                            'category': content_item.get('category', ""),
                            'commands': [
                                {'name': c.get('name', ""), 'description': c.get('description', "")}
                                for c in integration_commands]
                        })
                    elif current_directory == PackFolders.INCIDENT_FIELDS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'type': content_item.get('type', ""),
                            'description': content_item.get('description', "")
                        })
                    elif current_directory == PackFolders.INCIDENT_TYPES.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'playbook': content_item.get('playbookId', ""),
                            'closureScript': content_item.get('closureScript', ""),
                            'hours': int(content_item.get('hours', 0)),
                            'days': int(content_item.get('days', 0)),
                            'weeks': int(content_item.get('weeks', 0))
                        })
                    elif current_directory == PackFolders.DASHBOARDS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', "")
                        })
                    elif current_directory == PackFolders.INDICATOR_FIELDS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'type': content_item.get('type', ""),
                            'description': content_item.get('description', "")
                        })
                    elif current_directory == PackFolders.REPORTS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'description': content_item.get('description', "")
                        })
                    elif current_directory == PackFolders.INDICATOR_TYPES.value:
                        folder_collected_items.append({
                            'details': content_item.get('details', ""),
                            'reputationScriptName': content_item.get('reputationScriptName', ""),
                            'enhancementScriptNames': content_item.get('enhancementScriptNames', [])
                        })
                    elif current_directory == PackFolders.LAYOUTS.value:
                        folder_collected_items.append({
                            'typeId': content_item.get('typeId', ""),
                            'kind': content_item.get('kind', ""),
                            'version': 'v2' if 'tabs' in content_item.get('layout', {}) else 'v1'
                        })
                    elif current_directory == PackFolders.CLASSIFIERS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name') or content_item.get('id', ""),
                            'description': content_item.get('description', '')
                        })
                    elif current_directory == PackFolders.WIDGETS.value:
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'dataType': content_item.get('dataType', ""),
                            'widgetType': content_item.get('widgetType', "")
                        })

                if current_directory in PackFolders.pack_displayed_items():
                    content_item_key = content_item_name_mapping[current_directory]
                    content_items_result[content_item_key] = folder_collected_items

            print_color(f"Finished collecting content items for {self._pack_name} pack", LOG_COLORS.GREEN)
            task_status = True
        except Exception as e:
            print_error(f"Failed collecting content items in {self._pack_name} pack. Additional info:\n {e}")
        finally:
            return task_status, content_items_result

    def load_user_metadata(self):
        """ Loads user defined metadata and stores part of it's data in defined properties fields.

        Returns:
            dict: user metadata of pack defined in content repo pack (pack_metadata.json)

        """
        task_status = False
        user_metadata = {}

        try:
            user_metadata_path = os.path.join(self._pack_path, Pack.USER_METADATA)  # user metadata path before parsing

            if not os.path.exists(user_metadata_path):
                print_error(f"{self._pack_name} pack is missing {Pack.USER_METADATA} file.")
                return task_status, user_metadata

            with open(user_metadata_path, "r") as user_metadata_file:
                user_metadata = json.load(user_metadata_file)  # loading user metadata
                # part of old packs are initialized with empty list
                user_metadata = {} if isinstance(user_metadata, list) else user_metadata

            # store important user metadata fields
            self.support_type = user_metadata.get('support', Metadata.XSOAR_SUPPORT)
            self.current_version = user_metadata.get('currentVersion', '')
            self.hidden = user_metadata.get('hidden', False)
            self.description = user_metadata.get('description', False)
            self.display_name = user_metadata.get('name', '')

            print(f"Finished loading {self._pack_name} pack user metadata")
            task_status = True
        except Exception as e:
            print_error(f"Failed in loading {self._pack_name} user metadata. Additional info:\n{e}")
        finally:
            return task_status, user_metadata

    def format_metadata(self, user_metadata, pack_content_items, integration_images, author_image, index_folder_path,
                        packs_dependencies_mapping, build_number, commit_hash):
        """ Re-formats metadata according to marketplace metadata format defined in issue #19786 and writes back
        the result.

        Args:
            user_metadata (dict): user defined pack_metadata, prior the parsing process.
            pack_content_items (dict): content items that are located inside specific pack.
            integration_images (list): list of uploaded integration images with integration display name and image gcs
            public url.
            author_image (str): uploaded public gcs path to author image.
            index_folder_path (str): downloaded index folder directory path.
            packs_dependencies_mapping (dict): all packs dependencies lookup mapping.
            build_number (str): circleCI build number.
            commit_hash (str): current commit hash.

        Returns:
            bool: True is returned in case metadata file was parsed successfully, otherwise False.

        """
        task_status = False

        try:
            metadata_path = os.path.join(self._pack_path, Pack.METADATA)  # deployed metadata path after parsing

            if 'dependencies' not in user_metadata:
                user_metadata['dependencies'] = packs_dependencies_mapping.get(
                    self._pack_name, {}).get('dependencies', {})
                print(f"Adding auto generated dependencies for {self._pack_name} pack")

            if 'displayedImages' not in user_metadata:
                user_metadata['displayedImages'] = packs_dependencies_mapping.get(
                    self._pack_name, {}).get('displayedImages', [])
                print(f"Adding auto generated display images for {self._pack_name} pack")

            dependencies_data = self._load_pack_dependencies(index_folder_path,
                                                             user_metadata.get('dependencies', {}),
                                                             user_metadata.get('displayedImages', []))
            formatted_metadata = Pack._parse_pack_metadata(user_metadata=user_metadata,
                                                           pack_content_items=pack_content_items,
                                                           pack_id=self._pack_name,
                                                           integration_images=integration_images,
                                                           author_image=author_image,
                                                           dependencies_data=dependencies_data,
                                                           server_min_version=self.server_min_version,
                                                           build_number=build_number, commit_hash=commit_hash)

            with open(metadata_path, "w") as metadata_file:
                json.dump(formatted_metadata, metadata_file, indent=4)  # writing back parsed metadata

            print_color(f"Finished formatting {self._pack_name} packs's {Pack.METADATA} {metadata_path} file.",
                        LOG_COLORS.GREEN)
            task_status = True
        except Exception as e:
            print_error(f"Failed in formatting {self._pack_name} pack metadata. Additional info:\n{e}")
        finally:
            return task_status

    def prepare_for_index_upload(self):
        """ Removes and leaves only necessary files in pack folder.

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

    @staticmethod
    def _get_spitted_yml_image_data(root, target_folder_files):
        """ Retrieves pack integration image and integration display name and returns binding image data.

        Args:
            root (str): full path to the target folder to search integration image.
            target_folder_files (list): list of files inside the targeted folder.

        Returns:
            dict: path to integration image and display name of the integration.

        """
        image_data = {}

        for pack_file in target_folder_files:
            if pack_file.startswith('.'):
                continue
            elif pack_file.endswith('_image.png'):
                image_data['repo_image_path'] = os.path.join(root, pack_file)
            elif pack_file.endswith('.yml'):
                with open(os.path.join(root, pack_file), 'r') as integration_file:
                    integration_yml = yaml.safe_load(integration_file)
                    image_data['display_name'] = integration_yml.get('display', '')

        return image_data

    def _get_image_data_from_yml(self, pack_file_path):
        """ Creates temporary image file and retrieves integration display name.

        Args:
            pack_file_path (str): full path to the target yml_path integration yml to search integration image.

        Returns:
            dict: path to temporary integration image and display name of the integrations.

        """
        image_data = {}

        if pack_file_path.endswith('.yml'):
            with open(pack_file_path, 'r') as integration_file:
                integration_yml = yaml.safe_load(integration_file)

            image_data['display_name'] = integration_yml.get('display', '')
            # create temporary file of base64 decoded data
            integration_name = integration_yml.get('name', '')
            base64_image = integration_yml['image'].split(',')[1] if integration_yml.get('image') else None

            if not base64_image:
                print_warning(f"{integration_name} integration image was not found in {self._pack_name} pack")
                return {}

            temp_image_name = f'{integration_name.replace(" ", "")}_image.png'
            temp_image_path = os.path.join(self._pack_path, temp_image_name)

            with open(temp_image_path, 'wb') as image_file:
                image_file.write(base64.b64decode(base64_image))

            self._remove_files_list.append(temp_image_name)  # add temporary file to tracking list
            image_data['image_path'] = temp_image_path

            print(f"Created temporary integration {image_data['display_name']} image for {self._pack_name} pack")

        return image_data

    def _search_for_images(self, target_folder):
        """ Searches for png files in targeted folder.

        Args:
            target_folder (str): full path to directory to search.

        Returns:
            list: list of dictionaries that include image path and display name of integration, example:
            [{'image_path': image_path, 'display_name': integration_display_name},...]
        """
        target_folder_path = os.path.join(self._pack_path, target_folder)
        images_list = []

        if os.path.exists(target_folder_path):
            for pack_item in os.scandir(target_folder_path):
                image_data = self._get_image_data_from_yml(pack_item.path)

                if image_data and image_data not in images_list:
                    images_list.append(image_data)

        return images_list

    def upload_integration_images(self, storage_bucket):
        """ Uploads pack integrations images to gcs.

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
            pack_local_images = self._search_for_images(target_folder=PackFolders.INTEGRATIONS.value)

            if not pack_local_images:
                return uploaded_integration_images  # returned empty list if not images found

            pack_storage_root_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name)

            for image_data in pack_local_images:
                image_path = image_data.get('image_path')
                if not image_path:
                    raise Exception(f"{self._pack_name} pack integration image was not found")

                image_name = os.path.basename(image_path)
                image_storage_path = os.path.join(pack_storage_root_path, image_name)
                pack_image_blob = storage_bucket.blob(image_storage_path)

                print(f"Uploading {self._pack_name} pack integration image: {image_name}")
                with open(image_path, "rb") as image_file:
                    pack_image_blob.upload_from_file(image_file)

                if GCPConfig.USE_GCS_RELATIVE_PATH:
                    image_gcs_path = urllib.parse.quote(
                        os.path.join(GCPConfig.IMAGES_BASE_PATH, self._pack_name, image_name))
                else:
                    image_gcs_path = pack_image_blob.public_url

                uploaded_integration_images.append({
                    'name': image_data.get('display_name', ''),
                    'imagePath': image_gcs_path
                })

            print(f"Uploaded {len(pack_local_images)} images for {self._pack_name} pack.")
        except Exception as e:
            task_status = False
            print_error(f"Failed to upload {self._pack_name} pack integration images. Additional info:\n{e}")
        finally:
            return task_status, uploaded_integration_images

    def upload_author_image(self, storage_bucket):
        """ Uploads pack author image to gcs.

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
            author_image_path = os.path.join(self._pack_path, Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection

            if os.path.exists(author_image_path):
                image_to_upload_storage_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name,
                                                            Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection
                pack_author_image_blob = storage_bucket.blob(image_to_upload_storage_path)

                with open(author_image_path, "rb") as author_image_file:
                    pack_author_image_blob.upload_from_file(author_image_file)

                if GCPConfig.USE_GCS_RELATIVE_PATH:
                    author_image_storage_path = urllib.parse.quote(
                        os.path.join(GCPConfig.IMAGES_BASE_PATH, self._pack_name, Pack.AUTHOR_IMAGE_NAME))
                else:
                    author_image_storage_path = pack_author_image_blob.public_url

                print_color(f"Uploaded successfully {self._pack_name} pack author image", LOG_COLORS.GREEN)
            elif self.support_type == Metadata.XSOAR_SUPPORT:  # use default Base pack image for xsoar supported packs
                author_image_storage_path = os.path.join(GCPConfig.IMAGES_BASE_PATH, GCPConfig.BASE_PACK,
                                                         Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection

                if not GCPConfig.USE_GCS_RELATIVE_PATH:
                    # disable-secrets-detection-start
                    author_image_storage_path = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name,
                                                             author_image_storage_path)
                    # disable-secrets-detection-end
                print_color((f"Skipping uploading of {self._pack_name} pack author image "
                             f"and use default {GCPConfig.BASE_PACK} pack image"), LOG_COLORS.GREEN)
            else:
                print(f"Skipping uploading of {self._pack_name} pack. "
                      f"The pack is defined as {self.support_type} support type")

        except Exception as e:
            print_error(f"Failed uploading {self._pack_name} pack author image. Additional info:\n {e}")
            task_status = False
            author_image_storage_path = ""
        finally:
            return task_status, author_image_storage_path

    def cleanup(self):
        """ Finalization action, removes extracted pack folder.

        """
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path)
            print(f"Cleanup {self._pack_name} pack from: {self._pack_path}")


# HELPER FUNCTIONS

def init_storage_client(service_account=None):
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
        storage.Client: initialized google cloud storage client.
    """
    if service_account:
        storage_client = storage.Client.from_service_account_json(service_account)
        print("Created gcp service account")

        return storage_client
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        storage_client = storage.Client(credentials=credentials, project=project)
        print("Created gcp private account")

        return storage_client


def input_to_list(input_data, capitalize_input=False):
    """ Helper function for handling input list or str from the user.

    Args:
        input_data (list or str): input from the user to handle.
        capitalize_input (boo): whether to capitalize the input list data or not.

    Returns:
        list: returns the original list or list that was split by comma.

    """
    input_data = input_data if input_data else []
    input_data = input_data if isinstance(input_data, list) else [s for s in input_data.split(',') if s]

    if capitalize_input:
        return [i.title() for i in input_data]
    else:
        return input_data


def get_valid_bool(bool_input):
    """ Converts and returns valid bool.

    Returns:
        bool: converted bool input.
    """
    return bool(strtobool(bool_input)) if isinstance(bool_input, str) else bool_input


def convert_price(pack_id, price_value_input=None):
    """ Converts to integer value price input. In case no price input provided, return zero as price.

    Args:
        pack_id (str): pack unique identifier.
        price_value_input (str): price string to convert.

    Returns:
        int: converted to int pack price.
    """

    try:
        if not price_value_input:
            return 0  # in case no price was supported, return 0
        else:
            return int(price_value_input)  # otherwise convert to int and return result
    except Exception as e:
        print_warning(f"{pack_id} pack price is not valid. The price was set to 0. Additional "
                      f"details {e}")
        return 0


def get_higher_server_version(current_string_version, compared_content_item, pack_name):
    """ Compares two semantic server versions and returns the higher version between them.

    Args:
         current_string_version (str): current string version.
         compared_content_item (dict): compared content item entity.
         pack_name (str): the pack name (id).

    Returns:
        str: latest version between compared versions.
    """
    higher_version_result = current_string_version

    try:
        compared_string_version = compared_content_item.get('fromversion') or compared_content_item.get(
            'fromVersion') or "1.0.0"
        current_version, compared_version = LooseVersion(current_string_version), LooseVersion(compared_string_version)

        if current_version < compared_version:
            higher_version_result = compared_string_version
    except Exception as e:
        content_item_name = compared_content_item.get('name') or compared_content_item.get(
            'display') or compared_content_item.get('id') or compared_content_item.get('details', '')
        print_error(f"{pack_name} failed in version comparison of content item {content_item_name}. "
                    f"Additional info:\n {e}")
    finally:
        return higher_version_result
