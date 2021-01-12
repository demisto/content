import json
import os
import stat
import subprocess
import fnmatch
import re
import git
import sys
import shutil
import yaml
import google.auth
from google.cloud import storage
from google.cloud import bigquery
import enum
import base64
import urllib.parse
import logging
import warnings
from distutils.util import strtobool
from distutils.version import LooseVersion
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from Utils.release_notes_generator import aggregate_release_notes_for_marketplace
from typing import Tuple, Any, Union

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
PACKS_FOLDER = "Packs"  # name of base packs folder inside content repo
PACKS_FULL_PATH = os.path.join(CONTENT_ROOT_PATH, PACKS_FOLDER)  # full path to Packs folder in content repo
IGNORED_FILES = ['__init__.py', 'ApiModules', 'NonSupported']  # files to ignore inside Packs folder
IGNORED_PATHS = [os.path.join(PACKS_FOLDER, p) for p in IGNORED_FILES]


class BucketUploadFlow(object):
    """ Bucket Upload Flow constants

    """
    PACKS_RESULTS_FILE = "packs_results.json"
    PREPARE_CONTENT_FOR_TESTING = "prepare_content_for_testing"
    UPLOAD_PACKS_TO_MARKETPLACE_STORAGE = "upload_packs_to_marketplace_storage"
    SUCCESSFUL_PACKS = "successful_packs"
    FAILED_PACKS = "failed_packs"
    STATUS = "status"
    AGGREGATED = "aggregated"
    BUCKET_UPLOAD_BUILD_TITLE = "Upload Packs To Marketplace Storage"
    BUCKET_UPLOAD_TYPE = "bucket_upload_flow"
    UPLOAD_JOB_NAME = "Upload Packs To Marketplace"


class GCPConfig(object):
    """ Google cloud storage basic configurations

    """
    STORAGE_BASE_PATH = "content/packs"  # configurable base path for packs in gcs, can be modified
    IMAGES_BASE_PATH = "content/packs"  # images packs prefix stored in metadata
    BUILD_PATH_PREFIX = "content/builds"
    BUILD_BASE_PATH = ""
    PRIVATE_BASE_PATH = "content/packs"
    STORAGE_CONTENT_PATH = "content"  # base path for content in gcs
    USE_GCS_RELATIVE_PATH = True  # whether to use relative path in uploaded to gcs images
    GCS_PUBLIC_URL = "https://storage.googleapis.com"  # disable-secrets-detection
    PRODUCTION_BUCKET = "marketplace-dist"
    CI_BUILD_BUCKET = "marketplace-ci-build"
    PRODUCTION_PRIVATE_BUCKET = "marketplace-dist-private"
    CI_PRIVATE_BUCKET = "marketplace-ci-build-private"
    BASE_PACK = "Base"  # base pack name
    INDEX_NAME = "index"  # main index folder name
    CORE_PACK_FILE_NAME = "corepacks.json"  # core packs file name
    DOWNLOADS_TABLE = "oproxy-dev.shared_views.top_packs"  # packs downloads statistics table
    BIG_QUERY_MAX_RESULTS = 2000  # big query max row results

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_list.json'), 'r') as core_packs_list_file:
        CORE_PACKS_LIST = json.load(core_packs_list_file)


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
    FAILED_SEARCHING_PACK_IN_INDEX = "Failed in searching pack folder in index"
    FAILED_DECRYPT_PACK = "Failed to decrypt pack: a premium pack," \
                          " which should be encrypted, seems not to be encrypted."


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
        self._is_feed = False  # a flag that specifies if pack is a feed pack
        self._downloads_count = 0  # number of pack downloads
        self._bucket_url = None  # URL of where the pack was uploaded.
        self._aggregated = False  # weather the pack's rn was aggregated or not.
        self._aggregation_str = ""  # the aggregation string msg when the pack versions are aggregated

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

    @property
    def is_feed(self):
        """
        bool: whether the pack is a feed pack
        """
        return self._is_feed

    @is_feed.setter
    def is_feed(self, is_feed):
        """ setter of is_feed
        """
        self._is_feed = is_feed

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

    @property
    def downloads_count(self):
        """ str: packs downloads count.
        """
        return self._downloads_count

    @downloads_count.setter
    def downloads_count(self, download_count_value):
        """ setter of downloads count property of the pack.
        """
        self._downloads_count = download_count_value

    @property
    def bucket_url(self):
        """ str: pack bucket_url.
        """
        return self._bucket_url

    @bucket_url.setter
    def bucket_url(self, bucket_url):
        """ str: pack bucket_url.
        """
        self._bucket_url = bucket_url

    @property
    def aggregated(self):
        """ str: pack aggregated release notes or not.
        """
        return self._aggregated

    @property
    def aggregation_str(self):
        """ str: pack aggregated release notes or not.
        """
        return self._aggregation_str

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

    def is_feed_pack(self, yaml_content, yaml_type):
        """
        Checks if an integration is a feed integration. If so, updates Pack._is_feed
        Args:
            yaml_content: The yaml content extracted by yaml.safe_load().
            yaml_type: The type of object to check. Should be 'Playbook' or 'Integration'.

        Returns:
            Doesn't return
        """
        if yaml_type == 'Integration':
            if yaml_content.get('script', {}).get('feed', False) is True:
                self._is_feed = True
        if yaml_type == 'Playbook':
            if yaml_content.get('name').startswith('TIM '):
                self._is_feed = True

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
            logging.warning(f"{author} author doest not match {Metadata.XSOAR_AUTHOR} default value")
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
                             dependencies_data, server_min_version, build_number, commit_hash, downloads_count,
                             is_feed_pack=False):
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
            downloads_count (int): number of packs downloads.
            is_feed_pack (bool): a flag that indicates if the pack is a feed pack.

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
        if 'vendorId' in user_metadata:
            pack_metadata['premium'] = True
            pack_metadata['vendorId'] = user_metadata.get('vendorId')
            pack_metadata['vendorName'] = user_metadata.get('vendorName')
            if user_metadata.get('previewOnly'):
                pack_metadata['previewOnly'] = True
        pack_metadata['serverMinVersion'] = user_metadata.get('serverMinVersion') or server_min_version
        pack_metadata['currentVersion'] = user_metadata.get('currentVersion', '')
        pack_metadata['versionInfo'] = build_number
        pack_metadata['commit'] = commit_hash
        pack_metadata['downloads'] = downloads_count
        pack_metadata['tags'] = input_to_list(input_data=user_metadata.get('tags'))
        if is_feed_pack and 'TIM' not in pack_metadata['tags']:
            pack_metadata['tags'].append('TIM')
        pack_metadata['categories'] = input_to_list(input_data=user_metadata.get('categories'), capitalize_input=True)
        pack_metadata['contentItems'] = pack_content_items
        pack_metadata['integrations'] = Pack._get_all_pack_images(integration_images,
                                                                  user_metadata.get('displayedImages', []),
                                                                  dependencies_data)
        pack_metadata['useCases'] = input_to_list(input_data=user_metadata.get('useCases'), capitalize_input=True)
        if pack_metadata.get('useCases') and 'Use Case' not in pack_metadata['tags']:
            pack_metadata['tags'].append('Use Case')
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
                logging.warning(f"{self._pack_name} pack dependency with id {dependency_pack_id} was not found")
                continue

        return dependencies_data_result

    def _get_downloads_count(self, packs_statistic_df):
        """ Returns number of packs downloads.

        Args:
             packs_statistic_df (pandas.core.frame.DataFrame): packs downloads statistics table.

        Returns:
            int: number of packs downloads.
        """
        downloads_count = 0
        if self._pack_name in packs_statistic_df.index.values:
            downloads_count = int(packs_statistic_df.loc[self._pack_name]['num_count'].astype('int32'))

        return downloads_count

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
            for directory in Pack.EXCLUDE_DIRECTORIES:
                if delete_test_playbooks and os.path.isdir(f'{self._pack_path}/{directory}'):
                    shutil.rmtree(f'{self._pack_path}/{directory}')
                    logging.info(f"Deleted {directory} directory from {self._pack_name} pack")

            for root, dirs, files in os.walk(self._pack_path, topdown=True):
                for pack_file in files:
                    full_file_path = os.path.join(root, pack_file)
                    # removing unwanted files
                    if pack_file.startswith('.') \
                            or pack_file in [Pack.AUTHOR_IMAGE_NAME, Pack.USER_METADATA] \
                            or pack_file in self._remove_files_list:
                        os.remove(full_file_path)
                        logging.info(f"Deleted pack {pack_file} file for {self._pack_name} pack")
                        continue

        except Exception:
            task_status = False
            logging.exception(f"Failed to delete ignored files for pack {self._pack_name}")
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
                    logging.error(f"Failed to sign pack for {self._pack_name} - {str(err)}")
                    return

                logging.info(f"Signed {self._pack_name} pack successfully")
            else:
                logging.info(f"No signature provided. Skipped signing {self._pack_name} pack")
            task_status = True
        except Exception:
            logging.exception(f"Failed to sign pack for {self._pack_name}")
        finally:
            return task_status

    @staticmethod
    def encrypt_pack(zip_pack_path, pack_name, encryption_key, extract_destination_path):
        try:
            current_working_dir = os.getcwd()
            shutil.copy('./encryptor', os.path.join(extract_destination_path, 'encryptor'))
            os.chmod(os.path.join(extract_destination_path, 'encryptor'), stat.S_IXOTH)
            os.chdir(extract_destination_path)
            output_file = zip_pack_path.replace("_not_encrypted.zip", ".zip")
            subprocess.call('chmod +x ./encryptor', shell=True)
            full_command = f'./encryptor ./{pack_name}_not_encrypted.zip {output_file} "' \
                           f'{encryption_key}"'

            subprocess.call(full_command, shell=True)
            new_artefacts = os.path.join(current_working_dir, 'private_artifacts')
            if os.path.exists(new_artefacts):
                shutil.rmtree(new_artefacts)
            os.mkdir(path=new_artefacts)
            shutil.copy(zip_pack_path, os.path.join(new_artefacts, f'{pack_name}_not_encrypted.zip'))
            shutil.copy(output_file, os.path.join(new_artefacts, f'{pack_name}.zip'))
            os.chdir(current_working_dir)
        except subprocess.CalledProcessError as error:
            print(f"Error while trying to encrypt pack. {error}")

    def decrypt_pack(self, encrypted_zip_pack_path, decryption_key):
        """ decrypt the pack in order to see that the pack was encrypted in the first place.

        Args:
            encrypted_zip_pack_path (str): The path for the encrypted zip pack.
            decryption_key (str): The key which we can decrypt the pack with.

        Returns:
            bool: whether the decryption succeeded.
        """
        try:
            current_working_dir = os.getcwd()
            extract_destination_path = f'{current_working_dir}/decrypt_pack_dir'
            os.mkdir(extract_destination_path)

            shutil.copy('./decryptor', os.path.join(extract_destination_path, 'decryptor'))
            new_encrypted_pack_path = os.path.join(extract_destination_path, 'encrypted_zip_pack.zip')
            shutil.copy(encrypted_zip_pack_path, new_encrypted_pack_path)
            os.chmod(os.path.join(extract_destination_path, 'decryptor'), stat.S_IXOTH)
            output_decrypt_file_path = f"{extract_destination_path}/decrypt_pack.zip"
            os.chdir(extract_destination_path)

            subprocess.call('chmod +x ./decryptor', shell=True)
            full_command = f'./decryptor {new_encrypted_pack_path} {output_decrypt_file_path} "{decryption_key}"'
            process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = process.communicate()
            shutil.rmtree(extract_destination_path)
            os.chdir(current_working_dir)
            if stdout:
                logging.info(str(stdout))
            if stderr:
                logging.error(f"Error: Premium pack {self. _pack_name} should be encrypted, but isn't.")
                return False
            return True

        except subprocess.CalledProcessError as error:
            logging.exception(f"Error while trying to decrypt pack. {error}")
            return False

    def is_pack_encrypted(self, encrypted_zip_pack_path, decryption_key):
        """ Checks if the pack is encrypted by trying to decrypt it.

        Args:
            encrypted_zip_pack_path (str): The path for the encrypted zip pack.
            decryption_key (str): The key which we can decrypt the pack with.

        Returns:
            bool: whether the pack is encrypted.
        """
        return self.decrypt_pack(encrypted_zip_pack_path, decryption_key)

    def zip_pack(self, extract_destination_path="", pack_name="", encryption_key=""):
        """ Zips pack folder.

        Returns:
            bool: whether the operation succeeded.
            str: full path to created pack zip.
        """
        zip_pack_path = f"{self._pack_path}.zip" if not encryption_key else f"{self._pack_path}_not_encrypted.zip"
        task_status = False

        try:
            with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
                for root, dirs, files in os.walk(self._pack_path, topdown=True):
                    for f in files:
                        full_file_path = os.path.join(root, f)
                        relative_file_path = os.path.relpath(full_file_path, self._pack_path)
                        pack_zip.write(filename=full_file_path, arcname=relative_file_path)

            if encryption_key:
                self.encrypt_pack(zip_pack_path, pack_name, encryption_key, extract_destination_path)
            task_status = True
            logging.success(f"Finished zipping {self._pack_name} pack.")
        except Exception:
            logging.exception(f"Failed in zipping {self._pack_name} folder")
        finally:
            # If the pack needs to be encrypted, it is initially at a different location than this final path
            final_path_to_zipped_pack = f"{self._pack_path}.zip"
            return task_status, final_path_to_zipped_pack

    def detect_modified(self, content_repo, index_folder_path, current_commit_hash, previous_commit_hash):
        """ Detects pack modified files.

        The diff is done between current commit and previous commit that was saved in metadata that was downloaded from
        index. In case that no commit was found in index (initial run), the default value will be set to previous commit
        from origin/master.

        Args:
            content_repo (git.repo.base.Repo): content repo object.
            index_folder_path (str): full path to downloaded index folder.
            current_commit_hash (str): last commit hash of head.
            previous_commit_hash (str): the previous commit to diff with.

        Returns:
            bool: whether the operation succeeded.
            bool: whether pack was modified and override will be required.
        """
        task_status = False
        pack_was_modified = False

        try:
            pack_index_metadata_path = os.path.join(index_folder_path, self._pack_name, Pack.METADATA)

            if not os.path.exists(pack_index_metadata_path):
                logging.info(f"{self._pack_name} pack was not found in index, skipping detection of modified pack.")
                task_status = True
                return

            with open(pack_index_metadata_path, 'r') as metadata_file:
                downloaded_metadata = json.load(metadata_file)

            previous_commit_hash = downloaded_metadata.get('commit', previous_commit_hash)
            # set 2 commits by hash value in order to check the modified files of the diff
            current_commit = content_repo.commit(current_commit_hash)
            previous_commit = content_repo.commit(previous_commit_hash)

            for modified_file in current_commit.diff(previous_commit).iter_change_type('M'):
                if modified_file.a_path.startswith(PACKS_FOLDER):
                    modified_file_path_parts = os.path.normpath(modified_file.a_path).split(os.sep)

                    if modified_file_path_parts[1] and modified_file_path_parts[1] == self._pack_name:
                        logging.info(f"Detected modified files in {self._pack_name} pack")
                        task_status, pack_was_modified = True, True
                        return

            task_status = True
        except Exception:
            logging.exception(f"Failed in detecting modified files of {self._pack_name} pack")
        finally:
            return task_status, pack_was_modified

    def upload_to_storage(self, zip_pack_path, latest_version, storage_bucket, override_pack,
                          private_content=False, pack_artifacts_path=None):
        """ Manages the upload of pack zip artifact to correct path in cloud storage.
        The zip pack will be uploaded to following path: /content/packs/pack_name/pack_latest_version.
        In case that zip pack artifact already exist at constructed path, the upload will be skipped.
        If flag override_pack is set to True, pack will forced for upload.

        Args:
            zip_pack_path (str): full path to pack zip artifact.
            latest_version (str): pack latest version.
            storage_bucket (google.cloud.storage.bucket.Bucket): google cloud storage bucket.
            override_pack (bool): whether to override existing pack.
            private_content (bool): Is being used in a private content build.
            pack_artifacts_path (str): Path to where we are saving pack artifacts.

        Returns:
            bool: whether the operation succeeded.
            bool: True in case of pack existence at targeted path and upload was skipped, otherwise returned False.

        """
        task_status = True

        try:
            version_pack_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name, latest_version)
            existing_files = [f.name for f in storage_bucket.list_blobs(prefix=version_pack_path)]

            if existing_files and not override_pack:
                logging.warning(f"The following packs already exist at storage: {', '.join(existing_files)}")
                logging.warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
                return task_status, True, None

            pack_full_path = os.path.join(version_pack_path, f"{self._pack_name}.zip")
            blob = storage_bucket.blob(pack_full_path)
            blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob

            with open(zip_pack_path, "rb") as pack_zip:
                blob.upload_from_file(pack_zip)
            if private_content:
                #  In some cases the path given is actually a zip.
                if pack_artifacts_path.endswith('content_packs.zip'):
                    _pack_artifacts_path = pack_artifacts_path.replace('/content_packs.zip', '')
                else:
                    _pack_artifacts_path = pack_artifacts_path
                print(f"Copying {zip_pack_path} to {_pack_artifacts_path}/packs/{self._pack_name}.zip")
                shutil.copy(zip_pack_path, f'{_pack_artifacts_path}/packs/{self._pack_name}.zip')

            self.public_storage_path = blob.public_url
            logging.success(f"Uploaded {self._pack_name} pack to {pack_full_path} path.")

            return task_status, False, pack_full_path
        except Exception:
            task_status = False
            logging.exception(f"Failed in uploading {self._pack_name} pack to gcs.")
            return task_status, True, None

    def copy_and_upload_to_storage(self, production_bucket, build_bucket, latest_version, successful_packs_dict):
        """ Manages the copy of pack zip artifact from the build bucket to the production bucket.
        The zip pack will be copied to following path: /content/packs/pack_name/pack_latest_version if
        the pack exists in the successful_packs_dict from Prepare content step in Create Instances job.

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): google cloud production bucket.
            build_bucket (google.cloud.storage.bucket.Bucket): google cloud build bucket.
            latest_version (str): the pack's latest version.
            successful_packs_dict (dict): the dict of all packs were uploaded in prepare content step

        Returns:
            bool: Status - whether the operation succeeded.
            bool: Skipped pack - true in case of pack existence at the targeted path and the copy process was skipped,
             otherwise returned False.

        """
        build_version_pack_path = os.path.join(GCPConfig.BUILD_BASE_PATH, self._pack_name, latest_version)

        # Verifying that the latest version of the pack has been uploaded to the build bucket
        existing_bucket_version_files = [f.name for f in build_bucket.list_blobs(prefix=build_version_pack_path)]
        if not existing_bucket_version_files:
            logging.error(f"{self._pack_name} latest version ({latest_version}) was not found on build bucket at "
                          f"path {build_version_pack_path}.")
            return False, False

        pack_not_uploaded_in_prepare_content = self._pack_name not in successful_packs_dict
        if pack_not_uploaded_in_prepare_content:
            logging.warning("The following packs already exist at storage.")
            logging.warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
            return True, True

        # We upload the pack zip object taken from the build bucket into the production bucket
        prod_version_pack_path = os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name, latest_version)
        prod_pack_zip_path = os.path.join(prod_version_pack_path, f'{self._pack_name}.zip')
        build_pack_zip_path = os.path.join(build_version_pack_path, f'{self._pack_name}.zip')
        build_pack_zip_blob = build_bucket.blob(build_pack_zip_path)

        try:
            copied_blob = build_bucket.copy_blob(
                blob=build_pack_zip_blob, destination_bucket=production_bucket, new_name=prod_pack_zip_path
            )
            copied_blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob
            self.public_storage_path = copied_blob.public_url
            task_status = copied_blob.exists()
        except Exception as e:
            pack_suffix = os.path.join(self._pack_name, latest_version, f'{self._pack_name}.zip')
            logging.exception(f"Failed copying {pack_suffix}. Additional Info: {str(e)}")
            return False, False

        if not task_status:
            logging.error(f"Failed in uploading {self._pack_name} pack to production gcs.")
        else:
            # Determine if pack versions were aggregated during upload
            pack_uploaded_in_prepare_content = not pack_not_uploaded_in_prepare_content
            if pack_uploaded_in_prepare_content:
                agg_str = successful_packs_dict[self._pack_name].get('aggregated')
                if agg_str:
                    self._aggregated = True
                    self._aggregation_str = agg_str
            logging.success(f"Uploaded {self._pack_name} pack to {prod_pack_zip_path} path.")

        return task_status, False

    def get_changelog_latest_rn(self, changelog_index_path: str) -> Tuple[dict, LooseVersion]:
        """
        Returns the changelog file contents and the last version of rn in the changelog file
        Args:
            changelog_index_path (str): the changelog.json file path in the index

        Returns: the changelog file contents and the last version of rn in the changelog file

        """
        logging.info(f"Found Changelog for: {self._pack_name}")
        if os.path.exists(changelog_index_path):
            try:
                with open(changelog_index_path, "r") as changelog_file:
                    changelog = json.load(changelog_file)
            except json.JSONDecodeError:
                changelog = {}
        else:
            changelog = {}
        # get the latest rn version in the changelog.json file
        changelog_rn_versions = [LooseVersion(ver) for ver in changelog]
        # no need to check if changelog_rn_versions isn't empty because changelog file exists
        changelog_latest_rn_version = max(changelog_rn_versions)

        return changelog, changelog_latest_rn_version

    def get_release_notes_lines(self, release_notes_dir: str, changelog_latest_rn_version: LooseVersion) -> \
            Tuple[str, str]:
        """
        Prepares the release notes contents for the new release notes entry
        Args:
            release_notes_dir (str): the path to the release notes dir
            changelog_latest_rn_version (LooseVersion): the last version of release notes in the changelog.json file

        Returns: The release notes contents and the latest release notes version (in the release notes directory)

        """
        found_versions: list = list()
        pack_versions_dict: dict = dict()

        for filename in sorted(os.listdir(release_notes_dir)):
            _version = filename.replace('.md', '')
            version = _version.replace('_', '.')

            # Aggregate all rn files that are bigger than what we have in the changelog file
            if LooseVersion(version) > changelog_latest_rn_version:
                with open(os.path.join(release_notes_dir, filename), 'r') as rn_file:
                    rn_lines = rn_file.read()
                pack_versions_dict[version] = self._clean_release_notes(rn_lines).strip()

            found_versions.append(LooseVersion(version))

        latest_release_notes_version = max(found_versions)
        latest_release_notes = latest_release_notes_version.vstring
        logging.info(f"Latest ReleaseNotes version is: {latest_release_notes}")

        if len(pack_versions_dict) > 1:
            # In case that there is more than 1 new release notes file, wrap all release notes together for one
            # changelog entry
            aggregation_str = f"[{', '.join(lv.vstring for lv in found_versions if lv > changelog_latest_rn_version)}]"\
                              f" => {latest_release_notes}"
            logging.info(f"Aggregating ReleaseNotes versions: {aggregation_str}")
            release_notes_lines = aggregate_release_notes_for_marketplace(pack_versions_dict)
            self._aggregated = True
            self._aggregation_str = aggregation_str
        else:
            # In case where there is only one new release notes file, OR
            # In case where the pack is up to date, i.e. latest changelog is latest rn file
            latest_release_notes_suffix = f"{latest_release_notes.replace('.', '_')}.md"
            with open(os.path.join(release_notes_dir, latest_release_notes_suffix), 'r') as rn_file:
                release_notes_lines = self._clean_release_notes(rn_file.read())

        return release_notes_lines, latest_release_notes

    def assert_upload_bucket_version_matches_release_notes_version(self,
                                                                   changelog: dict,
                                                                   latest_release_notes: str) -> None:
        """
        Sometimes there is a the current bucket is not merged from master there could be another version in the upload
        bucket, that does not exist in the current branch.
        This case can cause unpredicted behavior and we want to fail the build.
        This method validates that this is not the case in the current build, and if it does - fails it with an
        assertion error.
        Args:
            changelog: The changelog from the production bucket.
            latest_release_notes: The latest release notes version string in the current branch
        """
        changelog_latest_release_notes = max(changelog, key=lambda k: LooseVersion(k))
        assert LooseVersion(latest_release_notes) >= LooseVersion(changelog_latest_release_notes), \
            f'{self._pack_name}: Version mismatch detected between upload bucket and current branch\n' \
            f'Upload bucket version: {changelog_latest_release_notes}\n' \
            f'current branch version: {latest_release_notes}\n' \
            'Please Merge from master and rebuild'

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
            # load changelog from downloaded index
            changelog_index_path = os.path.join(index_folder_path, self._pack_name, Pack.CHANGELOG_JSON)
            if os.path.exists(changelog_index_path):
                changelog, changelog_latest_rn_version = self.get_changelog_latest_rn(changelog_index_path)
                release_notes_dir = os.path.join(self._pack_path, Pack.RELEASE_NOTES)

                if os.path.exists(release_notes_dir):
                    release_notes_lines, latest_release_notes = self.get_release_notes_lines(
                        release_notes_dir, changelog_latest_rn_version
                    )
                    self.assert_upload_bucket_version_matches_release_notes_version(changelog, latest_release_notes)

                    if self._current_version != latest_release_notes:
                        # TODO Need to implement support for pre-release versions
                        logging.error(f"Version mismatch detected between current version: {self._current_version} "
                                      f"and latest release notes version: {latest_release_notes}")
                        task_status = False
                        return task_status, not_updated_build
                    else:
                        if latest_release_notes in changelog:
                            logging.info(f"Found existing release notes for version: {latest_release_notes}")
                            version_changelog = Pack._create_changelog_entry(release_notes=release_notes_lines,
                                                                             version_display_name=latest_release_notes,
                                                                             build_number=build_number,
                                                                             new_version=False)

                        else:
                            logging.info(f"Created new release notes for version: {latest_release_notes}")
                            version_changelog = Pack._create_changelog_entry(release_notes=release_notes_lines,
                                                                             version_display_name=latest_release_notes,
                                                                             build_number=build_number,
                                                                             new_version=True)

                        changelog[latest_release_notes] = version_changelog
                else:  # will enter only on initial version and release notes folder still was not created
                    if len(changelog.keys()) > 1 or Pack.PACK_INITIAL_VERSION not in changelog:
                        logging.warning(
                            f"{self._pack_name} pack mismatch between {Pack.CHANGELOG_JSON} and {Pack.RELEASE_NOTES}")
                        task_status, not_updated_build = True, True
                        return task_status, not_updated_build

                    changelog[Pack.PACK_INITIAL_VERSION] = Pack._create_changelog_entry(
                        release_notes=self.description,
                        version_display_name=Pack.PACK_INITIAL_VERSION,
                        build_number=build_number,
                        new_version=False)

                    logging.info(f"Found existing release notes for version: {Pack.PACK_INITIAL_VERSION} "
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
                logging.error(f"No release notes found for: {self._pack_name}")
                task_status = False
                return task_status, not_updated_build

            # write back changelog with changes to pack folder
            with open(os.path.join(self._pack_path, Pack.CHANGELOG_JSON), "w") as pack_changelog:
                json.dump(changelog, pack_changelog, indent=4)

            task_status = True
            logging.success(f"Finished creating {Pack.CHANGELOG_JSON} for {self._pack_name}")
        except Exception as e:
            logging.error(f"Failed creating {Pack.CHANGELOG_JSON} file for {self._pack_name}.\n "
                          f"Additional info: {e}")
        finally:
            return task_status, not_updated_build

    def create_local_changelog(self, build_index_folder_path):
        """ Copies the pack index changelog.json file to the pack path

        Args:
            build_index_folder_path: The path to the build index folder

        Returns:
            bool: whether the operation succeeded.

        """
        task_status = True

        build_changelog_index_path = os.path.join(build_index_folder_path, self._pack_name, Pack.CHANGELOG_JSON)
        pack_changelog_path = os.path.join(self._pack_path, Pack.CHANGELOG_JSON)

        if os.path.exists(build_changelog_index_path):
            try:
                shutil.copyfile(src=build_changelog_index_path, dst=pack_changelog_path)
                logging.success(f"Successfully copied pack index changelog.json file from {build_changelog_index_path}"
                                f" to {pack_changelog_path}.")
            except shutil.Error as e:
                task_status = False
                logging.error(f"Failed copying changelog.json file from {build_changelog_index_path} to "
                              f"{pack_changelog_path}. Additional info: {str(e)}")
                return task_status
        else:
            task_status = False
            logging.error(f"{self._pack_name} index changelog file is missing in build bucket path: {build_changelog_index_path}")

        return task_status and self.is_changelog_exists()

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
                PackFolders.LAYOUTS.value: "layoutscontainer",
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
                        logging.info(f"Deleted pack {pack_file_name} reputation file for {self._pack_name} pack")
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
                        logging.info(
                            f"{self._pack_name} pack content item {pack_file_name} has to version: {to_version}. "
                            f"{pack_file_name} file was deleted.")
                        continue

                    if current_directory not in PackFolders.pack_displayed_items():
                        continue  # skip content items that are not displayed in contentItems

                    logging.debug(
                        f"Iterating over {pack_file_path} file and collecting items of {self._pack_name} pack")
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
                        self.is_feed_pack(content_item, 'Playbook')
                        folder_collected_items.append({
                            'name': content_item.get('name', ""),
                            'description': content_item.get('description', "")
                        })
                    elif current_directory == PackFolders.INTEGRATIONS.value:
                        integration_commands = content_item.get('script', {}).get('commands', [])
                        self.is_feed_pack(content_item, 'Integration')
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
                        layout_metadata = {
                            'name': content_item.get('name', '')
                        }
                        layout_description = content_item.get('description')
                        if layout_description is not None:
                            layout_metadata['description'] = layout_description
                        folder_collected_items.append(layout_metadata)
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

            logging.success(f"Finished collecting content items for {self._pack_name} pack")
            task_status = True
        except Exception:
            logging.exception(f"Failed collecting content items in {self._pack_name} pack")
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
                logging.error(f"{self._pack_name} pack is missing {Pack.USER_METADATA} file.")
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

            logging.info(f"Finished loading {self._pack_name} pack user metadata")
            task_status = True
        except Exception:
            logging.exception(f"Failed in loading {self._pack_name} user metadata.")
        finally:
            return task_status, user_metadata

    def format_metadata(self, user_metadata, pack_content_items, integration_images, author_image, index_folder_path,
                        packs_dependencies_mapping, build_number, commit_hash, packs_statistic_df):
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
            packs_statistic_df (pandas.core.frame.DataFrame): packs downloads statistics table.

        Returns:
            bool: True is returned in case metadata file was parsed successfully, otherwise False.

        """
        task_status = False

        try:
            metadata_path = os.path.join(self._pack_path, Pack.METADATA)  # deployed metadata path after parsing

            self.set_pack_dependencies(user_metadata, packs_dependencies_mapping)

            if 'displayedImages' not in user_metadata:
                user_metadata['displayedImages'] = packs_dependencies_mapping.get(
                    self._pack_name, {}).get('displayedImages', [])
                logging.info(f"Adding auto generated display images for {self._pack_name} pack")

            dependencies_data = self._load_pack_dependencies(index_folder_path,
                                                             user_metadata.get('dependencies', {}),
                                                             user_metadata.get('displayedImages', []))

            if packs_statistic_df is not None:
                self.downloads_count = self._get_downloads_count(packs_statistic_df)

            formatted_metadata = Pack._parse_pack_metadata(user_metadata=user_metadata,
                                                           pack_content_items=pack_content_items,
                                                           pack_id=self._pack_name,
                                                           integration_images=integration_images,
                                                           author_image=author_image,
                                                           dependencies_data=dependencies_data,
                                                           server_min_version=self.server_min_version,
                                                           build_number=build_number, commit_hash=commit_hash,
                                                           downloads_count=self.downloads_count,
                                                           is_feed_pack=self._is_feed)

            with open(metadata_path, "w") as metadata_file:
                json.dump(formatted_metadata, metadata_file, indent=4)  # writing back parsed metadata

            logging.success(f"Finished formatting {self._pack_name} packs's {Pack.METADATA} {metadata_path} file.")
            task_status = True
        except Exception:
            logging.exception(f"Failed in formatting {self._pack_name} pack metadata.")
        finally:
            return task_status

    def set_pack_dependencies(self, user_metadata, packs_dependencies_mapping):
        pack_dependencies = packs_dependencies_mapping.get(self._pack_name, {}).get('dependencies', {})
        if 'dependencies' not in user_metadata:
            user_metadata['dependencies'] = {}

        # If it is a core pack, check that no new mandatory packs (that are not core packs) were added
        # They can be overridden in the user metadata to be not mandatory so we need to check there as well
        if self._pack_name in GCPConfig.CORE_PACKS_LIST:
            mandatory_dependencies = [k for k, v in pack_dependencies.items()
                                      if v.get('mandatory', False) is True
                                      and k not in GCPConfig.CORE_PACKS_LIST
                                      and k not in user_metadata['dependencies'].keys()]
            if mandatory_dependencies:
                raise Exception(f'New mandatory dependencies {mandatory_dependencies} were '
                                f'found in the core pack {self._pack_name}')

        pack_dependencies.update(user_metadata['dependencies'])
        user_metadata['dependencies'] = pack_dependencies

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
        except Exception:
            logging.exception(f"Failed in preparing index for upload in {self._pack_name} pack.")
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
                logging.warning(f"{integration_name} integration image was not found in {self._pack_name} pack")
                return {}

            temp_image_name = f'{integration_name.replace(" ", "")}_image.png'
            temp_image_path = os.path.join(self._pack_path, temp_image_name)

            with open(temp_image_path, 'wb') as image_file:
                image_file.write(base64.b64decode(base64_image))

            self._remove_files_list.append(temp_image_name)  # add temporary file to tracking list
            image_data['image_path'] = temp_image_path

            logging.info(f"Created temporary integration {image_data['display_name']} image for {self._pack_name} pack")

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

    def check_if_exists_in_index(self, index_folder_path):
        """ Checks if pack is sub-folder of downloaded index.

        Args:
            index_folder_path (str): index folder full path.

        Returns:
            bool: whether the operation succeeded.
            bool: whether pack exists in index folder.

        """
        task_status, exists_in_index = False, False

        try:
            if not os.path.exists(index_folder_path):
                logging.error(f"{GCPConfig.INDEX_NAME} does not exists.")
                return task_status, exists_in_index

            exists_in_index = os.path.exists(os.path.join(index_folder_path, self._pack_name))
            task_status = True
        except Exception:
            logging.exception(f"Failed searching {self._pack_name} pack in {GCPConfig.INDEX_NAME}")
        finally:
            return task_status, exists_in_index

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

                logging.info(f"Uploading {self._pack_name} pack integration image: {image_name}")
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

            logging.info(f"Uploaded {len(pack_local_images)} images for {self._pack_name} pack.")
        except Exception:
            task_status = False
            logging.exception(f"Failed to upload {self._pack_name} pack integration images")
        finally:
            return task_status, uploaded_integration_images

    def copy_integration_images(self, production_bucket, build_bucket):
        """ Copies all pack's integration images from the build bucket to the production bucket

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket

        Returns:
            bool: Whether the operation succeeded.

        """
        task_status = True

        build_integration_images_blobs = [f for f in
                                          build_bucket.list_blobs(
                                              prefix=os.path.join(GCPConfig.BUILD_BASE_PATH, self._pack_name)
                                          )
                                          if is_integration_image(os.path.basename(f.name))]

        for integration_image_blob in build_integration_images_blobs:
            image_name = os.path.basename(integration_image_blob.name)
            logging.info(f"Uploading {self._pack_name} pack integration image: {image_name}")
            # We upload each image object taken from the build bucket into the production bucket
            try:
                copied_blob = build_bucket.copy_blob(
                    blob=integration_image_blob, destination_bucket=production_bucket,
                    new_name=os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name, image_name)
                )
                task_status = task_status and copied_blob.exists()
                if not task_status:
                    logging.error(f"Upload {self._pack_name} integration image: {integration_image_blob.name} blob to "
                                  f"{copied_blob.name} blob failed.")
            except Exception as e:
                logging.exception(f"Failed copying {image_name}. Additional Info: {str(e)}")
                return False

        if not task_status:
            logging.error(f"Failed to upload {self._pack_name} pack integration images.")
        else:
            logging.success(f"Uploaded {len(build_integration_images_blobs)} images for {self._pack_name} pack.")

        return task_status

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

                logging.success(f"Uploaded successfully {self._pack_name} pack author image")
            elif self.support_type == Metadata.XSOAR_SUPPORT:  # use default Base pack image for xsoar supported packs
                author_image_storage_path = os.path.join(GCPConfig.IMAGES_BASE_PATH, GCPConfig.BASE_PACK,
                                                         Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection

                if not GCPConfig.USE_GCS_RELATIVE_PATH:
                    # disable-secrets-detection-start
                    author_image_storage_path = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name,
                                                             author_image_storage_path)
                    # disable-secrets-detection-end
                logging.info((f"Skipping uploading of {self._pack_name} pack author image "
                              f"and use default {GCPConfig.BASE_PACK} pack image"))
            else:
                logging.info(f"Skipping uploading of {self._pack_name} pack author image. "
                             f"The pack is defined as {self.support_type} support type")

        except Exception:
            logging.exception(f"Failed uploading {self._pack_name} pack author image.")
            task_status = False
            author_image_storage_path = ""
        finally:
            return task_status, author_image_storage_path

    def copy_author_image(self, production_bucket, build_bucket):
        """ Copies pack's author image from the build bucket to the production bucket

        Searches for `Author_image.png`, In case no such image was found, default Base pack image path is used and
        it's gcp path is returned.

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket

        Returns:
            bool: Whether the operation succeeded.

        """
        task_status = True

        build_author_image_path = os.path.join(GCPConfig.BUILD_BASE_PATH, self._pack_name, Pack.AUTHOR_IMAGE_NAME)
        build_author_image_blob = build_bucket.blob(build_author_image_path)

        if build_author_image_blob.exists():
            try:
                copied_blob = build_bucket.copy_blob(
                    blob=build_author_image_blob, destination_bucket=production_bucket,
                    new_name=os.path.join(GCPConfig.STORAGE_BASE_PATH, self._pack_name, Pack.AUTHOR_IMAGE_NAME)
                )
                task_status = task_status and copied_blob.exists()
            except Exception as e:
                logging.exception(f"Failed copying {Pack.AUTHOR_IMAGE_NAME}. Additional Info: {str(e)}")
                return False

        elif self.support_type == Metadata.XSOAR_SUPPORT:  # use default Base pack image for xsoar supported packs
            logging.info((f"Skipping uploading of {self._pack_name} pack author image "
                          f"and use default {GCPConfig.BASE_PACK} pack image"))
            return task_status
        else:
            logging.info(f"Skipping uploading of {self._pack_name} pack author image. The pack is defined as "
                         f"{self.support_type} support type")
            return task_status

        if not task_status:
            logging.error(f"Failed uploading {self._pack_name} pack author image.")
        else:
            logging.success(f"Uploaded successfully {self._pack_name} pack author image")

        return task_status

    def cleanup(self):
        """ Finalization action, removes extracted pack folder.

        """
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path)
            logging.info(f"Cleanup {self._pack_name} pack from: {self._pack_path}")

    def is_changelog_exists(self):
        """ Indicates whether the local changelog of a given pack exists or not

        Returns:
            bool: The answer

        """
        return os.path.isfile(os.path.join(self._pack_path, Pack.CHANGELOG_JSON))

    def is_failed_to_upload(self, failed_packs_dict):
        """
        Checks if the pack was failed to upload in Prepare Content step in Create Instances job
        Args:
            failed_packs_dict (dict): The failed packs file

        Returns:
            bool: Whether the operation succeeded.
            str: The pack's failing status

        """
        if self._pack_name in failed_packs_dict:
            return True, failed_packs_dict[self._pack_name].get('status')
        else:
            return False, str()


# HELPER FUNCTIONS


def get_successful_and_failed_packs(packs_results_file_path: str, stage: str) -> Tuple[dict, dict]:
    """ Loads the packs_results.json file to get the successful and failed packs dicts

    Args:
        packs_results_file_path (str): The path to the file
        stage (str): can be BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING or
        BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE

    Returns:
        dict: The successful packs dict
        dict: The failed packs dict

    """
    if os.path.exists(packs_results_file_path):
        packs_results_file = load_json(packs_results_file_path)
        successful_packs_dict = packs_results_file.get(stage, {}).get(BucketUploadFlow.SUCCESSFUL_PACKS, {})
        failed_packs_dict = packs_results_file.get(stage, {}).get(BucketUploadFlow.FAILED_PACKS, {})
        return successful_packs_dict, failed_packs_dict
    return {}, {}


def store_successful_and_failed_packs_in_ci_artifacts(packs_results_file_path: str, stage: str, successful_packs: list,
                                                      failed_packs: list):
    """ Write the successful and failed packs to the correct section in the packs_results.json file

    Args:
        packs_results_file_path (str): The path to the pack_results.json file
        stage (str): can be BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING or
        BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
        successful_packs (list): The list of all successful packs
        failed_packs (list): The list of all failed packs

    """
    packs_results = load_json(packs_results_file_path)
    packs_results[stage] = dict()

    if failed_packs:
        failed_packs_dict = {
            BucketUploadFlow.FAILED_PACKS: {
                pack.name: {
                    BucketUploadFlow.STATUS: pack.status,
                    BucketUploadFlow.AGGREGATED: pack.aggregation_str if pack.aggregated and pack.aggregation_str
                    else "False"
                } for pack in failed_packs
            }
        }
        packs_results[stage].update(failed_packs_dict)
        logging.debug(f"Failed packs {failed_packs_dict}")

    if successful_packs:
        successful_packs_dict = {
            BucketUploadFlow.SUCCESSFUL_PACKS: {
                pack.name: {
                    BucketUploadFlow.STATUS: pack.status,
                    BucketUploadFlow.AGGREGATED: pack.aggregation_str if pack.aggregated and pack.aggregation_str
                    else "False"
                } for pack in successful_packs
            }
        }
        packs_results[stage].update(successful_packs_dict)
        logging.debug(f"Successful packs {successful_packs_dict}")

    if packs_results:
        json_write(packs_results_file_path, packs_results)


def load_json(file_path: str) -> dict:
    """ Reads and loads json file.

    Args:
        file_path (str): full path to json file.

    Returns:
        dict: loaded json file.

    """
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path, 'r') as json_file:
                result = json.load(json_file)
        else:
            result = {}
        return result
    except json.decoder.JSONDecodeError:
        return {}


def json_write(file_path: str, data: Union[list, dict]):
    """ Writes given data to a json file

    Args:
        file_path: The file path
        data: The data to write

    """
    with open(file_path, "w") as f:
        f.write(json.dumps(data, indent=4))


def is_integration_image(file_name):
    """ Indicates whether a file_name in pack directory (in the bucket) is an integration image or not

    Args:
        file_name (str): The file name

    Returns:
        bool: True if the file is an integration image or False otherwise

    """
    return file_name.endswith('.png') and 'author' not in file_name.lower()


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
        logging.info("Created gcp service account")

        return storage_client
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        storage_client = storage.Client(credentials=credentials, project=project)
        logging.info("Created gcp private account")

        return storage_client


def init_bigquery_client(service_account=None):
    """Initialize google cloud big query client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
         google.cloud.bigquery.client.Client: initialized google cloud big query client.
    """
    if service_account:
        bq_client = bigquery.Client.from_service_account_json(service_account)
        logging.info("Created big query service account")
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        bq_client = bigquery.Client(credentials=credentials, project=project)
        logging.info("Created big query private account")

    return bq_client


def get_packs_statistics_dataframe(bq_client):
    """ Runs big query, selects all columns from top_packs table and returns table as pandas data frame.
    Additionally table index is set to pack_name (pack unique id).

    Args:
        bq_client (google.cloud.bigquery.client.Client): google cloud big query client.

    Returns:
        pandas.core.frame.DataFrame: downloads statistics table dataframe.
    """
    query = f"SELECT * FROM `{GCPConfig.DOWNLOADS_TABLE}` LIMIT {GCPConfig.BIG_QUERY_MAX_RESULTS}"
    # ignore missing package warning
    warnings.filterwarnings("ignore", message="Cannot create BigQuery Storage client, the dependency ")
    packs_statistic_table = bq_client.query(query).result().to_dataframe()
    packs_statistic_table.set_index('pack_name', inplace=True)

    return packs_statistic_table


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
        return [" ".join([w.title() if w.islower() else w for w in i.split()]) for i in input_data]
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
    except Exception:
        logging.exception(f"{pack_id} pack price is not valid. The price was set to 0.")
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
    except Exception:
        content_item_name = compared_content_item.get('name') or compared_content_item.get(
            'display') or compared_content_item.get('id') or compared_content_item.get('details', '')
        logging.exception(f"{pack_name} failed in version comparison of content item {content_item_name}.")
    finally:
        return higher_version_result


def get_content_git_client(content_repo_path: str):
    """ Initializes content repo client.

    Args:
        content_repo_path (str): content repo full path

    Returns:
        git.repo.base.Repo: content repo object.

    """
    return git.Repo(content_repo_path)


def get_recent_commits_data(content_repo: Any, index_folder_path: str, is_bucket_upload_flow: bool,
                            is_private_build: bool = False, circle_branch: str = "master"):
    """ Returns recent commits hashes (of head and remote master)

    Args:
        content_repo (git.repo.base.Repo): content repo object.
        index_folder_path (str): the path to the local index folder
        is_bucket_upload_flow (bool): indicates whether its a run of bucket upload flow or regular build
        is_private_build (bool): indicates whether its a run of private build or not
        circle_branch (str): CircleCi branch of current build

    Returns:
        str: last commit hash of head.
        str: previous commit depending on the flow the script is running
    """
    return content_repo.head.commit.hexsha, get_previous_commit(content_repo, index_folder_path, is_bucket_upload_flow,
                                                                is_private_build, circle_branch)


def get_previous_commit(content_repo, index_folder_path, is_bucket_upload_flow, is_private_build, circle_branch):
    """ If running in bucket upload workflow we want to get the commit in the index which is the index
    We've last uploaded to production bucket. Otherwise, we are in a commit workflow and the diff should be from the
    head of origin/master

    Args:
        content_repo (git.repo.base.Repo): content repo object.
        index_folder_path (str): the path to the local index folder
        is_bucket_upload_flow (bool): indicates whether its a run of bucket upload flow or regular build
        is_private_build (bool): indicates whether its a run of private build or not
        circle_branch (str): CircleCi branch of current build

    Returns:
        str: previous commit depending on the flow the script is running

    """
    if is_bucket_upload_flow:
        return get_last_upload_commit_hash(content_repo, index_folder_path)
    elif is_private_build:
        previous_master_head_commit = content_repo.commit('origin/master~1').hexsha
        logging.info(f"Using origin/master HEAD~1 commit hash {previous_master_head_commit} to diff with.")
        return previous_master_head_commit
    else:
        if circle_branch == 'master':
            head_str = "HEAD~1"
            # if circle branch is master than current commit is origin/master HEAD, so we need to diff with HEAD~1
            previous_master_head_commit = content_repo.commit('origin/master~1').hexsha
        else:
            head_str = "HEAD"
            # else we are on a regular branch and the diff should be done with origin/master HEAD
            previous_master_head_commit = content_repo.commit('origin/master').hexsha
        logging.info(f"Using origin/master {head_str} commit hash {previous_master_head_commit} to diff with.")
        return previous_master_head_commit


def get_last_upload_commit_hash(content_repo, index_folder_path):
    """
    Returns the last origin/master commit hash that was uploaded to the bucket
    Args:
        content_repo (git.repo.base.Repo): content repo object.
        index_folder_path: The path to the index folder

    Returns:
        The commit hash
    """

    inner_index_json_path = os.path.join(index_folder_path, f'{GCPConfig.INDEX_NAME}.json')
    if not os.path.exists(inner_index_json_path):
        logging.critical(f"{GCPConfig.INDEX_NAME}.json not found in {GCPConfig.INDEX_NAME} folder")
        sys.exit(1)
    else:
        inner_index_json_file = load_json(inner_index_json_path)
        if 'commit' in inner_index_json_file:
            last_upload_commit_hash = inner_index_json_file['commit']
            logging.info(f"Retrieved the last commit that was uploaded to production: {last_upload_commit_hash}")
        else:
            logging.critical(f"No commit field in {GCPConfig.INDEX_NAME}.json, content: {str(inner_index_json_file)}")
            sys.exit(1)

    try:
        last_upload_commit = content_repo.commit(last_upload_commit_hash).hexsha
        logging.info(f"Using commit hash {last_upload_commit} from index.json to diff with.")
        return last_upload_commit
    except Exception as e:
        logging.critical(f'Commit {last_upload_commit_hash} in {GCPConfig.INDEX_NAME}.json does not exist in content '
                         f'repo. Additional info:\n {e}')
        sys.exit(1)
