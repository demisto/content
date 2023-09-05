import base64
import fnmatch
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import urllib.parse
import warnings

from datetime import datetime, timedelta
from distutils.util import strtobool

from packaging.version import Version
from pathlib import Path
from typing import Any
from zipfile import ZipFile, ZIP_DEFLATED
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import Neo4jContentGraphInterface

import git
import google.auth
import sys
import yaml
from google.cloud import storage

import Tests.Marketplace.marketplace_statistics as mp_statistics
from Tests.Marketplace.marketplace_constants import PackFolders, Metadata, GCPConfig, BucketUploadFlow, PACKS_FOLDER, \
    PackTags, PackIgnored, Changelog, BASE_PACK_DEPENDENCY_DICT, SIEM_RULES_OBJECTS, PackStatus, PACK_FOLDERS_TO_ID_SET_KEYS, \
    CONTENT_ROOT_PATH, XSOAR_MP, XSIAM_MP, XPANSE_MP, TAGS_BY_MP, CONTENT_ITEM_NAME_MAPPING, \
    ITEMS_NAMES_TO_DISPLAY_MAPPING, RN_HEADER_TO_ID_SET_KEYS
from Utils.release_notes_generator import aggregate_release_notes_for_marketplace, merge_version_blocks, construct_entities_block
from Tests.scripts.utils import logging_wrapper as logging

PULL_REQUEST_PATTERN = '\(#(\d+)\)'
TAGS_SECTION_PATTERN = '(.|\s)+?'
SPECIAL_DISPLAY_NAMES_PATTERN = re.compile(r'- \*\*(.+?)\*\*')
MAX_TOVERSION = '99.99.99'


class Pack:
    """ Class that manipulates and manages the upload of pack's artifact and metadata to cloud storage.

    Args:
        pack_name (str): Pack root folder name.
        pack_path (str): Full path to pack folder.

    Attributes:
        PACK_INITIAL_VERSION (str): pack initial version that will be used as default.
        CHANGELOG_JSON (str): changelog json full name, may be changed in the future.
        README (str): pack's readme file name.
        METADATA (str): pack's metadata file name, the one that will be deployed to cloud storage.
        USER_METADATA (str); pack metadata file name, the one that located in content repo.
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

    def __init__(self, pack_name, pack_path, is_modified=None):
        self._pack_name = pack_name
        self._pack_path = pack_path
        self._zip_path = None  # zip_path will be updated as part of zip_pack
        self._marketplaces = []  # initialized in load_user_metadata function
        self._status = None
        self._public_storage_path = ""
        self._remove_files_list = []  # tracking temporary files, in order to delete in later step
        self._server_min_version = "99.99.99"  # initialized min version
        self._latest_version = None  # pack latest version found in changelog
        self._support_type = None  # initialized in load_user_metadata function
        self._current_version = None  # initialized in load_user_metadata function
        self._hidden = False  # initialized in load_user_metadata function
        self._description = None  # initialized in load_user_metadata function
        self._display_name = None  # initialized in load_user_metadata function
        self._user_metadata = {}  # initialized in load_user_metadata function
        self._eula_link = None  # initialized in load_user_metadata function
        self._is_feed = False  # a flag that specifies if pack is a feed pack
        self._downloads_count = 0  # number of pack downloads
        self._bucket_url = None  # URL of where the pack was uploaded.
        self._aggregated = False  # weather the pack's rn was aggregated or not.
        self._aggregation_str = ""  # the aggregation string msg when the pack versions are aggregated
        self._create_date = None  # initialized in enhance_pack_attributes function
        self._update_date = None  # initialized in enhance_pack_attributes function
        self._uploaded_author_image = False  # whether the pack author image was uploaded or not
        self._reademe_images = []
        self._uploaded_integration_images = []  # the list of all integration images that were uploaded for the pack
        self._uploaded_preview_images = []  # list of all preview images that were uploaded for the pack
        self._uploaded_dynamic_dashboard_images = []
        self._support_details = None  # initialized in enhance_pack_attributes function
        self._author = None  # initialized in enhance_pack_attributes function
        self._certification = None  # initialized in enhance_pack_attributes function
        self._legacy = None  # initialized in enhance_pack_attributes function
        self._author_image = None  # initialized in upload_author_image function
        self._displayed_integration_images = []  # initialized in upload_integration_images function
        self._price = 0  # initialized in enhance_pack_attributes function
        self._is_private_pack = False  # initialized in enhance_pack_attributes function
        self._is_premium = False  # initialized in enhance_pack_attributes function
        self._vendor_id = None  # initialized in enhance_pack_attributes function
        self._partner_id = None  # initialized in enhance_pack_attributes function
        self._partner_name = None  # initialized in enhance_pack_attributes function
        self._content_commit_hash = None  # initialized in enhance_pack_attributes function
        self._preview_only = None  # initialized in enhance_pack_attributes function
        self._disable_monthly = None  # initialized in enhance_pack_attributes
        self._tags = None  # initialized in enhance_pack_attributes function
        self._modules = None
        self._categories = None  # initialized in enhance_pack_attributes function
        self._content_items = None  # initialized in collect_content_items function
        self._content_displays_map = None  # initialized in collect_content_items function
        self._search_rank = None  # initialized in enhance_pack_attributes function
        self._related_integration_images = None  # initialized in enhance_pack_attributes function
        self._use_cases = None  # initialized in enhance_pack_attributes function
        self._keywords = None  # initialized in enhance_pack_attributes function
        self._pack_statistics_handler = None  # initialized in enhance_pack_attributes function
        self._contains_transformer = False  # initialized in collect_content_items function
        self._contains_filter = False  # initialized in collect_content_items function
        self._is_missing_dependencies = False  # initialized in _load_pack_dependencies function
        self._is_modified = is_modified
        self._modified_files = {}  # initialized in detect_modified function
        self._is_siem = False  # initialized in collect_content_items function
        self._has_fetch = False
        self._is_data_source = False
        self._single_integration = True  # pack assumed to have a single integration until processing a 2nd integration

        # Dependencies attributes - these contain only packs that are a part of this marketplace
        self._first_level_dependencies = {}  # initialized in set_pack_dependencies function
        self._all_levels_dependencies = []  # initialized in set_pack_dependencies function
        self._displayed_images_dependent_on_packs = []  # initialized in set_pack_dependencies function
        self._parsed_dependencies = None  # initialized in enhance_pack_attributes function

    @property
    def name(self):
        """ str: pack name.
        """
        return self._pack_name

    def id(self):
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

    @latest_version.setter
    def latest_version(self, latest_version):
        self._latest_version = latest_version

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

    @property
    def is_siem(self):
        """
        bool: whether the pack is a siem pack
        """
        return self._is_siem

    @is_siem.setter
    def is_siem(self, is_siem):
        """ setter of is_siem
        """
        self._is_siem = is_siem

    @property
    def is_data_source(self):
        """
        bool: whether the pack is a siem pack
        """
        return self._is_data_source

    @status.setter  # type: ignore[attr-defined,no-redef]
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

    @property
    def user_metadata(self):
        """ dict: the pack_metadata.
        """
        return self._user_metadata

    @display_name.setter  # type: ignore[attr-defined,no-redef]
    def display_name(self, display_name_value):
        """ setter of display name property of the pack.
        """
        self._display_name = display_name_value

    @property
    def server_min_version(self):
        """ str: server min version according to collected items.
        """
        if not self._server_min_version or self._server_min_version == "99.99.99":
            return Metadata.SERVER_DEFAULT_MIN_VERSION
        else:
            return self._server_min_version

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

    @property
    def create_date(self):
        """ str: pack create date.
        """
        return self._create_date

    @create_date.setter
    def create_date(self, value):
        self._create_date = value

    @property
    def update_date(self):
        """ str: pack update date.
        """
        return self._update_date

    @update_date.setter
    def update_date(self, value):
        self._update_date = value

    @property
    def uploaded_author_image(self):
        """ bool: whether the pack author image was uploaded or not.
        """
        return self._uploaded_author_image

    @uploaded_author_image.setter
    def uploaded_author_image(self, uploaded_author_image):
        """ bool: whether the pack author image was uploaded or not.
        """
        self._uploaded_author_image = uploaded_author_image

    @property
    def uploaded_integration_images(self):
        """ str: the list of uploaded integration images
        """
        return self._uploaded_integration_images

    @property
    def uploaded_preview_images(self):
        """ str: the list of uploaded preview images
        """
        return self._uploaded_preview_images

    @property
    def uploaded_dynamic_dashboard_images(self):
        """ str: the list of uploaded integration svg images for the dynamic dashboard
        """
        return self._uploaded_dynamic_dashboard_images

    @property
    def is_missing_dependencies(self):
        return self._is_missing_dependencies

    @property
    def zip_path(self):
        return self._zip_path

    @property
    def is_modified(self):
        return self._is_modified

    @property
    def marketplaces(self):
        return self._marketplaces

    @property
    def all_levels_dependencies(self):
        return self._all_levels_dependencies

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
            return self._current_version

        with open(changelog_path) as changelog_file:
            changelog = json.load(changelog_file)
            pack_versions = [Version(v) for v in changelog]
            pack_versions.sort(reverse=True)

            return str(pack_versions[0])

    @staticmethod
    def organize_integration_images(pack_integration_images: list, pack_dependencies_integration_images_dict: dict,
                                    pack_dependencies_by_download_count: list):
        """ By Issue #32038
        1. Sort pack integration images by alphabetical order
        2. Sort pack dependencies by download count
        Pack integration images are shown before pack dependencies integration images

        Args:
            pack_integration_images (list): list of pack integration images
            pack_dependencies_integration_images_dict: a mapping of pack dependency name to its integration images
            pack_dependencies_by_download_count: a list of pack dependencies sorted by download count

        Returns:
            list: list of sorted integration images

        """

        def sort_by_name(integration_image: dict):
            return integration_image.get('name', '')

        # sort packs integration images
        pack_integration_images = sorted(pack_integration_images, key=sort_by_name)

        # sort pack dependencies integration images
        all_dep_int_imgs = pack_integration_images
        for dep_pack_name in pack_dependencies_by_download_count:
            if dep_pack_name in pack_dependencies_integration_images_dict:
                logging.info(f'Adding {dep_pack_name} to deps int imgs')
                dep_int_imgs = sorted(pack_dependencies_integration_images_dict[dep_pack_name], key=sort_by_name)
                for dep_int_img in dep_int_imgs:
                    if dep_int_img not in all_dep_int_imgs:  # avoid duplicates
                        all_dep_int_imgs.append(dep_int_img)

        return all_dep_int_imgs

    @staticmethod
    def _get_all_pack_images(pack_integration_images: list, display_dependencies_images: list,
                             dependencies_metadata: dict,
                             pack_dependencies_by_download_count):
        """ Returns data of uploaded pack integration images and it's path in gcs. Pack dependencies integration images
        are added to that result as well.

        Args:
             pack_integration_images (list): list of uploaded to gcs integration images and it paths in gcs.
             display_dependencies_images (list): list of pack names of additional dependencies images to display.
             dependencies_metadata (dict): all level dependencies data.
             pack_dependencies_by_download_count (list): list of pack names that are dependencies of the given pack
            sorted by download count.

        Returns:
            list: collection of integration display name and it's path in gcs.

        """
        dependencies_integration_images_dict: dict = {}
        additional_dependencies_data = {k: v for k, v in dependencies_metadata.items() if k in
                                        display_dependencies_images}

        for dependency_data in additional_dependencies_data.values():
            for dep_int_img in dependency_data.get('integrations', []):
                dep_int_img_gcs_path = dep_int_img.get('imagePath', '')  # image public url
                dep_int_img['name'] = Pack.remove_contrib_suffix_from_name(dep_int_img.get('name', ''))
                dep_pack_name = os.path.basename(os.path.dirname(dep_int_img_gcs_path))

                if dep_pack_name not in display_dependencies_images:
                    continue  # skip if integration image is not part of displayed images of the given pack

                if dep_int_img not in pack_integration_images:  # avoid duplicates in list
                    if dep_pack_name in dependencies_integration_images_dict:
                        dependencies_integration_images_dict[dep_pack_name].append(dep_int_img)
                    else:
                        dependencies_integration_images_dict[dep_pack_name] = [dep_int_img]

        return Pack.organize_integration_images(
            pack_integration_images, dependencies_integration_images_dict, pack_dependencies_by_download_count
        )

    def is_data_source_pack(self, yaml_content):

        is_data_source = self._is_data_source
        # this's the first integration in the pack, and the pack is in xsiam
        if self._single_integration and 'marketplacev2' in self.marketplaces:

            # the integration contains isfetch or isfetchevents (no matter if its deprecated or not)
            if yaml_content.get('script', {}).get('isfetchevents', False) or \
                    yaml_content.get('script', {}).get('isfetch', False) is True:
                logging.info(f"{yaml_content.get('name')} makes the pack a Data Source potential")
                is_data_source = True
        # already has the pack as data source
        elif not self._single_integration and is_data_source:

            # found a second integration in the pack
            logging.info(f"{yaml_content.get('name')} is no longer a Data Source potential")
            is_data_source = False

        return is_data_source

    def add_pack_type_tags(self, yaml_content, yaml_type):
        """
        Checks if a pack objects is siem or feed object. If so, updates Pack._is_feed or Pack._is_siem
        Args:
            yaml_content: The yaml content extracted by yaml.safe_load().
            yaml_type: The type of object to check.

        Returns:
            Doesn't return
        """
        logging.info("adding pack type tags")
        if yaml_type == 'Integration':
            if yaml_content.get('script', {}).get('feed', False) is True:
                self._is_feed = True
            if yaml_content.get('script', {}).get('isfetchevents', False) is True:
                self._is_siem = True

            self._is_data_source = self.is_data_source_pack(yaml_content)

            # already found the first integration in the pack,
            self._single_integration = False

        if yaml_type == 'Playbook' and yaml_content.get('name').startswith('TIM '):
            self._is_feed = True
        if yaml_type in SIEM_RULES_OBJECTS:
            self._is_siem = True

    @staticmethod
    def _clean_release_notes(release_notes_lines):
        return re.sub(r'<\!--.*?-->', '', release_notes_lines, flags=re.DOTALL)

    def _parse_pack_dependencies(self, dependencies_metadata_dict):
        """ Parses user defined dependencies and returns dictionary with relevant data about each dependency pack.

        Args:
            first_level_dependencies (dict): first lever dependencies that were retrieved
            from user pack_metadata.json file.
            dependencies_metadata_dict (dict): dict of pack dependencies data.

        Returns:
            dict: parsed dictionary with pack dependency data.
        """
        parsed_result = {}

        first_level_dependencies = self.user_metadata.get(Metadata.DEPENDENCIES, {})
        for dependency_id, dependency_data in dependencies_metadata_dict.items():
            if dependency_id in self.user_metadata.get(Metadata.EXCLUDED_DEPENDENCIES, []):
                continue
            parsed_result[dependency_id] = {
                "mandatory": first_level_dependencies.get(dependency_id, {}).get('mandatory', True),
                "minVersion": dependency_data.get(Metadata.CURRENT_VERSION, Pack.PACK_INITIAL_VERSION),
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

        In case support type is xsoar or partner, CERTIFIED is returned.
        In case support is not xsoar or partner but pack_metadata has certification field, certification value will be
        taken from pack_metadata defined value.
        Otherwise empty certification value (empty string) will be returned

        Args:
            support_type (str): support type of pack.
            certification (str): certification value from pack_metadata, if exists.

        Returns:
            str: certification value
        """
        if support_type in [Metadata.XSOAR_SUPPORT, Metadata.PARTNER_SUPPORT]:
            return Metadata.CERTIFIED
        elif certification:
            return certification
        else:
            return ""

    def _get_tags_from_landing_page(self, landing_page_sections: dict) -> set:
        """
        Build the pack's tag list according to the user metadata and the landingPage sections file.
        Args:
            landing_page_sections (dict): landingPage sections and the packs in each one of them.

        Returns:
            set: Pack's tags.

        """

        tags = set()
        sections = landing_page_sections.get('sections', []) if landing_page_sections else []

        for section in sections:
            if self._pack_name in landing_page_sections.get(section, []):
                tags.add(section)

        return tags

    def _parse_pack_metadata(self, build_number, commit_hash):
        """ Parses pack metadata according to issue #19786 and #20091. Part of field may change over the time.

        Args:
            build_number (str): circleCI build number.
            commit_hash (str): current commit hash.

        Returns:
            dict: parsed pack metadata.

        """
        pack_metadata = {
            Metadata.NAME: self._display_name or self._pack_name,
            Metadata.ID: self._pack_name,
            Metadata.DESCRIPTION: self._description or self._pack_name,
            Metadata.CREATED: self._create_date,
            Metadata.UPDATED: self._update_date,
            Metadata.LEGACY: self._legacy,
            Metadata.SUPPORT: self._support_type,
            Metadata.SUPPORT_DETAILS: self._support_details,
            Metadata.EULA_LINK: self._eula_link,
            Metadata.AUTHOR: self._author,
            Metadata.AUTHOR_IMAGE: self._author_image,
            Metadata.CERTIFICATION: self._certification,
            Metadata.PRICE: self._price,
            Metadata.SERVER_MIN_VERSION: self.user_metadata.get(Metadata.SERVER_MIN_VERSION) or self.server_min_version,
            Metadata.CURRENT_VERSION: self.user_metadata.get(Metadata.CURRENT_VERSION, ''),
            Metadata.VERSION_INFO: build_number,
            Metadata.COMMIT: commit_hash,
            Metadata.DOWNLOADS: self._downloads_count,
            Metadata.TAGS: list(self._tags or []),
            Metadata.MODULES: list(self._modules or []),
            Metadata.CATEGORIES: self._categories,
            Metadata.CONTENT_ITEMS: self._content_items,
            Metadata.CONTENT_DISPLAYS: self._content_displays_map,
            Metadata.SEARCH_RANK: self._search_rank,
            Metadata.INTEGRATIONS: self._related_integration_images,
            Metadata.USE_CASES: self._use_cases,
            Metadata.KEY_WORDS: self._keywords,
            Metadata.DEPENDENCIES: self._parsed_dependencies,
            Metadata.EXCLUDED_DEPENDENCIES: self.user_metadata.get(Metadata.EXCLUDED_DEPENDENCIES, []),
            Metadata.MARKETPLACES: self._marketplaces,
            Metadata.VIDEOS: self.user_metadata.get(Metadata.VIDEOS) or [],
        }

        if self._is_private_pack:
            pack_metadata.update({
                Metadata.PREMIUM: self._is_premium,
                Metadata.VENDOR_ID: self._vendor_id,
                Metadata.PARTNER_ID: self._partner_id,
                Metadata.PARTNER_NAME: self._partner_name,
                Metadata.CONTENT_COMMIT_HASH: self._content_commit_hash,
                Metadata.PREVIEW_ONLY: self._preview_only,
                Metadata.DISABLE_MONTHLY: self._disable_monthly,
            })

        return pack_metadata

    def _load_pack_dependencies_metadata(self, index_folder_path, packs_dict):
        """ Loads dependencies metadata and returns mapping of pack id and it's loaded data.
            There are 3 cases:
              Case 1: The dependency is present in the index.zip. In this case, we add it to the dependencies results.
              Case 2: The dependency is missing from the index.zip since it is a new pack. In this case, handle missing
                dependency - This means we mark this pack as 'missing dependency', and once the new index.zip is
                created, and therefore it contains the new pack, we call this function again, and hitting case 1.
              Case 3: The dependency is of a pack that is not a part of this marketplace. In this case, we ignore this
              dependency.
        Args:
            index_folder_path (str): full path to download index folder.
            packs_dict (dict): dict of all packs relevant for current marketplace, as {pack_id: pack_object}.

        Returns:
            dict: pack id as key and loaded metadata of packs as value.
            bool: True if the pack is missing dependencies, False otherwise.

        """
        dependencies_metadata_result = {}
        dependencies_ids = set(self._first_level_dependencies)
        dependencies_ids.update(self._displayed_images_dependent_on_packs)

        for dependency_pack_id in dependencies_ids:
            dependency_metadata_path = os.path.join(index_folder_path, dependency_pack_id, Pack.METADATA)

            if os.path.exists(dependency_metadata_path):
                # Case 1: the dependency is found in the index.zip
                with open(dependency_metadata_path) as metadata_file:
                    dependency_metadata = json.load(metadata_file)
                    dependencies_metadata_result[dependency_pack_id] = dependency_metadata
            elif dependency_pack_id in packs_dict:
                # Case 2: the dependency is not in the index since it is a new pack
                self._is_missing_dependencies = True
                logging.warning(f"{self._pack_name} pack dependency with id {dependency_pack_id} "
                                f"was not found in index, marking it as missing dependencies - to be resolved in "
                                f"next iteration over packs")
            else:
                # Case 3: the dependency is not a part of this marketplace
                logging.warning(f"{self._pack_name} pack dependency with id {dependency_pack_id} "
                                f"is not part of this marketplace, ignoring this dependency")

        return dependencies_metadata_result, self._is_missing_dependencies

    def _get_updated_changelog_entry(self, changelog: dict, version: str, release_notes: str = None,
                                     version_display_name: str = None, build_number_with_prefix: str = None,
                                     released_time: str = None, pull_request_numbers=None, marketplace: str = 'xsoar',
                                     id_set: dict = None):
        """
        Args:
            changelog (dict): The changelog from the production bucket.
            version (str): The version that is the key in the changelog of the entry wished to be updated.
            release_notes (str): The release notes lines to update the entry with.
            version_display_name (str): The version display name to update the entry with.
            build_number_with_prefix(srt): the build number to modify the entry to, including the prefix R (if present).
            released_time: The released time to update the entry with.
            marketplace (str): The marketplace to which the upload is made.

        """
        id_set = id_set if id_set else {}

        changelog_entry = changelog.get(version)
        if not changelog_entry:
            raise Exception('The given version is not a key in the changelog')
        version_display_name = \
            version_display_name if version_display_name else changelog_entry[Changelog.DISPLAY_NAME].split('-')[0]
        build_number_with_prefix = \
            build_number_with_prefix if build_number_with_prefix else \
            changelog_entry[Changelog.DISPLAY_NAME].split('-')[1]

        changelog_entry[Changelog.RELEASE_NOTES] = release_notes
        changelog_entry, _ = self.filter_changelog_entries(
            changelog_entry=changelog_entry,
            version=version,
            marketplace=marketplace,
            id_set=id_set
        )
        changelog_entry[Changelog.DISPLAY_NAME] = f'{version_display_name} - {build_number_with_prefix}'
        changelog_entry[Changelog.RELEASED] = released_time if released_time else changelog_entry[Changelog.RELEASED]
        changelog_entry[Changelog.PULL_REQUEST_NUMBERS] = pull_request_numbers
        return changelog_entry

    def _create_changelog_entry(self, release_notes, version_display_name, build_number,
                                new_version=True, initial_release=False, pull_request_numbers=None,
                                marketplace='xsoar', id_set=None, is_override=False):
        """ Creates dictionary entry for changelog.

        Args:
            release_notes (str): release notes md.
            version_display_name (str): display name version.
            build_number (srt): current build number.
            new_version (bool): whether the entry is new or not. If not new, R letter will be appended to build number.
            initial_release (bool): whether the entry is an initial release or not.
            id_set (dict): The content id set dict.
            is_override (bool): Whether the flow overrides the packs on cloud storage.
        Returns:
            dict: release notes entry of changelog
            bool: Whether the pack is not updated

        """
        id_set = id_set if id_set else {}
        entry_result = {}

        if new_version:
            logging.debug(f"Creating changelog entry for a new version for pack {self.name} and version {version_display_name}")
            pull_request_numbers = self.get_pr_numbers_for_version(version_display_name)
            entry_result = {Changelog.RELEASE_NOTES: release_notes,
                            Changelog.DISPLAY_NAME: f'{version_display_name} - {build_number}',
                            Changelog.RELEASED: datetime.utcnow().strftime(Metadata.DATE_FORMAT),
                            Changelog.PULL_REQUEST_NUMBERS: pull_request_numbers}

        elif initial_release:
            logging.debug(
                f"Creating changelog entry for an initial version for pack {self.name} and version {version_display_name}")
            entry_result = {Changelog.RELEASE_NOTES: release_notes,
                            Changelog.DISPLAY_NAME: f'{version_display_name} - {build_number}',
                            Changelog.RELEASED: self._create_date,
                            Changelog.PULL_REQUEST_NUMBERS: pull_request_numbers}

        elif self.is_modified and not is_override:
            logging.debug(
                f"Creating changelog entry for an existing version for pack {self.name} and version {version_display_name}")
            entry_result = {Changelog.RELEASE_NOTES: release_notes,
                            Changelog.DISPLAY_NAME: f'{version_display_name} - R{build_number}',
                            Changelog.RELEASED: datetime.utcnow().strftime(Metadata.DATE_FORMAT),
                            Changelog.PULL_REQUEST_NUMBERS: pull_request_numbers}

        if entry_result and new_version:
            logging.info(f"Starting filtering entry for pack {self._pack_name} with version {version_display_name}")
            return self.filter_changelog_entries(
                entry_result,
                version_display_name,
                marketplace, id_set
            )

        return entry_result, False

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

            for root, _dirs, files in os.walk(self._pack_path, topdown=True):
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
                signing_process = subprocess.Popen(arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)  # noqa: S602
                output, err = signing_process.communicate()

                if err:
                    logging.error(f"Failed to sign pack for {self._pack_name} - {str(err)}")
                    return None

                logging.info(f"Signed {self._pack_name} pack successfully")
            else:
                logging.info(f"No signature provided. Skipped signing {self._pack_name} pack")
            task_status = True
        except Exception:
            logging.exception(f"Failed to sign pack for {self._pack_name}")
        finally:
            return task_status

    @staticmethod
    def zip_folder_items(source_path, source_name, zip_pack_path):
        """
        Zips the source_path
        Args:
            source_path (str): The source path of the folder the items are in.
            zip_pack_path (str): The path to the zip folder.
            source_name (str): The name of the source that should be zipped.
        """
        task_status = False
        try:
            with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
                for root, _dirs, files in os.walk(source_path, topdown=True):
                    for f in files:
                        full_file_path = os.path.join(root, f)
                        relative_file_path = os.path.relpath(full_file_path, source_path)
                        pack_zip.write(filename=full_file_path, arcname=relative_file_path)

            task_status = True
            logging.success(f"Finished zipping {source_name} folder.")
        except Exception:
            logging.exception(f"Failed in zipping {source_name} folder")
        finally:
            return task_status

    @staticmethod
    def encrypt_pack(zip_pack_path, pack_name, encryption_key, extract_destination_path,
                     private_artifacts_dir, secondary_encryption_key):
        """ decrypt the pack in order to see that the pack was encrypted in the first place.

        Args:
            zip_pack_path (str): The path to the encrypted zip pack.
            pack_name (str): The name of the pack that should be encrypted.
            encryption_key (str): The key which we can decrypt the pack with.
            extract_destination_path (str): The path in which the pack resides.
            private_artifacts_dir (str): The chosen name for the private artifacts directory.
            secondary_encryption_key (str) : A second key which we can decrypt the pack with.
        """
        try:
            current_working_dir = os.getcwd()
            shutil.copy('./encryptor', os.path.join(extract_destination_path, 'encryptor'))
            os.chmod(os.path.join(extract_destination_path, 'encryptor'), stat.S_IXOTH)
            os.chdir(extract_destination_path)

            subprocess.call('chmod +x ./encryptor', shell=True)  # noqa: S602

            output_file = zip_pack_path.replace("_not_encrypted.zip", ".zip")
            full_command = f'./encryptor ./{pack_name}_not_encrypted.zip {output_file} "{encryption_key}"'
            subprocess.call(full_command, shell=True)  # noqa: S602

            secondary_encryption_key_output_file = zip_pack_path.replace("_not_encrypted.zip", ".enc2.zip")
            full_command_with_secondary_encryption = f'./encryptor ./{pack_name}_not_encrypted.zip ' \
                                                     f'{secondary_encryption_key_output_file}' \
                                                     f' "{secondary_encryption_key}"'
            subprocess.call(full_command_with_secondary_encryption, shell=True)  # noqa: S602

            new_artefacts = Path(current_working_dir, private_artifacts_dir)
            if new_artefacts.exists():
                shutil.rmtree(new_artefacts)
            new_artefacts.mkdir(parents=True, exist_ok=True)
            shutil.copy(zip_pack_path, new_artefacts / f'{pack_name}_not_encrypted.zip')
            shutil.copy(output_file, new_artefacts / f'{pack_name}.zip')
            shutil.copy(secondary_encryption_key_output_file, new_artefacts / f'{pack_name}.enc2.zip')
            os.chdir(current_working_dir)
        except (subprocess.CalledProcessError, shutil.Error) as error:
            logging.error(f"Error while trying to encrypt pack. {error}")

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
            Path(extract_destination_path).mkdir(parents=True, exist_ok=True)

            shutil.copy('./decryptor', os.path.join(extract_destination_path, 'decryptor'))
            secondary_encrypted_pack_path = os.path.join(extract_destination_path, 'encrypted_zip_pack.zip')
            shutil.copy(encrypted_zip_pack_path, secondary_encrypted_pack_path)
            os.chmod(os.path.join(extract_destination_path, 'decryptor'), stat.S_IXOTH)
            output_decrypt_file_path = f"{extract_destination_path}/decrypt_pack.zip"
            os.chdir(extract_destination_path)

            subprocess.call('chmod +x ./decryptor', shell=True)  # noqa: S602
            full_command = f'./decryptor {secondary_encrypted_pack_path} {output_decrypt_file_path} "{decryption_key}"'
            process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)  # noqa: S602
            stdout, stderr = process.communicate()
            shutil.rmtree(extract_destination_path)
            os.chdir(current_working_dir)
            if stdout:
                logging.info(str(stdout))
            if stderr:
                logging.error(f"Error: Premium pack {self._pack_name} should be encrypted, but isn't.")
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

    def zip_pack(self, extract_destination_path="", encryption_key="",
                 private_artifacts_dir='private_artifacts', secondary_encryption_key=""):
        """ Zips pack folder.

        Returns:
            bool: whether the operation succeeded.
            str: full path to created pack zip.
        """
        self._zip_path = f"{self._pack_path}.zip" if not encryption_key else f"{self._pack_path}_not_encrypted.zip"
        source_path = self._pack_path
        source_name = self._pack_name
        task_status = self.zip_folder_items(source_path, source_name, self._zip_path)
        # if failed to zip, skip encryption
        if task_status and encryption_key:
            try:
                Pack.encrypt_pack(self._zip_path, source_name, encryption_key, extract_destination_path,
                                  private_artifacts_dir, secondary_encryption_key)
                # If the pack needs to be encrypted, it is initially at a different location than this final path
            except Exception:
                task_status = False
                logging.exception(f"Failed in encrypting {source_name} folder")
        final_path_to_zipped_pack = f"{source_path}.zip"
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
            list: list of RN files that were modified.
            bool: whether pack was modified and override will be required.
        """
        task_status = False
        modified_rn_files_paths = []
        pack_was_modified = False

        try:
            pack_index_metadata_path = os.path.join(index_folder_path, self._pack_name, Pack.METADATA)

            if not os.path.exists(pack_index_metadata_path):
                logging.info(f"{self._pack_name} pack was not found in index, skipping detection of modified pack.")
                task_status = True
                return None

            with open(pack_index_metadata_path) as metadata_file:
                downloaded_metadata = json.load(metadata_file)

            previous_commit_hash = downloaded_metadata.get(Metadata.COMMIT, previous_commit_hash)
            # set 2 commits by hash value in order to check the modified files of the diff
            current_commit = content_repo.commit(current_commit_hash)
            previous_commit = content_repo.commit(previous_commit_hash)

            for modified_file in current_commit.diff(previous_commit):
                if modified_file.a_path.startswith(PACKS_FOLDER):
                    modified_file_path_parts = os.path.normpath(modified_file.a_path).split(os.sep)
                    pack_name, entity_type_dir = modified_file_path_parts[1], modified_file_path_parts[2]

                    if pack_name and pack_name == self._pack_name:
                        if not is_ignored_pack_file(modified_file_path_parts):
                            logging.info(f"Detected modified files in {self._pack_name} pack - {modified_file.a_path}")
                            task_status, pack_was_modified = True, True
                            modified_rn_files_paths.append(modified_file.a_path)

                            if entity_type_dir in PackFolders.pack_displayed_items():
                                if entity_type_dir in self._modified_files:
                                    self._modified_files[entity_type_dir].append(modified_file.a_path)
                                else:
                                    self._modified_files[entity_type_dir] = [modified_file.a_path]

                        else:
                            logging.debug(f'{modified_file.a_path} is an ignored file')

            task_status = True
            if pack_was_modified:
                # Make sure the modification is not only of release notes files, if so count that as not modified
                pack_was_modified = any(
                    self.RELEASE_NOTES not in path
                    for path in modified_rn_files_paths
                )
                # Filter modifications in release notes config JSON file - they will be handled later on.
                modified_rn_files_paths = [path_ for path_ in modified_rn_files_paths if path_.endswith('.md')]
            return None
        except Exception:
            logging.exception(f"Failed in detecting modified files of {self._pack_name} pack")
        finally:
            return task_status, modified_rn_files_paths

    def filter_modified_files_by_id_set(self, id_set: dict, modified_rn_files_paths: list, marketplace):
        """
        Checks if the pack modification is relevant for the current marketplace.

        This is done by searching the modified files in the id_set, if the files were not found in id_set,
        then the modified entities probably not relevant for the current marketplace upload.
        This check is done to identify changed items inside a pack that have both XSIAM and XSOAR entities.

        Args:
            id_set (dict): The current id set.
            modified_rn_files_paths (list): list of paths of the pack's modified release notes files.

        Returns:
            bool: whether the operation succeeded and changes are relevant for marketplace.
            dict: data from id set for the modified files.
        """
        logging.debug(f"Starting to filter modified files of pack {self._pack_name} by the id set")

        task_status = False
        modified_files_data = {}

        for pack_folder, modified_file_paths in self._modified_files.items():
            modified_entities = []
            for path in modified_file_paths:
                if id_set:
                    if id_set_entity := get_id_set_entity_by_path(Path(path), pack_folder, id_set):
                        logging.debug(f"The entity with the path {path} is present in the id set")
                        modified_entities.append(id_set_entity)
                else:
                    if entity := get_graph_entity_by_path(Path(path), marketplace):
                        logging.debug(f"The entity with the path {path} is present in the content graph")
                        modified_entities.append(entity)

            if modified_entities:
                modified_files_data[pack_folder] = modified_entities

        if not self._modified_files or modified_files_data or modified_rn_files_paths:
            # The task status will be success if there are no modified files in the pack or if the modified files were found in
            # the id-set or if there are modified old release notes files for items that are not being modified.
            task_status = True

        return task_status, modified_files_data

    def upload_to_storage(self, zip_pack_path, latest_version, storage_bucket, override_pack, storage_base_path,
                          private_content=False, pack_artifacts_path=None, overridden_upload_path=None):
        """ Manages the upload of pack zip artifact to correct path in cloud storage.
        The zip pack will be uploaded by default to following path: /content/packs/pack_name/pack_latest_version.
        In case that zip pack artifact already exist at constructed path, the upload will be skipped.
        If flag override_pack is set to True, pack will forced for upload.
        If item_upload_path is provided it will override said path, and will save the item to that destination.

        Args:
            zip_pack_path (str): full path to pack zip artifact.
            latest_version (str): pack latest version.
            storage_bucket (google.cloud.storage.bucket.Bucket): google cloud storage bucket.
            override_pack (bool): whether to override existing pack.
            private_content (bool): Is being used in a private content build.
            storage_base_path (str): The upload destination in the target bucket for all packs (in the format of
                                     <some_path_in_the_target_bucket>/content/Packs).

            pack_artifacts_path (str): Path to where we are saving pack artifacts.
            overridden_upload_path (str): If provided, will override version_pack_path calculation and will use this path instead

        Returns:
            bool: whether the operation succeeded.
            bool: True in case of pack existence at targeted path and upload was skipped, otherwise returned False.
            str: Path to pack's zip in the bucket after the upload.

        """
        task_status = True

        try:
            if overridden_upload_path:
                if private_content:
                    logging.warning("Private content does not support overridden argument")
                    return task_status, True, None
                zip_to_upload_full_path = overridden_upload_path
            else:
                version_pack_path = os.path.join(storage_base_path, self._pack_name, latest_version)

                if override_pack:
                    logging.warning(f"Uploading {self._pack_name} pack to storage and overriding the existing pack "
                                    f"files already in storage.")

                else:
                    logging.warning(f"The following packs were not modified: {self._pack_name}")
                    logging.warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
                    return task_status, True, None

                zip_to_upload_full_path = os.path.join(version_pack_path, f"{self._pack_name}.zip")
            blob = storage_bucket.blob(zip_to_upload_full_path)
            blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob

            with open(zip_pack_path, "rb") as pack_zip:
                blob.upload_from_file(pack_zip)
            if private_content:
                secondary_encryption_key_pack_name = f"{self._pack_name}.enc2.zip"
                secondary_encryption_key_bucket_path = os.path.join(version_pack_path,
                                                                    secondary_encryption_key_pack_name)

                #  In some cases the path given is actually a zip.
                if isinstance(pack_artifacts_path, str) and pack_artifacts_path.endswith('content_packs.zip'):
                    _pack_artifacts_path = pack_artifacts_path.replace('/content_packs.zip', '')
                else:
                    _pack_artifacts_path = pack_artifacts_path

                secondary_encryption_key_artifacts_path = zip_pack_path.replace(f'{self._pack_name}',
                                                                                f'{self._pack_name}.enc2')

                blob = storage_bucket.blob(secondary_encryption_key_bucket_path)
                blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob
                with open(secondary_encryption_key_artifacts_path, "rb") as pack_zip:
                    blob.upload_from_file(pack_zip)

                logging.info(
                    f"Copying {secondary_encryption_key_artifacts_path} to {_pack_artifacts_path}/"
                    f"packs/{self._pack_name}.zip")
                shutil.copy(secondary_encryption_key_artifacts_path,
                            f'{_pack_artifacts_path}/packs/{self._pack_name}.zip')

            self.public_storage_path = blob.public_url
            logging.success(f"Uploaded {self._pack_name} pack to {zip_to_upload_full_path} path.")

            return task_status, False, zip_to_upload_full_path
        except Exception:
            task_status = False
            logging.exception(f"Failed in uploading {self._pack_name} pack to gcs.")
            return task_status, True, None

    def copy_and_upload_to_storage(self, production_bucket, build_bucket, successful_packs_dict,
                                   successful_uploaded_dependencies_zip_packs_dict, storage_base_path, build_bucket_base_path):
        """ Manages the copy of pack zip artifact from the build bucket to the production bucket.
        The zip pack will be copied to following path: /content/packs/pack_name/pack_latest_version if
        the pack exists in the successful_packs_dict from Prepare content step in Create Instances job.

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): google cloud production bucket.
            build_bucket (google.cloud.storage.bucket.Bucket): google cloud build bucket.
            successful_packs_dict (dict): the dict of all packs were uploaded in prepare content step
            successful_uploaded_dependencies_zip_packs_dict (dict): the dict of all packs that successfully updated
            their dependencies zip file.
            storage_base_path (str): The target destination of the upload in the target bucket.
            build_bucket_base_path (str): The path of the build bucket in gcp.
        Returns:
            bool: Status - whether the operation succeeded.
            bool: Skipped pack - true in case of pack existence at the targeted path and the copy process was skipped,
             otherwise returned False.

        """
        task_status = True
        pack_was_uploaded_in_prepare_content = self._pack_name in successful_packs_dict
        pack_dependencies_zip_was_uploaded = self._pack_name in successful_uploaded_dependencies_zip_packs_dict
        if not pack_was_uploaded_in_prepare_content and not pack_dependencies_zip_was_uploaded:
            logging.warning("The following packs already exist at storage.")
            logging.warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
            return True, True

        elif pack_was_uploaded_in_prepare_content:

            latest_version = successful_packs_dict[self._pack_name][BucketUploadFlow.LATEST_VERSION]
            self._latest_version = latest_version

            build_version_pack_path = os.path.join(build_bucket_base_path, self._pack_name, latest_version)

            # Verifying that the latest version of the pack has been uploaded to the build bucket
            existing_bucket_version_files = [f.name for f in build_bucket.list_blobs(prefix=build_version_pack_path)]
            if not existing_bucket_version_files:
                logging.error(f"{self._pack_name} latest version ({latest_version}) was not found on build bucket at "
                              f"path {build_version_pack_path}.")
                return False, False

            # We upload the pack zip object taken from the build bucket into the production bucket
            prod_version_pack_path = os.path.join(storage_base_path, self._pack_name, latest_version)
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
                agg_str = successful_packs_dict[self._pack_name].get('aggregated')
                if agg_str:
                    self._aggregated = True
                    self._aggregation_str = agg_str
                logging.success(f"Uploaded {self._pack_name} pack to {prod_pack_zip_path} path.")

        # handle dependenices zip upload when found in build bucket
        self.copy_and_upload_dependencies_zip_to_storage(
            build_bucket,
            build_bucket_base_path,
            production_bucket,
            storage_base_path
        )

        return task_status, False

    def copy_and_upload_dependencies_zip_to_storage(self, build_bucket, build_bucket_base_path, production_bucket,
                                                    storage_base_path):
        pack_with_deps_name = f'{self._pack_name}_with_dependencies.zip'
        build_pack_with_deps_path = os.path.join(build_bucket_base_path, self._pack_name, pack_with_deps_name)
        existing_bucket_deps_files = [f.name for f in build_bucket.list_blobs(prefix=build_pack_with_deps_path)]
        if existing_bucket_deps_files:
            logging.info(f"{self._pack_name} with dependencies was found. path {build_pack_with_deps_path}.")

            # We upload the pack dependencies zip object taken from the build bucket into the production bucket
            prod_version_pack_deps_zip_path = os.path.join(storage_base_path, self._pack_name, pack_with_deps_name)
            build_pack_deps_zip_blob = build_bucket.blob(build_pack_with_deps_path)

            try:
                copied_blob = build_bucket.copy_blob(
                    blob=build_pack_deps_zip_blob,
                    destination_bucket=production_bucket,
                    new_name=prod_version_pack_deps_zip_path
                )
                copied_blob.cache_control = "no-cache,max-age=0"  # disabling caching for pack blob
                self.public_storage_path = copied_blob.public_url
                dep_task_status = copied_blob.exists()
                if not dep_task_status:
                    logging.error(f"Failed in uploading {self._pack_name} pack with dependencies to production gcs.")
            except Exception as e:
                pack_deps_zip_suffix = os.path.join(self._pack_name, pack_with_deps_name)
                logging.exception(f"Failed copying {pack_deps_zip_suffix}. Additional Info: {str(e)}")

    def get_changelog_latest_rn(self, changelog_index_path: str) -> tuple[dict, Version, str]:
        """
        Returns the changelog file contents and the last version of rn in the changelog file
        Args:
            changelog_index_path (str): the changelog.json file path in the index

        Returns: the changelog file contents, the last version,  and contents of rn in the changelog file

        """
        logging.info(f"Found Changelog for: {self._pack_name}")
        if os.path.exists(changelog_index_path):
            try:
                with open(changelog_index_path) as changelog_file:
                    changelog = json.load(changelog_file)
            except json.JSONDecodeError:
                changelog = {}
        else:
            changelog = {}
        # get the latest rn version in the changelog.json file
        changelog_rn_versions = [Version(ver) for ver in changelog]
        # no need to check if changelog_rn_versions isn't empty because changelog file exists
        changelog_latest_rn_version = max(changelog_rn_versions)
        changelog_latest_rn = changelog[str(changelog_latest_rn_version)]["releaseNotes"]

        return changelog, changelog_latest_rn_version, changelog_latest_rn

    def get_modified_release_notes_lines(self, release_notes_dir: str, new_release_notes_versions: list,
                                         changelog: dict, modified_rn_files: list):
        """
        In the case where an rn file was changed, this function returns the new content
        of the release note in the format suitable for the changelog file.
        In general, if two rn files are created between two consecutive upload runs (i.e. pack was changed twice),
        the rn files are being aggregated and the latter version is the one that is being used as a key in the changelog
        file, and the aggregated rns as the value.
        Hence, in the case of changing an rn as such, this function re-aggregates all of the rns under the
        corresponding version key, and returns the aggregated data, in the right format, as value under that key.

        Args:
            release_notes_dir (str): the path to the release notes dir
            new_release_notes_versions (list): a list of the new versions of release notes in the pack since the
             last upload. This means they were already handled on this upload run (and aggregated if needed).
            changelog (dict): the changelog from the production bucket.
            modified_rn_files (list): a list of the rn files that were modified according to the last commit in
             'filename.md' format.

        Returns:
            A dict of modified version and their release notes contents, for modified
              in the current index file


        """

        modified_versions_dict = {}

        for rn_filename in modified_rn_files:
            version = underscore_file_name_to_dotted_version(rn_filename)
            # Should only apply on modified files that are not the last rn file
            if version in new_release_notes_versions:
                continue
            # The case where the version is a key in the changelog file,
            # and the value is not an aggregated release note
            if is_the_only_rn_in_block(release_notes_dir, version, changelog):
                logging.info("The version is a key in the changelog file and by itself in the changelog block")
                with open(os.path.join(release_notes_dir, rn_filename)) as rn_file:
                    rn_lines = rn_file.read()
                modified_versions_dict[version] = self._clean_release_notes(rn_lines).strip()
                logging.debug(f"Cleaned release notes from: {rn_lines} to: {modified_versions_dict[version]}")
            # The case where the version is not a key in the changelog file or it is a key of aggregated content
            else:
                logging.debug(f'The "{version}" version is not a key in the changelog file or it is a key of'
                              f' aggregated content')
                same_block_versions_dict, higher_nearest_version = self.get_same_block_versions(
                    release_notes_dir, version, changelog)
                modified_versions_dict[higher_nearest_version] = aggregate_release_notes_for_marketplace(
                    same_block_versions_dict)

        return modified_versions_dict

    def get_same_block_versions(self, release_notes_dir: str, version: str, changelog: dict):
        """
        Get a dict of the version as key and rn data as value of all of the versions that are in the same
        block in the changelog file as the given version (these are the versions that were aggregates together
        during a single upload priorly).

        Args:
            release_notes_dir (str): the path to the release notes dir
            version (str): the wanted version
            changelog (dict): the changelog from the production bucket.

        Returns:
            A dict of version, rn data for all corresponding versions, and the highest version among those keys as str

        """
        lowest_version = [Version(Pack.PACK_INITIAL_VERSION)]
        lower_versions: list = []
        higher_versions: list = []
        same_block_versions_dict: dict = {}
        for item in changelog:  # divide the versions into lists of lower and higher than given version
            (lower_versions if Version(item) < Version(version) else higher_versions).append(Version(item))
        higher_nearest_version = min(higher_versions)
        lower_versions = lower_versions + lowest_version  # if the version is 1.0.0, ensure lower_versions is not empty
        lower_nearest_version = max(lower_versions)
        for rn_filename in filter_dir_files_by_extension(release_notes_dir, '.md'):
            current_version = underscore_file_name_to_dotted_version(rn_filename)
            # Catch all versions that are in the same block
            if lower_nearest_version < Version(current_version) <= higher_nearest_version:
                with open(os.path.join(release_notes_dir, rn_filename)) as rn_file:
                    rn_lines = rn_file.read()
                same_block_versions_dict[current_version] = self._clean_release_notes(rn_lines).strip()
        return same_block_versions_dict, str(higher_nearest_version)

    def get_release_notes_lines(self, release_notes_dir: str, changelog_latest_rn_version: Version,
                                changelog_latest_rn: str) -> tuple[str, str, list]:
        """
        Prepares the release notes contents for the new release notes entry
        Args:
            release_notes_dir (str): the path to the release notes dir
            changelog_latest_rn_version (Version): the last version of release notes in the changelog.json file
            changelog_latest_rn (str): the last release notes in the changelog.json file

        Returns: The release notes contents, the latest release notes version (in the release notes directory),
        and a list of the new rn versions that this is the first time they have been uploaded.

        """
        found_versions: list = []
        pack_versions_dict: dict = {}
        for filename in sorted(filter_dir_files_by_extension(release_notes_dir, '.md')):
            version = underscore_file_name_to_dotted_version(filename)

            # Aggregate all rn files that are bigger than what we have in the changelog file
            if Version(version) > changelog_latest_rn_version:
                with open(os.path.join(release_notes_dir, filename)) as rn_file:
                    rn_lines = rn_file.read()
                pack_versions_dict[version] = self._clean_release_notes(rn_lines).strip()

            found_versions.append(Version(version))

        latest_release_notes_version = max(found_versions)
        latest_release_notes_version_str = str(latest_release_notes_version)
        logging.info(f"Latest ReleaseNotes version is: {latest_release_notes_version_str}")

        if len(pack_versions_dict) > 1:
            # In case that there is more than 1 new release notes file, wrap all release notes together for one
            # changelog entry
            aggregation_str = f"[{', '.join(str(lv) for lv in found_versions if lv > changelog_latest_rn_version)}]" \
                              f" => {latest_release_notes_version_str}"
            logging.info(f"Aggregating ReleaseNotes versions: {aggregation_str}")
            release_notes_lines = aggregate_release_notes_for_marketplace(pack_versions_dict)
            self._aggregated = True
            self._aggregation_str = aggregation_str
        elif len(pack_versions_dict) == 1:
            # In case where there is only one new release notes file
            release_notes_lines = pack_versions_dict[latest_release_notes_version_str]
        else:
            # In case where the pack is up to date, i.e. latest changelog is latest rn file
            # We should take the release notes from the index as it has might been aggregated
            logging.info(f'No new RN file was detected for pack {self._pack_name}, taking latest RN from the index')
            release_notes_lines = changelog_latest_rn
        new_release_notes_versions = list(pack_versions_dict.keys())

        return release_notes_lines, latest_release_notes_version_str, new_release_notes_versions

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
        changelog_latest_release_notes = max(changelog, key=lambda k: Version(k))  # pylint: disable=W0108
        assert Version(latest_release_notes) >= Version(changelog_latest_release_notes), \
            f'{self._pack_name}: Version mismatch detected between upload bucket and current branch\n' \
            f'Upload bucket version: {changelog_latest_release_notes}\n' \
            f'current branch version: {latest_release_notes}\n' \
            'Please Merge from master and rebuild'

    def get_rn_files_names(self, modified_rn_files_paths):
        """

        Args:
            modified_rn_files_paths: a list containing all modified files in the current pack, generated
            by comparing the old and the new commit hash.
        Returns:
            The names of the modified release notes files out of the given list only,
            as in the names of the files that are under ReleaseNotes directory in the format of 'filename.md'.

        """
        modified_rn_files = []
        for file_path in modified_rn_files_paths:
            modified_file_path_parts = os.path.normpath(file_path).split(os.sep)
            if self.RELEASE_NOTES in modified_file_path_parts:
                modified_rn_files.append(modified_file_path_parts[-1])
        return modified_rn_files

    def prepare_release_notes(self, index_folder_path, build_number, modified_rn_files_paths=None,
                              marketplace='xsoar', id_set=None, is_override=False):
        """
        Handles the creation and update of the changelog.json files.

        Args:
            index_folder_path (str): Path to the unzipped index json.
            build_number (str): circleCI build number.
            modified_rn_files_paths (list): list of paths of the pack's modified file
            marketplace (str): The marketplace to which the upload is made.
            is_override (bool): Whether the flow overrides the packs on cloud storage.

        Returns:
            bool: whether the operation succeeded.
            bool: whether running build has not updated pack release notes.
            list: pack versions to keep in the changelog
        """
        task_status = False
        not_updated_build = False
        release_notes_dir = os.path.join(self._pack_path, Pack.RELEASE_NOTES)

        modified_rn_files_paths = modified_rn_files_paths if modified_rn_files_paths else []
        id_set = id_set if id_set else {}
        pack_versions_to_keep: list[str] = []

        try:
            # load changelog from downloaded index
            logging.info(f"Loading changelog for {self._pack_name} pack")
            changelog_index_path = os.path.join(index_folder_path, self._pack_name, Pack.CHANGELOG_JSON)

            changelog: dict = {}
            if os.path.exists(changelog_index_path):
                changelog, changelog_latest_rn_version, changelog_latest_rn = \
                    self.get_changelog_latest_rn(changelog_index_path)

                if os.path.exists(release_notes_dir):
                    # Handling latest release notes files
                    release_notes_lines, latest_release_notes, new_release_notes_versions = \
                        self.get_release_notes_lines(
                            release_notes_dir, changelog_latest_rn_version, changelog_latest_rn)
                    self.assert_upload_bucket_version_matches_release_notes_version(changelog, latest_release_notes)

                    # Handling modified old release notes files, if there are any
                    rn_files_names = self.get_rn_files_names(modified_rn_files_paths)
                    modified_release_notes_lines_dict = self.get_modified_release_notes_lines(
                        release_notes_dir, new_release_notes_versions, changelog, rn_files_names)

                    if self._current_version != latest_release_notes:
                        logging.error(f"Version mismatch detected between the pack's current version in "
                                      f"pack_metadata.json: {self._current_version} and latest release notes "
                                      f"version: {latest_release_notes}.")
                        task_status = False
                        return task_status, not_updated_build, pack_versions_to_keep
                    else:
                        if latest_release_notes in changelog:
                            logging.debug(f"Found existing release notes for version: {latest_release_notes}")
                            version_changelog, not_updated_build = self._create_changelog_entry(
                                release_notes=release_notes_lines,
                                version_display_name=latest_release_notes,
                                build_number=build_number,
                                new_version=False,
                                pull_request_numbers=changelog.get(latest_release_notes,
                                                                   {}).get(Changelog.PULL_REQUEST_NUMBERS, []),
                                marketplace=marketplace,
                                id_set=id_set,
                                is_override=is_override
                            )

                        else:
                            logging.info(f"Created new release notes for version: {latest_release_notes}")
                            version_changelog, not_updated_build = self._create_changelog_entry(
                                release_notes=release_notes_lines,
                                version_display_name=latest_release_notes,
                                build_number=build_number,
                                new_version=True,
                                marketplace=marketplace,
                                id_set=id_set,
                            )

                        if version_changelog:
                            changelog[latest_release_notes] = version_changelog

                        if modified_release_notes_lines_dict:
                            logging.info(f"Updating changelog entries for modified release notes: "
                                         f"{modified_release_notes_lines_dict}")
                            for version, modified_release_notes_lines in modified_release_notes_lines_dict.items():
                                versions, _ = self.get_same_block_versions(release_notes_dir, version, changelog)
                                all_relevant_pr_nums_for_unified = list({pr_num for _version in versions
                                                                        for pr_num in self.get_pr_numbers_for_version(_version)})
                                logging.debug(f"{all_relevant_pr_nums_for_unified=}")
                                updated_entry = self._get_updated_changelog_entry(
                                    changelog=changelog,
                                    version=version,
                                    release_notes=modified_release_notes_lines,
                                    pull_request_numbers=all_relevant_pr_nums_for_unified,
                                    marketplace=marketplace,
                                    id_set=id_set
                                )
                                changelog[version] = updated_entry

                else:
                    if len(changelog.keys()) > 1:
                        # If there is no release notes dir but the changelog has a few entries in it,
                        # there is a mismatch
                        logging.warning(
                            f"{self._pack_name} pack mismatch between {Pack.CHANGELOG_JSON} and {Pack.RELEASE_NOTES}")
                        task_status, not_updated_build = True, True

                    else:
                        # allow changing the initial changelog version
                        first_key_in_changelog = list(changelog.keys())[0]
                        version_changelog, not_updated_build = self._create_changelog_entry(
                            release_notes=self.description,
                            version_display_name=first_key_in_changelog,
                            build_number=build_number,
                            initial_release=True,
                            new_version=False,
                            marketplace=marketplace,
                            id_set=id_set)

                        if version_changelog:
                            changelog[first_key_in_changelog] = version_changelog

                        logging.info(f"Found existing release notes in {Pack.CHANGELOG_JSON} for version: "
                                     f"{first_key_in_changelog} of pack {self._pack_name}. Modifying this version in "
                                     f"{Pack.CHANGELOG_JSON}")

            elif self._hidden:
                logging.warning(f"Pack {self._pack_name} is deprecated. Skipping release notes handling.")
                task_status = True
                not_updated_build = True
                return task_status, not_updated_build, pack_versions_to_keep

            else:
                # if there is no changelog file for the pack, this is a new pack, and we start it's changelog at it's
                # current version
                first_pack_release_notes = ''
                first_release_notes_path = os.path.join(release_notes_dir, '1_0_0.md')

                # If an 1_0_0.md release notes file exist then add it to the changelog, otherwise take the pack description
                if os.path.exists(first_release_notes_path):
                    with open(first_release_notes_path) as rn_file:
                        first_pack_release_notes = rn_file.read()
                else:
                    first_pack_release_notes = self.description

                version_changelog, not_updated_build = self._create_changelog_entry(
                    release_notes=first_pack_release_notes,
                    version_display_name=self._current_version,
                    build_number=build_number,
                    new_version=True,
                    initial_release=True,
                    marketplace=marketplace,
                    id_set=id_set
                )

                if version_changelog:
                    changelog = {
                        self._current_version: version_changelog
                    }

                logging.info(f'Created {Pack.CHANGELOG_JSON} for pack {self._pack_name} starting at version'
                             f' {self._current_version}')

            # Update change log entries with BC flag.
            self.add_bc_entries_if_needed(release_notes_dir, changelog)

            # Remove old entries from change log
            pack_versions_to_keep = remove_old_versions_from_changelog(changelog)

            logging.debug(f'Versions to keep for pack: {self._pack_name} = {pack_versions_to_keep}')
            # write back changelog with changes to pack folder
            with open(os.path.join(self._pack_path, Pack.CHANGELOG_JSON), "w") as pack_changelog:
                json.dump(changelog, pack_changelog, indent=4)

            task_status = True
            logging.success(f"Finished creating {Pack.CHANGELOG_JSON} for {self._pack_name}")
        except Exception as e:
            logging.error(f"Failed creating {Pack.CHANGELOG_JSON} file for {self._pack_name}.\n "
                          f"Additional info: {e}")
        finally:
            return task_status, not_updated_build, pack_versions_to_keep

    def filter_changelog_entries(self, changelog_entry: dict, version: str, marketplace: str, id_set: dict):
        """
        Filters the changelog entries by the entities that are given from id-set.
        This is to avoid RN entries/changes/messages that are not relevant to the current marketplace.

        The filter is done in two parts:
        1. Filter the entry by marketplace intended tags.
        2. Filter by the entity display name if it doesn't exist in id-set.

        If there are no entries after filtering then the pack will be skipped and not be uploaded.

        Args:
            changelog_entry: The version changelog object.
            version: The changelog's version.
            marketplace: The marketplace to which the upload is made.
            id_set: The id set dict.

        Returns:
            (dict) The filtered changelog entry.
            (bool) Whether the pack is not updated because the entries are not relevant to the current marketplace.
        """
        logging.debug(f"Starting to filter changelog entries by the entities that are given from id-set for pack "
                      f"{self._pack_name}")

        release_notes = self.filter_release_notes_by_tags(changelog_entry.get(Changelog.RELEASE_NOTES), marketplace)

        # Convert the RN entries to a Dict
        release_notes_dict = self.get_release_notes_dict(version, release_notes)
        logging.debug(f"Release notes entries in dict - {release_notes_dict}")

        if self.release_notes_dont_contain_entities_sections(release_notes_str=release_notes,
                                                             release_notes_dict=release_notes_dict):
            logging.debug(f"The pack {self._pack_name} release notes does not contain any entities")
            return changelog_entry, False

        filtered_release_notes_from_tags = self.filter_headers_without_entries(release_notes_dict)  # type: ignore[arg-type]
        filtered_release_notes = self.filter_entries_by_display_name(filtered_release_notes_from_tags, id_set, marketplace)

        # if not filtered_release_notes and self.are_all_changes_relevant_to_more_than_one_marketplace(modified_files_data):
        #     # In case all release notes were filtered out, verify that it also makes sense - by checking that the
        #     # modified files are actually relevant for the other marketplace.
        #     logging.debug(f"The pack {self._pack_name} does not have any release notes that are relevant to this "
        #                   f"marketplace")
        #     return {}, True

        # Convert the RN dict to string

        final_release_notes = construct_entities_block(filtered_release_notes).strip()
        if not final_release_notes:
            final_release_notes = f"Changes are not relevant for " \
                                  f"{'XSIAM' if marketplace == 'marketplacev2' else marketplace.upper()} marketplace."

        changelog_entry[Changelog.RELEASE_NOTES] = final_release_notes
        logging.debug(f"Finall release notes - \n{changelog_entry[Changelog.RELEASE_NOTES]}")
        return changelog_entry, False

    def are_all_changes_relevant_to_more_than_one_marketplace(self, modified_files_data):
        """
        Returns true if all the modified files are also relevant to another marketplace besides the current one
         this upload is done for.

        Args:
            modified_files_data (dict): The modified files data that are given from id-set.

        Return:
            (bool) True, if all the files are relevant to more than one marketplace.
                   False, if there is an item that is relevant only to the current marketplace.
        """
        modified_items = []

        for entities_data in modified_files_data.values():
            modified_items.extend([list(item.values())[0] for item in entities_data])

        return all(len(item['marketplaces']) != 1 for item in modified_items)

    @staticmethod
    def filter_entries_by_display_name(release_notes: dict, id_set: dict, marketplace="xsoar"):
        """
        Filters the entries by display names and also handles special entities that their display name is not an header.

        Args:
            release_notes (dict): The release notes in a dict.
            display_names (list): The display names that are give from the id-set.
            rn_header (str): The release notes entity header.

        Returns:
            (dict) The filtered release notes entries.
        """
        filtered_release_notes: dict = {}
        for content_type, content_type_rn_entries in release_notes.items():
            content_type_to_filtered_entries: dict = {}

            for content_item_display_name, content_item_rn_notes in content_type_rn_entries.items():

                logging.debug(f"Searching display name '{content_item_display_name}' with rn header "
                              f"'{content_type}' in in id set.")
                if content_item_display_name != '[special_msg]' and not is_content_item_in_id_set(
                        content_item_display_name.replace("New: ", ""), content_type, id_set, marketplace):
                    continue

                if content_item_display_name == '[special_msg]':
                    extracted_names_from_rn = SPECIAL_DISPLAY_NAMES_PATTERN.findall(content_item_rn_notes)

                    for name in extracted_names_from_rn:
                        if not is_content_item_in_id_set(name.replace("New: ", ""), content_type, id_set, marketplace):
                            content_item_rn_notes = content_item_rn_notes.replace(f'- **{name}**', '').strip()

                    if not content_item_rn_notes:
                        continue

                content_type_to_filtered_entries[content_item_display_name] = content_item_rn_notes

            if content_type_to_filtered_entries:
                filtered_release_notes[content_type] = content_type_to_filtered_entries

        logging.debug(f"Release notes after filtering by display -\n{filtered_release_notes}")

        if not filtered_release_notes:
            logging.debug(f"Didn't find relevant release notes entries after filtering by display name.\n \
                            Release notes: {release_notes}")

        return filtered_release_notes

    @staticmethod
    def filter_headers_without_entries(release_notes_dict: dict):
        """
        Filters out the entity type/name headers if their entries were filtered by tags.

        Args:
            release_notes_dict (dict): The release notes in a dict object.

        Returns:
            (dict) A new release notes dict after filtering.
        """
        new_release_notes_dict: dict = {}
        for entity_header, entity_entry in release_notes_dict.items():

            new_entity_entry = {name: entry.replace('\n\n', '\n') for name, entry in entity_entry.items()
                                if entry.strip() not in ['', '\n']}

            if new_entity_entry:
                new_release_notes_dict[entity_header] = new_entity_entry

        return new_release_notes_dict

    @staticmethod
    def release_notes_dont_contain_entities_sections(release_notes_str, release_notes_dict):
        """
        If the release notes didn't formatted into a dict it's because one of the following:
        - In case it's a first release of the pack then the release notes is taken from the pack description,
        - If it's just an important message for the customers who uses the pack.
        In both cases the RN entries will not contain the entity headers as in our templates.

        Args:
            release_notes_str (str): The release notes in string.
            release_notes_dict (dict): The release notes in dict object.

        Returns:
            (bool) Whther the dict contains the RN entries by the entities types.
        """
        return release_notes_str and not release_notes_dict

    def filter_release_notes_by_tags(self, release_notes, upload_marketplace):
        """
        Filters out from release notes the sub-entries that are wrapped by tags.

        Args:
            release_notes(str): The release notes entry.
            upload_marketplace (str): The marketplace to which the upload is made.

        Return:
            (str) The release notes entry after filtering.
        """

        def remove_tags_section_from_rn(release_notes, marketplace, upload_marketplace):

            start_tag, end_tag = TAGS_BY_MP[marketplace]
            if start_tag in release_notes and end_tag in release_notes and marketplace != upload_marketplace:
                logging.debug(f"Filtering irrelevant release notes by tags of marketplace "
                              f"{marketplace} for pack {self._pack_name} when uploading to marketplace "
                              f"{upload_marketplace}.")
                return re.sub(fr'{start_tag}{TAGS_SECTION_PATTERN}{end_tag}[\n]*', '', release_notes)
            else:
                logging.debug(f"Removing only the tags since the RN entry is relevant "
                              f"to marketplace {upload_marketplace}")
                return release_notes.replace(f"{start_tag}", '').replace(f"{end_tag}", '')

        # Filters out for XSIAM tags
        release_notes = remove_tags_section_from_rn(release_notes, XSIAM_MP, upload_marketplace)

        # Filters out for XSOAR tags
        release_notes = remove_tags_section_from_rn(release_notes, XSOAR_MP, upload_marketplace)

        # Filters out for XPANSE tags
        release_notes = remove_tags_section_from_rn(release_notes, XPANSE_MP, upload_marketplace)

        logging.debug(f"RN result after filtering for pack {self._pack_name} in marketplace "
                      f"{upload_marketplace}\n - {release_notes}")

        return release_notes

    @staticmethod
    def get_release_notes_dict(version, release_notes):
        """
        Gets the release notes in a dict format.
        This function uses the merge_version_blocks function that intended for merging multiple
        release versions into one version.

        Args:
            version (str): The release version.
            release_notes (str): The release notes entries.

        Return:
            (dict) The release notes in a dict that should look like: {<entity type>: {<display name>: <entries>}}
        """
        release_notes_dict, _ = merge_version_blocks({version: release_notes}, return_str=False)
        return release_notes_dict

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
            logging.error(
                f"{self._pack_name} index changelog file is missing in build bucket path: {build_changelog_index_path}")

        return task_status and self.is_changelog_exists()

    def is_replace_item_in_folder_collected_list(self, content_item: dict,
                                                 content_items_to_version_map: dict,
                                                 content_item_id: str):
        """ Checks the fromversion and toversion in the content_item with
            the fromversion toversion in content_items_to_version_map
            If the content_item has a more up to date toversion and fromversion will
            replace it in the map and metadata list
        Returns:
             A boolean whether the version in the list posted to metadata should be
             replaced with the current version from the content item.
        """
        content_item_fromversion = content_item.get('fromversion') or content_item.get('fromVersion') or ''
        content_item_toversion = content_item.get(
            'toversion') or content_item.get('toVersion') or MAX_TOVERSION
        content_item_latest_version = content_items_to_version_map.setdefault(
            content_item_id,
            {'fromversion': content_item_fromversion,
             'toversion': content_item_toversion,
             'added_to_metadata_list': False,
             })
        if (replace_old_playbook := content_item_latest_version.get('toversion') < content_item_fromversion):
            content_items_to_version_map[content_item_id] = {
                'fromversion': content_item_fromversion,
                'toversion': content_item_toversion,
                'added_to_metadata_list': True,
            }
        return replace_old_playbook

    def get_latest_versions(self, content_items_id_to_version_map: dict, content_item_id: str):
        """ Get the latest fromversion and toversion of a content item.
        Returns:
             A tuple containing the latest fromversion and toversion.
        """
        if (curr_content_item := content_items_id_to_version_map.get(
                content_item_id)):
            latest_fromversion = curr_content_item.get('fromversion', '')
            latest_toversion = curr_content_item.get('toversion', '')
        else:
            latest_fromversion = ''
            latest_toversion = ''
        latest_toversion = latest_toversion if latest_toversion != MAX_TOVERSION else ''
        return latest_fromversion, latest_toversion

    def collect_content_items(self):
        """ Iterates over content items folders inside pack and collects content items data.

        Returns:
            dict: Parsed content items
            .
        """
        task_status = False
        content_items_result: dict = {}
        content_items_id_to_version_map: dict = {}

        try:

            for root, _pack_dirs, pack_files_names in os.walk(self._pack_path, topdown=False):
                current_directory = root.split(os.path.sep)[-1]
                parent_directory = root.split(os.path.sep)[-2]

                if parent_directory in [PackFolders.GENERIC_TYPES.value, PackFolders.GENERIC_FIELDS.value]:
                    current_directory = parent_directory
                elif current_directory in [PackFolders.GENERIC_TYPES.value, PackFolders.GENERIC_FIELDS.value]:
                    continue

                folder_collected_items: list = []
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

                    with open(pack_file_path) as pack_file:
                        if current_directory in PackFolders.yml_supported_folders():
                            content_item = yaml.safe_load(pack_file)
                        elif current_directory in PackFolders.json_supported_folders():
                            content_item = json.load(pack_file)
                        else:
                            continue

                    # check if content item has to version
                    try:
                        to_version = content_item.get('toversion') or content_item.get('toVersion')
                    except Exception:
                        logging.exception(f"Failed on {pack_file_path=}. {content_item=}")

                    if to_version and Version(to_version) < Version(Metadata.SERVER_DEFAULT_MIN_VERSION):
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
                    self._server_min_version = get_updated_server_version(self._server_min_version, content_item,
                                                                          self._pack_name)

                    content_item_tags = content_item.get('tags', [])
                    metadata_toversion = to_version or ''

                    if current_directory == PackFolders.SCRIPTS.value:
                        metadata_output = {
                            'id': content_item.get('commonfields', {}).get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('comment', ''),
                            'tags': content_item_tags,
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                        if not self._contains_transformer and 'transformer' in content_item_tags:
                            self._contains_transformer = True

                        if not self._contains_filter and 'filter' in content_item_tags:
                            self._contains_filter = True

                    elif current_directory == PackFolders.PLAYBOOKS.value:
                        self.add_pack_type_tags(content_item, 'Playbook')
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ['xsoar', 'marketplacev2']),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }
                    elif current_directory == PackFolders.INTEGRATIONS.value:
                        integration_commands = content_item.get('script', {}).get('commands', [])
                        self.add_pack_type_tags(content_item, 'Integration')
                        metadata_output = {
                            'id': content_item.get('commonfields', {}).get('id', ''),
                            'name': content_item.get('display', ''),
                            'description': content_item.get('description', ''),
                            'category': content_item.get('category', ''),
                            'commands': [
                                {'name': c.get('name', ''), 'description': c.get('description', '')}
                                for c in integration_commands],
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                            'isfetch': content_item.get('script', {}).get('isfetch', False),
                            'isfetchevents': content_item.get('script', {}).get('isfetchevents', False),
                            'deprecated': content_item.get('deprecated', False),
                        }

                    elif current_directory == PackFolders.INCIDENT_FIELDS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'type': content_item.get('type', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.INCIDENT_TYPES.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'playbook': content_item.get('playbookId', ''),
                            'closureScript': content_item.get('closureScript', ''),
                            'hours': int(content_item.get('hours', 0)),
                            'days': int(content_item.get('days', 0)),
                            'weeks': int(content_item.get('weeks', 0)),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.DASHBOARDS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.INDICATOR_FIELDS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'type': content_item.get('type', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.REPORTS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.INDICATOR_TYPES.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'details': content_item.get('details', ''),
                            'reputationScriptName': content_item.get('reputationScriptName', ''),
                            'enhancementScriptNames': content_item.get('enhancementScriptNames', []),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.LAYOUTS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }
                        layout_description = content_item.get('description')
                        if layout_description is not None:
                            metadata_output['description'] = layout_description

                    elif current_directory == PackFolders.CLASSIFIERS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name') or content_item.get('id', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.WIDGETS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'dataType': content_item.get('dataType', ''),
                            'widgetType': content_item.get('widgetType', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.LISTS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.GENERIC_DEFINITIONS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif parent_directory == PackFolders.GENERIC_FIELDS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'type': content_item.get('type', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.GENERIC_MODULES.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif parent_directory == PackFolders.GENERIC_TYPES.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.PREPROCESS_RULES.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.JOBS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            # note that `name` may technically be blank, but shouldn't pass validations
                            'name': content_item.get('name', ''),
                            'details': content_item.get('details', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.PARSING_RULES.value and pack_file_name.startswith("external-"):
                        self.add_pack_type_tags(content_item, 'ParsingRule')
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.MODELING_RULES.value and pack_file_name.startswith("external-"):
                        self.add_pack_type_tags(content_item, 'ModelingRule')
                        schema: dict[str, Any] = json.loads(content_item.get('schema') or '{}')
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'datasets': list(schema.keys()),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.CORRELATION_RULES.value and pack_file_name.startswith("external-"):
                        self.add_pack_type_tags(content_item, 'CorrelationRule')
                        metadata_output = {
                            'id': content_item.get('global_rule_id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.XSIAM_DASHBOARDS.value and pack_file_name.startswith("external-"):
                        preview = self.get_preview_image_gcp_path(pack_file_name, PackFolders.XSIAM_DASHBOARDS.value)
                        metadata_output = {
                            'id': content_item.get('dashboards_data', [{}])[0].get('global_id', ''),
                            'name': content_item.get('dashboards_data', [{}])[0].get('name', ''),
                            'description': content_item.get('dashboards_data', [{}])[0].get('description', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                        if preview:
                            metadata_output.update({"preview": preview})

                    elif current_directory == PackFolders.XSIAM_REPORTS.value and pack_file_name.startswith("external-"):
                        preview = self.get_preview_image_gcp_path(pack_file_name, PackFolders.XSIAM_REPORTS.value)
                        metadata_output = {
                            'id': content_item.get('templates_data', [{}])[0].get('global_id', ''),
                            'name': content_item.get('templates_data', [{}])[0].get('report_name', ''),
                            'description': content_item.get('templates_data', [{}])[0].get('report_description', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                        if preview:
                            metadata_output.update({"preview": preview})

                    elif current_directory == PackFolders.WIZARDS.value:
                        metadata_output = {
                            'id': content_item.get('id', ''),
                            'name': content_item.get('name', ''),
                            'description': content_item.get('description', ''),
                            'dependency_packs': content_item.get('dependency_packs', {}),
                            'fromVersion': content_item.get('fromVersion', ''),
                            'toVersion': content_item.get('toVersion', ''),
                            'marketplaces': content_item.get('marketplaces', ["xsoar", "marketplacev2"]),
                        }

                    elif current_directory == PackFolders.XDRC_TEMPLATES.value and pack_file_name.startswith("external-"):
                        self.add_pack_type_tags(content_item, 'XDRCTemplate')
                        metadata_output = {
                            'id': content_item.get('content_global_id', ''),
                            'content_global_id': content_item.get('content_global_id', ''),
                            'name': content_item.get('name', ''),
                            'os_type': content_item.get('os_type', ''),
                            'profile_type': content_item.get('profile_type', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }

                    elif current_directory == PackFolders.LAYOUT_RULES.value and pack_file_name.startswith(
                            "external-"):
                        self.add_pack_type_tags(content_item, 'LayoutRule')
                        metadata_output = {
                            'id': content_item.get('rule_id', ''),
                            'name': content_item.get('rule_name', ''),
                            'layout_id': content_item.get('layout_id', ''),
                            'marketplaces': content_item.get('marketplaces', ["marketplacev2"]),
                            'fromversion': self._server_min_version,
                            'toversion': metadata_toversion,
                        }
                        layout_rule_description = content_item.get('description')
                        if layout_rule_description is not None:
                            metadata_output['description'] = layout_rule_description
                    else:
                        logging.info(f'Failed to collect: {current_directory}')
                        continue
                    content_item_type_and_id = f"{current_directory}_{metadata_output['id']}"
                    if self.is_replace_item_in_folder_collected_list(
                            content_item, content_items_id_to_version_map,
                            content_item_type_and_id):
                        latest_fromversion, latest_toversion = self.get_latest_versions(
                            content_items_id_to_version_map, content_item_type_and_id)
                        metadata_output['fromversion'] = latest_fromversion
                        metadata_output['toversion'] = latest_toversion
                        folder_collected_items = [metadata_output
                                                  if d["id"] == metadata_output["id"]
                                                  else d
                                                  for d in folder_collected_items]
                    elif not content_items_id_to_version_map.get(
                            content_item_type_and_id, {}).get('added_to_metadata_list', ''):
                        folder_collected_items.append(metadata_output)
                        content_items_id_to_version_map.get(content_item_type_and_id, {})['added_to_metadata_list'] = True

                if current_directory in PackFolders.pack_displayed_items():
                    content_item_key = CONTENT_ITEM_NAME_MAPPING[current_directory]

                    content_items_result[content_item_key] = \
                        content_items_result.get(content_item_key, []) + folder_collected_items

            logging.success(f"Finished collecting content items for {self._pack_name} pack")
            task_status = True
        except Exception:
            logging.exception(f"Failed collecting content items in {self._pack_name} pack")
        finally:
            self._content_items = content_items_result

            def display_getter(items, display):
                return f'{display}s' if items and len(items) > 1 else display

            self._content_displays_map = {
                name: display_getter(content_items_result.get(name), display)
                for name, display in ITEMS_NAMES_TO_DISPLAY_MAPPING.items()
                if content_items_result.get(name)
            }

            return task_status

    def load_user_metadata(self):
        """ Loads user defined metadata and stores part of it's data in defined properties fields.

        Returns:
            bool: whether the operation succeeded.

        """
        task_status = False
        user_metadata = {}

        try:
            user_metadata_path = os.path.join(self._pack_path, Pack.USER_METADATA)  # user metadata path before parsing
            if not os.path.exists(user_metadata_path):
                logging.error(f"{self._pack_name} pack is missing {Pack.USER_METADATA} file.")
                return task_status

            with open(user_metadata_path) as user_metadata_file:
                user_metadata = json.load(user_metadata_file)  # loading user metadata
                # part of old packs are initialized with empty list
                user_metadata = {} if isinstance(user_metadata, list) else user_metadata

            # store important user metadata fields
            self.support_type = user_metadata.get(Metadata.SUPPORT, Metadata.XSOAR_SUPPORT)
            self.current_version = user_metadata.get(Metadata.CURRENT_VERSION, '')
            self.hidden = user_metadata.get(Metadata.HIDDEN, False)
            self.description = user_metadata.get(Metadata.DESCRIPTION, False)
            self.display_name = user_metadata.get(Metadata.NAME, '')  # type: ignore[misc]
            self._user_metadata = user_metadata
            self._eula_link = user_metadata.get(Metadata.EULA_LINK, Metadata.EULA_URL)
            self._marketplaces = user_metadata.get(Metadata.MARKETPLACES, ['xsoar', 'marketplacev2'])
            self._modules = user_metadata.get(Metadata.MODULES, [])

            if 'xsoar' in self.marketplaces:
                self.marketplaces.append('xsoar_saas')

            logging.info(f"Finished loading {self._pack_name} pack user metadata")
            task_status = True

        except Exception:
            logging.exception(f"Failed in loading {self._pack_name} user metadata.")
        finally:
            return task_status

    def _collect_pack_tags(self, user_metadata, landing_page_sections, trending_packs, marketplace):
        tags = self._get_tags_by_marketplace(user_metadata, marketplace)
        tags |= self._get_tags_from_landing_page(landing_page_sections)
        tags |= {PackTags.TIM} if self._is_feed else set()
        tags |= {PackTags.USE_CASE} if self._use_cases else set()
        tags |= {PackTags.TRANSFORMER} if self._contains_transformer else set()
        tags |= {PackTags.FILTER} if self._contains_filter else set()
        tags |= {PackTags.COLLECTION} if self._is_siem else set()
        tags |= {PackTags.DATA_SOURCE} if self._is_data_source and marketplace == XSIAM_MP else set()

        if self._create_date:
            days_since_creation = (datetime.utcnow() - datetime.strptime(self._create_date, Metadata.DATE_FORMAT)).days
            if days_since_creation <= 30:
                tags |= {PackTags.NEW}
            else:
                tags -= {PackTags.NEW}

        if trending_packs:
            if self._pack_name in trending_packs:
                tags |= {PackTags.TRENDING}
            else:
                tags -= {PackTags.TRENDING}

        return tags

    def _get_tags_by_marketplace(self, user_metadata: dict, marketplace: str):
        """ Returns tags in according to the current marketplace"""
        tags = []
        for tag in user_metadata.get('tags', []):
            if ':' in tag:
                tag_data = tag.split(':')
                if marketplace in tag_data[0].split(','):
                    tags.append(tag_data[1])
            else:
                tags.append(tag)

        return set(input_to_list(input_data=tags))

    def _enhance_pack_attributes(self, index_folder_path, dependencies_metadata_dict, marketplace,
                                 statistics_handler=None, format_dependencies_only=False):
        """ Enhances the pack object with attributes for the metadata file

        Args:
            dependencies_metadata_dict (dict): mapping of pack dependencies metadata, for first level dependencies.
            format_dependencies_only (bool): Indicates whether the metadata formation is just for formatting the
            dependencies or not.

        Returns:
            dict: parsed pack metadata.

        """
        landing_page_sections = mp_statistics.StatisticsHandler.get_landing_page_sections()
        trending_packs = None
        pack_dependencies_by_download_count = self._displayed_images_dependent_on_packs
        if not format_dependencies_only:
            # ===== Pack Regular Attributes =====
            self._support_type = self.user_metadata.get(Metadata.SUPPORT, Metadata.XSOAR_SUPPORT)
            self._support_details = self._create_support_section(
                support_type=self._support_type, support_url=self.user_metadata.get(Metadata.URL),
                support_email=self.user_metadata.get(Metadata.EMAIL)
            )
            self._author = self._get_author(
                support_type=self._support_type, author=self.user_metadata.get(Metadata.AUTHOR, ''))
            self._certification = self._get_certification(
                support_type=self._support_type, certification=self.user_metadata.get(Metadata.CERTIFICATION)
            )
            self._legacy = self.user_metadata.get(Metadata.LEGACY, True)
            self._create_date = self._get_pack_creation_date(index_folder_path)
            self._update_date = self._get_pack_update_date(index_folder_path)
            self._use_cases = input_to_list(input_data=self.user_metadata.get(Metadata.USE_CASES),
                                            capitalize_input=True)
            self._categories = input_to_list(input_data=self.user_metadata.get(Metadata.CATEGORIES),
                                             capitalize_input=True)
            self._keywords = input_to_list(self.user_metadata.get(Metadata.KEY_WORDS))
        self._parsed_dependencies = self._parse_pack_dependencies(dependencies_metadata_dict)

        # ===== Pack Private Attributes =====
        if not format_dependencies_only:
            self._is_private_pack = Metadata.PARTNER_ID in self.user_metadata
            self._is_premium = self._is_private_pack
            self._preview_only = get_valid_bool(self.user_metadata.get(Metadata.PREVIEW_ONLY, False))
            self._price = convert_price(pack_id=self._pack_name, price_value_input=self.user_metadata.get('price'))
            if self._is_private_pack:
                self._vendor_id = self.user_metadata.get(Metadata.VENDOR_ID, "")
                self._partner_id = self.user_metadata.get(Metadata.PARTNER_ID, "")
                self._partner_name = self.user_metadata.get(Metadata.PARTNER_NAME, "")
                self._content_commit_hash = self.user_metadata.get(Metadata.CONTENT_COMMIT_HASH, "")
                self._disable_monthly = self.user_metadata.get(Metadata.DISABLE_MONTHLY, False)
                # Currently all content packs are legacy.
                # Since premium packs cannot be legacy, we directly set this attribute to false.
                self._legacy = False

        # ===== Pack Statistics Attributes =====
        if not self._is_private_pack and statistics_handler:  # Public Content case
            self._pack_statistics_handler = mp_statistics.PackStatisticsHandler(
                self._pack_name, statistics_handler.packs_statistics_df, statistics_handler.packs_download_count_desc,
                self._displayed_images_dependent_on_packs
            )
            self._downloads_count = self._pack_statistics_handler.download_count
            trending_packs = statistics_handler.trending_packs
            pack_dependencies_by_download_count = self._pack_statistics_handler.displayed_dependencies_sorted
        self._tags = self._collect_pack_tags(self.user_metadata, landing_page_sections, trending_packs, marketplace)
        self._search_rank = mp_statistics.PackStatisticsHandler.calculate_search_rank(
            tags=self._tags, certification=self._certification, content_items=self._content_items
        )
        self._related_integration_images = self._get_all_pack_images(
            self._displayed_integration_images, self._displayed_images_dependent_on_packs, dependencies_metadata_dict,
            pack_dependencies_by_download_count
        )

    def format_metadata(self, index_folder_path, packs_dependencies_mapping, build_number, commit_hash,
                        statistics_handler, packs_dict=None, marketplace='xsoar',
                        format_dependencies_only=False):
        """ Re-formats metadata according to marketplace metadata format defined in issue #19786 and writes back
        the result.

        Args:
            index_folder_path (str): downloaded index folder directory path.
            packs_dependencies_mapping (dict): all packs dependencies lookup mapping.
            build_number (str): circleCI build number.
            commit_hash (str): current commit hash.
            statistics_handler (StatisticsHandler): The marketplace statistics handler
            packs_dict (dict): dict of all packs relevant for current marketplace, as {pack_name: pack_object}.
            marketplace (str): Marketplace of current upload.
            format_dependencies_only (bool): Indicates whether the metadata formation is just for formatting the
             dependencies or not.

        Returns:
            bool: True is returned in case metadata file was parsed successfully, otherwise False.
            bool: True is returned in pack is missing dependencies.

        """
        task_status = False
        packs_dict = packs_dict if packs_dict else {}
        is_missing_dependencies = False

        try:
            self.set_pack_dependencies(packs_dependencies_mapping, packs_dict, marketplace=marketplace)

            logging.info(f"Loading pack dependencies metadata for {self._pack_name} pack")
            dependencies_metadata_dict, is_missing_dependencies = self._load_pack_dependencies_metadata(
                index_folder_path, packs_dict)

            self._enhance_pack_attributes(index_folder_path, dependencies_metadata_dict, marketplace,
                                          statistics_handler, format_dependencies_only)

            formatted_metadata = self._parse_pack_metadata(build_number, commit_hash)
            metadata_path = os.path.join(self._pack_path, Pack.METADATA)  # deployed metadata path after parsing
            json_write(metadata_path, formatted_metadata)  # writing back parsed metadata

            logging.success(f"Finished formatting {self._pack_name} packs's {Pack.METADATA} {metadata_path} file.")
            task_status = True

        except Exception as e:
            logging.exception(f"Failed in formatting {self._pack_name} pack metadata. Additional Info: {str(e)}")

        finally:
            return task_status, is_missing_dependencies

    @staticmethod
    def pack_created_in_time_delta(pack_name, time_delta: timedelta, index_folder_path: str) -> bool:
        """
        Checks if pack created before delta specified in the 'time_delta' argument and return boolean according
        to the result
        Args:
            pack_name: the pack name.
            time_delta: time_delta to check if pack was created before.
            index_folder_path: downloaded index folder directory path.

        Returns:
            True if pack was created before the time_delta from now, and False otherwise.
        """
        pack_creation_time_str = Pack._calculate_pack_creation_date(pack_name, index_folder_path)
        return datetime.utcnow() - datetime.strptime(pack_creation_time_str, Metadata.DATE_FORMAT) < time_delta

    def _get_pack_creation_date(self, index_folder_path):
        return self._calculate_pack_creation_date(self._pack_name, index_folder_path)

    @staticmethod
    def _calculate_pack_creation_date(pack_name, index_folder_path):
        """ Gets the pack created date.
        Args:
            index_folder_path (str): downloaded index folder directory path.
        Returns:
            datetime: Pack created date.
        """
        created_time = datetime.utcnow().strftime(Metadata.DATE_FORMAT)
        metadata = load_json(os.path.join(index_folder_path, pack_name, Pack.METADATA))

        if metadata:
            if metadata.get(Metadata.CREATED):
                created_time = metadata.get(Metadata.CREATED, '')
            else:
                raise Exception(f'The metadata file of the {pack_name} pack does not contain "{Metadata.CREATED}" time')

        return created_time

    def _get_pack_update_date(self, index_folder_path):
        """ Gets the pack update date.
        Args:
            index_folder_path (str): downloaded index folder directory path.
        Returns:
            datetime: Pack update date.
        """
        latest_changelog_released_date = datetime.utcnow().strftime(Metadata.DATE_FORMAT)
        changelog = load_json(os.path.join(index_folder_path, self._pack_name, Pack.CHANGELOG_JSON))

        if changelog and not self.is_modified:
            packs_latest_release_notes = max(Version(ver) for ver in changelog)
            latest_changelog_version = changelog.get(str(packs_latest_release_notes), {})
            latest_changelog_released_date = latest_changelog_version.get('released')

        return latest_changelog_released_date

    def set_pack_dependencies(self, packs_dependencies_mapping, packs_dict, marketplace='xsoar'):
        """
        Retrieve all pack's dependencies by merging the calculated dependencies from pack_dependencies.json file, given
        as input priorly, and the hard coded dependencies featured in the pack_metadata.json file.
        This is done for both first level dependencies and the all levels dependencies.
        Args:
            packs_dependencies_mapping: the calculated dependencies from pack_dependencies.json file
            packs_dict (dict): Dict of packs relevant for current marketplace as {pack_name: pack_object}
            marketplace: the current marketplace this upload is for
        """
        pack_dependencies_mapping = packs_dependencies_mapping.get(self._pack_name, {})
        first_level_dependencies = pack_dependencies_mapping.get(Metadata.DEPENDENCIES, {})
        all_levels_dependencies = list(pack_dependencies_mapping.get(Metadata.ALL_LEVELS_DEPENDENCIES, {}))
        displayed_images_dependent_on_packs = pack_dependencies_mapping.get(Metadata.DISPLAYED_IMAGES, [])
        logging.debug(f'(0) {first_level_dependencies=}')
        logging.debug(f'(0) {all_levels_dependencies=}')

        if Metadata.DISPLAYED_IMAGES not in self._user_metadata:
            self._user_metadata[Metadata.DISPLAYED_IMAGES] = displayed_images_dependent_on_packs

        if Metadata.DEPENDENCIES not in self._user_metadata:
            self._user_metadata[Metadata.DEPENDENCIES] = {}

        if self._pack_name != GCPConfig.BASE_PACK:
            # add base as a mandatory pack dependency, by design for all packs
            first_level_dependencies.update(BASE_PACK_DEPENDENCY_DICT)
            all_levels_dependencies.append(GCPConfig.BASE_PACK)
            logging.debug(f'(1) {first_level_dependencies=}')
            logging.debug(f'(1) {all_levels_dependencies=}')

        # If it is a core pack, check that no new mandatory packs (that are not core packs) were added
        # They can be overridden in the user metadata to be not mandatory so we need to check there as well
        core_packs = GCPConfig.get_core_packs(marketplace)
        logging.debug(f'{core_packs=}')

        if self._pack_name in core_packs:
            mandatory_dependencies = [k for k, v in first_level_dependencies.items()
                                      if v.get(Metadata.MANDATORY, False) is True
                                      and not v.get("is_test", False)
                                      and k not in core_packs
                                      and k not in self._user_metadata[Metadata.DEPENDENCIES].keys()
                                      and k not in self._user_metadata.get(Metadata.EXCLUDED_DEPENDENCIES, [])]
            if mandatory_dependencies:
                raise Exception(f'New mandatory dependencies {mandatory_dependencies} were '
                                f'found in the core pack {self._pack_name}')

        self._user_metadata[Metadata.DEPENDENCIES] = first_level_dependencies
        self._first_level_dependencies = first_level_dependencies
        self._all_levels_dependencies = all_levels_dependencies
        self._displayed_images_dependent_on_packs = displayed_images_dependent_on_packs

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
            if pack_file.endswith('_image.png'):
                image_data['repo_image_path'] = os.path.join(root, pack_file)
            elif pack_file.endswith('.yml'):
                with open(os.path.join(root, pack_file)) as integration_file:
                    integration_yml = yaml.safe_load(integration_file)
                    image_data['display_name'] = integration_yml.get('display', '')

        return image_data

    def _get_image_data_from_yml(self, pack_file_path):
        """ Creates temporary image file and retrieves integration display name.

        Args:
            pack_file_path (str): full path to the target yml_path integration yml to search integration image.

        Returns:
            dict: path to temporary integration image, display name of the integrations and the basename of
            the integration in content_pack.zip.

        """
        image_data = {}

        if pack_file_path.endswith('.yml'):
            with open(pack_file_path) as integration_file:
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
            image_data['integration_path_basename'] = os.path.basename(pack_file_path)

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

    @staticmethod
    def remove_contrib_suffix_from_name(display_name: str) -> str:
        """ Removes the contribution details suffix from the integration's display name
        Args:
            display_name (str): The integration display name.

        Returns:
            str: The display name without the contrib details suffix

        """
        contribution_suffixes = ('(Partner Contribution)', '(Developer Contribution)', '(Community Contribution)')
        for suffix in contribution_suffixes:
            index = display_name.find(suffix)
            if index != -1:
                display_name = display_name[:index].rstrip(' ')
                break
        return display_name

    @staticmethod
    def need_to_upload_integration_image(image_data: dict, integration_dirs: list, unified_integrations: list):
        """ Checks whether needs to upload the integration image or not.
        We upload in one of the two cases:
        1. The integration_path_basename is one of the integration dirs detected
        2. The integration_path_basename is one of the added/modified unified integrations

        Args:
            image_data (dict): path to temporary integration image, display name of the integrations and the basename of
            the integration in content_pack.zip.
            integration_dirs (list): The list of integrations to search in for images
            unified_integrations (list): The list of unified integrations to upload their image

        Returns:
            bool: True if we need to upload the image or not
        """
        integration_path_basename = image_data['integration_path_basename']
        return any([
            re.findall(BucketUploadFlow.INTEGRATION_DIR_REGEX, integration_path_basename)[0] in integration_dirs,
            integration_path_basename in unified_integrations
        ])

    def upload_integration_images(self, storage_bucket, storage_base_path, diff_files_list=None, detect_changes=False):
        """ Uploads pack integrations images to gcs.

        The returned result of integration section are defined in issue #19786.

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where image will be uploaded.
            storage_base_path (str): The target destination of the upload in the target bucket.
            detect_changes (bool): Whether to detect changes or upload all images in any case.
            diff_files_list (list): The list of all modified/added files found in the diff
        Returns:
            bool: whether the operation succeeded.
            list: list of dictionaries with uploaded pack integration images.

        """
        task_status = True
        integration_images = []
        integration_dirs = []
        unified_integrations = []

        try:
            if detect_changes:
                # detect added/modified integration images
                for file in diff_files_list:
                    if self.is_integration_image(file.a_path):
                        # integration dir name will show up in the unified integration file path in content_packs.zip
                        integration_dirs.append(os.path.basename(os.path.dirname(file.a_path)))
                    elif self.is_unified_integration(file.a_path):
                        # if the file found in the diff is a unified integration we upload its image
                        unified_integrations.append(os.path.basename(file.a_path))

            pack_local_images = self._search_for_images(target_folder=PackFolders.INTEGRATIONS.value)

            if not pack_local_images:
                return True  # return empty list if no images were found

            pack_storage_root_path = os.path.join(storage_base_path, self._pack_name)

            for image_data in pack_local_images:
                image_path = image_data.get('image_path')
                if not image_path:
                    raise Exception(f"{self._pack_name} pack integration image was not found")

                image_name = os.path.basename(image_path)
                image_storage_path = os.path.join(pack_storage_root_path, image_name)
                pack_image_blob = storage_bucket.blob(image_storage_path)

                if not detect_changes or \
                        self.need_to_upload_integration_image(image_data, integration_dirs, unified_integrations):
                    # upload the image if needed
                    logging.info(f"Uploading image: {image_name} of integration: {image_data.get('display_name')} "
                                 f"from pack: {self._pack_name}")
                    with open(image_path, "rb") as image_file:
                        pack_image_blob.upload_from_file(image_file)
                    self._uploaded_integration_images.append(image_name)

                if GCPConfig.USE_GCS_RELATIVE_PATH:
                    image_gcs_path = urllib.parse.quote(
                        os.path.join(GCPConfig.IMAGES_BASE_PATH, self._pack_name, image_name))
                else:
                    image_gcs_path = pack_image_blob.public_url

                integration_name = image_data.get('display_name', '')

                if self.support_type != Metadata.XSOAR_SUPPORT:
                    integration_name = self.remove_contrib_suffix_from_name(integration_name)

                integration_images.append({
                    'name': integration_name,
                    'imagePath': image_gcs_path
                })

            if self._uploaded_integration_images:
                logging.info(f"Uploaded {len(self._uploaded_integration_images)} images for {self._pack_name} pack.")
        except Exception as e:
            task_status = False
            logging.exception(f"Failed to upload {self._pack_name} pack integration images. Additional Info: {str(e)}")
        finally:
            self._displayed_integration_images = integration_images
            return task_status

    def copy_integration_images(self, production_bucket, build_bucket, images_data, storage_base_path,
                                build_bucket_base_path):
        """ Copies all pack's integration images from the build bucket to the production bucket

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
            images_data (dict): The images data structure from Prepare Content step
            storage_base_path (str): The target destination of the upload in the target bucket.
            build_bucket_base_path (str): The path of the build bucket in gcp.
        Returns:
            bool: Whether the operation succeeded.

        """
        task_status = True
        num_copied_images = 0
        err_msg = f"Failed copying {self._pack_name} pack integrations images."
        pc_uploaded_integration_images = images_data.get(self._pack_name, {}).get(BucketUploadFlow.INTEGRATIONS, [])

        for image_name in pc_uploaded_integration_images:
            build_bucket_image_path = os.path.join(build_bucket_base_path, self._pack_name, image_name)
            build_bucket_image_blob = build_bucket.blob(build_bucket_image_path)

            if not build_bucket_image_blob.exists():
                logging.error(f"Found changed/added integration image {image_name} in content repo but "
                              f"{build_bucket_image_path} does not exist in build bucket")
                task_status = False
            else:
                logging.info(f"Copying {self._pack_name} pack integration image: {image_name}")
                try:
                    copied_blob = build_bucket.copy_blob(
                        blob=build_bucket_image_blob, destination_bucket=production_bucket,
                        new_name=os.path.join(storage_base_path, self._pack_name, image_name)
                    )
                    if not copied_blob.exists():
                        logging.error(f"Copy {self._pack_name} integration image: {build_bucket_image_blob.name} "
                                      f"blob to {copied_blob.name} blob failed.")
                        task_status = False
                    else:
                        num_copied_images += 1

                except Exception as e:
                    logging.exception(f"{err_msg}. Additional Info: {str(e)}")
                    return False

        if not task_status:
            logging.error(err_msg)
        else:
            if num_copied_images == 0:
                logging.info(f"No added/modified integration images were detected in {self._pack_name} pack.")
            else:
                logging.success(f"Copied {num_copied_images} images for {self._pack_name} pack.")

        return task_status

    def upload_author_image(self, storage_bucket, storage_base_path, diff_files_list=None, detect_changes=False):
        """ Uploads pack author image to gcs.

        Searches for `Author_image.png` and uploads author image to gcs. In case no such image was found,
        default Base pack image path is used and it's gcp path is returned.

        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where author image will be uploaded.
            storage_base_path (str): the path under the bucket to upload to.
            diff_files_list (list): The list of all modified/added files found in the diff
            detect_changes (bool): Whether to detect changes or upload the author image in any case.

        Returns:
            bool: whether the operation succeeded.
            str: public gcp path of author image.

        """
        task_status = True
        author_image_storage_path = ""

        try:
            author_image_path = os.path.join(self._pack_path, Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection

            if os.path.exists(author_image_path):
                image_to_upload_storage_path = os.path.join(storage_base_path, self._pack_name,
                                                            Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection
                pack_author_image_blob = storage_bucket.blob(image_to_upload_storage_path)

                if not detect_changes or any(self.is_author_image(file.a_path) for file in diff_files_list):
                    # upload the image if needed
                    with open(author_image_path, "rb") as author_image_file:
                        pack_author_image_blob.upload_from_file(author_image_file)
                    self._uploaded_author_image = True
                    logging.success(f"Uploaded successfully {self._pack_name} pack author image")

                if GCPConfig.USE_GCS_RELATIVE_PATH:
                    author_image_storage_path = urllib.parse.quote(
                        os.path.join(GCPConfig.IMAGES_BASE_PATH, self._pack_name, Pack.AUTHOR_IMAGE_NAME))
                else:
                    author_image_storage_path = pack_author_image_blob.public_url

            elif self.support_type == Metadata.XSOAR_SUPPORT:  # use default Base pack image for xsoar supported packs
                author_image_storage_path = os.path.join(GCPConfig.IMAGES_BASE_PATH, GCPConfig.BASE_PACK,
                                                         Pack.AUTHOR_IMAGE_NAME)  # disable-secrets-detection

                if not GCPConfig.USE_GCS_RELATIVE_PATH:
                    # disable-secrets-detection-start
                    author_image_storage_path = os.path.join(GCPConfig.GCS_PUBLIC_URL, storage_bucket.name,
                                                             author_image_storage_path)
                    # disable-secrets-detection-end
                logging.info(f"Skipping uploading of {self._pack_name} pack author image "
                             f"and use default {GCPConfig.BASE_PACK} pack image")
            else:
                logging.info(f"Skipping uploading of {self._pack_name} pack author image. "
                             f"The pack is defined as {self.support_type} support type")

        except Exception:
            logging.exception(f"Failed uploading {self._pack_name} pack author image.")
            task_status = False
            author_image_storage_path = ""
        finally:
            self._author_image = author_image_storage_path
            return task_status

    def copy_author_image(self, production_bucket, build_bucket, images_data, storage_base_path,
                          build_bucket_base_path):
        """ Copies pack's author image from the build bucket to the production bucket

        Searches for `Author_image.png`, In case no such image was found, default Base pack image path is used and
        it's gcp path is returned.

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
            images_data (dict): The images data structure from Prepare Content step
            storage_base_path (str): The target destination of the upload in the target bucket.
            build_bucket_base_path (str): The path of the build bucket in gcp.
        Returns:
            bool: Whether the operation succeeded.

        """
        if images_data.get(self._pack_name, {}).get(BucketUploadFlow.AUTHOR, False):

            build_author_image_path = os.path.join(build_bucket_base_path, self._pack_name, Pack.AUTHOR_IMAGE_NAME)
            build_author_image_blob = build_bucket.blob(build_author_image_path)

            if build_author_image_blob.exists():
                try:
                    copied_blob = build_bucket.copy_blob(
                        blob=build_author_image_blob, destination_bucket=production_bucket,
                        new_name=os.path.join(storage_base_path, self._pack_name,
                                              Pack.AUTHOR_IMAGE_NAME))
                    if not copied_blob.exists():
                        logging.error(f"Failed copying {self._pack_name} pack author image.")
                        return False
                    else:
                        logging.success(f"Copied successfully {self._pack_name} pack author image.")
                        return True

                except Exception as e:
                    logging.exception(f"Failed copying {Pack.AUTHOR_IMAGE_NAME} for {self._pack_name} pack. "
                                      f"Additional Info: {str(e)}")
                    return False

            else:
                logging.error(f"Found changed/added author image in content repo for {self._pack_name} pack but "
                              f"image does not exist in build bucket in path {build_author_image_path}.")
                return False

        else:
            logging.info(f"No added/modified author image was detected in {self._pack_name} pack.")
            return True

    def upload_images(self, index_folder_path, storage_bucket, storage_base_path, diff_files_list, override_all_packs):
        """
        Upload the images related to the pack.
        The image is uploaded in the case it was modified, OR if this is the first time the current pack is being
        uploaded to this current marketplace (#46785).
        Args:
            index_folder_path (str): the path to the local index folder
            storage_bucket (google.cloud.storage.bucket.Bucket): gcs bucket where author image will be uploaded.
            storage_base_path (str): the path under the bucket to upload to.
            diff_files_list (list): The list of all modified/added files found in the diff
            override_all_packs (bool): Whether to override all packs without checking for changes
        Returns:
            True if the images were successfully uploaded, false otherwise.

        """

        detect_changes = False if override_all_packs else os.path.exists(os.path.join(index_folder_path, self.name,
                                                                                      Pack.METADATA)) or self.hidden

        # Don't check if the image was modified if this is the first time it is uploaded to this marketplace, meaning it
        # doesn't exist in the index (and it isn't deprecated), or if we want to override it (upload without
        # detecting changes)

        if not detect_changes:
            logging.info(f'Uploading images of pack {self.name} which did not exist in this marketplace before')

        task_status = self.upload_integration_images(storage_bucket, storage_base_path, diff_files_list, detect_changes)
        if not task_status:
            self._status = PackStatus.FAILED_IMAGES_UPLOAD.name
            self.cleanup()
            return False

        task_status = self.upload_author_image(storage_bucket, storage_base_path, diff_files_list, detect_changes)
        if not task_status:
            self._status = PackStatus.FAILED_AUTHOR_IMAGE_UPLOAD.name
            self.cleanup()
            return False

        return True

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
            return False, ''

    def is_integration_image(self, file_path: str):
        """ Indicates whether a file_path is an integration image or not
        Args:
            file_path (str): The file path
        Returns:
            bool: True if the file is an integration image or False otherwise
        """
        return all([
            file_path.startswith(os.path.join(PACKS_FOLDER, self._pack_name)),
            file_path.endswith('.png'),
            'image' in os.path.basename(file_path.lower()),
            os.path.basename(file_path) != Pack.AUTHOR_IMAGE_NAME
        ])

    def is_author_image(self, file_path: str):
        """ Indicates whether a file_path is an author image or not
        Args:
            file_path (str): The file path
        Returns:
            bool: True if the file is an author image or False otherwise
        """
        return file_path == os.path.join(PACKS_FOLDER, self._pack_name, Pack.AUTHOR_IMAGE_NAME)

    def is_raedme_file(self, file_path: str):
        """ Indicates whether a file_path is an pack readme
        Args:
            file_path (str): The file path
        Returns:
            bool: True if the file is a pack readme or False otherwise
        """
        return file_path == os.path.join(PACKS_FOLDER, self._pack_name, Pack.README)

    def is_unified_integration(self, file_path: str):
        """ Indicates whether a file_path is a unified integration yml file or not
        Args:
            file_path (str): The file path
        Returns:
            bool: True if the file is a unified integration or False otherwise
        """
        return all([
            file_path.startswith(os.path.join(PACKS_FOLDER, self._pack_name, PackFolders.INTEGRATIONS.value)),
            os.path.basename(os.path.dirname(file_path)) == PackFolders.INTEGRATIONS.value,
            os.path.basename(file_path).startswith('integration'),
            os.path.basename(file_path).endswith('.yml')
        ])

    def add_bc_entries_if_needed(self, release_notes_dir: str, changelog: dict[str, Any]) -> None:
        """
        Receives changelog, checks if there exists a BC version in each changelog entry (as changelog entry might be
        zipped into few RN versions, check if at least one of the versions is BC).
        Check if RN is BC is done by doing the following:
         1) Check if RN has corresponding config file, e.g 1_0_1.md has corresponding 1_0_1.json file.
         2) If it does, check if `isBreakingChanges` field is true
        If such version exists, adds a
        true value to 'breakingChanges' field.
        if JSON file also has breakingChangesNotes configures, adds `breakingChangesNotes` field to changelog file.
        This function iterates every entry in changelog because it takes into consideration four scenarios:
          a) Entry without breaking changes, changes to entry with breaking changes (because at least one of the
             versions in the entry was marked as breaking changes).
          b) Entry without breaking changes, does not change.
          c) Entry with breaking changes, changes to entry without breaking changes (because all the BC versions
             corresponding to the changelog entry were re-marked as not BC).
          d) Entry with breaking changes, does not change.
        Args:
            release_notes_dir (str): RN dir path.
            changelog (Dict[str, Any]): Changelog data represented as a dict.

        Returns:
            (None): Modifies changelog, adds bool value to 'breakingChanges' and `breakingChangesNotes` fields to every
             changelog entry, according to the logic described above.
        """
        if not os.path.exists(release_notes_dir):
            return
        bc_version_to_text: dict[str, str | None] = self._breaking_changes_versions_to_text(release_notes_dir)
        loose_versions: list[Version] = [Version(bc_ver) for bc_ver in bc_version_to_text]
        predecessor_version: Version = Version('0.0.0')
        for changelog_entry in sorted(changelog.keys(), key=Version):
            rn_loose_version: Version = Version(changelog_entry)
            if bc_versions := self._changelog_entry_bc_versions(predecessor_version, rn_loose_version, loose_versions,
                                                                bc_version_to_text):
                logging.info(f'Changelog entry {changelog_entry} contains BC versions')
                changelog[changelog_entry]['breakingChanges'] = True
                if bc_text := self._calculate_bc_text(release_notes_dir, bc_versions):
                    changelog[changelog_entry]['breakingChangesNotes'] = bc_text
                else:
                    changelog[changelog_entry].pop('breakingChangesNotes', None)
            else:
                changelog[changelog_entry].pop('breakingChanges', None)
            predecessor_version = rn_loose_version

    def _calculate_bc_text(self, release_notes_dir: str, bc_version_to_text: dict[str, str | None]) -> str | None:
        """
        Receives BC versions to text dict for current changelog entry. Calculates text for BC entry.
        Args:
            release_notes_dir (str): RN dir path.
            bc_version_to_text (Dict[str, Optional[str]): {bc version, bc_text}

        Returns:
            (Optional[str]): Text for entry if such was added.
            If none is returned, server will list the full RN as the BC notes instead.
        """
        # Handle cases of one BC version in entry.
        if len(bc_version_to_text) == 1:
            return list(bc_version_to_text.values())[0]
        # Handle cases of two or more BC versions in entry.
        text_of_bc_versions, bc_without_text = self._split_bc_versions_with_and_without_text(bc_version_to_text)

        if len(text_of_bc_versions) == 0:
            # Case 1: Not even one BC version contains breaking text.
            return None

        elif len(text_of_bc_versions) < len(bc_version_to_text):
            # Case 2: Only part of BC versions contains breaking text.
            return self._handle_many_bc_versions_some_with_text(release_notes_dir, text_of_bc_versions, bc_without_text)

        else:
            # Case 3: All BC versions contains text.
            # Important: Currently, implementation of aggregating BCs was decided to concat between them
            # In the future this might be needed to re-thought.
            return '\n'.join(bc_version_to_text.values())  # type: ignore[arg-type]

    def _handle_many_bc_versions_some_with_text(self, release_notes_dir: str, text_of_bc_versions: list[str],
                                                bc_versions_without_text: list[str], ) -> str:
        """
        Calculates text for changelog entry where some BC versions contain text and some don't.
        Important: Currently, implementation of aggregating BCs was decided to concat between them (and if BC version
        does not have a BC text - concat the whole RN). In the future this might be needed to re-thought.
        Args:
            release_notes_dir (str): RN dir path.
            text_of_bc_versions ([List[str]): List of text of BC versions with text.
            bc_versions_without_text ([List[str]): List of BC versions without text.

        Returns:
            (str): Text for BC entry.
        """
        bc_with_text_str = '\n'.join(text_of_bc_versions)
        rn_file_names_without_text = [f'''{bc_version.replace('.', '_')}.md''' for
                                      bc_version in bc_versions_without_text]
        other_rn_text: str = self._get_release_notes_concat_str(release_notes_dir, rn_file_names_without_text)
        if not other_rn_text:
            logging.error('No RN text, although text was expected to be found for versions'
                          f' {rn_file_names_without_text}.')
        return f'{bc_with_text_str}{other_rn_text}'

    @staticmethod
    def _get_release_notes_concat_str(release_notes_dir: str, rn_file_names: list[str]) -> str:
        """
        Concat all RN data found in given `rn_file_names`.
        Args:
            release_notes_dir (str): RN dir path.
            rn_file_names (List[str]): List of all RN files to concat their data.

        Returns:
            (str): Concat RN data
        """
        concat_str: str = ''
        for rn_file_name in rn_file_names:
            rn_file_path = os.path.join(release_notes_dir, rn_file_name)
            with open(rn_file_path) as f:
                # Will make the concat string start with new line on purpose.
                concat_str = f'{concat_str}\n{f.read()}'
        return concat_str

    @staticmethod
    def _split_bc_versions_with_and_without_text(bc_versions: dict[str, str | None]) -> tuple[list[str], list[str]]:
        """
        Splits BCs to tuple of BCs text of BCs containing text, and BCs versions that do not contain BC text.
        Args:
            bc_versions (Dict[str, Optional[str]): BC versions mapped to text if exists.

        Returns:
            (Tuple[List[str], List[str]]): (text of bc versions with text, bc_versions_without_text).
        """
        text_of_bc_versions_with_tests: list[str] = []
        bc_versions_without_text: list[str] = []
        for bc_version, bc_text in bc_versions.items():
            if bc_text:
                text_of_bc_versions_with_tests.append(bc_text)
            else:
                bc_versions_without_text.append(bc_version)
        return text_of_bc_versions_with_tests, bc_versions_without_text

    @staticmethod
    def _breaking_changes_versions_to_text(release_notes_dir: str) -> dict[str, str | None]:
        """
        Calculates every BC version in given RN dir and maps it to text if exists.
        Currently, text from a BC version is calculated in the following way:
        - If RN has `breakingChangesNotes` entry in its corresponding config file, then use the value of that field
          as the text of the BC to be represented.
        - Else, use the whole RN text as BC text.
        Args:
            release_notes_dir (str): RN dir path.

        Returns:
            (Dict[str, Optional[str]]): {dotted_version, text}.
        """
        bc_version_to_text: dict[str, str | None] = {}
        # Get all config files in RN dir
        rn_config_file_names = filter_dir_files_by_extension(release_notes_dir, '.json')

        for file_name in rn_config_file_names:
            file_data: dict = load_json(os.path.join(release_notes_dir, file_name))
            # Check if version is BC
            if file_data.get('breakingChanges'):
                # Processing name for easier calculations later on
                processed_name: str = underscore_file_name_to_dotted_version(file_name)
                bc_version_to_text[processed_name] = file_data.get('breakingChangesNotes')
        return bc_version_to_text

    @staticmethod
    def _changelog_entry_bc_versions(predecessor_version: Version, rn_version: Version,
                                     breaking_changes_versions: list[Version],
                                     bc_version_to_text: dict[str, str | None]) -> dict[str, str | None]:
        """
        Gets all BC versions of given changelog entry, every BC s.t predecessor_version < BC version <= rn_version.
        Args:
            predecessor_version (Version): Predecessor version in numeric version order.
            rn_version (Version): RN version of current processed changelog entry.
            breaking_changes_versions (List[Version]): List of BC versions.
            bc_version_to_text (Dict[str, Optional[str]): List of all BC to text in the given RN dir.

        Returns:
            Dict[str, Optional[str]]: Partial list of `bc_version_to_text`, containing only relevant versions between
                                      given versions.
        """
        return {str(bc_ver): bc_version_to_text.get(str(bc_ver)) for bc_ver in breaking_changes_versions if
                predecessor_version < bc_ver <= rn_version}

    def get_pr_numbers_for_version(self, version: str) -> list[int]:
        """
        Get List[PullRequests] for the given version
        Args:
            version: The pack version to find the pull request numbers for

        Returns:
            List[Pull Request Numbers]: A list of pr numbers of the pack version
        """
        if not os.path.exists(f"{self._pack_path}/{self.RELEASE_NOTES}"):
            return []

        pack_version_rn_file_path = f"Packs/{self.name}/{self.RELEASE_NOTES}/{version.replace('.', '_')}.md"
        packs_version_pr_numbers = get_pull_request_numbers_from_file(pack_version_rn_file_path)

        return packs_version_pr_numbers

    def get_preview_image_gcp_path(self, pack_file_name: str, folder_name: str) -> str | None:
        """ Genrate the preview image path as it stored in the gcp
        Args:
            pack_file_name: File name.
            folder_name: Folder name.

        Returns:
            The preview image path as it stored in the gcp if preview image exists, or None otherwise.
        """
        preview_image_name = self.find_preview_image_path(pack_file_name)
        try:
            preview_image_path = os.path.join(self.path, folder_name, preview_image_name)  # disable-secrets-detection
            if os.path.exists(preview_image_path):
                if not self._current_version:
                    self._current_version = ''
                return urllib.parse.quote(os.path.join(GCPConfig.CONTENT_PACKS_PATH, self.name,
                                                       self.current_version, folder_name, preview_image_name))
        except Exception:
            logging.exception(f"Failed uploading {self.name} pack preview image.")
        return None

    def upload_preview_images(self, storage_bucket, storage_base_path):
        """ Uploads pack preview images to gcs.
        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where image will be uploaded.
            storage_base_path (str): The target destination of the upload in the target bucket.
        Returns:
            bool: whether the operation succeeded.
        """
        pack_storage_root_path = os.path.join(storage_base_path, self.name, self.current_version)

        for _dir in [PackFolders.XSIAM_REPORTS.value, PackFolders.XSIAM_DASHBOARDS.value]:
            local_preview_image_dir = os.path.join(PACKS_FOLDER, self.name, _dir)
            if not os.path.isdir(local_preview_image_dir):
                logging.debug(f"Could not find content items with preview images for pack {self.name}")
                continue

            preview_image_relative_paths = glob.glob(os.path.join(local_preview_image_dir, '*.png'))
            if not preview_image_relative_paths:
                logging.debug(f"Could not find preview images in pack {local_preview_image_dir}")
                continue

            logging.info(f"Found preview image: {preview_image_relative_paths}")
            preview_image_relative_path: str = preview_image_relative_paths[0]
            image_name = os.path.basename(preview_image_relative_path)
            image_storage_path = os.path.join(pack_storage_root_path, _dir, image_name)
            pack_image_blob = storage_bucket.blob(image_storage_path)

            try:
                with open(preview_image_relative_path, "rb") as image_file:
                    pack_image_blob.upload_from_file(image_file)
            except Exception as e:
                logging.exception(f"Failed uploading {self.name} pack preview image. Additional info: {e}")
                return False

            self._uploaded_preview_images.append(preview_image_relative_path)

        return True

    def upload_dynamic_dashboard_images(self, storage_bucket, storage_base_path):
        """ Uploads pack dynamic dashboard images to gcs.
        Args:
            storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where image will be uploaded.
            storage_base_path (str): The target destination of the upload in the target bucket.
        Returns:
            bool: whether the operation succeeded.
        """
        pack_storage_root_path = os.path.join(storage_base_path, 'images').replace("packs/", "")
        logging.debug(f"Uploading dynamic dashboard to folder in path: {pack_storage_root_path}")

        local_dynamic_dashboard_image_dir = os.path.join(PACKS_FOLDER, self.name, PackFolders.INTEGRATIONS.value)
        if not os.path.isdir(local_dynamic_dashboard_image_dir):
            logging.debug(f"Could not find dynamic dashboard images for pack {self.name}")
            return True

        dynamic_dashboard_image_relative_paths = glob.glob(os.path.join(local_dynamic_dashboard_image_dir, '*/*.svg'))
        if not dynamic_dashboard_image_relative_paths:
            logging.debug(f"Could not find dynamic dashboard images in pack {local_dynamic_dashboard_image_dir}")
            return True

        logging.debug(f"Found dynamic dashboard image: {dynamic_dashboard_image_relative_paths}")
        for dynamic_dashboard_image in dynamic_dashboard_image_relative_paths:
            integration_dir = Path(dynamic_dashboard_image).parts[:-1]
            integration_yaml_path = glob.glob(os.path.join(*integration_dir, '*.yml'))

            with open(integration_yaml_path[0]) as pack_file:
                integration_yaml_content = yaml.safe_load(pack_file)

            image_storage_path = os.path.join(pack_storage_root_path,
                                              f"{integration_yaml_content.get('commonfields', {}).get('id', '')}.svg")
            pack_image_blob = storage_bucket.blob(image_storage_path)

            try:
                with open(dynamic_dashboard_image, "rb") as image_file:
                    pack_image_blob.upload_from_file(image_file)
            except Exception as e:
                logging.exception(f"Failed uploading {self.name} pack dynamic dashboard image. Additional info: {e}")
                return False

            self._uploaded_dynamic_dashboard_images.append(image_storage_path)

        return True

    def copy_preview_images(self, production_bucket, build_bucket, images_data, storage_base_path, build_bucket_base_path):
        """ Copies pack's preview image from the build bucket to the production bucket

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
            images_data (dict): The images data structure from Prepare Content step
            storage_base_path (str): The target destination of the upload in the target bucket.
            build_bucket_base_path (str): The path of the build bucket in gcp.
        Returns:
            bool: Whether the operation succeeded.

        """
        task_status = True
        num_copied_images = 0
        err_msg = f"Failed copying {self._pack_name} pack preview images."
        pc_uploaded_preview_images = images_data.get(self._pack_name, {}).get(BucketUploadFlow.PREVIEW_IMAGES, [])

        for image_name in pc_uploaded_preview_images:
            image_pack_path = Path(image_name).parts[-2:]
            build_bucket_image_path = os.path.join(build_bucket_base_path, self._pack_name,
                                                   self.current_version, *image_pack_path)
            build_bucket_image_blob = build_bucket.blob(build_bucket_image_path)

            if not build_bucket_image_blob.exists():
                logging.error(f"Found changed/added preview image {image_name} in content repo but "
                              f"{build_bucket_image_path} does not exist in build bucket")
                task_status = False
            else:
                logging.info(f"Copying {self._pack_name} pack preview image: {image_name}")
                try:
                    copied_blob = build_bucket.copy_blob(
                        blob=build_bucket_image_blob, destination_bucket=production_bucket,
                        new_name=os.path.join(storage_base_path, self._pack_name, self.current_version,
                                              *image_pack_path)
                    )
                    if not copied_blob.exists():
                        logging.error(f"Copy {self._pack_name} preview image: {build_bucket_image_blob.name} "
                                      f"blob to {copied_blob.name} blob failed.")
                        task_status = False
                    else:
                        num_copied_images += 1

                except Exception as e:
                    logging.exception(f"{err_msg}. Additional Info: {str(e)}")
                    return False

        if not task_status:
            logging.error(err_msg)
        else:
            if num_copied_images == 0:
                logging.info(f"No added/modified preview images were detected in {self._pack_name} pack.")
            else:
                logging.success(f"Copied {num_copied_images} images for {self._pack_name} pack.")

        return task_status

    def copy_dynamic_dashboard_images(self, production_bucket, build_bucket, images_data, storage_base_path,
                                      build_bucket_base_path):
        """ Copies pack's dynamic dashboard image from the build bucket to the production bucket

        Args:
            production_bucket (google.cloud.storage.bucket.Bucket): The production bucket
            build_bucket (google.cloud.storage.bucket.Bucket): The build bucket
            images_data (dict): The images data structure from Prepare Content step
            storage_base_path (str): The target destination of the upload in the target bucket.
            build_bucket_base_path (str): The path of the build bucket in gcp.
        Returns:
            bool: Whether the operation succeeded.

        """
        task_status = True
        num_copied_images = 0
        err_msg = f"Failed copying {self._pack_name} pack dynamic dashboard images."
        pc_uploaded_dynamic_dashboard_images = images_data.get(self._pack_name,
                                                               {}).get(BucketUploadFlow.DYNAMIC_DASHBOARD_IMAGES, [])

        for image_name in pc_uploaded_dynamic_dashboard_images:
            build_bucket_image_path = os.path.join(build_bucket_base_path, 'images',
                                                   os.path.basename(image_name)).replace("packs/", "")
            build_bucket_image_blob = build_bucket.blob(build_bucket_image_path)

            if not build_bucket_image_blob.exists():
                logging.error(f"Found changed/added dynamic dashboard image {image_name} in content repo but "
                              f"{build_bucket_image_path} does not exist in build bucket")
                task_status = False
            else:
                logging.info(f"Copying {self._pack_name} pack dynamic dashboard image: {image_name}")
                try:
                    copied_blob = build_bucket.copy_blob(
                        blob=build_bucket_image_blob, destination_bucket=production_bucket,
                        new_name=os.path.join(storage_base_path, 'images', os.path.basename(image_name)).replace("packs/", "")
                    )
                    if not copied_blob.exists():
                        logging.error(f"Copy {self._pack_name} dynamic dashboard image: {build_bucket_image_blob.name} "
                                      f"blob to {copied_blob.name} blob failed.")
                        task_status = False
                    else:
                        num_copied_images += 1

                except Exception as e:
                    logging.exception(f"{err_msg}. Additional Info: {str(e)}")
                    return False

        if not task_status:
            logging.error(err_msg)
        else:
            if num_copied_images == 0:
                logging.info(f"No added/modified dynamic dashboard images were detected in {self._pack_name} pack.")
            else:
                logging.success(f"Copied {num_copied_images} images for {self._pack_name} pack.")

        return task_status

    def does_preview_image_exist(self, file_path: str) -> bool:
        """ Indicates whether a file_path is a valid preview image or not:
            - The file exists (is not removed in the latest upload)
            - Belong to the current pack
            - Id of type png
            - path include the word '_image'
            - Located in either XSIAMDashboards or XSIAMReports folder
        Args:
            file_path (str): The file path
        Returns:
            bool: True if the file is a preview image or False otherwise
        """
        valid_image = all([
            file_path.startswith(os.path.join(PACKS_FOLDER, self.name)),
            file_path.endswith('.png'),
            '_image' in os.path.basename(file_path.lower()),
            (PackFolders.XSIAM_DASHBOARDS.value in file_path or PackFolders.XSIAM_REPORTS.value in file_path)
        ])
        if not valid_image:
            return False

        # In cases where a preview image was deleted valid_image will be true but we don't want to upload it as it does
        # not exist anymore
        elif not os.path.exists(file_path):
            logging.warning(f'Image: {file_path} was deleted and therefore will not be uploaded')
            return False

        return True

    @staticmethod
    def find_preview_image_path(file_name: str) -> str:
        """ Generate preview image file name according to related file.
        Args:
            file_name: File name.

        Returns:
            Preview image file path.
        """
        prefixes = ['xsiamdashboard', 'xsiamreport']
        file_name = file_name.replace('external-', '')
        for prefix in prefixes:
            file_name = file_name.replace(f'{prefix}-', '')
        image_file_name = os.path.splitext(file_name)[0] + '_image.png'
        return image_file_name


# HELPER FUNCTIONS


def get_pull_request_numbers_from_file(file_path) -> list[int]:
    """
    Uses git and regex to find the pull request numbers for the given file
    Args:
        file_path: The file to find PRs for

    Returns:
        A list of relevant pull request numbers for the given file
    """
    log_info: str = git.Git(CONTENT_ROOT_PATH).log(file_path)
    return re.findall(PULL_REQUEST_PATTERN, log_info)


def get_upload_data(packs_results_file_path: str, stage: str) -> tuple[dict, dict, dict, dict, dict]:
    """ Loads the packs_results.json file to get the successful and failed packs together with uploaded images dicts

    Args:
        packs_results_file_path (str): The path to the file
        stage (str): can be BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING or
        BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE

    Returns:
        dict: The successful packs dict
        dict: The failed packs dict
        dict: the successful uploaded dependencies zip packs
        dict : The successful private packs dict
        dict: The images data dict

    """
    if os.path.exists(packs_results_file_path):
        packs_results_file = load_json(packs_results_file_path)
        stage_data: dict = packs_results_file.get(stage, {})
        successful_packs_dict = stage_data.get(BucketUploadFlow.SUCCESSFUL_PACKS, {})
        successful_uploaded_dependencies_zip_packs_dict = \
            stage_data.get(BucketUploadFlow.SUCCESSFUL_UPLOADED_DEPENDENCIES_ZIP_PACKS, {})
        failed_packs_dict = stage_data.get(BucketUploadFlow.FAILED_PACKS, {})
        successful_private_packs_dict = stage_data.get(BucketUploadFlow.SUCCESSFUL_PRIVATE_PACKS, {})
        images_data_dict = stage_data.get(BucketUploadFlow.IMAGES, {})
        return successful_packs_dict, successful_uploaded_dependencies_zip_packs_dict, \
            failed_packs_dict, successful_private_packs_dict, images_data_dict

    logging.debug(f'{packs_results_file_path} does not exist in artifacts')
    return {}, {}, {}, {}, {}


def store_successful_and_failed_packs_in_ci_artifacts(packs_results_file_path: str, stage: str, successful_packs: list,
                                                      successful_uploaded_dependencies_zip_packs: list,
                                                      failed_packs: list,
                                                      updated_private_packs: list, images_data: dict = None):
    """ Write the successful, successful_uploaded_dependencies_zip_packs and failed packs to the correct section in the
        packs_results.json file

    Args:
        packs_results_file_path (str): The path to the pack_results.json file
        stage (str): can be BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING or
        BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
        successful_packs (list): The list of all successful packs
        successful_uploaded_dependencies_zip_packs (list): The list of all packs that successfully updated their
        dependencies zip file.
        failed_packs (list): The list of all failed packs
        updated_private_packs (list) : The list of all private packs that were updated
        images_data (dict): A dict containing all images that were uploaded for each pack

    """
    packs_results = load_json(packs_results_file_path)
    packs_results[stage] = {}

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
                    else "False",
                    BucketUploadFlow.LATEST_VERSION: pack.latest_version
                } for pack in successful_packs
            }
        }
        packs_results[stage].update(successful_packs_dict)
        logging.debug(f"Successful packs {successful_packs_dict}")

    if successful_uploaded_dependencies_zip_packs:
        successful_uploaded_dependencies_zip_packs_dict = {
            BucketUploadFlow.SUCCESSFUL_UPLOADED_DEPENDENCIES_ZIP_PACKS: {
                pack.name: {
                    BucketUploadFlow.STATUS: pack.status,
                    BucketUploadFlow.LATEST_VERSION: pack.latest_version
                } for pack in successful_uploaded_dependencies_zip_packs
            }
        }

        packs_results[stage].update(successful_uploaded_dependencies_zip_packs_dict)
        logging.debug(f"successful uploaded dependencies zip_packs {successful_uploaded_dependencies_zip_packs_dict}")

    if updated_private_packs:
        successful_private_packs_dict: dict = {
            BucketUploadFlow.SUCCESSFUL_PRIVATE_PACKS: {pack_name: {} for pack_name in updated_private_packs}
        }
        packs_results[stage].update(successful_private_packs_dict)
        logging.debug(f"Successful private packs {successful_private_packs_dict}")

    if images_data:
        # adds a list with all the packs that were changed with images
        packs_results[stage].update({BucketUploadFlow.IMAGES: images_data})
        logging.info(f"Images data {images_data}")

    if packs_results:
        if stage == BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING:
            json_write(packs_results_file_path, packs_results)

        elif stage == BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE:
            # write to another file
            packs_results_file_path = Path(packs_results_file_path)  # type: ignore[assignment]
            packs_results_file_path = packs_results_file_path.with_name(  # type: ignore[attr-defined]
                f"{packs_results_file_path.stem}_upload.json")  # type: ignore[attr-defined]
            json_write(str(packs_results_file_path), packs_results)


def load_json(file_path: str) -> dict:
    """ Reads and loads json file.

    Args:
        file_path (str): full path to json file.

    Returns:
        dict: loaded json file.

    """
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path) as json_file:
                result = json.load(json_file)
        else:
            result = {}
        return result
    except json.decoder.JSONDecodeError:
        return {}


def json_write(file_path: str, data: list | dict):
    """ Writes given data to a json file

    Args:
        file_path: The file path
        data: The data to write

    """
    with open(file_path, "w") as f:
        f.write(json.dumps(data, indent=4))


def init_storage_client(service_account=None):
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CircleCI.

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


def get_updated_server_version(current_string_version, compared_content_item, pack_name):
    """ Compares two semantic server versions and returns the higher version between them.

    Args:
         current_string_version (str): current string version.
         compared_content_item (dict): compared content item entity.
         pack_name (str): the pack name (id).

    Returns:
        str: latest version between compared versions.
    """
    lower_version_result = current_string_version

    try:
        compared_string_version = compared_content_item.get('fromversion') or compared_content_item.get(
            'fromVersion') or "99.99.99"
        current_version, compared_version = Version(current_string_version), Version(compared_string_version)

        if current_version > compared_version:
            lower_version_result = compared_string_version
    except Exception:
        content_item_name = compared_content_item.get('name') or compared_content_item.get(
            'display') or compared_content_item.get('id') or compared_content_item.get('details', '')
        logging.exception(f"{pack_name} failed in version comparison of content item {content_item_name}.")
    finally:
        return lower_version_result


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


def is_ignored_pack_file(modified_file_path_parts):
    """ Indicates whether a pack file needs to be ignored or not.

    Args:
        modified_file_path_parts: The modified file parts, e.g. if file path is "a/b/c" then the
         parts list is ["a", "b", "c"]

    Returns:
        (bool): True if the file should be ignored, False otherwise

    """
    for file_suffix in PackIgnored.ROOT_FILES:
        if file_suffix in modified_file_path_parts:
            return True

    for pack_folder, file_suffixes in PackIgnored.NESTED_FILES.items():
        if pack_folder in modified_file_path_parts:
            if not file_suffixes:  # Ignore all pack folder files
                return True

            for file_suffix in file_suffixes:  # type: ignore[attr-defined]
                if file_suffix in modified_file_path_parts[-1]:
                    return True

    for pack_folder in PackIgnored.NESTED_DIRS:
        if pack_folder in modified_file_path_parts:
            pack_folder_path = os.sep.join(modified_file_path_parts[:modified_file_path_parts.index(pack_folder) + 1])
            file_path = os.sep.join(modified_file_path_parts)
            for folder_path in [f for f in glob.glob(os.path.join(pack_folder_path, '*/*')) if os.path.isdir(f)]:
                # Checking for all 2nd level directories. e.g. test_data directory
                if file_path.startswith(folder_path):
                    return True

    return False


def filter_dir_files_by_extension(release_notes_dir: str, extension: str) -> list[str]:
    """
    Receives path to RN dir, filters only files in RN dir corresponding to the extension.
    Needed because RN directory will be extended to contain JSON files for configurations,
    see 'release_notes_bc_calculator.py'
    Args:
        release_notes_dir (str): Path to RN dir
        extension (str): Extension to filter by.

    Returns:
        (List[str]): List of all of the files in directory corresponding to the extension.
    """
    return [file_name for file_name in os.listdir(release_notes_dir) if file_name.endswith(extension)]


def is_the_only_rn_in_block(release_notes_dir: str, version: str, changelog: dict):
    """
    Check if the given version is a key of an aggregated changelog block, as in its value in the changelog
    doesn't contains other release notes that have been aggregated in previous uploads.

    If that is the case, the adjacent previous release note in the changelog will be equal to the one in the
    release notes directory, and false otherwise (meaning there are versions in the release notes directory that are
    missing in the changelog, therefore they have been aggregated) and this function asserts that.

    Note: The comparison is done against the release notes directory to avoid cases where there are missing versions in
    the changelog due to inconsistent versions numbering, such as major version bumps. (For example, if the versions
    1.2.7 and 1.3.0 are two consecutive keys in the changelog, we need to determine if 1.3.0 has aggregated the versions
    1.2.8-1.3.0, OR 1.3.0 is the consecutive version right after 1.2.7 but is a major bump. in order to check that, we
    check it against the files in the release notes directory.)


    Args:
        release_notes_dir: the path to the release notes dir.
        version (str): the wanted version.
        changelog (dict): the changelog from the production bucket.

    Returns:
        True if this version's value in the changelog is not an aggregated release notes block. False otherwise.
    """
    if not changelog.get(version):
        return False
    all_rn_versions = []
    lowest_version = [Version('1.0.0')]
    for filename in filter_dir_files_by_extension(release_notes_dir, '.md'):
        current_version = underscore_file_name_to_dotted_version(filename)
        all_rn_versions.append(Version(current_version))
    lower_versions_all_versions = [item for item in all_rn_versions if item < Version(version)] + lowest_version
    lower_versions_in_changelog = [Version(item) for item in changelog if
                                   Version(item) < Version(version)] + lowest_version
    return max(lower_versions_all_versions) == max(lower_versions_in_changelog)


def underscore_file_name_to_dotted_version(file_name: str) -> str:
    """
    Receives file name with expected format of x_x_x<extension>, and transforms it to dotted string.
    Examples
        - underscore_file_name_to_dotted_version(1_2_3.md) --> 1.2.3
        - underscore_file_name_to_dotted_version(1_4_2.json) --> 1.4.2
    Args:
        file_name (str): File name.

    Returns:
        (str): Dotted version of file name
    """
    return os.path.splitext(file_name)[0].replace('_', '.')


def get_last_commit_from_index(service_account):
    """ Downloading index.json from GCP and extract last upload commit.

    Args:
        service_account: service account to connect to GCP

    Returns: last upload commit.

    """
    storage_client = init_storage_client(service_account)
    storage_bucket = storage_client.bucket(GCPConfig.PRODUCTION_BUCKET)
    index_storage_path = os.path.join('content/packs/', f"{GCPConfig.INDEX_NAME}.json")
    index_blob = storage_bucket.blob(index_storage_path)
    index_string = index_blob.download_as_string()
    index_json = json.loads(index_string)
    return index_json.get('commit')


def get_graph_entity_by_path(entity_path: Path, marketplace):
    with Neo4jContentGraphInterface() as content_graph_interface:
        return content_graph_interface.search(marketplace, path=entity_path)[0]


def get_id_set_entity_by_path(entity_path: Path, pack_folder: str, id_set: dict):
    """
    Get the full entity dict from the id set of the entity given as a path, if it does not exist in the id set
    return None. The item's path in the id set is of the yml/json file, so for integrations, scripts and playbooks this
    function checks if there is an item in the id set that the containing folder of it's yml file is the same as the
    containing folder of the entity path given. For all other content items, we check if the path's are identical.
    Args:
        entity_path: path to entity (content item)
        pack_folder: containing folder of that item
        id_set: id set dict

    Returns:
        id set dict entity if exists, otherwise {}
    """
    logging.debug(f"Checking if the entity with the path {entity_path} is present in the id set")

    for id_set_entity in id_set[PACK_FOLDERS_TO_ID_SET_KEYS[pack_folder]]:

        if len(entity_path.parts) == 5:  # Content items that have a sub folder (integrations, scripts, etc)
            if Path(list(id_set_entity.values())[0]['file_path']).parent == entity_path.parent:
                return id_set_entity

        else:  # Other content items
            if list(id_set_entity.values())[0]['file_path'] == str(entity_path):
                return id_set_entity

    if pack_folder == PackFolders.CLASSIFIERS.value:  # For Classifiers, check also in Mappers
        for id_set_entity in id_set['Mappers']:
            if list(id_set_entity.values())[0]['file_path'] == str(entity_path):
                return id_set_entity
    return {}


def is_content_item_in_graph(display_name: str, content_type, marketplace) -> bool:
    with Neo4jContentGraphInterface() as interface:
        res = interface.search(content_type=content_type, marketplace=marketplace, display_name=display_name)
        logging.debug(f'Content type for {display_name} is {content_type}, result is {bool(res)}')
        return bool(res)


def is_content_item_in_id_set(display_name: str, rn_header: str, id_set: dict, marketplace="xsoar"):
    """
    Get the full entity dict from the id set of the entity given it's display name, if it does not exist in the id set
    return None.

    Args:
        display_name: The display name of the entity (content item).
        rn_header: The release notes header of the entity.
        id_set: id set dict.

    Returns:
        (bool) True if the item exists in id set, otherwise False.
    """
    logging.debug(f"Checking if the entity with the display name {display_name} is present in the id set")

    if not id_set:
        logging.debug("id_set does not exist, searching in graph")
        content_type = rn_header.replace(' ', '')[:-1]

        if not is_content_item_in_graph(display_name=display_name,
                                        content_type=content_type,
                                        marketplace=marketplace):
            logging.debug(f"Could not find the content entity of type {content_type} with display name "
                          f"'{display_name}' in the graph")
            return False
        return True

    for id_set_entity in id_set[RN_HEADER_TO_ID_SET_KEYS[rn_header]]:

        if list(id_set_entity.values())[0]['display_name'] == display_name:
            return True

    logging.debug(f"Could not find the entity with display name {display_name} in id_set.")
    return False


def remove_old_versions_from_changelog(changelog: dict):
    """
    Removes old pack versions from changelog in order to reduce index.zip size.
    We are keeping the maximum number of versions between the following options:
    1.  Versions were released last year.
    2.  Last minor version and one version before it.
    3.  Last five versions.
    Edits the changelog entries in place.

    Args:
        changelog (dict): The changelog of some pack.
    Returns:
        (list) last pack versions
    """
    versions_to_keep: list[str] = []
    if not changelog:
        return versions_to_keep

    last_same_minor_versions = []
    last_year_versions = []
    last_five_versions = list(changelog.keys())[-5:]

    year_ago_datetime_obj = datetime.utcnow() - timedelta(days=365)
    last_version = Version(list(changelog.keys())[-1])
    save_last_minor_versions = not (last_version.minor == 0 and last_version.major == 1)

    prev_version = None
    for version, info in changelog.items():
        # get versions that were released in last year
        if version_release_date := info.get(Changelog.RELEASED):
            version_released_datetime_obj = datetime.strptime(version_release_date, Metadata.DATE_FORMAT)
            if version_released_datetime_obj > year_ago_datetime_obj:
                last_year_versions.append(version)

        # get versions with same minor version
        if save_last_minor_versions and Version(version).minor == last_version.minor \
                and Version(version).major == last_version.major:
            last_same_minor_versions.append(version)
            if prev_version and prev_version not in last_same_minor_versions:
                last_same_minor_versions.append(prev_version)

        prev_version = version

    versions_to_keep = max([last_five_versions, last_year_versions, last_same_minor_versions], key=len)

    [changelog.pop(version) for version in list(changelog.keys()) if version not in versions_to_keep]

    return versions_to_keep
