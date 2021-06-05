import os
import json
import enum
from Tests.scripts.utils.content_packs_util import IGNORED_FILES

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
PACKS_FOLDER = "Packs"  # name of base packs folder inside content repo
PACKS_FULL_PATH = os.path.join(CONTENT_ROOT_PATH, PACKS_FOLDER)  # full path to Packs folder in content repo
IGNORED_PATHS = [os.path.join(PACKS_FOLDER, p) for p in IGNORED_FILES]
LANDING_PAGE_SECTIONS_PATH = os.path.abspath(os.path.join(__file__, '../landingPage_sections.json'))


class BucketUploadFlow(object):
    """ Bucket Upload Flow constants

    """
    PACKS_RESULTS_FILE = "packs_results.json"
    PREPARE_CONTENT_FOR_TESTING = "prepare_content_for_testing"
    UPLOAD_PACKS_TO_MARKETPLACE_STORAGE = "upload_packs_to_marketplace_storage"
    SUCCESSFUL_PACKS = "successful_packs"
    SUCCESSFUL_PRIVATE_PACKS = "successful_private_packs"
    FAILED_PACKS = "failed_packs"
    STATUS = "status"
    AGGREGATED = "aggregated"
    IMAGES = 'images'
    AUTHOR = 'author'
    INTEGRATIONS = 'integrations'
    BUCKET_UPLOAD_BUILD_TITLE = "Upload Packs To Marketplace Storage"
    BUCKET_UPLOAD_TYPE = "bucket_upload_flow"
    # Different upload job names relate to different CI platforms:
    # "Upload Packs To Marketplace" - CircleCI
    # "upload-packs-to-marketplace" - Gitlab
    UPLOAD_JOB_NAMES = ["Upload Packs To Marketplace", "upload-packs-to-marketplace"]
    LATEST_VERSION = 'latest_version'
    INTEGRATION_DIR_REGEX = r"^integration-(.+).yml$"


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

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_list.json'), 'r') as core_packs_list_file:
        CORE_PACKS_LIST = json.load(core_packs_list_file)


class PackTags(object):
    """ Pack tag constants """
    TRENDING = "Trending"
    NEW = "New"
    TIM = "TIM"
    USE_CASE = "Use Case"


class Metadata(object):
    """ Metadata constants and default values that are used in metadata parsing.
    """
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    XSOAR_SUPPORT = "xsoar"
    PARTNER_SUPPORT = "partner"
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


class PackIgnored(object):
    """ A class that represents all pack files/directories to be ignored if a change is detected in any of them

    ROOT_FILES: The files in the pack root directory
    NESTED_FILES: The files to be ignored inside the pack entities directories. Empty list = all files.
    NESTED_DIRS: The 2nd level directories under the pack entities directories to ignore all of their files.

    """
    PACK_IGNORE = ".pack-ignore"
    SECRETS_IGNORE = ".secrets-ignore"

    ROOT_FILES = [SECRETS_IGNORE, PACK_IGNORE]
    NESTED_FILES = {
        PackFolders.INTEGRATIONS.value: ["README.md", "Pipfile", "Pipfile.lock", "_test.py", "commands.txt"],
        PackFolders.SCRIPTS.value: ["README.md", "Pipfile", "Pipfile.lock", "_test.py"],
        PackFolders.TEST_PLAYBOOKS.value: [],
        PackFolders.PLAYBOOKS.value: ["_README.md"],
    }
    NESTED_DIRS = [PackFolders.INTEGRATIONS.value, PackFolders.SCRIPTS.value]


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
