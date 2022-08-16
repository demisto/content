import os
import json
import enum
from typing import List
from Tests.scripts.utils.content_packs_util import IGNORED_FILES

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
PACKS_FOLDER = "Packs"  # name of base packs folder inside content repo
PACKS_FULL_PATH = os.path.join(CONTENT_ROOT_PATH, PACKS_FOLDER)  # full path to Packs folder in content repo
IGNORED_PATHS = [os.path.join(PACKS_FOLDER, p) for p in IGNORED_FILES]
LANDING_PAGE_SECTIONS_PATH = os.path.abspath(os.path.join(__file__, '../landingPage_sections.json'))
BASE_PACK_DEPENDENCY_DICT = {
    'Base':
        {
            'mandatory': True,
            'author': 'Cortex XSOAR',
            'minVersion': '1.0.0',
            'name': 'Base',
            'certification': ''
        }
}


SIEM_RULES_OBJECTS = ['ParsingRule', 'ModelingRule', 'CorrelationRule']
XSIAM_MP = "marketplacev2"
XSOAR_MP = "xsoar"
XSIAM_START_TAG = "<~XSIAM>"
XSIAM_END_TAG = "</~XSIAM>"
XSOAR_START_TAG = "<~XSOAR>"
XSOAR_END_TAG = "</~XSOAR>"
TAGS_BY_MP = {
    XSIAM_MP: (XSIAM_START_TAG, XSIAM_END_TAG),
    XSOAR_MP: (XSOAR_START_TAG, XSOAR_END_TAG)
}


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
    CONTENT_PACKS_PATH = "content/packs"
    PRODUCTION_STORAGE_BASE_PATH = "content/packs"
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
    BUILD_BUCKET_PACKS_ROOT_PATH = 'content/builds/{branch}/{build}/{marketplace}/content/packs'

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_list.json'), 'r') as core_packs_list_file:
        CORE_PACKS_LIST = json.load(core_packs_list_file)
    with open(os.path.join(os.path.dirname(__file__), 'core_packs_mpv2_list.json'), 'r') as core_packs_list_file:
        CORE_PACKS_MPV2_LIST = json.load(core_packs_list_file)

    with open(os.path.join(os.path.dirname(__file__), 'upgrade_core_packs_list.json'), 'r') as upgrade_core_packs_list:
        packs_list = json.load(upgrade_core_packs_list)
        CORE_PACKS_LIST_TO_UPDATE = packs_list.get("update_core_packs_list")
    CORE_PACKS_MPV2_LIST_TO_UPDATE: List[str] = []

    @classmethod
    def get_core_packs(cls, marketplace):
        mapping = {
            'xsoar': cls.CORE_PACKS_LIST,
            'marketplacev2': cls.CORE_PACKS_MPV2_LIST,
        }
        return mapping.get(marketplace, GCPConfig.CORE_PACKS_LIST)

    @classmethod
    def get_core_packs_to_upgrade(cls, marketplace):
        mapping = {
            'xsoar': cls.CORE_PACKS_LIST_TO_UPDATE,
            'marketplacev2': cls.CORE_PACKS_MPV2_LIST_TO_UPDATE,
        }
        return mapping.get(marketplace, GCPConfig.CORE_PACKS_LIST_TO_UPDATE)


class PackTags(object):
    """ Pack tag constants """
    TRENDING = "Trending"
    NEW = "New"
    TIM = "TIM"
    USE_CASE = "Use Case"
    TRANSFORMER = "Transformer"
    FILTER = "Filter"
    COLLECTION = "Collection"


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
    CURRENT_VERSION = 'currentVersion'
    SERVER_MIN_VERSION = 'serverMinVersion'
    HIDDEN = 'hidden'
    NAME = 'name'
    ID = 'id'
    DESCRIPTION = 'description'
    CREATED = 'created'
    UPDATED = 'updated'
    LEGACY = 'legacy'
    SUPPORT = 'support'
    SUPPORT_DETAILS = 'supportDetails'
    EULA_LINK = 'eulaLink'
    AUTHOR = 'author'
    AUTHOR_IMAGE = 'authorImage'
    CERTIFICATION = 'certification'
    PRICE = 'price'
    VERSION_INFO = 'versionInfo'
    COMMIT = 'commit'
    DOWNLOADS = 'downloads'
    TAGS = 'tags'
    CATEGORIES = 'categories'
    CONTENT_ITEMS = 'contentItems'
    SEARCH_RANK = 'searchRank'
    INTEGRATIONS = 'integrations'
    USE_CASES = 'useCases'
    KEY_WORDS = 'keywords'
    DEPENDENCIES = 'dependencies'
    ALL_LEVELS_DEPENDENCIES = 'allLevelDependencies'
    PREMIUM = 'premium'
    VENDOR_ID = 'vendorId'
    PARTNER_ID = 'partnerId'
    PARTNER_NAME = 'partnerName'
    CONTENT_COMMIT_HASH = 'contentCommitHash'
    PREVIEW_ONLY = 'previewOnly'
    MANDATORY = 'mandatory'
    VIDEOS = 'videos'
    DISPLAYED_IMAGES = 'displayedImages'
    EMAIL = 'email'
    URL = 'url'
    DISABLE_MONTHLY = 'disableMonthly'


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
    GENERIC_DEFINITIONS = "GenericDefinitions"
    GENERIC_FIELDS = "GenericFields"
    GENERIC_MODULES = "GenericModules"
    GENERIC_TYPES = "GenericTypes"
    LISTS = 'Lists'
    PREPROCESS_RULES = "PreProcessRules"
    JOBS = 'Jobs'
    PARSING_RULES = 'ParsingRules'
    MODELING_RULES = 'ModelingRules'
    CORRELATION_RULES = 'CorrelationRules'
    XSIAM_DASHBOARDS = 'XSIAMDashboards'
    XSIAM_REPORTS = 'XSIAMReports'
    TRIGGERS = 'Triggers'
    WIZARDS = 'Wizards'

    @classmethod
    def pack_displayed_items(cls):
        return {
            PackFolders.SCRIPTS.value, PackFolders.DASHBOARDS.value, PackFolders.INCIDENT_FIELDS.value,
            PackFolders.INCIDENT_TYPES.value, PackFolders.INTEGRATIONS.value, PackFolders.PLAYBOOKS.value,
            PackFolders.INDICATOR_FIELDS.value, PackFolders.REPORTS.value, PackFolders.INDICATOR_TYPES.value,
            PackFolders.LAYOUTS.value, PackFolders.CLASSIFIERS.value, PackFolders.WIDGETS.value,
            PackFolders.GENERIC_DEFINITIONS.value, PackFolders.GENERIC_FIELDS.value, PackFolders.GENERIC_MODULES.value,
            PackFolders.GENERIC_TYPES.value, PackFolders.LISTS.value, PackFolders.JOBS.value,
            PackFolders.PARSING_RULES.value, PackFolders.MODELING_RULES.value, PackFolders.CORRELATION_RULES.value,
            PackFolders.XSIAM_DASHBOARDS.value, PackFolders.XSIAM_REPORTS.value, PackFolders.TRIGGERS.value,
            PackFolders.WIZARDS.value,
        }

    @classmethod
    def yml_supported_folders(cls):
        return {PackFolders.INTEGRATIONS.value, PackFolders.SCRIPTS.value, PackFolders.PLAYBOOKS.value,
                PackFolders.TEST_PLAYBOOKS.value, PackFolders.PARSING_RULES.value, PackFolders.MODELING_RULES.value,
                PackFolders.CORRELATION_RULES.value}

    @classmethod
    def json_supported_folders(cls):
        return {
            PackFolders.CLASSIFIERS.value, PackFolders.CONNECTIONS.value, PackFolders.DASHBOARDS.value,
            PackFolders.INCIDENT_FIELDS.value, PackFolders.INCIDENT_TYPES.value, PackFolders.INDICATOR_FIELDS.value,
            PackFolders.LAYOUTS.value, PackFolders.INDICATOR_TYPES.value, PackFolders.REPORTS.value,
            PackFolders.WIDGETS.value, PackFolders.GENERIC_DEFINITIONS.value, PackFolders.GENERIC_FIELDS.value,
            PackFolders.GENERIC_MODULES.value, PackFolders.GENERIC_TYPES.value, PackFolders.LISTS.value,
            PackFolders.PREPROCESS_RULES.value, PackFolders.JOBS.value, PackFolders.XSIAM_DASHBOARDS.value,
            PackFolders.XSIAM_REPORTS.value, PackFolders.TRIGGERS.value, PackFolders.WIZARDS.value,
        }


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


PACK_FOLDERS_TO_ID_SET_KEYS = {
    PackFolders.SCRIPTS.value: 'scripts',
    PackFolders.INTEGRATIONS.value: 'integrations',
    PackFolders.PLAYBOOKS.value: "playbooks",
    PackFolders.TEST_PLAYBOOKS.value: "TestPlaybooks",
    PackFolders.CLASSIFIERS.value: "Classifiers",
    PackFolders.INCIDENT_FIELDS.value: "IncidentFields",
    PackFolders.INCIDENT_TYPES.value: "IncidentTypes",
    PackFolders.INDICATOR_FIELDS.value: "IndicatorFields",
    PackFolders.INDICATOR_TYPES.value: "IndicatorTypes",
    PackFolders.LISTS.value: "Lists",
    PackFolders.JOBS.value: "Jobs",
    PackFolders.GENERIC_TYPES.value: "GenericTypes",
    PackFolders.GENERIC_FIELDS.value: "GenericFields",
    PackFolders.GENERIC_MODULES.value: "GenericModules",
    PackFolders.GENERIC_DEFINITIONS.value: "GenericDefinitions",
    PackFolders.LAYOUTS.value: "Layouts",
    PackFolders.REPORTS.value: "Reports",
    PackFolders.WIDGETS.value: "Widgets",
    PackFolders.DASHBOARDS.value: "Dashboards",
    PackFolders.PARSING_RULES.value: "ParsingRules",
    PackFolders.MODELING_RULES.value: "ModelingRules",
    PackFolders.CORRELATION_RULES.value: "CorrelationRules",
    PackFolders.XSIAM_DASHBOARDS.value: "XSIAMDashboards",
    PackFolders.XSIAM_REPORTS.value: "XSIAMReports",
    PackFolders.TRIGGERS.value: "Triggers",
    PackFolders.WIZARDS.value: "Wizards"
}


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
    FAILED_METADATA_REFORMATING = "Failed to reparse and create metadata.json when missing dependencies"
    NOT_RELEVANT_FOR_MARKETPLACE = "Pack is not relevant for current marketplace."
    CHANGES_ARE_NOT_RELEVANT_FOR_MARKETPLACE = "Pack changes are not relevant for current marketplace."
    FAILED_CREATING_DEPENDENCIES_ZIP_SIGNING = "Failed creating dependencies zip since a depending pack or this " \
                                               "pack failed signing or zipping"
    FAILED_CREATING_DEPENDENCIES_ZIP_UPLOADING = "Failed uploading pack while creating dependencies zip"


SKIPPED_STATUS_CODES = {
    PackStatus.PACK_ALREADY_EXISTS.name,
    PackStatus.PACK_IS_NOT_UPDATED_IN_RUNNING_BUILD.name,
    PackStatus.NOT_RELEVANT_FOR_MARKETPLACE.name,
    PackStatus.CHANGES_ARE_NOT_RELEVANT_FOR_MARKETPLACE.name,
}


class Changelog(object):
    """
    A class that represents all the keys that are present in a Changelog entry.
    """

    RELEASE_NOTES = 'releaseNotes'
    DISPLAY_NAME = 'displayName'
    RELEASED = 'released'
    PULL_REQUEST_NUMBERS = 'pullRequests'


RN_HEADER_BY_PACK_FOLDER = {
    PackFolders.PLAYBOOKS.value: 'Playbooks',
    PackFolders.INTEGRATIONS.value: 'Integrations',
    PackFolders.SCRIPTS.value: 'Scripts',
    PackFolders.INCIDENT_FIELDS.value: 'Incident Fields',
    PackFolders.INDICATOR_FIELDS.value: 'Indicator Fields',
    PackFolders.INDICATOR_TYPES.value: 'Indicator Types',
    PackFolders.INCIDENT_TYPES.value: 'Incident Types',
    PackFolders.PREPROCESS_RULES.value: 'PreProcess Rules',
    PackFolders.CLASSIFIERS.value: 'Classifiers',
    PackFolders.LAYOUTS.value: 'Layouts',
    PackFolders.REPORTS.value: 'Reports',
    PackFolders.WIDGETS.value: 'Widgets',
    PackFolders.DASHBOARDS.value: 'Dashboards',
    PackFolders.CONNECTIONS.value: 'Connections',
    PackFolders.GENERIC_DEFINITIONS.value: 'Objects',
    PackFolders.GENERIC_MODULES.value: 'Modules',
    PackFolders.GENERIC_TYPES.value: 'Object Types',
    PackFolders.GENERIC_FIELDS.value: 'Object Fields',
    PackFolders.LISTS.value: 'Lists',
    PackFolders.JOBS.value: 'Jobs',
    PackFolders.PARSING_RULES.value: 'Parsing Rules',
    PackFolders.MODELING_RULES.value: 'Modeling Rules',
    PackFolders.CORRELATION_RULES.value: 'Correlation Rules',
    PackFolders.XSIAM_DASHBOARDS.value: 'XSIAM Dashboards',
    PackFolders.XSIAM_REPORTS.value: 'XSIAM Reports',
    PackFolders.TRIGGERS.value: 'Triggers Recommendations',  # https://github.com/demisto/etc/issues/48153#issuecomment-1111988526
    PackFolders.WIZARDS.value: 'Wizards',
}
