import os
import json
import enum

IGNORED_FILES = ['__init__.py', 'ApiModules', 'NonSupported', 'index']  # files to ignore inside Packs folder
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

SIEM_RULES_OBJECTS = ['ParsingRule', 'ModelingRule', 'CorrelationRule', 'XDRCTemplate']
XSIAM_MP = "marketplacev2"
XSOAR_MP = "xsoar"
XPANSE_MP = "xpanse"
XSOAR_SAAS_MP = "xsoar_saas"
XSIAM_START_TAG = "<~XSIAM>"
XSIAM_END_TAG = "</~XSIAM>"
XSOAR_START_TAG = "<~XSOAR>"
XSOAR_END_TAG = "</~XSOAR>"
XPANSE_START_TAG = "<~XPANSE>"
XPANSE_END_TAG = "</~XPANSE>"
XSOAR_SAAS_START_TAG = "<~XSOAR_SAAS>"
XSOAR_SAAS_END_TAG = "<~/XSOAR_SAAS>"
TAGS_BY_MP = {
    XSIAM_MP: (XSIAM_START_TAG, XSIAM_END_TAG),
    XSOAR_MP: (XSOAR_START_TAG, XSOAR_END_TAG),
    XPANSE_MP: (XPANSE_START_TAG, XPANSE_END_TAG),
    XSOAR_SAAS_MP: (XSOAR_SAAS_START_TAG, XSOAR_SAAS_END_TAG)
}


class BucketUploadFlow:
    """ Bucket Upload Flow constants

    """
    PACKS_RESULTS_FILE = "packs_results.json"
    PACKS_RESULTS_FILE_FOR_SLACK = "packs_results_upload.json"
    PREPARE_CONTENT_FOR_TESTING = "prepare_content_for_testing"
    UPLOAD_PACKS_TO_MARKETPLACE_STORAGE = "upload_packs_to_marketplace_storage"
    SUCCESSFUL_PACKS = "successful_packs"
    SUCCESSFUL_UPLOADED_DEPENDENCIES_ZIP_PACKS = "successful_uploaded_dependencies_zip_packs"
    SUCCESSFUL_PRIVATE_PACKS = "successful_private_packs"
    FAILED_PACKS = "failed_packs"
    STATUS = "status"
    AGGREGATED = "aggregated"
    IMAGES = 'images'
    AUTHOR = 'author'
    README_IMAGES = 'readme_images'
    INTEGRATIONS = 'integrations'
    PREVIEW_IMAGES = 'preview_images'
    DYNAMIC_DASHBOARD_IMAGES = 'dynamic_dashboard_images'
    BUCKET_UPLOAD_BUILD_TITLE = "Upload Packs To Marketplace Storage"
    BUCKET_UPLOAD_TYPE = "bucket_upload_flow"
    # Different upload job names relate to different CI platforms:
    # "Upload Packs To Marketplace" - CircleCI
    # "upload-packs-to-marketplace" - Gitlab
    UPLOAD_JOB_NAMES = ["Upload Packs To Marketplace", "upload-packs-to-marketplace"]
    LATEST_VERSION = 'latest_version'
    INTEGRATION_DIR_REGEX = r"^integration-(.+).yml$"
    MARKDOWN_IMAGES_ARTIFACT_FILE_NAME = "markdown_images.json"
    MARKDOWN_IMAGES = 'markdown_images'


class ImagesFolderNames(enum.Enum):
    README_IMAGES = "readme_images"
    INTEGRATION_DESCRIPTION_IMAGES = "integration_description_images"


class GCPConfig:
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
    PRODUCTION_BUCKET_V2 = "marketplace-v2-dist"
    CI_BUILD_BUCKET = "marketplace-ci-build"
    PRODUCTION_PRIVATE_BUCKET = "marketplace-dist-private"
    CI_PRIVATE_BUCKET = "marketplace-ci-build-private"
    BASE_PACK = "Base"  # base pack name
    INDEX_NAME = "index"  # main index folder name
    CORE_PACK_FILE_NAME = "corepacks.json"  # core packs file name
    VERSIONS_METADATA_FILE = 'versions-metadata.json'
    COREPACKS_OVERRIDE_FILE = 'corepacks_override.json'
    BUILD_BUCKET_PACKS_ROOT_PATH = 'content/builds/{branch}/{build}/{marketplace}/content/packs'

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_list.json')) as core_packs_xsoar_list_file:
        packs_list = json.load(core_packs_xsoar_list_file)
        CORE_PACKS_LIST = packs_list.get('core_packs_list')
        CORE_PACKS_LIST_TO_UPDATE = packs_list.get('update_core_packs_list')

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_mpv2_list.json')) as core_packs_xsiam_list_file:
        packs_list_xsiam = json.load(core_packs_xsiam_list_file)
        CORE_PACKS_MPV2_LIST = packs_list_xsiam.get('core_packs_list')
        CORE_PACKS_MPV2_LIST_TO_UPDATE = packs_list_xsiam.get('update_core_packs_list')

    with open(os.path.join(os.path.dirname(__file__), 'core_packs_xpanse_list.json')) as core_packs_xpanse_list_file:
        packs_list_xpanse = json.load(core_packs_xpanse_list_file)
        CORE_PACKS_XPANSE_LIST = packs_list_xpanse.get('core_packs_list')
        CORE_PACKS_XPANSE_LIST_TO_UPDATE = packs_list_xpanse.get('update_core_packs_list')

    with open(os.path.join(os.path.dirname(__file__), VERSIONS_METADATA_FILE)) as server_versions_metadata:
        versions_metadata_contents = json.load(server_versions_metadata)
        core_packs_file_versions = versions_metadata_contents.get('version_map')

    with open(os.path.join(os.path.dirname(__file__), COREPACKS_OVERRIDE_FILE)) as corepacks_override_file:
        corepacks_override_contents = json.load(corepacks_override_file)

    @classmethod
    def get_core_packs(cls, marketplace):
        mapping = {
            'xsoar': cls.CORE_PACKS_LIST,
            'marketplacev2': cls.CORE_PACKS_MPV2_LIST,
            'xpanse': cls.CORE_PACKS_XPANSE_LIST,
        }
        return mapping.get(marketplace, GCPConfig.CORE_PACKS_LIST)

    @classmethod
    def get_core_packs_to_upgrade(cls, marketplace):
        mapping = {
            'xsoar': cls.CORE_PACKS_LIST_TO_UPDATE,
            'marketplacev2': cls.CORE_PACKS_MPV2_LIST_TO_UPDATE,
            'xpanse': cls.CORE_PACKS_XPANSE_LIST_TO_UPDATE,
        }
        return mapping.get(marketplace, GCPConfig.CORE_PACKS_LIST_TO_UPDATE)

    @classmethod
    def get_core_packs_unlocked_files(cls, marketplace):
        """
        Find the current server versions that are unlocked and return the matching corepacks files.
        """
        unlocked_corepacks_files = []
        for _version, core_pack_file_value in cls.core_packs_file_versions.items():
            # check if the file is unlocked
            if not core_pack_file_value.get('core_packs_file_is_locked'):
                # check if version should be used for this marketplace (all are used by default if none was specified)
                supported_marketplaces = core_pack_file_value.get('marketplaces', [])
                if not supported_marketplaces or marketplace in supported_marketplaces:
                    unlocked_corepacks_files.append(core_pack_file_value.get('core_packs_file'))
        return unlocked_corepacks_files


class PackTags:
    """ Pack tag constants """
    TRENDING = "Trending"
    NEW = "New"
    TIM = "TIM"
    USE_CASE = "Use Case"
    TRANSFORMER = "Transformer"
    FILTER = "Filter"
    COLLECTION = "Collection"
    DATA_SOURCE = "Data Source"


class Metadata:
    """ Metadata constants and default values that are used in metadata parsing.
    """
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    XSOAR_SUPPORT = "xsoar"
    PARTNER_SUPPORT = "partner"
    COMMUNITY_SUPPORT = "community"
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
    CONTENT_DISPLAYS = 'contentDisplays'
    SEARCH_RANK = 'searchRank'
    INTEGRATIONS = 'integrations'
    USE_CASES = 'useCases'
    KEY_WORDS = 'keywords'
    DEPENDENCIES = 'dependencies'
    EXCLUDED_DEPENDENCIES = 'excludedDependencies'
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
    MARKETPLACES = 'marketplaces'
    DISABLE_MONTHLY = 'disableMonthly'
    MODULES = 'modules'


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
    XDRC_TEMPLATES = 'XDRCTemplates'
    LAYOUT_RULES = 'LayoutRules'

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
            PackFolders.XSIAM_DASHBOARDS.value, PackFolders.XSIAM_REPORTS.value,
            PackFolders.WIZARDS.value, PackFolders.XDRC_TEMPLATES.value, PackFolders.LAYOUT_RULES.value
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
            PackFolders.XDRC_TEMPLATES.value, PackFolders.LAYOUT_RULES.value
        }


class PackIgnored:
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
    PackFolders.WIZARDS.value: "Wizards",
    PackFolders.XDRC_TEMPLATES.value: "XDRCTemplates",
    PackFolders.LAYOUT_RULES.value: "LayoutRules"
}


class PackStatus(enum.Enum):
    """ Enum of pack upload status, is used in printing upload summary.

    """
    SUCCESS = "Successfully uploaded pack data to gcs"
    SUCCESS_CREATING_DEPENDENCIES_ZIP_UPLOADING = "Successfully uploaded pack while creating dependencies zip"
    FAILED_LOADING_USER_METADATA = "Failed in loading user-defined pack metadata"
    FAILED_IMAGES_UPLOAD = "Failed to upload pack integration images to gcs"
    FAILED_AUTHOR_IMAGE_UPLOAD = "Failed to upload pack author image to gcs"
    FAILED_PREVIEW_IMAGES_UPLOAD = "Failed to upload pack preview images to gcs"
    FAILED_DYNAMIC_DASHBOARD_IMAGES_UPLOAD = "Failed to upload pack dynamic dashboard images to gcs"
    FAILED_README_IMAGE_UPLOAD = "Failed to upload readme images to gcs"
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


class Changelog:
    """
    A class that represents all the keys that are present in a Changelog entry.
    """

    RELEASE_NOTES = 'releaseNotes'
    DISPLAY_NAME = 'displayName'
    RELEASED = 'released'
    PULL_REQUEST_NUMBERS = 'pullRequests'


RN_HEADER_TO_ID_SET_KEYS = {
    'Playbooks': 'playbooks',
    'Integrations': 'integrations',
    'Scripts': 'scripts',
    'Incident Fields': 'IncidentFields',
    'Indicator Fields': 'IndicatorFields',
    'Indicator Types': 'IndicatorTypes',
    'Incident Types': 'IncidentTypes',
    'Classifiers': 'Classifiers',
    'Mappers': 'Mappers',
    'Layouts': 'Layouts',
    'Reports': 'Reports',
    'Widgets': 'Widgets',
    'Dashboards': 'Dashboards',
    'Objects': 'GenericDefinitions',
    'Modules': 'GenericModules',
    'Object Types': 'GenericTypes',
    'Object Fields': 'GenericFields',
    'Lists': 'Lists',
    'Jobs': 'Jobs',
    'Parsing Rules': 'ParsingRules',
    'Modeling Rules': 'ModelingRules',
    'Correlation Rules': 'CorrelationRules',
    'XSIAM Dashboards': 'XSIAMDashboards',
    'XSIAM Reports': 'XSIAMReports',
    'Triggers Recommendations': 'Triggers',
    'Wizards': 'Wizards',
    'XDRC Templates': 'XDRCTemplates',
    'Layout Rules': 'LayoutRules'
}

# the format is defined in issue #19786, may change in the future
CONTENT_ITEM_NAME_MAPPING = {
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
    PackFolders.WIDGETS.value: "widget",
    PackFolders.GENERIC_DEFINITIONS.value: "genericdefinition",
    PackFolders.GENERIC_FIELDS.value: "genericfield",
    PackFolders.GENERIC_MODULES.value: "genericmodule",
    PackFolders.GENERIC_TYPES.value: "generictype",
    PackFolders.LISTS.value: "list",
    PackFolders.PREPROCESS_RULES.value: "preprocessrule",
    PackFolders.JOBS.value: "job",
    PackFolders.PARSING_RULES.value: "parsingrule",
    PackFolders.MODELING_RULES.value: "modelingrule",
    PackFolders.CORRELATION_RULES.value: "correlationrule",
    PackFolders.XSIAM_DASHBOARDS.value: "xsiamdashboard",
    PackFolders.XSIAM_REPORTS.value: "xsiamreport",
    PackFolders.TRIGGERS.value: "trigger",
    PackFolders.WIZARDS.value: "wizard",
    PackFolders.XDRC_TEMPLATES.value: "xdrctemplate",
    PackFolders.LAYOUT_RULES.value: "layoutrule"
}

ITEMS_NAMES_TO_DISPLAY_MAPPING = {
    CONTENT_ITEM_NAME_MAPPING[PackFolders.SCRIPTS.value]: "Automation",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.PLAYBOOKS.value]: "Playbook",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.INTEGRATIONS.value]: "Integration",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.INCIDENT_FIELDS.value]: "Incident Field",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.INCIDENT_TYPES.value]: "Incident Type",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.DASHBOARDS.value]: "Dashboard",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.INDICATOR_FIELDS.value]: "Indicator Field",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.REPORTS.value]: "Report",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.INDICATOR_TYPES.value]: "Reputation",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.LAYOUTS.value]: "Layouts Container",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.CLASSIFIERS.value]: "Classifier",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.WIDGETS.value]: "Widget",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.GENERIC_DEFINITIONS.value]: "Generic Definition",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.GENERIC_FIELDS.value]: "Generic Field",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.GENERIC_MODULES.value]: "Generic Module",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.GENERIC_TYPES.value]: "Generic Type",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.LISTS.value]: "List",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.PREPROCESS_RULES.value]: "Pre Process Rule",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.JOBS.value]: "Job",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.PARSING_RULES.value]: "Parsing Rule",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.MODELING_RULES.value]: "Modeling Rule",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.CORRELATION_RULES.value]: "Correlation Rule",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.XSIAM_DASHBOARDS.value]: "XSIAM Dashboard",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.XSIAM_REPORTS.value]: "XSIAM Report",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.WIZARDS.value]: "Wizard",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.XDRC_TEMPLATES.value]: "XDRC Template",
    CONTENT_ITEM_NAME_MAPPING[PackFolders.LAYOUT_RULES.value]: "Layout Rule"
}
