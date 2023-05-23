from demisto_sdk.commands.common.constants import (SAMPLES_DIR,
                                                   TESTS_AND_DOC_DIRECTORIES,
                                                   FileType,
                                                   MarketplaceVersions)

XSOAR_SANITY_TEST_NAMES: tuple[str, ...] = (
    # Skipped until helloworld server will be fixed
    # 'Sanity Test - Playbook with integration',
    'Sanity Test - Playbook with no integration',
    # 'Sanity Test - Playbook with mocked integration',
    'Sanity Test - Playbook with Unmockable Whois Integration',
)
SANITY_TEST_TO_PACK: dict[str, str] = {
    'Sanity Test - Playbook with Unmockable Whois Integration': 'Whois',
    'Sanity Test - Playbook with integration': 'HelloWorld',
    'Sanity Test - Playbook with no integration': 'HelloWorld',
    'Sanity Test - Playbook with mocked integration': 'HelloWorld',
}

ALWAYS_INSTALLED_PACKS_XSOAR = (
    'Base',
    'DeveloperTools',
)

ALWAYS_INSTALLED_PACKS_MARKETPLACE_V2 = ALWAYS_INSTALLED_PACKS_XSOAR + ('CoreAlertFields',)

ALWAYS_INSTALLED_PACKS_XPANSE = ALWAYS_INSTALLED_PACKS_MARKETPLACE_V2

ALWAYS_INSTALLED_PACKS_MAPPING = {
    MarketplaceVersions.XSOAR: ALWAYS_INSTALLED_PACKS_XSOAR,
    MarketplaceVersions.MarketplaceV2: ALWAYS_INSTALLED_PACKS_MARKETPLACE_V2,
    MarketplaceVersions.XPANSE: ALWAYS_INSTALLED_PACKS_XPANSE,
}

DEFAULT_MARKETPLACE_WHEN_MISSING: MarketplaceVersions = MarketplaceVersions.XSOAR

SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK: set[str] = {
    # these are not under packs, and are not supported anymore.
    'playbook-Jask_Test-4.0.0.yml',
    'playbook-Recorded_Future_Test_4_0.yml',
    'playbook-TestCommonPython_4_1.yml',
}

ONLY_INSTALL_PACK_FILE_TYPES: set[FileType] = {
    # upon collection, no tests are collected, but the pack is installed.
    FileType.RELEASE_NOTES_CONFIG,
    FileType.RELEASE_NOTES,
    FileType.IMAGE,
    FileType.DESCRIPTION,
    FileType.METADATA,
    FileType.INCIDENT_TYPE,
    FileType.INCIDENT_FIELD,
    FileType.INDICATOR_FIELD,
    FileType.LAYOUT,
    FileType.WIDGET,
    FileType.DASHBOARD,
    FileType.REPORT,
    FileType.PARSING_RULE,
    FileType.MODELING_RULE,
    FileType.MODELING_RULE_TEST_DATA,
    FileType.MODELING_RULE_XIF,
    FileType.CORRELATION_RULE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.GENERIC_TYPE,
    FileType.GENERIC_FIELD,
    FileType.GENERIC_MODULE,
    FileType.GENERIC_DEFINITION,
    FileType.PRE_PROCESS_RULES,
    FileType.JOB,
    FileType.CONNECTION,
    FileType.XSOAR_CONFIG,
    FileType.AUTHOR_IMAGE,
    FileType.CHANGELOG,
    FileType.DOC_IMAGE,
    FileType.BUILD_CONFIG_FILE,
    FileType.WIZARD,
    FileType.TRIGGER,
    FileType.LISTS,
    FileType.CONF_JSON,
    FileType.MODELING_RULE_SCHEMA,
    FileType.LAYOUTS_CONTAINER,
    FileType.XDRC_TEMPLATE,
    FileType.PARSING_RULE_XIF,
    FileType.LAYOUT_RULE,
}

ONLY_UPLOAD_PACK_FILE_TYPES: set[FileType] = {
    FileType.README,
}

IGNORED_FILE_TYPES: set[FileType] = {
    FileType.PACK_IGNORE,
    FileType.XIF_FILE,
    FileType.SECRET_IGNORE,
    FileType.PACK,
    FileType.CONTRIBUTORS,
    FileType.DOC_FILE,
    FileType.OLD_CLASSIFIER,
    FileType.WHITE_LIST,
    FileType.TEST_SCRIPT,
    FileType.LANDING_PAGE_SECTIONS_JSON,
    FileType.XDRC_TEMPLATE_YML,
    FileType.XSIAM_DASHBOARD_IMAGE,
    FileType.XSIAM_REPORT_IMAGE,
    FileType.PIPFILE,
    FileType.PIPFILE_LOCK,
    FileType.TXT,
    FileType.PYLINTRC,
    FileType.INI,
    FileType.PEM,
    FileType.LICENSE,
}

NON_CONTENT_FOLDERS: set[str] = set(TESTS_AND_DOC_DIRECTORIES) | {SAMPLES_DIR}

MODELING_RULE_COMPONENT_FILES: set[FileType] = {
    FileType.MODELING_RULE,  # the modeling rule yml file
    FileType.MODELING_RULE_XIF,
    FileType.MODELING_RULE_SCHEMA,
    FileType.MODELING_RULE_TEST_DATA,
}

XSIAM_COMPONENT_FILES: set[FileType] = {
    FileType.PARSING_RULE,
    FileType.PARSING_RULE_XIF,
    FileType.CORRELATION_RULE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.TRIGGER,
    FileType.MODELING_RULE_SCHEMA,
    FileType.XDRC_TEMPLATE,
    FileType.LAYOUT_RULE,
    FileType.XDRC_TEMPLATE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.TRIGGER,
    FileType.CORRELATION_RULE,
}
