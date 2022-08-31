from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions

XSOAR_SANITY_TEST_NAMES: tuple[str, ...] = (
    'Sanity Test - Playbook with integration',
    'Sanity Test - Playbook with no integration',
    'Sanity Test - Playbook with mocked integration',
    'Sanity Test - Playbook with Unmockable Whois Integration',
)
SANITY_TEST_TO_PACK: dict[str, str] = {
    'Sanity Test - Playbook with Unmockable Whois Integration': 'Whois',
    'Sanity Test - Playbook with integration': 'HelloWorld',
    'Sanity Test - Playbook with no integration': 'HelloWorld',
    'Sanity Test - Playbook with mocked integration': 'HelloWorld',
}

DEFAULT_REPUTATION_TESTS: tuple[str, ...] = (
    'FormattingPerformance - Test',
    'reputations.json Test',
    'Indicators reputation-.json Test',
)

ALWAYS_INSTALLED_PACKS = (
    'Base',
    'DeveloperTools',
)

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
    FileType.RELEASE_NOTES_CONFIG,
    FileType.INCIDENT_TYPE,
    FileType.INCIDENT_FIELD,
    FileType.INDICATOR_FIELD,
    FileType.LAYOUT,
    FileType.WIDGET,
    FileType.DASHBOARD,
    FileType.REPORT,
    FileType.PARSING_RULE,
    FileType.MODELING_RULE,
    FileType.CORRELATION_RULE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.REPORT,
    FileType.GENERIC_TYPE,
    FileType.GENERIC_FIELD,
    FileType.GENERIC_MODULE,
    FileType.GENERIC_DEFINITION,
    FileType.PRE_PROCESS_RULES,
    FileType.JOB,
    FileType.CONNECTION,
    FileType.RELEASE_NOTES_CONFIG,
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
}

IGNORED_FILE_TYPES: set[FileType] = {
    FileType.README,
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
}
