from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions

XSOAR_SANITY_TEST_NAMES: tuple[str, ...] = (
    'Sanity Test - Playbook with integration',
    'Sanity Test - Playbook with no integration',
    'Sanity Test - Playbook with mocked integration',
    'Sanity Test - Playbook with Unmockable Whois Integration',
)
DEFAULT_REPUTATION_TESTS: tuple[str, ...] = (
    'FormattingPerformance - Test',
    'reputations.json Test',
    'Indicators reputation-.json Test',
)
DEFAULT_MARKETPLACE_WHEN_MISSING: MarketplaceVersions = MarketplaceVersions.XSOAR

SKIPPED_CONTENT_ITEMS: set[str] = {
    # these are not under packs, and are not supported anymore.
    'playbook-Jask_Test-4.0.0.yml'
    'playbook-Recorded_Future_Test_4_0.yml',
    'playbook-TestCommonPython_4_1.yml',
}

ONLY_INSTALL_PACK: set[FileType] = {
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
}
