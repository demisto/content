import os
from pathlib import Path
from typing import Iterable

from demisto_sdk.commands.common.constants import MarketplaceVersions, FileType

MASTER = 'master'  # todo use
CONTENT_PATH = Path(__file__).absolute().parents[3]
PACKS_PATH = CONTENT_PATH / 'Packs'
ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'  # todo use
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'  # todo use
DEBUG_ID_SET_PATH = CONTENT_PATH / 'Tests' / 'id_set.json'
DEBUG_CONF_PATH = CONTENT_PATH / 'Tests' / 'conf.json'
OUTPUT_TESTS = ARTIFACTS_PATH / 'filter_file.txt'
OUTPUT_PACKS = ARTIFACTS_PATH / 'content_packs_to_install.txt'
XSOAR_SANITY_TEST_NAMES = (
    'Sanity Test - Playbook with integration',
    'Sanity Test - Playbook with no integration',
    'Sanity Test - Playbook with mocked integration',
    'Sanity Test - Playbook with Unmockable Integration',
)
DEFAULT_REPUTATION_TESTS = (
    'FormattingPerformance - Test',
    'reputations.json Test',
    'Indicators reputation-.json Test'
)
DEFAULT_MARKETPLACE_WHEN_MISSING: MarketplaceVersions = MarketplaceVersions.XSOAR

SKIPPED_CONTENT_ITEMS = {
    # these are not under packs, and are not supported anymore.
    'playbook-Jask_Test-4.0.0.yml'
}


def _calculate_excluded_files() -> set[Path]:
    def glob(paths: Iterable[str]):
        result = []
        for partial_path in paths:
            path = CONTENT_PATH / partial_path

            if path.is_dir():
                result.extend(path.glob('*'))
            elif '*' in path.name:
                result.extend(path.parent.glob(path.name))
            elif not path.exists():
                raise FileNotFoundError(path)
            else:
                result.append(path)
        return set(result)

    excluded = glob((
        'Tests',
        '.gitlab',
        'Documentation',
        'dev-requirements*',
    ))
    not_excluded = glob((
        'Tests/scripts/infrastructure_tests',
        'Tests/Marketplace/Tests',
        'Tests/tests',
        'Tests/setup',
        'Tests/sdknightly',
        'Tests/known_words.txt',
        'Tests/secrets_white_list.json',
    ))

    return excluded - not_excluded


EXCLUDED_FILES = _calculate_excluded_files()

ONLY_INSTALL_PACK = {
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
