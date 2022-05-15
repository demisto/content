import os
from pathlib import Path

from demisto_sdk.commands.common.constants import FileType

MASTER = 'master'  # todo use
CONTENT_PATH = Path(__file__).absolute().parents[3]
PACKS_PATH = CONTENT_PATH / 'Packs'
ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'  # todo use
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'  # todo use
DEBUG_ID_SET_PATH = CONTENT_PATH / 'Utils' / 'tests' / 'id_set.json'
DEBUG_CONF_PATH = CONTENT_PATH / 'Tests' / 'conf.json'
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
