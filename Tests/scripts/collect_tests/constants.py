import os
from demisto_sdk.commands.common.constants import FileType

from pathlib import Path

SKIPPED_PACKS = {'DeprecatedContent', 'NonSupported', 'ApiModules'}
MASTER = 'master'
CONTENT_PATH = Path(__file__).absolute().parents[3]
PACKS_PATH = CONTENT_PATH / 'Packs'
ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'
DEBUG_ID_SET_PATH = CONTENT_PATH / 'Utils' / 'tests' / 'id_set.json'
DEBUG_CONF_PATH = CONTENT_PATH / 'Tests' / 'conf.json'