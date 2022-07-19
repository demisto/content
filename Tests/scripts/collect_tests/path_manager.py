import logging
from os import getenv
from pathlib import Path
from typing import Iterable


class PathManager:
    """
    Used for getting paths of various files and folders during the test collection process.
    """

    ARTIFACTS_PATH = Path(getenv('ARTIFACTS_FOLDER', './artifacts'))

    def __init__(self, content_path: Path):
        self.content_path = content_path
        self.excluded_files = _calculate_excluded_files(self.content_path)

    @property
    def packs_path(self):
        return self.content_path / 'Packs'

    @property
    def artifacts_path(self):
        return PathManager.ARTIFACTS_PATH

    @property
    def id_set_path(self):
        return PathManager.ARTIFACTS_PATH / 'id_set.json'

    @property
    def artifacts_conf_path(self):
        return PathManager.ARTIFACTS_PATH / 'conf.json'

    @property
    def debug_id_set_path(self):
        return self.content_path / 'Tests' / 'id_set.json'

    @property
    def debug_conf_path(self):
        return self.content_path / 'Tests' / 'conf.json'

    @property
    def output_tests_file(self):
        return PathManager.ARTIFACTS_PATH / 'filter_file_new.txt'  # todo change

    @property
    def output_packs_file(self):
        return PathManager.ARTIFACTS_PATH / 'content_packs_to_install_new.txt'  # todo change


def _calculate_excluded_files(content_path: Path) -> set[Path]:
    """
    :param content_path: path to the content root
    :return: set of Paths that should be excluded from test collection
    """

    def glob(paths: Iterable[str]):
        result: list[Path] = []
        for partial_path in paths:
            path = content_path / partial_path

            if path.is_dir():
                result.extend(path.glob('*'))
            elif '*' in path.name:
                result.extend(path.parent.glob(path.name))
            elif not path.exists():
                logging.warning(
                    f'could not find {path} for calculating excluded paths'
                )
                continue
            else:
                result.append(path)
        return set(result)

    excluded = glob(
        (
            'Tests',
            '.gitlab',
            'Documentation',
            'dev-requirements*',
        )
    )
    not_excluded = glob(
        (
            'Tests/scripts/infrastructure_tests',
            'Tests/Marketplace/Tests',
            'Tests/tests',
            'Tests/setup',
            'Tests/sdknightly',
            'Tests/known_words.txt',
            'Tests/secrets_white_list.json',
        )
    )

    return excluded - not_excluded
