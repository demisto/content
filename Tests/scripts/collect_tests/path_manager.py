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
        logging.debug(f'PathManager uses {self.content_path.resolve()=}, {PathManager.ARTIFACTS_PATH.resolve()=}')

        self.packs_path = self.content_path / 'Packs'
        self.excluded_files = _calculate_excluded_files(self.content_path)

        self.id_set_path = PathManager.ARTIFACTS_PATH / 'id_set.json'
        self.conf_path = PathManager.ARTIFACTS_PATH / 'conf.json'
        self.output_tests_file = PathManager.ARTIFACTS_PATH / 'filter_file_v2.txt'
        self.output_packs_file = PathManager.ARTIFACTS_PATH / 'content_packs_to_install_v2.txt'
        self.output_machines_file = PathManager.ARTIFACTS_PATH / 'filter_envs_v2.json'


def _calculate_excluded_files(content_path: Path) -> set[Path]:
    """
    :param content_path: path to the content root
    :return: set of Paths that should be excluded from test collection
    """

    excluded = glob(
        content_path,
        (
            'Tests',
            '.gitlab',
            'Documentation',
        )
    )
    not_excluded = glob(
        content_path,
        (
            'Tests/scripts/infrastructure_tests',
            'Tests/Marketplace/Tests',
            'Tests/tests',
            'Tests/scripts/collect_tests',
            'Tests/setup',
            'Tests/sdknightly',
            'Tests/known_words.txt',
            'Tests/secrets_white_list.json',
        )
    )

    logging.debug(f'not excluded: {not_excluded}')
    logging.debug(f'excluded paths: {excluded - not_excluded}')
    return excluded - not_excluded


def glob(content_path: Path, paths: Iterable[str]) -> set[Path]:
    result: list[Path] = []
    for partial_path in paths:
        path = content_path / partial_path

        if path.is_dir():
            result.extend((_ for _ in path.rglob('*') if _.is_file()))
        elif '*' in path.name:
            result.extend((_ for _ in path.rglob(path.name) if _.is_file()))
        elif not path.exists():
            logging.error(f'could not find {path} for calculating excluded paths')
            continue
        else:  # file without *s
            result.append(path)
    return set(result)
