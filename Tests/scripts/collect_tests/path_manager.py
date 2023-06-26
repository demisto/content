import logging
import os
from pathlib import Path
from typing import Iterable, Union

from git import InvalidGitRepositoryError, Repo

_SANITY_FILES_FOR_GLOB = (
    # if any of the files under this list (or descendants) is changed, and no other files are changed,
    # sanity test will be run. All other files NOT under /Packs are ignored.
    '.gitlab',
    'Documentation',
    'Tests/tools.py',
    'Tests/update_content_data.py',
    'Tests/Marketplace',
    'Tests/private_build',
    'Tests/scripts'
)


class PathManager:
    """
    Used for getting paths of various files and folders during the test collection process.
    """
    ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))

    def __init__(self, content_path: Path):
        self.content_path = content_path
        try:
            self.content_repo = Repo(content_path)
        except InvalidGitRepositoryError:
            if not os.getenv('UNIT_TESTING'):
                raise
            self.content_repo = None  # type: ignore[assignment]
        logging.debug(f'PathManager uses {self.content_path.resolve()=}, {PathManager.ARTIFACTS_PATH.resolve()=}')

        self.packs_path = self.content_path / 'Packs'
        self.files_triggering_sanity_tests = self._glob(_SANITY_FILES_FOR_GLOB)

        content_root_files = set(filter(lambda f: f.is_file(), self.content_path.iterdir()))
        non_content_files = self._glob(
            filter(lambda p: p.is_dir() and p.name != 'Packs', self.content_path.iterdir()))  # type: ignore[arg-type, union-attr]
        non_content = non_content_files | content_root_files

        infrastructure_test_data = self._glob(('Tests/scripts/infrastructure_tests/tests_data',))

        self.files_to_ignore = (non_content | infrastructure_test_data) - self.files_triggering_sanity_tests

        self.id_set_path = PathManager.ARTIFACTS_PATH / 'id_set.json'
        self.conf_path = PathManager.ARTIFACTS_PATH / 'conf.json'
        self.output_tests_file = PathManager.ARTIFACTS_PATH / 'filter_file.txt'
        self.output_modeling_rules_to_test_file = PathManager.ARTIFACTS_PATH / 'modeling_rules_to_test.txt'
        self.output_packs_file = PathManager.ARTIFACTS_PATH / 'content_packs_to_install.txt'
        self.output_packs_to_upload_file = PathManager.ARTIFACTS_PATH / 'content_packs_to_upload.txt'
        self.output_machines_file = PathManager.ARTIFACTS_PATH / 'filter_envs.json'

    def _glob_single(self, relative_path: str) -> set[Path]:
        """
        :param relative_path: string representing a path relative to content
        :return: all files under the path (if folder)
                OR all files matching the pattern (if '*' in path)
                OR a set including the file (in case it's a single file)
        """
        result: set[Path] = set()
        path = self.content_path / relative_path

        if not path.exists():
            logging.error(f'could not find {path} for calculating excluded paths')
        elif path.is_dir():
            result.update((_ for _ in path.rglob('*') if _.is_file()))
        elif '*' in path.name:
            result.update((_ for _ in path.rglob(path.name) if _.is_file()))
        elif path.is_file() and '*' not in path.name:
            result.add(path)
        else:
            logging.error(f'could not glob {path} - unexpected case')
        return set(result)

    def _glob(self, paths: Iterable[Union[str, Path]]) -> set[Path]:
        """
        :param paths: to glob
        :return: set of all results
        """
        result = set()
        for path in paths:
            result.update(self._glob_single(str(path)))
        return result
