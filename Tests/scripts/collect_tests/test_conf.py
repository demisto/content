from collections import defaultdict
from pathlib import Path
from typing import Optional

from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               to_tuple)


class TestConfItem(DictBased):
    def __init__(self, dict_: dict):
        super().__init__(dict_)
        self.playbook_id: str = self['playbookID']

    @property
    def integrations(self) -> tuple[str, ...]:
        return to_tuple(self.get('integrations', (), warn_if_missing=False))

    @property
    def has_api(self):
        # if there are no integrations- the test playbook is for a script and by default doesn't use api
        default_value = bool(self.integrations)
        return self.get('has_api', default_value, warn_if_missing=False)

    @property
    def scripts(self) -> tuple[str, ...]:
        return to_tuple(self.get('scripts', (), warn_if_missing=False))

    @property
    def classifier(self):
        return self.get('instance_configuration', {}, warn_if_missing=False).get('classifier_id')

    @property
    def incoming_mapper(self):
        return self.content.get('instance_configuration', {}).get('incoming_mapper_id')


class TestConf(DictFileBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self, conf_path: Path):
        super().__init__(conf_path, is_infrastructure=True)
        self.tests = tuple(TestConfItem(value) for value in self['tests'])
        self.test_id_to_test = {test.playbook_id: test
                                for test in self.tests}

        tests_to_integration_set: dict[str, set[str]] = defaultdict(set)
        for test in self.tests:
            tests_to_integration_set[test.playbook_id].update(test.integrations)
        self.tests_to_integrations: dict[str, tuple[str, ...]] = {
            test: tuple(sorted(test_integrations)) for test, test_integrations in tests_to_integration_set.items()
        }

        self.integrations_to_tests: dict[str, list[str]] = self._calculate_integration_to_tests()

        # Attributes
        self.skipped_tests: dict[str, str] = self['skipped_tests']
        self.skipped_integrations: dict[str, str] = self['skipped_integrations']
        self.private_tests: set[str] = set(self['private_tests'])
        self.nightly_packs: set[str] = set(self['nightly_packs'])

        self.classifier_to_test: dict[TestConfItem, str] = {
            test.classifier: test.playbook_id
            for test in self.tests if test.classifier
        }
        self.incoming_mapper_to_test: dict[TestConfItem, str] = {
            test.incoming_mapper: test.playbook_id
            for test in self.tests if test.incoming_mapper
        }

        self.non_api_tests = [test.playbook_id for test in self.tests if not test.has_api]

    def _calculate_integration_to_tests(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for test, integrations in self.tests_to_integrations.items():
            for integration in integrations:
                result[integration].append(test)
        return dict(result)

    def get_test(self, test_id: str) -> Optional[TestConfItem]:
        try:
            return self.test_id_to_test[test_id]
        except KeyError:
            # todo fix CIAC-4006
            logger.warning(f'test {test_id} is missing from conf.json, under `tests`')
            return None
