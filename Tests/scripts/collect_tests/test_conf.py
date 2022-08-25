from collections import defaultdict
from pathlib import Path

from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               to_tuple)


class TestConf(DictFileBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self, conf_path: Path):
        super().__init__(conf_path, is_infrastructure=True)
        self.tests = tuple(TestConfItem(value) for value in self['tests'])
        self.test_ids = {test.playbook_id for test in self.tests}

        self.tests_to_integrations: dict[str, tuple[str]] = {
            test.playbook_id: test.integrations for test in self.tests if test.integrations
        }
        self.integrations_to_tests: dict[str, list[str]] = self._calculate_integration_to_tests()

        # Attributes
        self.skipped_tests: dict[str, str] = self['skipped_tests']
        self.skipped_integrations: dict[str, str] = self['skipped_integrations']
        self.private_tests: set[str] = set(self['private_tests'])
        self.nightly_integrations: set[str] = set(self['nightly_integrations'])
        self.nightly_packs: set[str] = set(self['nightly_packs'])

        self.classifier_to_test: dict[TestConfItem, str] = {
            test.classifier: test.playbook_id
            for test in self.tests if test.classifier
        }
        self.incoming_mapper_to_test: dict[TestConfItem, str] = {
            test.incoming_mapper: test.playbook_id
            for test in self.tests if test.incoming_mapper
        }

        self.non_api_tests = [test.playbook_id for test in self.tests if test.non_api]

    def _calculate_integration_to_tests(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for test, integrations in self.tests_to_integrations.items():
            for integration in integrations:
                result[integration].append(test)
        return dict(result)


class TestConfItem(DictBased):
    def __init__(self, dict_: dict):
        super().__init__(dict_)
        self.playbook_id: str = self['playbookID']

    @property
    def non_api(self):
        return self.get('non_api', False, warn_if_missing=False)

    @property
    def integrations(self) -> tuple[str]:
        return to_tuple(self.get('integrations', (), warn_if_missing=False))

    @property
    def classifier(self):
        return self.get('instance_configuration', {}, warn_if_missing=False).get('classifier_id')

    @property
    def incoming_mapper(self):
        return self.content.get('instance_configuration', {}).get('incoming_mapper_id')
