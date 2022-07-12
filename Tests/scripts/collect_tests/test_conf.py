from collections import defaultdict
from pathlib import Path

from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               to_tuple)


class TestConf(DictFileBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self, conf_path: Path):
        super().__init__(conf_path, is_infrastructure=True)  # todo not use debug
        self.tests = tuple(TestConfItem(value) for value in self['tests'])
        self.test_ids = {test.playbook_id for test in self.tests}

        self.tests_to_integrations = {test.playbook_id: test.integrations for test in self.tests if test.integrations}
        self.integrations_to_tests = self._calculate_integration_to_tests()

        # Attributes
        self.skipped_tests_dict: dict = self['skipped_tests']  # todo use
        self.skipped_integrations_dict: dict[str, str] = self['skipped_integrations']  # todo is used?
        self.unmockable_integrations_dict: dict[str, str] = self['unmockable_integrations']  # todo is used?
        self.nightly_integrations: list[str] = self['nightly_integrations']  # todo is used?
        self.parallel_integrations: list[str] = self['parallel_integrations']  # todo is used?
        self.private_tests: list[str] = self['private_tests']  # todo is used?

        self.classifier_to_test = {
            test.classifier: test.playbook_id
            for test in self.tests if test.classifier
        }
        self.incoming_mapper_to_test = {
            test.incoming_mapper: test.playbook_id
            for test in self.tests if test.incoming_mapper
        }

    def _calculate_integration_to_tests(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for test, integrations in self.tests_to_integrations.items():
            for integration in integrations:
                result[integration].append(test)
        return dict(result)

    # def get_skipped_tests(self):  # todo is used?
    #     return tuple(self.get('skipped_tests', {}).keys())


class TestConfItem(DictBased):
    def __init__(self, dict_: dict):
        super().__init__(dict_)
        self.playbook_id: str = self['playbookID']

    @property
    def integrations(self) -> tuple[str]:
        return to_tuple(self.get('integrations', (), warn_if_missing=False))  # todo warn?

    @property
    def is_mockable(self):
        return self.get('is_mockable')

    @property
    def classifier(self):
        return self.get('instance_configuration', {}, warn_if_missing=False).get('classifier_id')

    @property
    def incoming_mapper(self):
        return self.content.get('instance_configuration', {}).get('incoming_mapper_id')
