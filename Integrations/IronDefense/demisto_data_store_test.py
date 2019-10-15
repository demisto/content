import unittest
import demistomock as demisto
from IronDefense import DemistoDataStore
from unittest import TestCase
import mock


class DemistoDataStoreTest(TestCase):

    def setUp(self):
        self.class_under_test = DemistoDataStore(demisto)

    @mock.patch('demistomock.command')
    def test_init(self, mock_command):

        mock_command.return_value = 'fetch-incidents'
        class_under_test = DemistoDataStore(demisto)
        self.assertEqual(DemistoDataStore.DataStoreMethod.LAST_RUN, class_under_test.data_store_method,
                         'Incorrect datastore method: Should be LAST_RUN')

        mock_command.return_value = 'some-command'
        class_under_test = DemistoDataStore(demisto)
        self.assertEqual(DemistoDataStore.DataStoreMethod.CONTEXT, class_under_test.data_store_method,
                         'Incorrect datastore method: Should be CONTEXT')

        mock_command.return_value = 'test-module'
        class_under_test = DemistoDataStore(demisto)
        self.assertEqual(None, class_under_test.data_store_method, 'Incorrect datastore method: Should be None')

    @mock.patch('demistomock.results', autospec=True)
    def test_set_context(self, mock_results):
        key = 'somekey'
        value = 'somevalue'
        msg = 'somemsg'

        self.class_under_test.set_context(key, value, msg=msg)

        mock_results.assert_called_once_with({
            'Type': 1,
            'Contents': msg,
            'ContentsFormat': 'text',
            'EntryContext': {key: [value]}
        })

    def test_set_last_run(self):
        key = 'somekey'
        value = 'somevalue'

        self.class_under_test.set_last_run(key, value)
        self.assertEqual(value, self.class_under_test.last_run[key], 'Unexpected value set')

    def test_get(self):
        key1 = 'somekey'
        value1 = 'somevalue'
        key2 = 'somekey2'
        value2 = 'somevalue2'

        self.class_under_test.last_run = {key1: value1}
        self.class_under_test.context = {key2: value2}

        # Test last run data store
        self.class_under_test.data_store_method = DemistoDataStore.DataStoreMethod.LAST_RUN
        self.assertEqual(value1, self.class_under_test.get(key1), 'Retrieved unexpected value')

        # Test context data store
        self.class_under_test.data_store_method = DemistoDataStore.DataStoreMethod.CONTEXT
        self.assertEqual(value2, self.class_under_test.get(key2), 'Retrieved unexpected value')


if __name__ == '__main__':
    unittest.main()
