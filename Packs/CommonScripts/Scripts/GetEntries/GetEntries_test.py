import demistomock as demisto
from GetEntries import main
import json


class SideEffectExecuteCommand:
    def __init__(self, ents):
        self.__ents = ents

    def execute_command(self, cmd, args, extract_contents=True, fail_on_error=True):
        assert cmd == 'getEntries'
        return self.__ents


class TestGetEntries:
    def test_main(self, mocker):
        original_ents = [{
            'ID': 'test-ID',
            'Type': 'test-Type',
            'Metadata': {
                'tags': 'test-tags',
                'category': 'test-category',
                'created': 'test-created',
                'modified': 'test-modified'
            }
        }]
        output_ents = {
            'Entry': [{
                'ID': 'test-ID',
                'Type': 'test-Type',
                'Tags': 'test-tags',
                'Category': 'test-category',
                'Created': 'test-created',
                'Modified': 'test-modified'
            }]
        }

        mocker.patch('GetEntries.execute_command', side_effect=SideEffectExecuteCommand(original_ents).execute_command)
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        entry_context = results.get('EntryContext')
        assert json.dumps(entry_context) == json.dumps(output_ents)

    def test_main_no_ents(self, mocker):
        original_ents = []

        mocker.patch('GetEntries.execute_command', side_effect=SideEffectExecuteCommand(original_ents).execute_command)
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        if isinstance(results, dict):
            assert not results.get('EntryContext')
