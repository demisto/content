
from YaraScan import main
import demistomock as demisto
from CommonServerPython import entryTypes


def test_main(mocker):
    rule = '''rule PE_file_identifier
{
    meta:
        author = "Adam Burt"
        description = "Detects PE files"
        date = "12/08/2016"

    strings:
        $MZ = "MZ" ascii

    condition:
        $MZ at 0
}'''

    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/unzip.exe',
                        'name': 'unzip.exe',
                        'ID': 'testfileid'
                    }
                }
            ]
        else:
            raise ValueError(f'Unimplemented command called: {name}')

    mocker.patch.object(demisto, 'args', return_value={
        'entryIDs': 'test',
        'yaraRule': rule
    })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['Contents'][0]['HasMatch']
    assert results[0]['Contents'][0]['Matches'][0]['RuleName'] == 'PE_file_identifier'
