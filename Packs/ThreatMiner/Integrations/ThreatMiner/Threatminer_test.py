import json
import pytest
import demistomock as demisto
from ThreatMiner import file_command

def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)

def test_file(mocker):
    mocker.patch.object(demisto, 'params', return_value={'threat_miner_url': 'https://api.threatminer.org/v2/',
                                                            'verify_certificates': True,
                                                            'reliability': 'C - Fairly reliable',
                                                            'max_array_size': 30,
                                                            'proxy': False
                                                         })
    args = {
        'threat_miner_url': 'https://api.threatminer.org/v2/',
        'verify_certificates': True,
        'reliability': 'C - Fairly reliable',
        'max_array_size': 30
    }
    res = file_command(**args)
    print(res)
