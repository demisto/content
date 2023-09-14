import pytest


@pytest.mark.parametrize('resCmd, expected', [
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': 2}}], [{'Type': 1,
                                    'ContentsFormat': 'json',
                                    'Contents': 1,
                                    'EntryContext': {
                                        'DBotScore': {
                                            'Indicator': 'CVE-2023-1111',
                                            'Type': 'CVE',
                                            'Score': 1,
                                            'Vendor': 'DBot'}}}]),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': 5}}], [{'Type': 1,
                                    'ContentsFormat': 'json',
                                    'Contents': 2,
                                    'EntryContext': {
                                        'DBotScore': {
                                            'Indicator': 'CVE-2023-1111',
                                            'Type': 'CVE',
                                            'Score': 2,
                                            'Vendor': 'DBot'}}}]),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': 9}}], [{'Type': 1,
                                    'ContentsFormat': 'json',
                                    'Contents': 3,
                                    'EntryContext': {
                                        'DBotScore': {
                                            'Indicator': 'CVE-2023-1111',
                                            'Type': 'CVE',
                                            'Score': 3,
                                            'Vendor': 'DBot'}}}]),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': -1}}], [{'Type': 1,
                                     'ContentsFormat': 'json',
                                     'Contents': 0,
                                     'EntryContext': {
                                         'DBotScore': {
                                             'Indicator': 'CVE-2023-1111',
                                             'Type': 'CVE',
                                             'Score': 0,
                                             'Vendor': 'DBot'}}}]),
    ([{}, {'Contents': {'id': 'CVE-2023-1111',
                        'cvss': 7}}], [{'Type': 1,
                                        'ContentsFormat': 'json',
                                        'Contents': 3,
                                        'EntryContext': {
                                            'DBotScore': {
                                                'Indicator': 'CVE-2023-1111',
                                                'Type': 'CVE',
                                                'Score': 3,
                                                'Vendor': 'DBot'}}}]),
    ([], []),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': None}}], [{'Type': 1,
                                       'ContentsFormat': 'json',
                                       'Contents': 0,
                                       'EntryContext': {
                                           'DBotScore': {
                                               'Indicator': 'CVE-2023-1111',
                                               'Type': 'CVE',
                                               'Score': 0,
                                               'Vendor': 'DBot'}}}]),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': {'Score': 7}}}], [{'Type': 1,
                                               'ContentsFormat': 'json',
                                               'Contents': 3,
                                               'EntryContext': {
                                                   'DBotScore': {
                                                       'Indicator': 'CVE-2023-1111',
                                                       'Type': 'CVE',
                                                       'Score': 3,
                                                       'Vendor': 'DBot'}}}]),
    ([{'Contents': {'id': 'CVE-2023-1111',
                    'cvss': {'Score': None}}}], [{'Type': 1,
                                                  'ContentsFormat': 'json',
                                                  'Contents': 0,
                                                  'EntryContext': {
                                                      'DBotScore': {
                                                          'Indicator': 'CVE-2023-1111',
                                                          'Type': 'CVE',
                                                          'Score': 0,
                                                          'Vendor': 'DBot'}}}]),
])
def test_get_dbot_score(resCmd, expected):
    from CveReputationV2 import get_dbot_score
    assert get_dbot_score(resCmd) == expected
