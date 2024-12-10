import demistomock as demisto
from CommonServerPython import *  # noqa: F401
import pytest
from typing import List, Dict, Any


def equals_object(obj1, obj2) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


class GetIndicator:
    def __init__(self, indicators: List[str]):
        self.__indicators = indicators

    def get_indicator(self, cmd: str, params: Dict[str, Any]) -> list:
        indicator = params.get('value')
        if indicator in self.__indicators:
            return [{'value': indicator}]
        return []


@pytest.mark.parametrize(argnames='encoded_indicators, existing_indicators, encoding, expected_results',
                         argvalues=[
                             (
                                 [
                                     '1.2.3.4'
                                 ],
                                 [
                                     '1.2.3.4'
                                 ],
                                 'none',
                                 [
                                     {
                                         'Indicator': '1.2.3.4',
                                         'EncodedIndicator': '1.2.3.4',
                                         'Exists': True,
                                     }
                                 ]
                             ),
                             (
                                 [
                                     'MS4yLjMuNA=='
                                 ],
                                 [
                                     '1.2.3.4'
                                 ],
                                 'base64',
                                 [
                                     {
                                         'Indicator': '1.2.3.4',
                                         'EncodedIndicator': 'MS4yLjMuNA==',
                                         'Exists': True,
                                     }
                                 ]
                             ),
                             (
                                 [
                                     '%2C'
                                 ],
                                 [
                                     ','
                                 ],
                                 'url-encoding',
                                 [
                                     {
                                         'Indicator': ',',
                                         'EncodedIndicator': '%2C',
                                         'Exists': True,
                                     }
                                 ]
                             ),
                             (
                                 '1.2.3.4, %2C, www.paloaltonetworks.com',
                                 [
                                     '1.2.3.4'
                                 ],
                                 'url-encoding',
                                 [
                                     {
                                         'Indicator': '1.2.3.4',
                                         'EncodedIndicator': '1.2.3.4',
                                         'Exists': True,
                                     },
                                     {
                                         'Indicator': ',',
                                         'EncodedIndicator': '%2C',
                                         'Exists': False,
                                     },
                                     {
                                         'Indicator': 'www.paloaltonetworks.com',
                                         'EncodedIndicator': 'www.paloaltonetworks.com',
                                         'Exists': False,
                                     }
                                 ]
                             ),
                             (
                                 '%61%61%61, aaa',
                                 [
                                     'aaa'
                                 ],
                                 'url-encoding',
                                 [
                                     {
                                         'Indicator': 'aaa',
                                         'EncodedIndicator': 'aaa',
                                         'Exists': True,
                                     }
                                 ]
                             ),
                             (
                                 'aaa, %61%61%61',
                                 [
                                     'aaa'
                                 ],
                                 'url-encoding',
                                 [
                                     {
                                         'Indicator': 'aaa',
                                         'EncodedIndicator': '%61%61%61',
                                         'Exists': True,
                                     }
                                 ]
                             ),
                             (
                                 [
                                     '1.2.3.4'
                                 ],
                                 [
                                 ],
                                 'none',
                                 [
                                     {
                                         'Indicator': '1.2.3.4',
                                         'EncodedIndicator': '1.2.3.4',
                                         'Exists': False,
                                     }
                                 ]
                             ),
                         ])
def test_check_indicators(mocker, encoded_indicators, existing_indicators, encoding, expected_results):
    """
        Given:
            Indicators to check and expected results

        When:
            Running script to check indictors.

        Then:
            Validate the right output returns.
    """
    from CheckIndicatorValue import check_indicators
    mocker.patch('CheckIndicatorValue.execute_command', side_effect=GetIndicator(existing_indicators).get_indicator)

    results = check_indicators(argToList(encoded_indicators), encoding)
    assert equals_object(results, expected_results)


def test_main(mocker):
    """
        Given:
            an indicator that exist in the DB.

        When:
            Running script to check an indictor.

        Then:
            Validate the right output returns.
    """
    from CheckIndicatorValue import main

    encoded_indicator = '1.2.3.4'
    decoded_indicator = '1.2.3.4'

    mocker.patch.object(demisto, 'args', return_value={
        'indicator': encoded_indicator,
        'encoding': 'none',
    })
    mocker.patch('CheckIndicatorValue.execute_command', return_value=[{'value': f'{decoded_indicator}'}])
    return_results = mocker.patch('CheckIndicatorValue.return_results')

    main()

    assert return_results.call_count == 1
    results = return_results.call_args[0][0].to_context()

    assert equals_object(results['EntryContext'], {
        'CheckIndicatorValue(val.Indicator && val.Indicator == obj.Indicator)': [{
            'Indicator': decoded_indicator,
            'EncodedIndicator': encoded_indicator,
            'Exists': True
        }]
    })
