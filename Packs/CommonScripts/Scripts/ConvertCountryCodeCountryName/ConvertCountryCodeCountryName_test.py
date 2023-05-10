import pytest

import ConvertCountryCodeCountryName
import demistomock as demisto


upper_country_code = ('IL', None, 'Israel')
lower_country_code = ('il', None, 'Israel')
mixed_country_code = ('tT', None, 'Trinidad and Tobago')
regular_country_name = (None, 'Kenya', 'KE')
lower_long_country_name = (None, 'trinidad and tobago', 'TT')


@pytest.mark.parametrize('country_code, country_name, expected_result', [upper_country_code,
                                                                         lower_country_code,
                                                                         mixed_country_code,
                                                                         regular_country_name,
                                                                         lower_long_country_name,
                                                                         ])
def test_valid_convert_country_code_country_name(mocker, country_code, country_name, expected_result):
    mocker.patch.object(demisto, 'args', return_value={'country_code': country_code, 'country_name': country_name})
    return_results_mocker = mocker.patch.object(ConvertCountryCodeCountryName, 'return_results')

    ConvertCountryCodeCountryName.main()
    return_results_mocker.assert_called_once_with(expected_result)


both_provided = ('IL', 'Israel', 'Only one of country_code or country_name can be provided.')
invalid_country_code = ('invalid', None, 'Invalid Country Code')
invalid_country_name = (None, 'Invalid', 'Invalid Country Name')


@pytest.mark.parametrize('country_code, country_name, expected_error', [both_provided,
                                                                        invalid_country_code,
                                                                        invalid_country_name,
                                                                        ])
def test_invalid_convert_country_code_country_name(mocker, country_code, country_name, expected_error):
    mocker.patch.object(demisto, 'args', return_value={'country_code': country_code, 'country_name': country_name})
    return_error_mocker = mocker.patch.object(ConvertCountryCodeCountryName, 'return_error')

    ConvertCountryCodeCountryName.main()
    return_error_mocker.assert_called_once_with(f'Failed to execute ConvertCountryCodeCountryName. Error: {expected_error}')
