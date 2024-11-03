from Forescout import dict_to_formatted_string

# disable-secrets-detection-start
example_dict = {
    'again': 'FsoDxgFGKJYhqNQPmWRY',
    'church': {
        'buy': 'omarjoseph@gmail.com',
        'cut': 14,
        'full': 6526,
        'go': 'pArcBeCGHYaqtfhFqVzU',
        'grow': 'gtaylor@hotmail.com',
        'month': '2009-08-11 16:42:51',
        'phone': 2311,
        'recent': 7775,
        'second': -66328998740807.2,
        'see': 'woodchristine@delgado-tucker.com',
        'some': 'TYuihvEVpjSzyzMdVlbc',
        'thus': 9646,
        'win': 6003
    },
    'investment': 'HEIWSzGzpPSVsBdIePAh',
    'line': 'lambertkevin@vincent-thomas.com',
    'maintain': 'KucNqjHoKxPVoKGhocyk',
    'production': 5507,
    'so': [
        9350,
        9854,
        'awznwdFCSyFiGcCEZRLS',
        7105,
        'mMRxcMllqqxMcrBaIaYX',
        'NrGaqvEJQSEVjkgGiglk',
        'UbuLUckTjNVemGIfGaDs',
        'ZOhHcMjlXpWgbNkdSrDP',
        'XWOejRXLOvujrZyPvTKp',
        4.7568,
        'http://gonzales.org/',
        2643
    ]
}
#  disable-secrets-detection-end


class TestDictToFormattedString:
    def test_dict_to_formatted_string_1(self):
        example_dict_string = dict_to_formatted_string(example_dict)
        assert not example_dict_string.startswith('{')
        assert not example_dict_string.endswith('}')
        assert '\'' not in example_dict_string
        assert '"' not in example_dict_string
