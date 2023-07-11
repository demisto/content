import pytest
import demistomock as demisto
from CVECVSSColor import *


@pytest.mark.parametrize('cvss, color', [(10, '#FF4040'), (6, '#FFA07A'), (1, '#50C878'), (0, '#000000')])
def test_cvss_color(cvss, color):
    """
    Given:
        A CVSS score in the correct structure within the context

    When:
        The script is called

    Then:
        return a color in hef format
    """

    from CVECVSSColor import get_color
    assert get_color(cvss) == color


@pytest.mark.parametrize('context, result', [({"args": {"indicator": {"CustomFields": {"cvssscore": "7.1"}}},
                                               "context": {"User": {"theme": "dark"}}}, '# <-:->{{color:#FF6347}}(**7.1**)'),
                                             ({"args": {"indicator": {"CustomFields": {"cvssscore": ""}}},
                                               "context": {"User": {"theme": "dark"}}}, '# <-:->{{color:#FFFFFF}}(**N\\A**)'),
                                             ({"args": {"indicator": {"CustomFields": {"cvssscore": ""}}},
                                               "context": {"User": {"theme": "light"}}}, '# <-:->{{color:#000000}}(**N\\A**)'),
                                             ({"args": {"indicator": {"CustomFields": {"cvssscore": None}}},
                                               "context": {"User": {"theme": "light"}}}, '# <-:->{{color:#000000}}(**N\\A**)'),
                                             ({"args": {"indicator": {"CustomFields": {"cvssscore": 7.1}}},
                                               "context": {"User": {"theme": "light"}}}, '# <-:->{{color:#FF6347}}(**7.1**)'),
                                             ])
def test_main(mocker, context, result):
    mocker.patch.object(demisto, 'callingContext', new=context)
    results_mock = mocker.patch.object(demisto, 'results')
    main()

    results = results_mock.call_args[0]

    assert results[0]['HumanReadable'] == result
