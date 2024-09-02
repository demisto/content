from VerdictResult import main
import demistomock as demisto
import pytest


@pytest.mark.parametrize(
    'verdict, html',
    [
        ('Malicious', '<h1 style=color:#FF1744;text-align:center;font-size:300%;padding-top:1em>Malicious</h1>'),
        ('Non-Malicious', '<h1 style=color:#00CD33;text-align:center;font-size:300%;padding-top:1em>Non-Malicious</h1>'),
        ('Suspicious', '<h1 style=color:#FF9000;text-align:center;font-size:300%;padding-top:1em>Suspicious</h1>'),
        ('blabla', '<h1 style=color:#808080;text-align:center;font-size:300%;padding-top:1em>Not Determined</h1>')
    ]
)
def test_main(mocker, verdict, html):
    mocker.patch.object(demisto, 'incidents', return_value=[{'CustomFields': {'verdict': verdict}}])
    mock_results = mocker.patch.object(demisto, 'results')
    main()
    assert mock_results.call_args[0][0]['Contents'] == html
