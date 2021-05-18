import pytest
import demistomock as demisto

from IncidentsCheck_NumberofIncidentsNoOwner import main, RED_HTML_STYLE, GREEN_HTML_STYLE


@pytest.mark.parametrize('incident_ids, expected', [
    (['1', '2', '3'], f"<h1 style={RED_HTML_STYLE}3</h1>"),
    (['2'], f"<h1 style={RED_HTML_STYLE}1</h1>"),
    ([], f"<h1 style={GREEN_HTML_STYLE}0</h1>"),
    (None, f"<h1 style={GREEN_HTML_STYLE}0</h1>")
])
def test_script(mocker, incident_ids, expected):
    mocker.patch.object(demisto, 'incidents', return_value=[{'CustomFields': {'unassignedincidents': incident_ids}}])
    mocker.patch.object(demisto, 'results')

    main()

    html = demisto.results.call_args[0][0].get('Contents')
    assert html == expected
